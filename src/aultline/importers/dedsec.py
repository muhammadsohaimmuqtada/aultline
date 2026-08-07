from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from aultline.graph import ApplicationGraph, stable_id


class DedsecImportError(ValueError):
    """Raised when a DEDSEC report cannot be safely loaded or interpreted."""


@dataclass(frozen=True)
class DedsecImportResult:
    graph: ApplicationGraph
    scan_id: str | None
    schema_version: str | None
    warnings: tuple[str, ...]
    source_path: str


def _endpoint_key(method: str, url: str) -> str:
    parsed = urlsplit(url)
    return f"{method.upper()} {parsed.path or '/'}"


def _object_tokens(url: str) -> list[str]:
    parsed = urlsplit(url)
    tokens: list[str] = []
    for segment in parsed.path.split("/"):
        value = segment.strip()
        if not value:
            continue
        if value.isdigit() or (len(value) >= 8 and any(ch.isdigit() for ch in value)):
            tokens.append(value)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower = name.lower()
        if lower == "id" or lower.endswith("_id") or lower.endswith("id"):
            tokens.append(f"{name}={value}")
    return tokens


class DedsecImporter:
    """Import a DEDSEC schema-3 report into Aultline's unified graph.

    Importing evidence is deliberately separate from declaring vulnerabilities.
    Candidate surfaces remain observations until Aultline analysis and validation
    produce sufficient differential evidence.
    """

    SUPPORTED_SCHEMA_MAJOR = "3"

    def load(self, path: str | Path) -> DedsecImportResult:
        source = Path(path).expanduser().resolve()
        if not source.exists():
            raise DedsecImportError(f"report not found: {source}")
        if not source.is_file():
            raise DedsecImportError(f"report path is not a file: {source}")

        try:
            with source.open("r", encoding="utf-8") as handle:
                report = json.load(handle)
        except json.JSONDecodeError as exc:
            raise DedsecImportError(
                f"invalid JSON report: {source} (line {exc.lineno}, column {exc.colno})"
            ) from None
        except UnicodeDecodeError:
            raise DedsecImportError(f"report is not valid UTF-8 JSON: {source}") from None
        except OSError as exc:
            raise DedsecImportError(f"unable to read report: {source}: {exc}") from None

        if not isinstance(report, dict):
            raise DedsecImportError(f"report root must be a JSON object: {source}")
        return self.ingest(report, source_path=str(source))

    def ingest(self, report: dict[str, Any], *, source_path: str = "<memory>") -> DedsecImportResult:
        graph = ApplicationGraph()
        warnings: list[str] = []
        schema = str(report.get("schema_version") or "") or None
        if schema and schema.split(".", 1)[0] != self.SUPPORTED_SCHEMA_MAJOR:
            warnings.append(f"unexpected DEDSEC schema version: {schema}")

        scan_id = report.get("scan_id")
        target = report.get("target") or {}
        target_url = str(target.get("url") or "")
        domain = str(target.get("domain") or "")
        target_node = graph.upsert_node(
            "target",
            target_url or domain or "unknown",
            attributes={"domain": domain, "scan_id": scan_id, "schema_version": schema},
            sources=("dedsec:target",),
        )

        workspace = report.get("workspace") or {}
        id_map: dict[str, str] = {}

        for asset in workspace.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            old_id = str(asset.get("id") or "")
            node = graph.upsert_node(
                str(asset.get("kind") or "asset"),
                str(asset.get("key") or old_id or "unknown"),
                attributes=dict(asset.get("attributes") or {}),
                sources=tuple(asset.get("sources") or ("dedsec:asset",)),
            )
            if old_id:
                id_map[old_id] = node.id
            graph.link(target_node.id, node.id, "contains_surface")

        for identity in workspace.get("identities") or []:
            if not isinstance(identity, dict):
                continue
            old_id = str(identity.get("id") or "identity-unknown")
            node = graph.upsert_node(
                "identity",
                old_id,
                attributes={
                    "label": identity.get("label"),
                    "kind": identity.get("kind"),
                    "role": identity.get("role"),
                    "tenant": identity.get("tenant"),
                    "authenticated": identity.get("authenticated"),
                },
                sources=("dedsec:identity",),
            )
            id_map[old_id] = node.id

        for request in workspace.get("requests") or []:
            if not isinstance(request, dict):
                continue
            method = str(request.get("method") or "GET").upper()
            url = str(request.get("url") or "")
            request_id = str(request.get("id") or stable_id("request", {"method": method, "url": url}))
            insertion_points = list(request.get("insertion_points") or [])
            request_node = graph.upsert_node(
                "request",
                request_id,
                attributes={
                    "method": method,
                    "url": url,
                    "source": request.get("source"),
                    "tags": list(request.get("tags") or []),
                    "metadata": dict(request.get("metadata") or {}),
                    "insertion_points": insertion_points,
                    "object_tokens": _object_tokens(url),
                },
                sources=(f"dedsec:request:{request.get('source') or 'unknown'}",),
            )
            endpoint = graph.upsert_node(
                "endpoint",
                _endpoint_key(method, url),
                attributes={
                    "method": method,
                    "url": url,
                    "path": urlsplit(url).path or "/",
                    "query_parameters": sorted({name for name, _ in parse_qsl(urlsplit(url).query)}),
                    "object_tokens": _object_tokens(url),
                },
                sources=("dedsec:request",),
            )
            graph.link(target_node.id, endpoint.id, "exposes_endpoint")
            graph.link(request_node.id, endpoint.id, "observes_endpoint")

            identity_id = str(request.get("identity_id") or "identity-anonymous")
            identity_node = graph.upsert_node(
                "identity",
                identity_id,
                attributes={"authenticated": identity_id != "identity-anonymous"},
                sources=("dedsec:request",),
            )
            graph.link(identity_node.id, request_node.id, "issued_request")
            graph.link(identity_node.id, endpoint.id, "observed_endpoint")

            for point in insertion_points:
                if not isinstance(point, dict):
                    continue
                point_key = f"{request_id}:{point.get('location')}:{point.get('name')}"
                point_node = graph.upsert_node(
                    "input",
                    point_key,
                    attributes=dict(point),
                    sources=("dedsec:insertion-point",),
                )
                graph.link(endpoint.id, point_node.id, "accepts_input")

        for observation in workspace.get("observations") or []:
            if not isinstance(observation, dict):
                continue
            obs_id = str(observation.get("id") or stable_id("observation", observation))
            obs_node = graph.upsert_node(
                "observation",
                obs_id,
                attributes={
                    "category": observation.get("category"),
                    "classification": observation.get("classification"),
                    "confidence": observation.get("confidence"),
                    "severity": observation.get("severity"),
                    "title": observation.get("title"),
                    "evidence": dict(observation.get("evidence") or {}),
                },
                sources=(f"dedsec:observation:{observation.get('source') or 'unknown'}",),
            )
            graph.link(target_node.id, obs_node.id, "has_observation")
            request_id = str(observation.get("request_id") or "")
            if request_id:
                request_node = next((n for n in graph.by_kind("request") if n.key == request_id), None)
                if request_node:
                    graph.link(request_node.id, obs_node.id, "produced_observation")

        for edge in workspace.get("edges") or []:
            if not isinstance(edge, dict):
                continue
            source_id = id_map.get(str(edge.get("source_id") or ""))
            target_id = id_map.get(str(edge.get("target_id") or ""))
            if source_id and target_id:
                graph.link(
                    source_id,
                    target_id,
                    str(edge.get("relation") or "related_to"),
                    attributes=dict(edge.get("metadata") or {}),
                )

        project_diff = report.get("project_diff") or {}
        if project_diff:
            diff_node = graph.upsert_node(
                "historical-diff",
                str(scan_id or "current"),
                attributes=project_diff,
                sources=("dedsec:project-diff",),
            )
            graph.link(target_node.id, diff_node.id, "has_historical_diff")

        return DedsecImportResult(
            graph=graph,
            scan_id=str(scan_id) if scan_id else None,
            schema_version=schema,
            warnings=tuple(warnings),
            source_path=source_path,
        )
