from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

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


_STATIC_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mp3",
    ".mp4",
    ".ogg",
    ".pdf",
    ".png",
    ".svg",
    ".ttf",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.IGNORECASE)
_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def _canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))
    return path


def _endpoint_key(method: str, url: str) -> str:
    return f"{method.upper()} {_canonical_url(url)}"


def _split_endpoint_asset(key: str, attributes: dict[str, Any]) -> tuple[str, str] | None:
    raw = key.strip()
    if not raw:
        return None
    parts = raw.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _HTTP_METHODS:
        return parts[0].upper(), parts[1]
    method = str(attributes.get("method") or "").upper()
    url = str(attributes.get("url") or "")
    if method in _HTTP_METHODS and url:
        return method, url
    return None


def _is_static_resource(url: str) -> bool:
    path = unquote(urlsplit(url).path).lower().rstrip("/")
    if not path or "." not in path.rsplit("/", 1)[-1]:
        return False
    suffix = "." + path.rsplit(".", 1)[-1]
    return suffix in _STATIC_EXTENSIONS


def _object_tokens(url: str) -> list[str]:
    """Return high-signal object references without treating ordinary slugs/files as IDs."""

    if _is_static_resource(url):
        return []

    parsed = urlsplit(url)
    tokens: list[str] = []
    for segment in parsed.path.split("/"):
        value = unquote(segment).strip()
        if not value:
            continue
        if value.isdigit() or _UUID_RE.fullmatch(value) or _HEX_ID_RE.fullmatch(value) or _ULID_RE.fullmatch(value):
            tokens.append(value)

    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower = name.lower()
        if not value:
            continue
        if lower == "id" or lower.endswith("_id") or lower.endswith("-id") or lower.endswith("id"):
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
            kind = str(asset.get("kind") or "asset").strip().lower()
            key = str(asset.get("key") or old_id or "unknown")
            attributes = dict(asset.get("attributes") or {})

            if kind == "endpoint":
                endpoint_parts = _split_endpoint_asset(key, attributes)
                if endpoint_parts:
                    method, url = endpoint_parts
                    key = _endpoint_key(method, url)
                    attributes.update(
                        {
                            "method": method,
                            "url": _canonical_url(url),
                            "path": urlsplit(url).path or "/",
                            "object_tokens": _object_tokens(url),
                            "static_resource": _is_static_resource(url),
                        }
                    )

            node = graph.upsert_node(
                kind,
                key,
                attributes=attributes,
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
            object_tokens = _object_tokens(url)
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
                    "object_tokens": object_tokens,
                    "static_resource": _is_static_resource(url),
                },
                sources=(f"dedsec:request:{request.get('source') or 'unknown'}",),
            )
            id_map[request_id] = request_node.id
            endpoint = graph.upsert_node(
                "endpoint",
                _endpoint_key(method, url),
                attributes={
                    "method": method,
                    "url": _canonical_url(url),
                    "path": urlsplit(url).path or "/",
                    "query_parameters": sorted({name for name, _ in parse_qsl(urlsplit(url).query)}),
                    "object_tokens": object_tokens,
                    "static_resource": _is_static_resource(url),
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
            request_node_id = id_map.get(request_id)
            if request_node_id:
                graph.link(request_node_id, obs_node.id, "produced_observation")

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
