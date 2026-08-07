import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from aultline.cli import main


class CliInputTests(unittest.TestCase):
    def test_missing_report_returns_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-report.json"
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main(["graph", str(missing)])

        self.assertEqual(result, 2)
        self.assertIn("aultline: error: report not found:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_json_returns_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "broken.json"
            report.write_text('{"schema_version": ', encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main(["analyze", str(report)])

        self.assertEqual(result, 2)
        self.assertIn("aultline: error: invalid JSON report:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_non_object_json_returns_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "array.json"
            report.write_text("[]", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                result = main(["graph", str(report)])

        self.assertEqual(result, 2)
        self.assertIn("aultline: error: report root must be a JSON object:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
