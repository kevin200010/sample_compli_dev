import os
import re
from pathlib import Path

FILE_PATH = Path(__file__).resolve().parents[1] / "app/accounts/compliance.py"
content = FILE_PATH.read_text()

s3_match = re.search(r"S3_REPORT_PREFIX\s*=\s*.+", content)
extract_match = re.search(
    r"def _extract_compliance\(finding\):[\s\S]*?return compliance", content
)
func_match = re.search(
    r"def generate_reports_data\([\s\S]*?return compliance_report",
    content,
)
namespace = {"os": os}
exec(s3_match.group(0), namespace)
exec(extract_match.group(0), namespace)
exec(func_match.group(0), namespace)

generate_reports_data = namespace["generate_reports_data"]
S3_REPORT_PREFIX = namespace["S3_REPORT_PREFIX"]
PREFIX = S3_REPORT_PREFIX.rstrip("/") + "/"


def test_generate_reports_data_legacy_schema(tmp_path):
    data = [
        {"status_code": "PASS", "unmapped": {"compliance": {"ISO-27001": {}}}},
        {"status_code": "FAIL", "unmapped": {"compliance": {"ISO-27001": {}}}},
    ]
    result = generate_reports_data(data, str(tmp_path), "alias", "user")
    assert result == [
        {
            "finding_name": "ISO-27001",
            "total_findings": 2,
            "passed": 1,
            "failed": 1,
            "pdf": f"{PREFIX}user_alias_ISO_27001_Compliance_Report.pdf",
            "compliance_percentage": "50.00%",
        }
    ]


def test_generate_reports_data_new_schema(tmp_path):
    data = [
        {"status_code": "PASS", "compliance": {"ISO-27001": {}}},
        {"status_code": "FAIL", "ocsf": {"compliance": {"ISO-27001": {}}}},
    ]
    result = generate_reports_data(data, str(tmp_path), "alias", "user")
    assert result == [
        {
            "finding_name": "ISO-27001",
            "total_findings": 2,
            "passed": 1,
            "failed": 1,
            "pdf": f"{PREFIX}user_alias_ISO_27001_Compliance_Report.pdf",
            "compliance_percentage": "50.00%",
        }
    ]


def test_generate_reports_data_with_custom_prefix(tmp_path):
    data = [
        {"status_code": "PASS", "compliance": {"ISO-27001": {}}},
        {"status_code": "FAIL", "compliance": {"ISO-27001": {}}},
    ]
    custom_prefix = "custom/prefix/"
    result = generate_reports_data(
        data,
        str(tmp_path),
        "alias",
        "user",
        storage_prefix=custom_prefix,
    )
    assert result[0]["pdf"].startswith("custom/prefix/")
