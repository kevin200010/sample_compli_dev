import json
import os
import re
from pathlib import Path

FILE_PATH = Path(__file__).resolve().parents[1] / "app/accounts/compliance.py"
content = FILE_PATH.read_text()

s3_match = re.search(r"S3_REPORT_PREFIX\s*=\s*.+", content)
extract_match = re.search(
    r"def _extract_compliance\(finding\):[\s\S]*?return compliance", content
)
reports_match = re.search(
    r"def generate_reports\([\s\S]*?return compliance_report, pdf_paths",
    content,
)

namespace = {"os": os, "json": json}

def generate_pdf_report_for_compliance_type(data, compliance_type, output_pdf_path):
    Path(output_pdf_path).write_text("pdf")

namespace["generate_pdf_report_for_compliance_type"] = generate_pdf_report_for_compliance_type
exec(s3_match.group(0), namespace)
exec(extract_match.group(0), namespace)
exec(reports_match.group(0), namespace)

generate_reports = namespace["generate_reports"]
S3_REPORT_PREFIX = namespace["S3_REPORT_PREFIX"]
PREFIX = S3_REPORT_PREFIX.rstrip("/") + "/"


def _write_input(data, path):
    path.write_text(json.dumps(data))
    return str(path)


def _expected(compliance_type):
    sanitized = compliance_type.replace("-", "_")
    return {
        "finding_name": compliance_type,
        "total_findings": 2,
        "passed": 1,
        "failed": 1,
        "pdf": f"{PREFIX}user_alias_{sanitized}_Compliance_Report.pdf",
        "compliance_percentage": "50.00%",
    }


def test_generate_reports_unmapped_schema(tmp_path):
    data = [
        {"status_code": "PASS", "unmapped": {"compliance": {"ISO-27001": {}}}},
        {"status_code": "FAIL", "unmapped": {"compliance": {"ISO-27001": {}}}},
    ]
    input_file = _write_input(data, tmp_path / "input.json")
    output_dir = tmp_path / "out"
    report, paths = generate_reports(input_file, str(output_dir), "alias", "user")
    expected_pdf = output_dir / "user_alias_ISO_27001_Compliance_Report.pdf"
    assert report == [_expected("ISO-27001")]
    assert paths == [str(expected_pdf)]
    assert expected_pdf.exists()


def test_generate_reports_top_level_schema(tmp_path):
    data = [
        {"status_code": "PASS", "compliance": {"ISO-27001": {}}},
        {"status_code": "FAIL", "compliance": {"ISO-27001": {}}},
    ]
    input_file = _write_input(data, tmp_path / "input.json")
    output_dir = tmp_path / "out"
    report, paths = generate_reports(input_file, str(output_dir), "alias", "user")
    expected_pdf = output_dir / "user_alias_ISO_27001_Compliance_Report.pdf"
    assert report == [_expected("ISO-27001")]
    assert paths == [str(expected_pdf)]
    assert expected_pdf.exists()


def test_generate_reports_ocsf_schema(tmp_path):
    data = [
        {"status_code": "PASS", "ocsf": {"compliance": {"ISO-27001": {}}}},
        {"status_code": "FAIL", "ocsf": {"compliance": {"ISO-27001": {}}}},
    ]
    input_file = _write_input(data, tmp_path / "input.json")
    output_dir = tmp_path / "out"
    report, paths = generate_reports(input_file, str(output_dir), "alias", "user")
    expected_pdf = output_dir / "user_alias_ISO_27001_Compliance_Report.pdf"
    assert report == [_expected("ISO-27001")]
    assert paths == [str(expected_pdf)]
    assert expected_pdf.exists()


def test_generate_reports_with_custom_prefix(tmp_path):
    data = [
        {"status_code": "PASS", "compliance": {"ISO-27001": {}}},
        {"status_code": "FAIL", "compliance": {"ISO-27001": {}}},
    ]
    input_file = _write_input(data, tmp_path / "input.json")
    output_dir = tmp_path / "out"
    custom_prefix = "custom/prefix/"
    report, _ = generate_reports(
        input_file,
        str(output_dir),
        "alias",
        "user",
        storage_prefix=custom_prefix,
    )
    assert report[0]["pdf"].startswith("custom/prefix/")
