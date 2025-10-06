import subprocess
import json
import os
import traceback
from datetime import datetime


def run_prowler_scan(
    aws_profile=None,
    compliance_framework="aws_foundational_security_best_practices_aws",
    output_dir="prowler_reports",
):
    try:
        # Force UTF-8 encoding for the entire process
        os.environ["PYTHONIOENCODING"] = "utf-8"

        os.environ["PYTHONUTF8"] = "1"

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(
            output_dir, f"prowler_{compliance_framework}_{timestamp}.json"
        )
        print("00000000")

        command = [
            "prowler",
            "aws",
            "-M",
            "json-asff",
            "-c",
            compliance_framework,
            "-F",
            output_file,
        ]

        # if aws_profile:
        #     command.extend(['--profile', aws_profile])

        # Run with explicit UTF-8 encoding
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        print("11111111")
        if result.returncode != 0:
            print(f"Error running Prowler: {str(result.stderr)}")
            return None
        print("22222222")
        if os.path.exists(output_file):
            # Read with explicit UTF-8 encoding
            with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                findings = json.load(f)
                print(
                    f"Successfully generated report with {len(findings.get('Findings', []))} findings"
                )
                return output_file
        else:
            print("Report file not created")
            return None

    except json.JSONDecodeError as json_err:
        print(f"JSON Error: {str(json_err)}")
        print(f"Error occurred at line {json_err.lineno} column {json_err.colno}")
        return None
    except Exception as e:
        print(f"Error: {str(e)}")
        print(traceback.format_exc())
        return None


if __name__ == "__main__":
    # Force UTF-8 for Windows console
    if os.name == "nt":
        os.system("chcp 65001 > nul")

    report_path = run_prowler_scan(
        aws_profile="",  # Empty string for default profile
        compliance_framework="cis_1.5_aws",
        output_dir="prowler_reports",
    )

    if report_path:
        print(f"Report saved to: {report_path}")
