
import os
import sys
import json
import subprocess

from pathlib import Path

import boto3
from botocore.exceptions import NoCredentialsError, ClientError

from flask import Flask, render_template, request, send_file

from scanner.main_scanner import run_all_checks


# =====================================
# 1. 기본 설정
# =====================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"

SCAN_RESULT_PATH = OUTPUT_DIR / "scan_result.json"
REPORT_MD_PATH = OUTPUT_DIR / "security_report.md"
REPORT_PDF_PATH = OUTPUT_DIR / "security_report.pdf"


# =====================================
# 2. 13개 검사 항목
# =====================================

EXPECTED = [
    "전체 포트 개방 검사",
    "권한 사용자 검사",
    "Access Key 미사용 검사",
    "CloudTrail 활성화 검사",
    "루트 계정 MFA 검사",
    "IAM 사용자 MFA 검사",
    "IAM 비밀번호 정책 검사",
    "S3 Public Access 검사",
    "S3 버킷 암호화 검사",
    "S3 버킷 버전 관리 검사",
    "보안 그룹 SSH 개방 검사",
    "보안 그룹 RDP 개방 검사",
    "RDS Public Access 검사",
]


# =====================================
# 3. 검사 결과 정리
# =====================================

def group_results(raw_results):

    grouped = {
        name: {
            "item_name": name,
            "status": "PASS",
            "detail": "",
            "target": "-"
        }
        for name in EXPECTED
    }

    for result in raw_results:

        if not isinstance(result, dict):
            continue

        text = json.dumps(
            result,
            ensure_ascii=False,
            default=str
        ).lower()

        status = str(result.get("status", "")).lower()

        for name in EXPECTED:

            keywords = name.lower().split()

            if any(keyword in text for keyword in keywords):

                if status == "fail":
                    grouped[name]["status"] = "FAIL"

                grouped[name]["detail"] = str(
                    result.get("detail", result.get("message", ""))
                )

                grouped[name]["target"] = str(
                    result.get("target", "-")
                )

    return list(grouped.values())


# =====================================
# 4. 보고서 스크립트 실행
# =====================================

def run_script(script_name):

    script_path = BASE_DIR / script_name

    if not script_path.exists():
        raise FileNotFoundError(
            f"파일을 찾을 수 없습니다: {script_path}"
        )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{script_name} 실행 실패\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )


# =====================================
# 5. Gemini 보고서 및 PDF 생성
# =====================================

def generate_reports():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 이전 보고서 삭제
    if REPORT_MD_PATH.exists():
        REPORT_MD_PATH.unlink()

    if REPORT_PDF_PATH.exists():
        REPORT_PDF_PATH.unlink()

    # 검사 결과 보완
    run_script("reporting/enrich_findings.py")

    # Gemini 자연어 보고서 생성
    run_script("reporting/generate_report.py")

    # PDF 보고서 생성
    run_script("reporting/generate_pdf.py")


# =====================================
# 6. 자연어 보고서 읽기
# =====================================

def load_report():

    if not REPORT_MD_PATH.exists():
        return ""

    with open(
        REPORT_MD_PATH,
        "r",
        encoding="utf-8"
    ) as file:
        return file.read()


# =====================================
# 7. 첫 화면: AWS 인증정보 입력
# =====================================

@app.route("/", methods=["GET"])
def index():

    return render_template(
        "index.html",
        error=None,
        region="ap-northeast-2"
    )


# =====================================
# 8. AWS 보안 검사 실행
# =====================================

@app.route("/scan", methods=["POST"])
def scan():

    access_key = request.form.get(
        "access_key", ""
    ).strip()

    secret_key = request.form.get(
        "secret_key", ""
    ).strip()

    region = request.form.get(
        "region", "ap-northeast-2"
    ).strip()

    if not access_key or not secret_key or not region:

        return render_template(
            "index.html",
            error="AWS 인증정보를 모두 입력해주세요.",
            region=region
        )

    try:

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        print("[1/5] AWS 인증정보 확인 중...")

        # AWS 인증정보 환경변수 설정
        os.environ["AWS_ACCESS_KEY_ID"] = access_key
        os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
        os.environ["AWS_DEFAULT_REGION"] = region
        os.environ["AWS_REGION"] = region

        # AWS 인증 확인
        aws_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        sts = aws_session.client("sts")
        sts.get_caller_identity()

        print("[2/5] AWS 보안 검사 실행 중...")

        # 기존 보안 검사 실행
        data = run_all_checks()

        raw_results = data.get("results", [])
        summary_raw = data.get("summary", {})

        # 원본 검사 결과 저장
        with open(
            SCAN_RESULT_PATH,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                ensure_ascii=False,
                indent=4,
                default=str
            )

        # 13개 검사 결과 정리
        results = group_results(raw_results)

        # 검사 결과 집계 (보안 점수 제외)
        summary = {
            "total_checks": len(results),

            "pass_count": sum(
                1 for r in results
                if r["status"] == "PASS"
            ),

            "fail_count": sum(
                1 for r in results
                if r["status"] == "FAIL"
            )
        }

        print("[3/5] Gemini 보고서 생성 중...")

        report_error = None

        try:

            generate_reports()

            print("[4/5] 보고서 및 PDF 생성 완료")

        except Exception as e:

            report_error = str(e)

            print(
                "[보고서 생성 오류]",
                report_error
            )

        # 보고서 내용 읽기
        report_md = load_report()

        print("[5/5] 결과 화면 표시")

        # 별도의 결과 화면 표시
        return render_template(
            "result.html",
            results=results,
            summary=summary,
            report_md=report_md,
            report_error=report_error,
            pdf_exists=REPORT_PDF_PATH.exists()
        )

    except NoCredentialsError:

        error = "AWS 인증정보를 확인할 수 없습니다."

    except ClientError as e:

        error = f"AWS 인증 오류: {e}"

    except Exception as e:

        error = f"보안 검사 중 오류가 발생했습니다: {e}"

    return render_template(
        "index.html",
        error=error,
        region=region
    )


# =====================================
# 9. PDF 다운로드
# =====================================

@app.route("/download-report", methods=["GET"])
def download_report():

    if not REPORT_PDF_PATH.exists():
        return "PDF 보고서가 존재하지 않습니다.", 404

    return send_file(
        REPORT_PDF_PATH,
        as_attachment=True,
        download_name="AWS_Security_Report.pdf"
    )


# =====================================
# 10. Flask 서버 실행
# =====================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
