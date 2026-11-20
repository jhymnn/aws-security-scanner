from flask import Flask, request, render_template_string, send_file
import boto3
from botocore.exceptions import NoCredentialsError
import json
import subprocess
import sys
import os
import time
from pathlib import Path
import yaml
from scanner.aws_client import AWS_CLIENT_CONFIG


app = Flask(__name__)
app.secret_key = "change-this-secret-key"


# =========================
# 경로 설정
# =========================
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
SCAN_RESULT_PATH = OUTPUT_DIR / "scan_result.json"
REPORT_MD_PATH = OUTPUT_DIR / "security_report.md"
REPORT_PDF_PATH = OUTPUT_DIR / "security_report.pdf"


# =========================
# 전체 스캐너 모듈 설정
# =========================
SCANNER_MODULE = "scanner.main_scanner"


# =========================
# 공통 실행 함수
# =========================
def run_script(script_path):
    result = subprocess.run(
        [sys.executable, script_path],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120
    )

    if result.returncode != 0:
        stdout = result.stdout if result.stdout else "(출력 없음)"
        stderr = result.stderr if result.stderr else "(에러 출력 없음)"

        raise RuntimeError(
            f"{script_path} 실행 실패\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}"
        )

    return result.stdout


def run_module_with_aws_credentials(module_name, access_key, secret_key, region):
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_DEFAULT_REGION"] = region
    env["AWS_REGION"] = region

    result = subprocess.run(
        [sys.executable, "-m", module_name],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=180
    )

    if result.returncode != 0:
        stdout = result.stdout if result.stdout else "(출력 없음)"
        stderr = result.stderr if result.stderr else "(에러 출력 없음)"

        raise RuntimeError(
            f"{module_name} 실행 실패\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}"
        )

    return result.stdout


# =========================
# 결과 정규화 함수
# =========================
def normalize_status(status):
    status = str(status).strip().upper()

    if status == "PASS":
        return "Pass"

    if status == "FAIL":
        return "Fail"

    if status == "INFO":
        return "INFO"

    if status == "ERROR":
        return "ERROR"

    return "INFO"


def recompute_summary(results, original_score=None):
    normalized_results = []

    for item in results:
        fixed = dict(item)
        fixed["status"] = normalize_status(fixed.get("status"))
        normalized_results.append(fixed)

    total_checks = len(normalized_results)

    pass_count = sum(
        1 for item in normalized_results
        if item.get("status") == "Pass"
    )

    fail_count = sum(
        1 for item in normalized_results
        if item.get("status") == "Fail"
    )

    info_count = sum(
        1 for item in normalized_results
        if item.get("status") == "INFO"
    )
    error_count = sum(1 for item in normalized_results if item.get("status") == "ERROR")

    # scanner의 점수가 정상이라면 그대로 사용
    if isinstance(original_score, (int, float)) and original_score > 0:
        security_score = int(original_score)

    # scanner 점수가 0인데 PASS가 있으면 화면 표시용 점수 재계산
    else:
        score_target_count = pass_count + fail_count

        if score_target_count > 0:
            security_score = int((pass_count / score_target_count) * 100)
        else:
            security_score = 0

    summary = {
        "total_checks": total_checks,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "info_count": info_count,
        "error_count": error_count,
        "security_score": security_score
    }

    return summary, normalized_results


def load_and_fix_scan_result():
    if not SCAN_RESULT_PATH.exists():
        raise FileNotFoundError(
            "outputs/scan_result.json 파일이 없습니다."
        )

    with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
        scan_result = json.load(f)

    results = scan_result.get("results", [])
    old_summary = scan_result.get("summary", {})
    original_score = old_summary.get("security_score")

    summary, fixed_results = recompute_summary(
        results,
        original_score=original_score
    )

    fixed_scan_result = {
        "summary": summary,
        "results": fixed_results,
        "guide_coverage": scan_result.get("guide_coverage", []),
    }

    with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(
            fixed_scan_result,
            f,
            ensure_ascii=False,
            indent=2
        )

    return fixed_scan_result


GUIDE_ID_BY_ITEM = {
    "IAM Admin User": "1.7",
    "IAM Access Key Unused": "1.8",
    "Root Account MFA Enabled": "1.9",
    "IAM User MFA Enabled": "1.9",
    "IAM Password Policy": "1.10",
    "Security Group ALL Open": "3.1",
    "Security Group SSH Open": "3.1",
    "Security Group RDP Open": "3.1",
    "S3 Public Access Block": "3.7",
    "S3 Bucket Encryption": "4.3",
    "RDS Public Access": "3.8",
    "RDS Multi-AZ": "3.8",
    "RDS Encryption": "4.2",
    "RDS Backup": "4.13",
    "RDS Check": "3.8",
    "CloudTrail Enabled": "4.7",
    "CloudTrail Logging": "4.7",
    "CloudTrail Multi-Region": "4.7",
    "CloudTrail Log Encryption": "4.5",
    "CloudTrail Check": "4.7",
}

CONSOLE_LOCATIONS = {
    "1.7": "AWS 콘솔 > IAM > 사용자 및 권한 정책",
    "1.8": "AWS 콘솔 > IAM > 사용자 > 보안 자격 증명",
    "1.9": "AWS 콘솔 > IAM > 사용자 또는 계정 설정 > MFA",
    "1.10": "AWS 콘솔 > IAM > 계정 설정 > 비밀번호 정책",
    "3.1": "AWS 콘솔 > EC2 > 네트워크 및 보안 > 보안 그룹",
    "3.7": "AWS 콘솔 > S3 > 버킷 > 권한 및 퍼블릭 액세스 차단",
    "3.8": "AWS 콘솔 > RDS > 데이터베이스 > 연결 및 가용성",
    "4.2": "AWS 콘솔 > RDS > 데이터베이스 > 구성 > 암호화",
    "4.3": "AWS 콘솔 > S3 > 버킷 > 속성 > 기본 암호화",
    "4.5": "AWS 콘솔 > CloudTrail > 추적 > 암호화 설정",
    "4.7": "AWS 콘솔 > CloudTrail > 추적 및 이벤트 기록",
    "4.13": "AWS 콘솔 > RDS > 데이터베이스 > 유지 관리 및 백업",
}

SERVICE_BY_ITEM = (
    ("IAM", "IAM"),
    ("Security Group", "EC2 / 네트워크"),
    ("S3", "S3"),
    ("RDS", "RDS"),
    ("CloudTrail", "CloudTrail"),
)


def decorate_results(results):
    """Attach display-only labels and guide remediation context to scan rows."""
    kb_path = BASE_DIR / "base" / "sk_aws_kb.yaml"
    try:
        guide_kb = yaml.safe_load(kb_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        guide_kb = {}

    status_labels = {
        "Pass": "양호", "Fail": "취약", "INFO": "대상 없음", "ERROR": "점검 오류"
    }
    risk_labels = {"Critical": "긴급", "High": "높음", "Medium": "보통", "Low": "낮음", "Info": ""}

    decorated = []
    for raw in results:
        item = dict(raw)
        item["item"] = str(item.get("item") or "점검 항목")
        item["target"] = str(item.get("target") or "대상 정보 없음")
        item["detail"] = str(item.get("detail") or "상세 정보 없음")
        item["risk"] = str(item.get("risk") or "Info")
        guide_id = GUIDE_ID_BY_ITEM.get(item.get("item", ""))
        guide = guide_kb.get(guide_id, {}) if guide_id else {}
        item["guide_id"] = guide_id or ""
        item["guide"] = guide
        item["status_label"] = status_labels.get(item.get("status"), "확인 필요")
        item["risk_label"] = risk_labels.get(item.get("risk"), item.get("risk", "확인 필요"))
        item["service"] = next(
            (service for prefix, service in SERVICE_BY_ITEM if item.get("item", "").startswith(prefix)),
            "기타",
        )
        item["console_location"] = CONSOLE_LOCATIONS.get(guide_id, "해당 AWS 서비스 콘솔에서 대상 리소스를 확인하세요.")
        decorated.append(item)
    return decorated


def generate_security_report():
    for script_path in (
        "reporting/enrich_findings.py",
        "reporting/generate_report.py",
        "reporting/generate_pdf.py",
    ):
        stage_started = time.perf_counter()
        output = run_script(script_path)
        if output.strip():
            app.logger.info("[scan] %s\n%s", script_path, output.strip())
        app.logger.info(
            "[scan] %s: %.1f초",
            script_path,
            time.perf_counter() - stage_started,
        )


def load_report_markdown():
    if REPORT_MD_PATH.exists():
        return REPORT_MD_PATH.read_text(encoding="utf-8")

    return ""


# =========================
# 메인 화면
# =========================
@app.route("/")
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>AWS 보안 점검 시스템</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f4f6f8;
                padding: 40px;
            }

            .container {
                max-width: 720px;
                margin: auto;
                background: white;
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }

            h1 {
                text-align: center;
                color: #1f2937;
            }

            label {
                display: block;
                margin-top: 20px;
                font-weight: bold;
            }

            input {
                width: 100%;
                padding: 12px;
                margin-top: 8px;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                font-size: 15px;
                box-sizing: border-box;
            }

            button {
                width: 100%;
                margin-top: 30px;
                padding: 15px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 18px;
                cursor: pointer;
            }

            button:hover {
                background: #1d4ed8;
            }

            button:disabled {
                background: #64748b;
                cursor: wait;
            }

            .loading {
                display: none;
                align-items: center;
                gap: 12px;
                margin-top: 18px;
                color: #334155;
                line-height: 1.5;
            }

            .loading.active {
                display: flex;
            }

            .spinner {
                width: 20px;
                height: 20px;
                flex: 0 0 20px;
                border: 3px solid #cbd5e1;
                border-top-color: #2563eb;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .notice {
                margin-top: 20px;
                padding: 15px;
                background: #fef3c7;
                border-radius: 8px;
                color: #92400e;
                font-size: 14px;
            }

            .notice strong {
                color: #78350f;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AWS 보안 점검 시스템</h1>

            <form action="/scan" method="POST" id="scan-form">
                <label>AWS Access Key ID</label>
                <input type="text" name="access_key" required>

                <label>AWS Secret Access Key</label>
                <input type="password" name="secret_key" required>

                <label>Region</label>
                <input type="text" name="region" value="ap-northeast-2" required>

                <button type="submit" id="scan-button">보안 점검 실행</button>
            </form>

            <div class="loading" id="loading-indicator" role="status" aria-live="polite">
                <span class="spinner" aria-hidden="true"></span>
                <span>AWS 점검과 보고서를 생성 중입니다. 계정의 리소스 수와 API 응답에 따라 시간이 걸릴 수 있습니다.</span>
            </div>

            <div class="notice">
                <strong>안내:</strong>
                입력한 AWS 키는 서버에 저장하지 않고 점검 요청 처리에만 사용됩니다.
                점검 후 보안 점검 리포트가 생성됩니다.
            </div>
        </div>
        <script>
            document.getElementById("scan-form").addEventListener("submit", function () {
                const button = document.getElementById("scan-button");
                button.disabled = true;
                button.textContent = "점검 중...";
                document.getElementById("loading-indicator").classList.add("active");
            });
        </script>
    </body>
    </html>
    """)


# =========================
# 점검 실행
# =========================
@app.route("/scan", methods=["POST"])
def scan():
    access_key = request.form.get("access_key")
    secret_key = request.form.get("secret_key")
    region = request.form.get("region")

    report_error = None
    report_md = ""
    scan_result = None
    results = []

    try:
        # 1. AWS 자격 증명 확인
        aws_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        sts = aws_session.client("sts", config=AWS_CLIENT_CONFIG)
        stage_started = time.perf_counter()
        sts.get_caller_identity()
        app.logger.info("[scan] AWS 자격 증명 확인: %.1f초", time.perf_counter() - stage_started)

        # 2. scanner/main_scanner.py 전체 점검 실행
        stage_started = time.perf_counter()
        run_module_with_aws_credentials(
            SCANNER_MODULE,
            access_key,
            secret_key,
            region
        )
        app.logger.info("[scan] AWS 리소스 점검: %.1f초", time.perf_counter() - stage_started)

        # 3. scan_result.json 읽고 상태값/점수 정리 후 다시 저장
        stage_started = time.perf_counter()
        scan_result = load_and_fix_scan_result()
        results = scan_result.get("results", [])
        app.logger.info("[scan] 결과 정리: %.1f초", time.perf_counter() - stage_started)

        # 4. 리포트 생성
        try:
            stage_started = time.perf_counter()
            generate_security_report()
            report_md = load_report_markdown()
            app.logger.info("[scan] 보고서 및 PDF 생성: %.1f초", time.perf_counter() - stage_started)
        except Exception as e:
            report_error = str(e)

    except NoCredentialsError:
        return "<h2>AWS 자격 증명이 올바르지 않습니다.</h2>"

    except Exception as e:
        return f"<h2>점검 중 오류 발생</h2><pre>{str(e)}</pre>"

    summary = scan_result.get("summary", {})

    results = decorate_results(results)

    total_checks = summary.get("total_checks", len(results))
    pass_count = summary.get("pass_count", 0)
    fail_count = summary.get("fail_count", 0)
    info_count = summary.get("info_count", 0)
    error_count = summary.get("error_count", sum(1 for item in results if item.get("status") == "ERROR"))
    fail_results = [item for item in results if item.get("status") == "Fail"]
    service_options = sorted({item.get("service", "기타") for item in results})

    pdf_exists = REPORT_PDF_PATH.exists()

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>AWS 클라우드 보안 점검 결과</title>
        <style>
            * { box-sizing: border-box; }
            body { font-family: Arial, sans-serif; background: #f3f6fb; color: #172033; margin: 0; padding: 32px; }

            .container {
                max-width: 1440px;
                margin: auto;
            }

            .summary {
                background: white;
                padding: 28px;
                border-radius: 18px;
                box-shadow: 0 8px 28px rgba(24, 39, 75, 0.08);
                margin-bottom: 22px;
            }
            h1 { margin: 0 0 10px; font-size: 32px; }
            .subtitle { color: #64748b; margin: 0 0 24px; font-size: 16px; }
            .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
            .card { background: #f8fafc; border: 1px solid #e7edf5; border-radius: 14px; padding: 17px 19px; }
            .card h3 { margin: 0 0 11px; color: #64748b; font-size: 15px; font-weight: 600; }
            .card p { margin: 0; font-size: 29px; font-weight: 750; }
            .card small { color: #64748b; display: block; margin-top: 5px; }
            .metric-fail p, .severity-high p, .severity-critical p { color: #b42318; }
            .severity-medium p { color: #b54708; }
            .severity-low p { color: #475569; }
            .toolbar, .section-card { background: white; border-radius: 16px; padding: 22px; margin: 20px 0; box-shadow: 0 5px 20px rgba(24,39,75,.06); }
            .toolbar h2, .section-card h2 { margin: 0 0 14px; font-size: 20px; }
            .filter-row { display: flex; flex-wrap: wrap; gap: 10px; }
            .filter-row input, .filter-row select { min-height: 42px; padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 9px; background: white; color: #172033; }
            .filter-row input { flex: 1 1 240px; }
            .filter-row select { flex: 1 1 160px; }
            .section-note { color: #64748b; font-size: 13px; }
            .finding-list { display: grid; gap: 10px; }
            .finding { border: 1px solid #fecaca; background: #fffafa; border-left: 4px solid #dc2626; border-radius: 10px; padding: 14px 16px; }
            .finding summary { cursor: pointer; font-weight: 700; }
            .finding-meta { color: #64748b; font-size: 13px; margin-top: 7px; }
            .finding details { margin-top: 10px; }
            .empty { color: #64748b; padding: 14px; background: #f8fafc; border-radius: 10px; }

            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 5px 20px rgba(24,39,75,.06);
                margin-bottom: 24px;
            }

            th, td {
                padding: 15px 16px;
                border-bottom: 1px solid #e5e7eb;
                text-align: left;
                font-size: 16px;
                vertical-align: top;
            }

            th { background: #202b3c; color: white; white-space: nowrap; font-size: 16px; }
            th[data-sort] { cursor: pointer; }
            th[data-sort]:hover { background: #34445d; }
            .status-pill { display: inline-block; border-radius: 999px; padding: 4px 9px; font-size: 12px; font-weight: 700; white-space: nowrap; }
            .Pass { color: #067647; background: #dcfae6; }
            .Fail { color: #b42318; background: #fee4e2; }
            .INFO { color: #475569; background: #e2e8f0; }
            .ERROR { color: #9a3412; background: #ffedd5; }
            .risk-high, .risk-critical { color: #b42318; font-weight: 700; }
            .risk-medium { color: #b54708; font-weight: 700; }
            .risk-low { color: #475569; }
            .table-wrap { overflow-x: auto; border-radius: 12px; }
            .table-wrap table { min-width: 950px; }
            .detail-summary { cursor: pointer; color: #175cd3; font-weight: 600; font-size: 15px; }
            .detail-content { min-width: 280px; max-width: 560px; padding: 10px 2px; white-space: normal; line-height: 1.55; }
            .detail-content h4 { margin: 12px 0 4px; font-size: 13px; }
            .detail-content p, .detail-content ul { margin: 4px 0; }

            .pdf-button {
                display: inline-block;
                padding: 14px 20px;
                background: #2563eb;
                color: white;
                border-radius: 10px;
                text-decoration: none;
                font-weight: bold;
                margin-bottom: 0;
            }
            .report-box { background: white; padding: 22px; border-radius: 16px; margin-top: 22px; }
            .report-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 14px; }
            .report-header h2 { margin: 0; }
            pre { white-space: pre-wrap; word-break: break-word; background: #f8fafc; padding: 16px; border-radius: 10px; max-height: 500px; overflow: auto; }
            .error-box { background: #fee2e2; color: #991b1b; padding: 20px; border-radius: 12px; margin-bottom: 30px; white-space: pre-wrap; }
            .back { display: inline-block; margin-top: 25px; color: #175cd3; text-decoration: none; font-weight: bold; }
            @media (max-width: 640px) { body { padding: 14px; } .summary, .toolbar, .section-card { padding: 17px; } h1 { font-size: 24px; } }
        </style>
    </head>
    <body>
        <div class="container">

            <div class="summary">
                <h1>AWS 보안 점검 결과</h1>
                <p class="subtitle">region: {{ region }}</p>

                <div class="cards">
                    <div class="card">
                        <h3>전체 점검</h3>
                        <p>{{ total_checks }}개</p>
                    </div>
                    <div class="card">
                        <h3>양호</h3>
                        <p>{{ pass_count }}개</p>
                    </div>
                    <div class="card metric-fail">
                        <h3>취약</h3>
                        <p>{{ fail_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>점검 대상 없음</h3>
                        <p>{{ info_count }}개</p>
                    </div>
                    <div class="card">
                        <h3>점검 오류</h3>
                        <p>{{ error_count }}개</p>
                    </div>
                </div>
            </div>

            {% if report_error %}
            <div class="error-box">
                <strong>리포트 생성 중 오류가 발생했습니다.</strong>
                <br><br>
                {{ report_error }}
            </div>
            {% endif %}

            <section class="section-card">
                <h2>우선 조치가 필요한 취약 항목 <span class="section-note">{{ fail_results|length }}건</span></h2>
                {% if fail_results %}
                <div class="finding-list">
                    {% for item in fail_results %}
                    <article class="finding">
                        <details>
                            <summary>{{ item.risk_label }} 위험 · {{ item.item }} · {{ item.target }}</summary>
                            <div class="finding-meta">{{ item.service }} · {{ item.guide_id if item.guide_id else '가이드 연결 없음' }} · {{ item.detail }}</div>
                            <details>
                                <summary class="detail-summary">영향과 조치 방법 보기</summary>
                                <div class="detail-content">
                                    <h4>왜 문제인가요?</h4><p>{{ item.guide.description if item.guide else item.detail }}</p>
                                    <h4>어떤 영향이 있나요?</h4><p>{{ item.guide.bad_condition if item.guide else '가이드 설명을 확인할 수 없습니다. 상세 내용을 검토하고 실제 설정 상태를 확인하세요.' }}</p>
                                    <h4>AWS 콘솔 위치</h4><p>{{ item.console_location }}</p>
                                    <h4>단계별 조치</h4>
                                    {% if item.guide.remediation_steps %}<ol>{% for step in item.guide.remediation_steps %}<li>{{ step }}</li>{% endfor %}</ol>{% else %}<p>이 항목의 YAML 조치 절차가 아직 연결되지 않았습니다. AWS 콘솔에서 해당 설정을 직접 검토하세요.</p>{% endif %}
                                    <h4>조치 후 확인</h4>
                                    {% if item.guide.verification_steps %}<ul>{% for step in item.guide.verification_steps %}<li>{{ step }}</li>{% endfor %}</ul>{% else %}<p>설정을 수정한 뒤 보안 점검을 다시 실행해 상태가 양호로 바뀌었는지 확인하세요.</p>{% endif %}
                                </div>
                            </details>
                        </details>
                    </article>
                    {% endfor %}
                </div>
                {% else %}<p class="empty">현재 취약으로 판정된 항목이 없습니다.</p>{% endif %}
            </section>

            <section class="toolbar">
                <h2>점검 결과 찾기</h2>
                <div class="filter-row">
                    <input id="result-search" type="search" placeholder="점검 항목, 대상, 상세 내용 검색">
                    <select id="status-filter"><option value="">모든 상태</option><option value="Pass">양호</option><option value="Fail">취약</option><option value="INFO">대상 없음</option><option value="ERROR">점검 오류</option></select>
                    <select id="risk-filter"><option value="">모든 위험도</option><option value="Critical">긴급</option><option value="High">높음</option><option value="Medium">보통</option><option value="Low">낮음</option><option value="Info">-</option></select>
                    <select id="service-filter"><option value="">모든 서비스</option>{% for service in service_options %}<option value="{{ service }}">{{ service }}</option>{% endfor %}</select>
                    <select id="sort-filter"><option value="default">기본 정렬</option><option value="risk">위험도 높은 순</option><option value="status">취약 항목 먼저</option><option value="service">서비스별</option></select>
                </div>
                <p class="section-note"><span id="visible-count">{{ results|length }}</span> / {{ results|length }}개 항목 표시 · 열 제목을 눌러도 정렬할 수 있습니다.</p>
            </section>

            <div class="table-wrap"><table id="results-table">
                <thead>
                    <tr>
                        <th data-sort="service">서비스</th>
                        <th data-sort="item">점검 항목</th>
                        <th data-sort="target">대상</th>
                        <th data-sort="risk">위험도</th>
                        <th data-sort="status">상태</th>
                        <th>KISA / SK 가이드</th>
                        <th>상세 및 조치 정보</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in results %}
                    <tr data-service="{{ item.service }}" data-status="{{ item.status }}" data-risk="{{ item.risk }}" data-item="{{ item.item|lower }}" data-target="{{ item.target|lower }}" data-detail="{{ item.detail|lower }}" data-risk-order="{{ {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}.get(item.risk, 5) }}" data-status-order="{{ {'Fail': 0, 'ERROR': 1, 'INFO': 2, 'Pass': 3}.get(item.status, 4) }}">
                        <td>{{ item.service }}</td>
                        <td>{{ item.item }}</td>
                        <td>{{ item.target }}</td>
                        <td class="risk-{{ item.risk|lower }}">{{ item.risk_label }}</td>
                        <td><span class="status-pill {{ item.status }}">{{ item.status_label }}</span></td>
                        <td>{{ item.kisa_code }}{% if item.guide_id %}<br><small>SK {{ item.guide_id }}</small>{% endif %}</td>
                        <td>
                            <details>
                                <summary class="detail-summary">상세 보기</summary>
                                <div class="detail-content">
                                    <p>{{ item.detail }}</p>
                                    {% if item.status == 'Fail' and item.guide %}
                                    <h4>SK쉴더스 가이드 {{ item.guide_id }} · {{ item.guide.title }}</h4>
                                    <p><strong>기준:</strong> {{ item.guide.bad_condition }}</p>
                                    <h4>AWS 콘솔 위치</h4><p>{{ item.console_location }}</p>
                                    <h4>단계별 조치</h4><ol>{% for step in item.guide.remediation_steps %}<li>{{ step }}</li>{% endfor %}</ol>
                                    <h4>조치 후 확인</h4><ul>{% for step in item.guide.verification_steps %}<li>{{ step }}</li>{% endfor %}</ul>
                                    {% elif item.status == 'Fail' %}<p>연결된 SK 가이드의 상세 절차를 찾지 못했습니다. 다시 점검한 뒤 보고서를 확인하세요.</p>
                                    {% else %}<p>이 항목은 {{ item.status_label }} 상태입니다. 조치가 필요한 취약 항목이 아닙니다.</p>{% endif %}
                                </div>
                            </details>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table></div>

            <div class="report-box">
                <div class="report-header">
                    <h2>리포트 미리보기</h2>
                    {% if pdf_exists %}<a class="pdf-button" href="/download-report">PDF 리포트 다운로드</a>{% endif %}
                </div>
                {% if report_md %}
                    <pre>{{ report_md }}</pre>
                {% else %}
                    <p>리포트가 아직 생성되지 않았습니다.</p>
                {% endif %}
            </div>

            <a class="back" href="/">← 다시 점검하기</a>
        </div>
        <script>
            (() => {
                const table = document.getElementById('results-table');
                const body = table.tBodies[0];
                const rows = Array.from(body.rows);
                const originalOrder = rows.slice();
                const controls = ['result-search', 'status-filter', 'risk-filter', 'service-filter'].map(id => document.getElementById(id));
                const visibleCount = document.getElementById('visible-count');
                const applyFilters = () => {
                    const query = controls[0].value.trim().toLowerCase();
                    rows.forEach(row => {
                        const matches = (!query || `${row.dataset.item} ${row.dataset.target} ${row.dataset.detail}`.includes(query))
                            && (!controls[1].value || row.dataset.status === controls[1].value)
                            && (!controls[2].value || row.dataset.risk === controls[2].value)
                            && (!controls[3].value || row.dataset.service === controls[3].value);
                        row.hidden = !matches;
                    });
                    visibleCount.textContent = rows.filter(row => !row.hidden).length;
                };
                controls.forEach(control => control.addEventListener('input', applyFilters));
                controls.forEach(control => control.addEventListener('change', applyFilters));
                document.getElementById('sort-filter').addEventListener('change', event => {
                    const mode = event.target.value;
                    if (mode === 'default') {
                        originalOrder.forEach(row => body.appendChild(row));
                        return;
                    }
                    const key = mode === 'risk' ? 'riskOrder' : mode === 'status' ? 'statusOrder' : 'service';
                    rows.sort((a, b) => String(a.dataset[key]).localeCompare(String(b.dataset[key]), 'ko', {numeric: true}));
                    rows.forEach(row => body.appendChild(row));
                });
                table.querySelectorAll('th[data-sort]').forEach(header => header.addEventListener('click', () => {
                    const key = header.dataset.sort;
                    const sortKey = key === 'risk' ? 'riskOrder' : key === 'status' ? 'statusOrder' : key;
                    rows.sort((a, b) => String(a.dataset[sortKey] || '').localeCompare(String(b.dataset[sortKey] || ''), 'ko', {numeric: true}));
                    rows.forEach(row => body.appendChild(row));
                }));
                applyFilters();
            })();
        </script>
    </body>
    </html>
    """,
    results=results,
    total_checks=total_checks,
    pass_count=pass_count,
    fail_count=fail_count,
    info_count=info_count,
    error_count=error_count,
    fail_results=fail_results,
    service_options=service_options,
    region=region,
    pdf_exists=pdf_exists,
    report_md=report_md,
    report_error=report_error)


# =========================
# PDF 다운로드
# =========================
@app.route("/download-report")
def download_report():
    if not REPORT_PDF_PATH.exists():
        return "<h2>PDF 리포트가 아직 생성되지 않았습니다.</h2>"

    return send_file(
        REPORT_PDF_PATH,
        as_attachment=True,
        download_name="security_report.pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
