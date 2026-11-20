import time
import os
import json
import random
import re
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types

STATUS_LABELS = {
    "PASS": "양호",
    "FAIL": "취약",
    "INFO": "점검 대상 없음",
    "ERROR": "점검 오류"
}

RISK_LABELS = {
    "High": "높음",
    "Medium": "중간",
    "Low": "낮음",
    "Info": "점검 대상 없음",
    "상": "높음",
    "중": "중간",
    "하": "낮음"
}

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

INPUT_ENRICHED = "outputs/enriched_findings.json"
INPUT_SCAN_RESULT = "outputs/scan_result.json"
OUTPUT_MD = "outputs/security_report.md"
OUTPUT_GEMINI_ERROR = "outputs/gemini_error.txt"

# API 키가 있을 때만 Gemini 클라이언트 생성
client = None

if GEMINI_API_KEY:
    client = genai.Client(
        api_key=GEMINI_API_KEY,
        http_options=types.HttpOptions(timeout=30_000)
    )


def call_gemini(prompt):

    if client is None:
        raise RuntimeError("Gemini API 키가 설정되지 않았습니다.")

    try:
        print("Gemini 보고서 생성 요청 중...")

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )

        if not response.text:
            raise RuntimeError("Gemini 응답 내용이 비어 있습니다.")

        print("Gemini 보고서 생성 성공")
        return response.text

    except Exception as e:
        print(f"Gemini 요청 실패: {e}")
        raise


def safe_error_message(error):
    """Save useful API diagnostics without writing an API key to reports."""
    message = str(error)
    message = re.sub(r"AIza[0-9A-Za-z_-]{20,}", "[API KEY REDACTED]", message)
    message = re.sub(
        r"(?i)(x-goog-api-key\s*[:=]\s*)[^\s,]+",
        r"\1[REDACTED]",
        message,
    )
    return f"{type(error).__name__}: {message}"


def build_full_report_prompt(scan_result, enriched_findings):

    return f"""
너는 클라우드 보안 진단 리포트를 작성하는 보안 컨설턴트다.

[절대 규칙]
1. 제공된 스캔 결과와 승인된 YAML 컨텍스트만 사용한다.
2. 입력 데이터에 없는 사실을 만들어내지 않는다.
3. 취약 여부는 Python 진단 결과를 그대로 따른다.
4. target, risk, kisa_code를 변경하지 않는다.
5. remediation_steps를 우선 사용한다.
6. 쉬운 한국어로 작성한다.
7. Markdown 형식으로만 작성한다.
8. PASS 항목을 취약점으로 설명하지 않는다.
9. INFO는 대상 없음으로 표시한다.
10. ERROR는 점검 오류로 표시한다.
11. INFO와 ERROR를 취약점 개수에 포함하지 않는다.
12. 보안 점수를 임의로 변경하지 않는다.
13. 입력 데이터에 없는 위험을 추측하지 않는다.
14. 취약점이 없으면 상세 취약점 분석을 만들지 않는다.

[스캔 결과]
{json.dumps(scan_result, ensure_ascii=False, indent=2)}

[승인된 취약점 컨텍스트]
{json.dumps(enriched_findings, ensure_ascii=False, indent=2)}

[출력 형식]

# 보안 진단 리포트

## 1. 진단 요약

## 2. 우선 조치 대상

## 3. 상세 취약점 분석

각 취약점마다 다음 내용을 작성한다.

### 취약점명

#### 점검 항목

#### 원인 분석

#### 보안 영향

#### 단계별 조치 가이드

#### 조치 후 확인 방법

#### 근거 출처

"""


def get_results(scan_result):

    results = scan_result.get("results", [])

    if isinstance(results, list):
        return results

    return []


def build_fallback_report(scan_result, enriched_findings):

    """
    Gemini 실패 시 Python이 생성하는 기본 보고서.

    enriched_findings의 YAML 컨텍스트를 활용하여
    취약점 설명, 조치 방법, 확인 방법, 출처를 생성한다.
    """

    results = get_results(scan_result)

    # 상태별 결과 분류
    fail_results = [
        item for item in results
        if str(item.get("status", "")).upper() == "FAIL"
    ]

    pass_results = [
        item for item in results
        if str(item.get("status", "")).upper() == "PASS"
    ]

    info_results = [
        item for item in results
        if str(item.get("status", "")).upper() == "INFO"
    ]

    error_results = [
        item for item in results
        if str(item.get("status", "")).upper() == "ERROR"
    ]

    summary = scan_result.get("summary", {})

    security_score = scan_result.get(
        "security_score",
        summary.get("security_score", "확인 필요")
    )

    # 취약점별 YAML 컨텍스트 검색을 위한 인덱스
    context_map = {}

    for enriched in enriched_findings:

        finding = enriched.get("finding", {})

        key = (
            finding.get("item"),
            finding.get("kisa_code")
        )

        context_map[key] = enriched

    report = []

    report.append("# AWS 보안 진단 리포트\n")

    report.append("## 1. 진단 요약\n")

    report.append(f"- 전체 점검 수: {len(results)}개")
    report.append(f"- 양호 항목: {len(pass_results)}개")
    report.append(f"- 취약 항목: {len(fail_results)}개")
    report.append(f"- 대상 없음: {len(info_results)}개")
    report.append(f"- 점검 오류: {len(error_results)}개")
    

    report.append(
        "> Gemini API 요청 실패로 Python 기본 보고서를 생성했습니다.\n"
    )

    # 우선 조치 대상
    report.append("## 2. 우선 조치 대상\n")

    if fail_results:

        for item in fail_results:

            name = item.get("item", "항목명 없음")
            risk = item.get("risk", "확인 필요")
            target = item.get("target", "확인 필요")

            report.append(
                f"- **{name}** / "
                f"위험도: {RISK_LABELS.get(risk, risk)} / "
                f"대상: {target}"
            )

    else:

        report.append("취약 항목이 발견되지 않았습니다.")

    # 상세 취약점 분석
    report.append("\n## 3. 상세 취약점 분석\n")

    for item in fail_results:

        name = item.get("item", "항목명 없음")
        target = item.get("target", "확인 필요")
        risk = item.get("risk", "확인 필요")
        kisa_code = item.get("kisa_code", "정보 없음")
        detail = item.get("detail", "상세 내용 없음")

        key = (name, kisa_code)

        enriched = context_map.get(key, {})

        finding = enriched.get("finding", {})
        guide = enriched.get("guide_context", {})
        guide_id = finding.get("sk_guide_id")

        source = guide.get("source", {})

        report.append(f"### {name}\n")

        report.append("#### 점검 항목\n")

        report.append(f"- 진단 항목: {name}")
        report.append(f"- 대상: {target}")
        report.append(
            f"- 위험도: {RISK_LABELS.get(risk, risk)}"
        )
        report.append(f"- KISA 코드: {kisa_code}")
        if guide_id and enriched.get("context_status") == "FOUND":
            report.append(f"- SK쉴더스 가이드: {guide_id}")
        elif guide_id:
            report.append(f"- SK쉴더스 가이드: {guide_id} (YAML 항목 확인 필요)")
        else:
            report.append("- SK쉴더스 가이드: 직접 매핑된 항목 없음")

        report.append("\n#### 원인 분석\n")

        report.append(detail)

        # YAML 설명 및 취약 판정 기준
        if enriched.get("context_status") == "FOUND" and guide:

            description = guide.get("description")
            bad_condition = guide.get("bad_condition")

            if description:
                report.append(f"\n#### 보안 점검 목적\n")
                report.append(description)

            if bad_condition:
                report.append(f"\n#### 취약 판정 기준\n")
                report.append(bad_condition)

            # 보안 영향
            report.append("\n#### 보안 영향\n")
            report.append(
                "해당 항목은 제공된 보안 가이드의 취약 판정 기준에 "
                "해당합니다. 구체적인 영향은 위 점검 목적과 "
                "취약 판정 기준을 참고해야 합니다."
            )

            # 단계별 조치 방법
            report.append("\n#### 단계별 조치 가이드\n")

            remediation_steps = guide.get(
                "remediation_steps", []
            )

            if remediation_steps:

                for index, step in enumerate(
                    remediation_steps, start=1
                ):
                    report.append(f"{index}. {step}")

            else:

                report.append(
                    "YAML 지식베이스에 등록된 조치 방법이 없습니다. "
                    "추가 확인이 필요합니다."
                )

            # 조치 후 확인
            report.append("\n#### 조치 후 확인 방법\n")

            verification_steps = guide.get(
                "verification_steps", []
            )

            if verification_steps:

                for index, step in enumerate(
                    verification_steps, start=1
                ):
                    report.append(f"{index}. {step}")

            else:

                report.append(
                    "YAML 지식베이스에 등록된 확인 방법이 없습니다."
                )

            # 근거 출처
            report.append("\n#### 근거 출처\n")

            report.append(
                f"- 문서: {source.get('document', '정보 없음')}"
            )

            report.append(
                f"- 항목: {source.get('section', '정보 없음')}"
            )

        else:

            report.append("\n#### 조치 가이드\n")

            report.append(
                "승인된 YAML 지식베이스에서 해당 항목의 "
                "상세 컨텍스트를 찾지 못했습니다. "
                "추가 확인이 필요합니다."
            )

        report.append("\n---\n")

    # 양호 항목
    report.append("\n## 4. 양호 항목\n")

    if pass_results:

        for item in pass_results:

            report.append(
                f"- {item.get('item', '항목명 없음')}: "
                f"{item.get('detail', '양호')}"
            )

    else:

        report.append("양호 항목이 없습니다.")

    # 대상 없음
    report.append("\n## 5. 점검 대상 없음\n")

    if info_results:

        for item in info_results:

            report.append(
                f"- {item.get('item', '항목명 없음')}: "
                f"{item.get('detail', '점검 대상 없음')}"
            )

    else:

        report.append("해당 항목이 없습니다.")

    # 점검 오류
    report.append("\n## 6. 점검 오류\n")

    if error_results:

        for item in error_results:

            report.append(
                f"- {item.get('item', '항목명 없음')}: "
                f"{item.get('detail', '오류 내용 없음')}"
            )

    else:

        report.append("점검 오류가 없습니다.")

    return "\n".join(report)

def main():

    print("보안 통합 리포트 생성 시작")

    Path("outputs").mkdir(exist_ok=True)

    with open(INPUT_SCAN_RESULT, "r", encoding="utf-8") as f:
        scan_result = json.load(f)

    with open(INPUT_ENRICHED, "r", encoding="utf-8") as f:
        enriched_findings = json.load(f)

    print(f"전체 점검 항목: {len(get_results(scan_result))}개")
    print(f"사용 모델: {MODEL_NAME}")

    prompt = build_full_report_prompt(
        scan_result,
        enriched_findings
    )

    try:

        report = call_gemini(prompt)

        print("보고서 생성 성공")
        Path(OUTPUT_GEMINI_ERROR).unlink(missing_ok=True)

    except Exception as e:

        error_message = safe_error_message(e)
        print("Gemini 보고서 생성 실패")
        print(f"오류 내용: {error_message}")

        Path(OUTPUT_GEMINI_ERROR).write_text(error_message, encoding="utf-8")

        print("Python 기본 보고서로 전환합니다.")

        report = build_fallback_report(
            scan_result,
            enriched_findings
        )
        report = report.replace(
            "> Gemini API 요청 실패로 Python 기본 보고서를 생성했습니다.",
            "> Gemini API 요청 실패로 Python 기본 보고서를 생성했습니다. "
            f"오류: `{error_message}`",
        )

    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"보고서 생성 완료: {OUTPUT_MD}")


if __name__ == "__main__":
    main()
