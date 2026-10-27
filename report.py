import json
import requests
from pathlib import Path

INPUT_PATH = Path("outputs/scan_result.json")
OUTPUT_JSON = Path("outputs/report.json")
OUTPUT_TXT = Path("outputs/report.txt")


# ---------------------------
# LLM 호출
# ---------------------------
def call_llm(prompt: str):
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3:8b",
            "prompt": prompt,
            "stream": False
        },
        timeout=1200
    )
    response.raise_for_status()
    return response.json()["response"]


# ---------------------------
# 프롬프트 생성 (핵심)
# ---------------------------
def build_prompt(scan_data):
    return f"""
당신은 클라우드 보안 점검 결과를 설명하는 AI이다.

이 데이터는 AWS 보안 점검 결과이며, 절대 학습, 시험, 평가 등으로 해석하지 말라.

[핵심 규칙]
1. 입력 JSON에 있는 정보만 사용하라.
2. 없는 리소스, 계정, 설정을 생성하지 말라.
3. 숫자(개수, 점수)를 절대 변경하지 말라.
4. Fail 항목만 취약점으로 설명하라.
5. Pass 항목은 양호 항목으로 설명하라.
6. 한국어로 작성하라.
7. 불필요한 설명 금지 (간결하게 작성)
8. 코드블록, 마크다운 출력 금지
9. 반드시 JSON 형식으로만 출력하라

[보안 컨텍스트]
- IAM User MFA Enabled → MFA 활성화 필요
- S3 Public Access Block → Public 접근 차단 필요
- Security Group SSH Open → 22번 포트 접근 제한 필요

[출력 JSON 형식]
{{
  "summary": "문장",
  "vulnerabilities": [
    {{
      "item": "문자열",
      "risk": "문자열",
      "targets": ["문자열"],
      "analysis": "원인 설명",
      "action_guide": ["단계1", "단계2", "단계3"]
    }}
  ],
  "good_items": [
    {{
      "item": "문자열",
      "targets": ["문자열"],
      "description": "양호 설명"
    }}
  ]
}}

[입력 JSON]
{json.dumps(scan_data, ensure_ascii=False, indent=2)}
"""


# ---------------------------
# JSON 추출
# ---------------------------
def extract_json(text):
    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end == -1:
        raise ValueError("JSON 형식 아님")

    json_str = text[start:end + 1]

    return json.loads(json_str)


# ---------------------------
# fallback
# ---------------------------
def fallback_report(scan_data):
    summary = scan_data.get("summary", {})

    return {
        "summary": f"전체 {summary.get('total_checks',0)}개 점검 중 "
                   f"{summary.get('fail_count',0)}개 취약점이 확인되었습니다.",
        "vulnerabilities": [],
        "good_items": []
    }


# ---------------------------
# 보고서 생성
# ---------------------------
def generate_report(scan_data):
    prompt = build_prompt(scan_data)
    raw = call_llm(prompt)

    try:
        return extract_json(raw)
    except Exception as e:
        print("⚠️ JSON 파싱 실패")
        print(raw)
        return fallback_report(scan_data)


# ---------------------------
# TXT 변환
# ---------------------------
def save_txt(report):
    lines = []

    lines.append("=== 클라우드 보안 점검 보고서 ===\n")
    lines.append(report["summary"] + "\n")

    lines.append("[취약점]\n")
    for v in report["vulnerabilities"]:
        lines.append(f"- {v['item']} ({v['risk']})")
        lines.append(f"  대상: {', '.join(v['targets'])}")
        lines.append(f"  원인: {v['analysis']}")
        lines.append("  조치:")
        for step in v["action_guide"]:
            lines.append(f"   - {step}")
        lines.append("")

    lines.append("[양호 항목]\n")
    for g in report["good_items"]:
        lines.append(f"- {g['item']}")
        lines.append(f"  대상: {', '.join(g['targets'])}")
        lines.append(f"  설명: {g['description']}")
        lines.append("")

    OUTPUT_TXT.parent.mkdir(exist_ok=True)

    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------
# JSON 저장
# ---------------------------
def save_json(report):
    OUTPUT_JSON.parent.mkdir(exist_ok=True)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


# ---------------------------
# main
# ---------------------------
def main():
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    report = generate_report(scan_data)

    save_json(report)
    save_txt(report)

    print("✅ 보고서 생성 완료")


if __name__ == "__main__":
    main()