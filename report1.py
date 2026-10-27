import json
import requests
from pathlib import Path
from collections import defaultdict

INPUT_PATH = Path("outputs/scan_result.json")
OUTPUT_JSON = Path("outputs/report.json")
OUTPUT_TXT = Path("outputs/report.txt")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3:latest"
REQUEST_TIMEOUT = 60


def load_json():
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def call_llm(prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0
        }
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=REQUEST_TIMEOUT
    )
    response.raise_for_status()
    data = response.json()
    return data["response"].strip()


def safe_call_llm(prompt: str, fallback: str) -> str:
    try:
        result = call_llm(prompt)
        if not result:
            return fallback
        return clean_text(result)
    except Exception as e:
        print(f"⚠️ LLM 호출 실패: {e}")
        return fallback


def clean_text(text: str) -> str:
    banned = ["```", "`", "{", "}", "json"]
    cleaned = text
    for token in banned:
        cleaned = cleaned.replace(token, "")
    return cleaned.strip()


def group_results(results):
    fail_groups = defaultdict(lambda: {
        "item": "",
        "risk": "",
        "kisa_code": "",
        "targets": [],
        "details": []
    })
    pass_groups = defaultdict(lambda: {
        "item": "",
        "risk": "",
        "kisa_code": "",
        "targets": [],
        "details": []
    })

    for row in results:
        status = row.get("status", "")
        item = row.get("item", "Unknown")

        if status == "Fail":
            group = fail_groups[item]
        elif status == "Pass":
            group = pass_groups[item]
        else:
            continue

        group["item"] = item
        group["risk"] = row.get("risk", "Unknown")
        group["kisa_code"] = row.get("kisa_code", "Unknown")
        group["targets"].append(row.get("target", "Unknown"))
        group["details"].append(row.get("detail", ""))

    vulnerabilities = []
    for _, group in fail_groups.items():
        vulnerabilities.append({
            "item": group["item"],
            "risk": group["risk"],
            "kisa_code": group["kisa_code"],
            "affected_count": len(group["targets"]),
            "targets": group["targets"],
            "details": group["details"]
        })

    good_items = []
    for _, group in pass_groups.items():
        good_items.append({
            "item": group["item"],
            "risk": group["risk"],
            "kisa_code": group["kisa_code"],
            "target_count": len(group["targets"]),
            "targets": group["targets"],
            "details": group["details"]
        })

    return vulnerabilities, good_items


def build_summary_text(summary: dict) -> str:
    total_checks = summary.get("total_checks", 0)
    pass_count = summary.get("pass_count", 0)
    fail_count = summary.get("fail_count", 0)
    security_score = summary.get("security_score", 0)

    return (
        f"총 {total_checks}개 점검 중 {pass_count}개는 양호, "
        f"{fail_count}개는 취약으로 확인되었습니다. "
        f"현재 보안 점수는 {security_score}점입니다."
    )

    prompt = f"""
당신은 클라우드 보안 점검 결과를 사용자에게 이해하기 쉽게 설명하는 AI이다.

[규칙]
1. 이 데이터는 보안 점검 결과이다.
2. 사람 평가, 학습, 시험 결과처럼 해석하지 말라.
3. 입력 숫자를 절대 바꾸지 말라.
4. 없는 정보를 추가하지 말라.
5. 한국어로만 작성하라.
6. 2문장 이내로 작성하라.
7. 마크다운, 코드블록, 기호 없이 일반 문장만 출력하라.

[입력]
- 전체 점검 수: {total_checks}
- Pass: {pass_count}
- Fail: {fail_count}
- Security Score: {security_score}
""".strip()

    return safe_call_llm(prompt, fallback)


def build_vulnerability_analysis(vuln: dict) -> str:
    base_text = (
        f"{vuln['item']} 항목에서 "
        f"{vuln['affected_count']}개 대상이 Fail 상태입니다."
    )

    fallback = base_text

    prompt = f"""
당신은 보안 점검 결과 문장을 자연스럽게 정리하는 AI이다.

[규칙]
1. 아래 입력 문장의 의미를 절대 바꾸지 말라.
2. item 이름, 숫자, Fail 상태를 바꾸지 말라.
3. 새로운 원인이나 설정값을 추가하지 말라.
4. 한국어 1문장만 출력하라.
5. 짧고 간단하게 작성하라.

[입력 문장]
{base_text}
""".strip()

    return safe_call_llm(prompt, fallback)


def build_good_description(good: dict) -> str:
    base_text = (
        f"{good['item']} 항목에서 "
        f"{good['target_count']}개 대상이 Pass 상태입니다."
    )

    fallback = base_text

    prompt = f"""
당신은 보안 점검 결과 문장을 자연스럽게 정리하는 AI이다.

[규칙]
1. 아래 입력 문장의 의미를 절대 바꾸지 말라.
2. item 이름, 숫자, Pass 상태를 바꾸지 말라.
3. 새로운 정보를 추가하지 말라.
4. 한국어 1문장만 출력하라.
5. 짧고 간단하게 작성하라.

[입력 문장]
{base_text}
""".strip()

    return safe_call_llm(prompt, fallback)


def default_action_guide(item_name: str) -> list:
    guide_map = {
        "IAM User MFA Enabled": [
            "MFA가 설정되지 않은 계정을 확인합니다.",
            "해당 계정에 MFA를 활성화합니다.",
            "적용 후 다시 점검합니다."
        ],
        "Security Group SSH Open": [
            "보안그룹의 22번 포트 규칙을 확인합니다.",
            "불필요한 전체 개방 규칙을 제거합니다.",
            "허용 대상을 최소 범위로 제한합니다."
        ],
        "S3 Public Access Block": [
            "버킷의 Public Access Block 설정을 확인합니다.",
            "필요 시 퍼블릭 접근 차단을 활성화합니다.",
            "버킷 정책과 접근 권한을 다시 점검합니다."
        ]
    }

    return guide_map.get(item_name, [
        f"{item_name} 설정 상태를 확인합니다.",
        "보안 기준에 맞게 설정을 적용합니다.",
        "변경 후 다시 점검합니다."
    ])


def generate_report(scan_data: dict) -> dict:
    summary = scan_data.get("summary", {})
    results = scan_data.get("results", [])

    vulnerabilities, good_items = group_results(results)

    report = {
        "summary_text": build_summary_text(summary),
        "summary": {
            "total_checks": summary.get("total_checks", 0),
            "pass_count": summary.get("pass_count", 0),
            "fail_count": summary.get("fail_count", 0),
            "security_score": summary.get("security_score", 0)
        },
        "vulnerabilities": [],
        "good_items": []
    }

    for vuln in vulnerabilities:
        report["vulnerabilities"].append({
        "item": vuln["item"],
        "risk": vuln["risk"],
        "kisa_code": vuln["kisa_code"],
        "affected_count": vuln["affected_count"],
        "targets": vuln["targets"],
        "details": vuln["details"],
        "analysis": build_issue_explanation(
            item_name=vuln["item"],
            risk=vuln["risk"],
            details=vuln["details"],
            affected_count=vuln["affected_count"]
        ),
        "action_guide": default_action_guide(vuln["item"])
    })

    for good in good_items:
        report["good_items"].append({
        "item": good["item"],
        "risk": good["risk"],
        "kisa_code": good["kisa_code"],
        "target_count": good["target_count"],
        "targets": good["targets"],
        "details": good["details"],
        "description": build_good_explanation(
            item_name=good["item"],
            risk=good["risk"],
            details=good["details"],
            target_count=good["target_count"]
        )
    })

    return report


def save_json(report: dict):
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def save_txt(report: dict):
    lines = []

    lines.append("=== 클라우드 보안 점검 보고서 ===")
    lines.append("")
    lines.append(report.get("summary_text", ""))
    lines.append("")

    summary = report.get("summary", {})
    lines.append("[점검 요약]")
    lines.append(f"- 전체 점검 수: {summary.get('total_checks', 0)}")
    lines.append(f"- Pass: {summary.get('pass_count', 0)}")
    lines.append(f"- Fail: {summary.get('fail_count', 0)}")
    lines.append(f"- Security Score: {summary.get('security_score', 0)}")
    lines.append("")

    lines.append("[취약점 항목]")
    vulns = report.get("vulnerabilities", [])
    if vulns:
        for idx, v in enumerate(vulns, start=1):
            lines.append(f"{idx}. 항목명: {v['item']}")
            lines.append(f"   - 위험도: {v['risk']}")
            lines.append(f"   - KISA 코드: {v['kisa_code']}")
            lines.append(f"   - 영향 대상 수: {v['affected_count']}")
            lines.append(f"   - 대상: {', '.join(v['targets'])}")
            lines.append(f"   - 설명: {v['analysis']}")
            if v.get("details"):
                lines.append("   - 근거:")
                for detail in v["details"]:
                    lines.append(f"     · {detail}")
            lines.append("   - 조치 가이드:")
            for step_no, step in enumerate(v["action_guide"], start=1):
                lines.append(f"     {step_no}) {step}")
            lines.append("")
    else:
        lines.append("- 취약점 항목이 없습니다.")
        lines.append("")

    lines.append("[양호 항목]")
    goods = report.get("good_items", [])
    if goods:
        for idx, g in enumerate(goods, start=1):
            lines.append(f"{idx}. 항목명: {g['item']}")
            lines.append(f"   - 위험도: {g['risk']}")
            lines.append(f"   - KISA 코드: {g['kisa_code']}")
            lines.append(f"   - 대상 수: {g['target_count']}")
            lines.append(f"   - 대상: {', '.join(g['targets'])}")
            lines.append(f"   - 설명: {g['description']}")
            if g.get("details"):
                lines.append("   - 근거:")
                for detail in g["details"]:
                    lines.append(f"     · {detail}")
            lines.append("")
    else:
        lines.append("- 양호 항목이 없습니다.")
        lines.append("")

    OUTPUT_TXT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def build_issue_explanation(item_name: str, risk: str, details: list, affected_count: int) -> str:
    fallback_map = {
        "IAM Admin User": (
            f"관리자 권한을 가진 계정이 {affected_count}개 확인되었습니다. "
            f"과도한 권한은 계정 오남용 시 피해를 크게 만들 수 있습니다."
        ),
        "CloudTrail Enabled": (
            "CloudTrail이 설정되지 않아 계정 내 주요 활동을 추적하기 어렵습니다. "
            "이 경우 사고 발생 시 원인 분석과 대응이 늦어질 수 있습니다."
        ),
        "Root Account MFA Enabled": (
            "루트 계정에 MFA가 설정되지 않았습니다. "
            "루트 계정은 권한 범위가 매우 크므로 추가 인증 수단이 필요합니다."
        ),
        "IAM User MFA Enabled": (
            f"IAM 사용자 중 {affected_count}개 계정에 MFA가 설정되지 않았습니다. "
            "비밀번호만으로 로그인하는 계정은 탈취 위험에 더 취약할 수 있습니다."
        ),
        "IAM Password Policy": (
            "IAM 비밀번호 정책이 설정되지 않았습니다. "
            "비밀번호 복잡도와 변경 주기 기준이 없으면 계정 보안 수준이 낮아질 수 있습니다."
        ),
        "Security Group ALL Open": (
            "전체 포트가 외부에 개방된 보안그룹은 확인되지 않았습니다. "
            "불필요한 네트워크 노출이 제한된 상태입니다."
        ),
        "Security Group SSH Open": (
            "22번 포트가 전체에 개방된 보안그룹은 확인되지 않았습니다. "
            "원격 접속 경로가 무분별하게 열려 있지 않은 상태입니다."
        ),
        "Security Group RDP Open": (
            "3389번 포트가 전체에 개방된 보안그룹은 확인되지 않았습니다. "
            "원격 데스크톱 접근 범위가 제한된 상태입니다."
        ),
        "IAM Access Key Unused": (
            "장기간 미사용된 액세스 키는 확인되지 않았습니다. "
            "불필요한 인증 정보가 남아 있을 가능성이 낮은 상태입니다."
        ),
        "S3 Public Access Block": (
            "퍼블릭 접근 차단 측면에서 점검 대상 S3 버킷이 없거나 추가 조치가 필요하지 않은 상태입니다."
        ),
        "S3 Bucket Encryption": (
            "버킷 암호화 측면에서 점검 대상 S3 버킷이 없거나 추가 조치가 필요하지 않은 상태입니다."
        ),
        "S3 Bucket Versioning": (
            "버전 관리 측면에서 점검 대상 S3 버킷이 없거나 추가 조치가 필요하지 않은 상태입니다."
        ),
    }

    fallback = fallback_map.get(
        item_name,
        f"{item_name} 항목과 관련된 보안 설정을 확인할 필요가 있습니다."
    )

    prompt = f"""
당신은 클라우드 보안 점검 결과를 비전문가도 이해할 수 있게 설명하는 AI이다.

[규칙]
1. 입력 정보만 사용하라.
2. 없는 계정명, 리소스명, 설정값을 만들지 말라.
3. 한국어로 1~2문장만 작성하라.
4. 과장하지 말라.
5. 마크다운, 코드블록 없이 일반 문장만 출력하라.
6. 첫 문장은 현재 상태, 둘째 문장은 왜 중요한지 설명하라.
7. details에 없는 구체 사실은 추가하지 말라.

[입력]
item: {item_name}
risk: {risk}
affected_count: {affected_count}
details: {details[:3]}
""".strip()

    return safe_call_llm(prompt, fallback)

def build_good_explanation(item_name: str, risk: str, details: list, target_count: int) -> str:
    fallback_map = {
        "Security Group ALL Open": (
            "전체 포트가 외부에 개방된 보안그룹은 확인되지 않았습니다. "
            "네트워크 노출 범위가 적절히 제한된 상태입니다."
        ),
        "Security Group SSH Open": (
            "22번 포트가 전체에 개방된 보안그룹은 확인되지 않았습니다. "
            "SSH 접근 통제가 기본적으로 잘 유지되고 있습니다."
        ),
        "Security Group RDP Open": (
            "3389번 포트가 전체에 개방된 보안그룹은 확인되지 않았습니다. "
            "원격 데스크톱 접근 범위가 제한된 상태입니다."
        ),
        "IAM Access Key Unused": (
            "장기간 미사용된 액세스 키가 확인되지 않았습니다. "
            "불필요한 인증 정보 관리 측면에서 양호한 상태입니다."
        ),
        "S3 Public Access Block": (
            "퍼블릭 접근 차단 기준에서 추가 위험이 확인되지 않았습니다."
        ),
        "S3 Bucket Encryption": (
            "버킷 암호화 기준에서 추가 위험이 확인되지 않았습니다."
        ),
        "S3 Bucket Versioning": (
            "버전 관리 기준에서 추가 위험이 확인되지 않았습니다."
        ),
    }

    fallback = fallback_map.get(
        item_name,
        f"{item_name} 항목은 현재 양호한 상태로 확인되었습니다."
    )

    prompt = f"""
당신은 클라우드 보안 점검 결과를 비전문가도 이해할 수 있게 설명하는 AI이다.

[규칙]
1. 입력 정보만 사용하라.
2. 없는 리소스, 계정, 설정을 만들지 말라.
3. 한국어로 1~2문장만 작성하라.
4. 과장하지 말라.
5. 마크다운 없이 일반 문장만 출력하라.
6. 현재 양호한 상태와 그 의미를 설명하라.

[입력]
item: {item_name}
risk: {risk}
target_count: {target_count}
details: {details[:3]}
""".strip()

    return safe_call_llm(prompt, fallback)


def main():
    scan_data = load_json()
    report = generate_report(scan_data)
    save_json(report)
    save_txt(report)
    print("✅ report.json, report.txt 생성 완료")


if __name__ == "__main__":
    main()