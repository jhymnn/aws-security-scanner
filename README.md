# AWS Security Scanner
KISA 가이드라인 기반 클라우드 보안 진단 및 생성형 AI 리포팅 시스템


## 프로젝트 소개
AWS 환경에서 보안 설정을 자동으로 점검하는 시스템입니다.
IAM, S3, RDS, CloudTrail 등 주요 서비스를 대상으로 취약점을 탐지하고 Security Score를 계산합니다.

AWS 클라우드 환경에서 보안 취약점을 자동으로 탐지하고, 국내 정보보호 기준에 맞추어 보안 상태를 진단하며, 생성형 AI 를 활용하여
사용자 친화적인 보안 리포트를 자동 생성하는 것을 목표로 한다. 
기존의 단순 취약점 탐지 도구와 달리, 본 시스템은 단순히 보안 설정의 이상 여부를 알려주는 것에서 그치지 않고, 취약점의 원인, 위험성, 개선 방안까지
자연어 형태로 설명함으로써 실제 활용 가능한 보안 컨설팅 도구의 역할까지 수행하도록 설계되었다.

---


## 실행 방법

### 1. 프로젝트 다운로드

```bash
git clone https://github.com/kiera0219-dot/grad-project.git
cd grad-project

```

### 2. 가상환경 생성 및 실행

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. 라이브러리 설치

```bash
pip install boto3
```

### 4. 실행

```bash
python -m scanner.main_scanner
```

---

## AWS 사전 설정 (필수)

### 1. Region

* 반드시 `ap-northeast-2 (서울)` 사용

---

### 2. RDS 생성 (테스트용)

* Public access: No
* Multi-AZ: No
* Encryption: OFF

---

### 3. CloudTrail 생성

* Multi-Region: ON
* 로그 암호화: OFF

---

## 결과 설명

* PASS → 안전
* FAIL → 취약
* Security Score → 전체 보안 수준 점수

---

## 주의사항

* 테스트 후 반드시 RDS 삭제 (비용 발생 방지)
* CloudTrail도 필요 없으면 삭제

---

## 팀원 역할

* Detection: AWS 설정 점검
* Reporting: 결과 분석 및 리포트 생성
* UI: 웹 화면 구현

---

## 향후 계획

* LLM 기반 보안 리포트 생성
* Flask 기반 웹 UI 개발
