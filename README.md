# Security-Aware CI/CD Pipeline

> SAST 결과를 기반으로 서비스 맥락을 반영한 위험도를 산정하고, 위험 수준에 따라 Jenkins 빌드를 자동 차단하는 Risk-Based Security Gate 프로젝트

---

## 📌 프로젝트 소개

기존 SAST 도구는 CVSS 기반으로 취약점을 평가하지만, 실제 운영 환경에서는 동일한 취약점이라도 서비스 중요도, 노출 범위, 비즈니스 영향도에 따라 우선순위가 달라질 수 있습니다.

본 프로젝트는 이러한 한계를 개선하기 위해 취약점 정보를 수집하고, 서비스 맥락을 반영한 위험도 산정 모델을 적용하여 Jenkins CI/CD 환경에서 자동 보안 검증이 가능하도록 구현하였습니다.

---

## 🎯 주요 기능

- SAST 결과 수집
- Security Metrics 계산
- Endpoint 기반 위험도 분석
- 비즈니스 중요도 반영
- Risk Score 계산
- Jenkins Security Gate
- Grafana Dashboard 시각화

---

## 🏗️ 시스템 구성

![Architecture](images/architecture.png)

<img width="751" height="450" alt="image" src="https://github.com/user-attachments/assets/2e9af83f-c41c-419e-a009-591feb574ec2" />


---

## 🚨 High-Risk Endpoint 분석

취약 Endpoint를 분석하여 HTTP Method 분포와 비즈니스 기능별 분포를 시각화하였습니다.

이를 통해 단순 취약점 개수가 아닌 실제 영향도가 높은 기능 영역을 식별할 수 있도록 구현하였습니다.

![Endpoint Analysis](images/endpoint-analysis.png)

### 분석 결과 예시

- 총 43개 고위험 Endpoint 탐지
- GET / POST 요청에 위험 Endpoint 집중
- Internal, Personal 영역에 취약점 다수 분포

---

## 🔒 Jenkins Security Gate

위험 점수가 임계치를 초과할 경우 Jenkins Pipeline을 자동으로 중단하도록 구현하였습니다.

이를 통해 위험한 코드가 배포 단계로 진행되는 것을 방지할 수 있습니다.

![Jenkins Security Gate](images/jenkins-gate.png)

### 적용 정책

```text
Risk Score > Threshold

→ Build Failed
→ Deployment Blocked
```

---

## 📊 Security Dashboard

수집된 취약점 데이터를 기반으로 위험도와 취약점 현황을 실시간으로 시각화하였습니다.

![Security Dashboard](images/security-dashboard.png)

Dashboard 주요 정보

- 전체 위험 점수
- 차단 대상 취약점 수
- 고위험 Endpoint 수
- 취약점 추이
- 취약 패키지 현황

---

## 📦 Top Risk Packages

취약 패키지와 관련 CVE를 분석하여 우선 조치가 필요한 항목을 식별하였습니다.

![Top Risk Packages](images/top-risk-packages.png)

### 제공 정보

- 패키지명
- CVE 정보
- Severity
- 위험 점수

---

## 🛠️ 기술 스택

### CI/CD

- Jenkins
- Git

### Security

- SAST
- Security Metrics
- CVE Analysis

### Backend

- Python

### Visualization

- Grafana

### Environment

- Docker
- Linux

---

## 👨‍💻 담당 역할

- Security Metrics 계산 로직 구현
- Risk Score 산정 모델 개발
- Endpoint 위험도 분석 기능 구현
- Jenkins Security Gate 구현
- Grafana Dashboard 구축
- 취약 패키지 분석 기능 구현

---

## 📚 배운 점

- CVSS 점수만으로는 실제 위험도를 충분히 표현하기 어렵다는 점을 확인
- 서비스 맥락과 비즈니스 중요도를 반영한 평가가 필요함을 경험
- 정적 분석만으로는 실제 악용 가능성을 판단하는 데 한계가 존재함을 확인
- 향후 DAST 및 Runtime 정보를 연계한다면 더욱 현실적인 위험도 평가가 가능할 것으로 판단
