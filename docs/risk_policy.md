# Risk Policy — CVSS·EPSS 기반 Risk Scoring 정책

## 1. 목적

이 문서는 ASM-Lite 프로젝트의 **4번 역할: CVSS·EPSS 기반 Risk Scoring**에서 사용하는 위험 점수 산정 기준을 설명한다.

Risk Scoring의 목적은 단순히 열린 포트나 취약점 목록을 나열하는 것이 아니라, 탐지된 보안 이슈를 **조치 우선순위(P1~P4)** 로 변환하는 것이다.

본 정책은 다음 정보를 종합하여 위험도를 계산한다.

- 열린 포트 및 서비스 노출 상태
- nmap 서비스/버전 탐지 결과
- nuclei finding severity
- CVSS 점수
- EPSS 악용 가능성
- CISA KEV 등재 여부
- 신규 포트 또는 신규 취약점 여부
- 자산 중요도
- CVE 탐지 신뢰도: validated vs candidate

---

## 2. 참고 기준

본 프로젝트는 상용 ASM 제품이나 Qualys/Tenable 수준의 통계 기반 모델을 그대로 구현한 것은 아니다.  
다만 다음 공식 지표와 개념을 기반으로 세미 프로젝트 범위에 맞춘 **정책 기반 Risk Scoring 모델**을 구현했다.

### 2.1 CVSS

CVSS(Common Vulnerability Scoring System)는 취약점의 기술적 심각도를 수치화하는 표준 지표다.

본 프로젝트는 CVSS v3.x의 severity 구간을 기준으로 위험도를 나눈다.

| CVSS 점수 | 등급 |
|---:|---|
| 0.1 ~ 3.9 | Low |
| 4.0 ~ 6.9 | Medium |
| 7.0 ~ 8.9 | High |
| 9.0 ~ 10.0 | Critical |

참고:
- FIRST CVSS v3.1 Specification: https://www.first.org/cvss/v3.1/specification-document

### 2.2 EPSS

EPSS(Exploit Prediction Scoring System)는 특정 CVE가 향후 30일 내 실제 악용될 가능성을 0~1 사이의 확률값으로 제공하는 지표다.

본 프로젝트에서는 EPSS를 단독 점수로 사용하지 않고, CVSS, KEV, 탐지 신뢰도와 함께 사용한다.

예를 들어 CVSS가 높고 EPSS도 높은 취약점은 우선순위를 높게 부여한다.  
반대로 EPSS가 낮거나, 단순 후보 CVE인 경우에는 과도하게 P1으로 승격되지 않도록 제한한다.

참고:
- FIRST EPSS: https://www.first.org/epss/
- FIRST EPSS User Guide: https://www.first.org/epss/user-guide

### 2.3 CISA KEV

CISA KEV(Known Exploited Vulnerabilities)는 실제 공격에 악용된 이력이 있는 취약점 목록이다.

본 프로젝트에서는 KEV에 포함된 CVE를 매우 높은 위험 신호로 본다.  
KEV CVE가 탐지되면 P1 승격 조건에 강하게 반영한다.

참고:
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### 2.4 SSVC 개념

SSVC(Stakeholder-Specific Vulnerability Categorization)는 취약점 대응 우선순위를 결정하기 위한 방법론이다.

ASM-Lite는 SSVC를 그대로 구현하지는 않았지만, “취약점의 심각도만 보는 것이 아니라 실제 조치 우선순위를 결정한다”는 개념을 참고하여 P1~P4 우선순위 체계를 사용한다.

참고:
- CISA SSVC: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc

---

## 3. 핵심 설계 원칙

### 3.1 확정 탐지와 후보 탐지를 구분한다

Risk Scoring에서 가장 중요한 기준은 **검증된 취약점(validated vulnerability)** 과 **후보 취약점(candidate vulnerability)** 을 구분하는 것이다.

| 구분 | 설명 | 점수 반영 |
|---|---|---|
| Validated CVE | nuclei가 직접 탐지한 CVE 또는 명확한 취약점 finding | 강하게 반영 |
| KEV CVE | CISA KEV에 포함된 실제 악용 취약점 | 매우 강하게 반영 |
| Candidate CVE | nmap product/version 기반 NVD 후보 | 제한적으로 반영 |
| Info Finding | 기술/문서/엔드포인트 존재 확인 | 낮게 반영 |

### 3.2 후보 CVE만으로 P1이 되지 않게 한다

nmap product/version 기반 CVE는 실제 취약점이 아니라 “가능성 있는 후보”다.

따라서 다음 제한을 둔다.

- nmap/NVD 후보 CVE만으로는 Critical/P1으로 승격하지 않는다.
- nmap/NVD 후보 증거는 confidence를 낮게 적용한다.
- nmap/NVD 후보 증거에는 점수 상한을 둔다.
- 확정 finding이나 KEV가 없으면 후보 기반 위험도는 최대 High/P2 수준으로 제한한다.

이 정책은 서비스 배너 기반 오탐을 줄이기 위한 장치다.

### 3.3 정보성 finding은 낮게 반영한다

nuclei의 `info` severity는 “취약점 확정”이 아니라 정보성 탐지다.

예:

- OpenAPI 문서 탐지
- Swagger/ReDoc 탐지
- robots.txt 탐지
- OWASP Juice Shop 식별
- SMB enumeration 정보

이런 항목들은 공격 표면을 이해하는 데 유용하지만, 그 자체만으로 Critical/P1이 되면 안 된다.

---

## 4. Risk Score 구성 요소

최종 점수는 0~100 범위로 제한한다.

```text
최종 Risk Score =
  포트 노출 점수
+ 서비스/버전 식별 점수
+ CPE 식별 점수
+ nuclei severity 점수
+ CVSS 점수
+ EPSS 점수
+ KEV 점수
+ 신규 노출 점수
± 정책 보정
× 자산 중요도 multiplier
```

최종 점수는 100점을 넘지 않도록 cap을 적용한다.

---

## 5. 포트 위험도 정책

열린 포트는 공격 표면을 의미하므로 기본 위험 점수에 반영한다.

| 포트 | 서비스 예시 | 위험도 해석 |
|---:|---|---|
| 21 | FTP | 평문 인증 가능성, 오래된 서비스 가능성 |
| 22 | SSH | 관리 서비스 외부 노출 |
| 23 | Telnet | 평문 원격 접속, 고위험 |
| 80/443 | HTTP/HTTPS | 웹 공격 표면 |
| 135 | MSRPC | Windows RPC 노출 |
| 445 | SMB | 파일 공유/Windows 공격 표면, 고위험 |
| 3306 | MySQL | DB 외부 노출 |
| 3389 | RDP | 원격 데스크톱 노출 |
| 5432 | PostgreSQL | DB 외부 노출 |
| 6379 | Redis | 인증 설정 미흡 시 고위험 |
| 9200 | Elasticsearch | 데이터 노출 가능성 |

주의:
- 포트 노출만으로 취약점이 확정되는 것은 아니다.
- 다만 외부 공격자 관점에서 접근 가능한 서비스이므로 Risk Score에 반영한다.

---

## 6. CVSS 점수 정책

CVSS는 취약점 자체의 기술적 심각도를 반영한다.

| CVSS 구간 | 의미 | 점수 반영 방향 |
|---:|---|---|
| 9.0 ~ 10.0 | Critical | 매우 강하게 반영 |
| 7.0 ~ 8.9 | High | 강하게 반영 |
| 4.0 ~ 6.9 | Medium | 중간 수준 반영 |
| 0.1 ~ 3.9 | Low | 낮게 반영 |

정책 원칙:

- CVSS 9.0 이상은 기술적 심각도가 매우 높으므로 P1 후보가 될 수 있다.
- 단, nmap/NVD 후보 CVE인 경우에는 확정 취약점이 아니므로 별도 cap을 적용한다.
- CVSS만으로 최종 우선순위를 결정하지 않고 EPSS, KEV, 탐지 신뢰도와 함께 판단한다.

---

## 7. EPSS 점수 정책

EPSS는 실제 악용 가능성을 반영한다.

| EPSS 구간 | 해석 | 점수 반영 방향 |
|---:|---|---|
| 0.70 이상 | 매우 높은 악용 가능성 | 강하게 반영 |
| 0.30 이상 | 높은 악용 가능성 | 중간~높게 반영 |
| 0.10 이상 | 주의 필요 | 제한적으로 반영 |
| 0.10 미만 | 낮은 악용 가능성 | 낮게 반영 |

정책 원칙:

- EPSS는 단독으로 P1을 만들지 않는다.
- CVSS가 높고 EPSS도 높은 경우 우선순위를 올린다.
- KEV에 포함된 CVE는 EPSS가 낮아도 실제 악용 이력이 있으므로 별도 우선순위 상승 조건을 적용한다.

---

## 8. KEV 정책

CISA KEV에 포함된 CVE는 실제 악용된 이력이 있는 취약점으로 본다.

정책:

- KEV CVE가 탐지되면 강한 가중치를 부여한다.
- KEV + CVSS High 이상 또는 EPSS 유의미 구간이면 P1로 승격할 수 있다.
- KEV는 단순 후보보다 우선순위가 높다.

---

## 9. nmap/NVD 후보 CVE 정책

nmap으로 탐지한 `product/version` 또는 CPE 정보를 기반으로 NVD를 검색하면 관련 CVE 후보를 얻을 수 있다.

하지만 이 방식은 실제 취약점 검증이 아니다.

예:

```text
Apache httpd 2.4.7
OpenSSH 6.6.1p1
```

이런 배너 기반 정보는 실제 패치 백포트 여부, 배포판 보안 패치 여부, 설정 상태를 정확히 반영하지 못할 수 있다.

따라서 nmap/NVD 후보에는 다음 정책을 적용한다.

| 항목 | 정책 |
|---|---|
| confidence | 낮게 적용 |
| 점수 상한 | 후보 증거 합산 상한 적용 |
| P1 승격 | 후보만으로는 금지 |
| Critical 승격 | 후보만으로는 제한 |
| 설명 | risk_reasons에 candidate임을 명시 |

예시 reason:

```text
Nmap/NVD service CVE candidate severity=high
candidate evidence cap applied
not a validated vulnerability
```

---

## 10. Risk Level 정책

최종 점수에 따라 위험 등급을 부여한다.

| Risk Score | Risk Level |
|---:|---|
| 90 ~ 100 | Critical |
| 70 ~ 89 | High |
| 30 ~ 69 | Medium |
| 0 ~ 29 | Low |

정책 의도:

- 90점 이상만 Critical로 분류한다.
- 70~89점은 High로 분류하여 중요한 조치 대상으로 본다.
- 30~69점은 Medium으로 분류하여 계획 조치 대상으로 본다.
- 0~29점은 Low로 분류한다.

---

## 11. Priority 정책

우선순위는 단순 점수뿐 아니라 KEV, CVSS, EPSS 조건을 함께 고려한다.

| Priority | 의미 | 예시 |
|---|---|---|
| P1 | 즉시 조치 | Critical CVE, KEV, CVSS+EPSS 모두 높음 |
| P2 | 우선 조치 | High 위험, nmap/NVD 후보 중 높은 CVSS/EPSS |
| P3 | 계획 조치 | Medium 위험, 관리 포트 노출 |
| P4 | 관찰/참고 | Low 위험, 정보성 finding |

정책 예시:

- score >= 90 → P1
- KEV + 유의미한 CVSS/EPSS → P1
- CVSS 9.0 이상 + EPSS 0.70 이상 + 충분한 점수 → P1
- score >= 70 → P2
- CVSS High + EPSS 유의미 → P2
- score >= 30 → P3
- 그 외 → P4

---

## 12. SLA 정책

Priority에 따라 조치 권장 시간을 매핑한다.

| Priority | SLA |
|---|---:|
| P1 | 24시간 |
| P2 | 72시간 |
| P3 | 336시간 |
| P4 | 720시간 |

SLA는 실제 조직 정책에 따라 조정 가능하다.

---

## 13. risk_reasons 정책

Risk Score는 반드시 설명 가능해야 한다.

각 점수 기여 요소는 `risk_reasons`에 저장한다.

예:

```json
{
  "scan_id": 2,
  "category": "cvss",
  "severity": "high",
  "score_delta": 20,
  "reason": "CVSS 8.2 for CVE-2021-44224 (+20, confidence=0.65)"
}
```

저장 목적:

- 왜 점수가 나왔는지 추적
- 과점수/오탐 여부 검토
- 팀원 간 디버깅
- 대시보드/리포트 연동
- Risk Scoring 정책 검증

---

## 14. 테스트 정책

Risk Scoring은 실제 스캔 결과에만 의존하지 않고 단독 테스트로 검증한다.

필수 테스트 케이스:

| 케이스 | 기대 결과 |
|---|---|
| SSH + HTTP only | Medium / P3 |
| New SMB exposure | High / P2 |
| Critical CVE + High EPSS | Critical / P1 |
| KEV CVE | Critical / P1 |
| Nmap/NVD candidate only | candidate cap 적용, P1 금지 |

성공 기준:

```text
ALL RISK SCORING POLICY TESTS PASSED
```

---

## 15. 한계

본 Risk Scoring은 세미 프로젝트 범위의 정책 기반 모델이다.

다음 한계가 있다.

- 실제 상용 ASM처럼 대규모 위협 인텔리전스를 지속 반영하지는 않는다.
- 점수 가중치는 프로젝트 정책값이며, 통계적으로 검증된 산업 표준 수치는 아니다.
- nmap/NVD 후보는 실제 취약점 검증이 아니므로 오탐 가능성이 있다.
- OS 배포판의 보안 패치 백포트 여부를 완전히 반영하지 못한다.
- CVSS Temporal / Environmental Metric을 완전 구현하지는 않았다.
- 실제 기업 자산 가치, 인터넷 노출 범위, 보상 통제 여부까지 완전 반영하지는 않는다.

---

## 16. 결론

ASM-Lite의 Risk Scoring은 다음을 목표로 한다.

```text
탐지 결과를 단순 나열하지 않고,
공식 지표(CVSS, EPSS, KEV)를 참고하여
조치 가능한 우선순위(P1~P4)로 변환한다.
```

본 정책은 상용 ASM 수준의 완전한 통계 모델은 아니지만, 세미 프로젝트 범위에서는 다음 요소를 갖춘 Risk Scoring 프로토타입이다.

- CVSS 기반 기술 심각도 반영
- EPSS 기반 실제 악용 가능성 반영
- CISA KEV 기반 실제 악용 이력 반영
- 포트/서비스 노출 기반 공격 표면 반영
- 신규 노출 변화 감지
- 자산 중요도 반영
- 후보 CVE 과점수 방지
- risk_reasons 기반 설명 가능성
- 자동 테스트 기반 정책 검증

따라서 본 모듈은 “경험적 점수화”를 넘어서, 공식 보안 지표를 참고한 **정책 기반 Risk Scoring 엔진**으로 정의한다.
