# Interview Prep — Project KESTREL

## 30-second explanation
"I built the entire security program of a fictional fintech — on one laptop, for $0. I modeled its risks, stood up a
vulnerable payments API, wrote tested detections as code, emulated a real intrusion, ran the incident response, hardened
everything, and measured the improvement: zero to 100% detection coverage of the attack, zero false positives, and I
eliminated every attack path to the crown jewels. It all reproduces with a couple of `make` commands."

## 60-second explanation
Add: "The company, Kestrel Pay, sells an embedded-payments API, so its crown jewels are the signing keys, the cloud
account, and cardholder data. I emulated a financially-motivated actor — 'SCATTERED SABLE' — that starts with MFA
fatigue on an engineer, steals a session, moves through the endpoint and API, then pivots into AWS to read the signing
key and escalate IAM. Because my hardware can't run a heavyweight SIEM, I built a SIEM-less detection-as-code pipeline
with Sigma and DuckDB. The point wasn't the tools — it was showing the whole lifecycle and proving it worked with
numbers and passing tests."

## 3-minute technical explanation (structure)
1. **Context & crown jewels** (fintech, identity is the perimeter).
2. **Architecture choice + tradeoff** (SIEM-less on 8 GB; document enterprise equivalent).
3. **Telemetry** (normalize app/nginx/Sysmon/CloudTrail/identity → DuckDB).
4. **Detection-as-code** (Sigma → SQL, 23 rules, 56 unit tests, coverage matrix with gaps).
5. **Emulation → incident** (18-step chain → 25 alerts → IR/DFIR → RCA).
6. **Remediation + measurement** (hardened build retested; 0→100%, 7→0 paths, 0 FP).

## Architecture walkthrough
Point at `docs/architecture/current-state.md` → `target-state.md`: 10 gaps → controls, each tied to a risk and evidence.
Emphasize the log-flow and that detections are batch (honest) with the enterprise streaming equivalent noted.

## Incident walkthrough
INC-2026-0821: first alert = KP-0001 MFA fatigue → correlate same IP/actor across identity+endpoint+cloud → SEV-1 on
secrets access → contain (disable/revoke/isolate/detach/revert/freeze) → eradicate (rotate keys, re-image) → RCA:
identity + cloud IAM weren't treated as the primary perimeter.

## Toughest technical challenge
"Making detections *testable* without a real SIEM. I wrote a small Sigma→DuckDB compiler with a temporal-aggregation
extension so velocity rules (MFA fatigue, IDOR enumeration) work, then unit-tested every rule against crafted malicious
and benign events. Getting the false-positive rate to 0 on the baseline while still firing on the attack was real
threshold-tuning, not luck."

## Failure / lesson learned
"My first multi-source telemetry samples silently dropped — a JSON-escaping bug meant the Sysmon events never loaded and
my endpoint rules looked like they worked when they had no data. I caught it because the source counts didn't add up. The
lesson: validate your telemetry *ingestion* before trusting any detection result — no data looks exactly like no threats."

## Security tradeoff example
"Batch detection vs streaming. Batch fit my hardware and made everything reproducible and testable, but it isn't
real-time. I documented that explicitly and described the enterprise streaming equivalent, rather than pretending a
laptop is a production SOC."

## Business-risk example
"I prioritized an IAM wildcard and an SSRF above a 'publicly accessible database' because they sit on the attack path
from a phished laptop to the payment-signing key. CVSS alone would have misordered them. Prioritization should follow
the crown-jewel attack path, not just severity scores."

## "Why did you build this?"
"I wanted to prove I can think across the whole security lifecycle — attack, defend, investigate, improve, and
communicate to executives — not just run one tool. And I wanted something a skeptic could clone and re-run, so the work
speaks for itself."

## Likely interviewer questions + answer frameworks
| Question | Framework |
|---|---|
| "Walk me through a detection you wrote." | Pick KP-0001: threat → data source → logic (≥3 denials/10m) → FP tuning → test → response |
| "How do you know it works?" | Unit tests + emulation firing + 0 FP on baseline; show `evidence/alerts/` |
| "What would you do differently at scale?" | Streaming SIEM, cross-host correlation, EDR fleet, real IdP logs, SOAR |
| "How do you prioritize vulns?" | Exploitability + exposure + asset value + attack-path; EPSS/KEV in prod |
| "What did you NOT cover?" | Coverage-matrix gaps (T1566/T1110/T1114.003/T1195) — honesty signals maturity |
| "Explain this to a CEO." | Use `incident-response/exec-summary.md` — money, data, SOC 2, what we changed |
