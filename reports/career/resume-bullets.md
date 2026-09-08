# Resume Bullets — Project KESTREL

Framed as **independent project** experience (never as employment). Structure:
ACTION + ENVIRONMENT + SECURITY PROBLEM + TECHNICAL METHOD + MEASURABLE RESULT.
Use the header line + 3–5 role-tailored bullets.

**Project KESTREL — Independent Security Program & Purple-Team Range** (Python, Docker, Sigma, DuckDB, Terraform, MITRE ATT&CK)

## Core bullets (use anywhere)
- Designed and built the end-to-end security program for a fictional fintech on a single 8 GB host for $0, using a
  SIEM-less **detection-as-code** pipeline (Sigma → DuckDB); engineered **23 unit-tested detections** achieving **100%
  technique coverage** of an emulated multi-stage intrusion with **0 false positives** on a benign baseline.
- Emulated a financially-motivated intrusion (identity → endpoint → cloud → API) mapped to **MITRE ATT&CK**, then ran
  the full **detect → investigate → contain → remediate → retest** loop, cutting **7 identity/cloud attack paths to the
  crown jewels to 0** via least-privilege.
- Automated the defensive workflow (log normalization, detection execution, metrics, and a generated HTML dashboard) so
  the entire attack-to-evidence pipeline reproduces with `make emulate && make detect && make report`.

## SOC Analyst
- Investigated an emulated intrusion from first alert (MFA-fatigue) to containment using a normalized multi-source
  telemetry store, extracting **11 IOCs** and building an incident timeline that showed a **~7-minute detection window
  before business impact**.
- Tuned detection thresholds against a benign baseline to hold **false positives at 0/40 events** while catching all
  15 attack steps.

## Detection Engineer
- Authored **23 Sigma detections** across identity, endpoint, cloud, API, and LLM sources with a purpose-built
  Sigma→SQL runner, and wrote **56 unit tests** asserting each rule fires on malicious input and stays silent on benign.
- Generated an **ATT&CK coverage matrix + Navigator layer from the rules themselves**, documenting real coverage gaps
  rather than claiming full coverage.

## Cloud Security
- Modeled a fintech AWS footprint in **Terraform**, identified **41 misconfigurations + a hardcoded secret** with
  **Checkov**, and eliminated an IAM privilege-escalation path (wildcard role) that turned an SSRF into full account control.

## Incident Responder / DFIR
- Produced a full incident report + one-page **executive summary** + DFIR notes with reproducible DuckDB pivots for a
  SEV-1 intrusion touching payment-signing keys, cloud IAM, and cardholder data.

## GRC / Risk
- Built a 12-risk register scored to residual risk and mapped controls to **NIST CSF 2.0, CIS v8, and SOC 2** with
  operating evidence; prioritized 12 vulnerabilities by exploitability + exposure + asset value + attack-path (not CVSS alone).

## AppSec / Product Security
- Built and secured a vulnerable payments API (IDOR, SQLi, SSRF, JWT alg=none) **plus an LLM copilot vulnerable to
  prompt injection**, then remediated and **retested** the auth-bypass and injection flaws with passing unit tests.
