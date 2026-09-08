# LinkedIn Assets — Project KESTREL

## Project title
Project KESTREL — Security Program & Purple-Team Range for a Fictional Fintech (detection-as-code, $0)

## Short description (Projects section)
Designed and built a small fintech's entire security program on one laptop for $0: threat model, telemetry pipeline,
15 unit-tested Sigma detections, a benign multi-stage intrusion emulation mapped to MITRE ATT&CK, full incident
response + DFIR, cloud IAM attack-path analysis, DevSecOps CI, and a risk register mapped to NIST CSF 2.0 / CIS v8 —
with measurable before/after results. Repo + evidence linked.

## Launch post
I spent [N] weeks building the strongest single security portfolio project I could — for $0, on an 8 GB laptop.

Instead of another "install Splunk + Kali" home SOC (which won't even run on my hardware), I built **Project KESTREL**:
the full security program of a fictional fintech, "Kestrel Pay."

I played the whole team — modeled the business + threats, stood up a vulnerable payments API (with an LLM copilot),
engineered **23 detection-as-code rules with unit tests**, emulated a financially-motivated intrusion end-to-end, ran
the incident + DFIR, hardened everything, and **measured the improvement**:
• 0% → 100% technique coverage of the intrusion
• 0 false positives on the benign baseline
• 7 → 0 attack paths to the crown jewels
• 41 IaC misconfigs caught pre-deploy

Everything reproduces with `make`. Repo + evidence in comments. Feedback welcome 👇
#cybersecurity #detectionengineering #blueteam #cloudsecurity #DevSecOps

## Technical follow-up post
A detail I'm proud of in Project KESTREL: the detections are **tested code**, not screenshots.

Each of the 23 Sigma rules ships with unit tests asserting it (a) fires on malicious input and (b) stays silent on a
benign baseline. The ATT&CK coverage matrix is generated *from the rules*, so it can't drift — and it lists the gaps I
*didn't* cover. Honest coverage > impressive-looking dashboards.

Here's how the pipeline works [thread/diagram] …

## Skills to list
Detection Engineering · MITRE ATT&CK · Sigma · Incident Response · DFIR · Threat Modeling · Cloud/IAM Security ·
Terraform · Checkov · Python · Purple Teaming · DevSecOps · Vulnerability Management · GRC (NIST CSF, CIS, SOC 2) · LLM/AI security
