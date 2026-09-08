# Attack Scenarios

Three connected but distinct threat models against Kestrel Pay — each exercises different detections and defensive
muscles. Run any with `make emulate SCENARIO=<dir>` then `make detect`.

| Scenario | Threat model | Kill chain | Key detections |
|---|---|---|---|
| [**SCATTERED SABLE**](scattered-sable/) | External financially-motivated eCrime (flagship) | phishing → identity → endpoint → API → cloud → exfil/fraud (18 steps) | KP-0001/02/10-16/20-22/30-32/40-42 |
| [**HOLLOW HERON**](insider-heron/) | Malicious **insider** (legitimate access) | off-hours login → bulk read → mass export → personal-cloud exfil | KP-0050, KP-0014, KP-0051 |
| [**SPLINTER VIPER**](supply-chain-viper/) | **Software supply-chain / CI-CD** compromise | leaked CI secret → malicious dependency → unsigned prod deploy | KP-0060, KP-0061, KP-0062 |

**Why three?** They cover the three ways a fintech actually gets hurt: an outsider breaks in, an insider abuses trust,
or the pipeline is poisoned. Each needs *different* telemetry and detections — an external-IP/volume rule that catches
SABLE misses the insider (legit IP, legit auth) and the supply-chain attacker (never touches prod directly).

The flagship metrics (`metrics/metrics.json`, dashboard) are measured on **SCATTERED SABLE**; the other two ship their
own detections + tests and their firing is captured in [`../evidence/alerts/all-scenarios-detection-run.txt`](../evidence/alerts/all-scenarios-detection-run.txt).
All 23 detections are unit-tested (`make test`).
