# Safety, Scope & Ethics

**Project KESTREL** is a self-contained security-engineering portfolio project against a **fictional** company
recreated as a local lab. It exists to demonstrate the full defensive lifecycle: *attack → telemetry → detection →
investigation → response → remediation → validation.*

## Rules of engagement (non-negotiable)
- **Targets:** only this project's own containers, IaC, sample logs, and a scoped local lab folder on the builder's own machine.
- **No third parties.** Nothing here targets any real company, employer, school, website, or internet host.
- **No live malware.** The "malware analysis" component uses the industry-standard **EICAR** test string and a
  **self-authored, benign** demonstration artifact that only writes a marker file and beacons to a local sink. It has
  no payload, no persistence beyond a documented lab key, and ships with a cleanup routine.
- **Offensive activity is benign & reversible.** Adversary emulation uses lab-safe techniques that generate the right
  *telemetry* without causing harm; every scenario includes a **scope note** and a **cleanup/rollback** step.
- **Synthetic data only.** All "customer", "cardholder", and "PII" data is randomly generated and fake.
- **Endpoint telemetry** is collected from the builder's own Windows host using free Microsoft/Sysinternals tooling
  (Sysmon, PowerShell logging) under the builder's own authorization.

## If you fork/reproduce this
Run it only against your own systems. Read each scenario's scope note before executing anything. Restore/clean up when done.
