# Resilience & Recovery (Phase 13)

Security is part of operational resilience: after an incident, how fast can Kestrel Pay safely restore service and
monitoring? Ties the SCATTERED SABLE incident to recovery priorities.

## Recovery priorities (by business criticality)
| Priority | Service | RTO (target) | RPO (target) | Why |
|---|---|---|---|---|
| 1 | Payment-signing / secrets (rotate) | 1h | 0 | Money movement blocked until keys are trusted |
| 2 | Identity / SSO (restore + FIDO2) | 2h | 0 | Everything depends on trusted identity |
| 3 | Payments API + ledger DB | 4h | 15m | Core product / customer money |
| 4 | Security telemetry + detections | 4h | 0 | Restore visibility for continued IR |
| 5 | CI/CD | 8h | 1h | Ship fixes safely |

## Backup / recovery considerations
- **Immutable, encrypted backups** of the ledger DB + config (object-lock), tested restores (a backup you haven't
  restored is a hope, not a backup).
- **Offline/second-region copy** of the signing-key material custody and of security logs (so an attacker who reaches
  prod can't destroy the evidence — ties to R-12, log integrity).
- **Golden IaC**: `hardened.tf.example` is the known-good rebuild target; recovery = redeploy from code, not snowflakes.

## Post-incident recovery of monitoring
Restoring the app is not "recovered" until detections are green again: after INC-2026-0821, re-run `make emulate &&
make detect` on the rebuilt stack to confirm coverage before declaring recovery (detections must still fire, and the
hardened build must show the app rules going quiet on the fixed paths).

## Lab vs enterprise
Lab: documented RTO/RPO + golden IaC + reproducible detection re-validation. Enterprise: cross-region DR, tested
runbooks, backup immutability (object-lock), and a separate logging account so telemetry survives a prod compromise.
