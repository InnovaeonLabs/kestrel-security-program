# Executive Incident Summary — INC-2026-0821

**Audience:** CEO / Board / customers' security teams. **One page. No jargon.**

## What happened
On 21 Aug, an attacker tricked an engineer into approving a login (repeated push notifications until they accepted),
then used that access to move from the laptop into our cloud and payments system. They reached our most sensitive
assets — the key that authorizes payments, our cloud administrator controls, and customer records — and attempted to
export data and redirect a payout.

## Did it succeed?
The attempt was **caught by our monitoring at the very first step** and again at every stage. In this exercise the
payout was frozen before release and no customer funds moved. Because the attacker briefly held the payment-signing key
and admin access, we treated those as compromised and **rotated them** as a precaution.

## Why it mattered to the business
A successful version of this attack could have meant **fraudulent transfers, exposure of customer card/bank data,
regulatory penalties (PCI / privacy), and loss of our SOC 2 standing** — the things our customers require to keep using us.

## How well we responded (measured)
- Detected at **initial access**, ~**7 minutes before** the first fraud action — enough time to contain.
- **100%** of the attack's techniques (16/16) were caught by our detections; **25 alerts** fired.
- **Zero false alarms** on normal activity, so analysts weren't distracted by noise.

## What we're changing
1. **Stronger login security** that can't be phished (hardware-key / number-matching MFA).
2. **Tighter cloud permissions** so one stolen account can't become an administrator.
3. **Fixes to the payments API** that close the specific weaknesses used (already built; see hardened build).
4. **Alerting on access to the signing key and admin changes**, plus two new detections for gaps we found.

## Bottom line
The controls worked and the business impact was contained. The changes above remove the root cause — treating identity
and cloud permissions as the primary line of defense — and are tracked to completion in the risk register.
