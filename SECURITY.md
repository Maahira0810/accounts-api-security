# Security Policy

## Reporting a vulnerability
Do **not** open a public issue. Email `security@example.com` (placeholder: replace with the real address) or use GitHub's private "Report a vulnerability" feature. Include affected component, reproduction steps, and impact. Do not include real customer data.

Targets: acknowledge within 2 business days; triage within 5; coordinated disclosure after a fix.

## Handling rules for contributors
- Never commit secrets, customer data, or production dumps. If you do, treat the secret as compromised: rotate it first, then remove it from history.
- Security findings and exceptions follow `DECISIONS.md` (waiver mechanism). No silent suppressions.
- Changes to `waivers/`, `k8s/policies/`, `.github/`, `scripts/` and `terraform/` require security-team review (`.github/CODEOWNERS`; effective only with branch protection enabled).
- Suspected incidents: follow `docs/LOGGING_AND_IR.md`.
