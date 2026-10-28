# Threat Model: accounts-api

## 1. Scope and assets
`accounts-api` (EKS `ap-south-1`, behind CloudFront + ALB) handles customer PII, IBANs, balances and card last-four digits. It uses RDS PostgreSQL, a message stream, an audit log, and a third-party KYC provider. It shares a cluster with ~12 other services; ~40 engineers can merge; the platform team is 2 people.

| Asset | Why it matters |
|---|---|
| A1 Customer PII + financial data (RDS, API responses, logs) | Regulatory and reputational impact |
| A2 Workload/AWS credentials (IRSA role, DB/KYC secrets) | Pivot to A1 |
| A3 Build/release pipeline and signing identity | Controls what runs in production |
| A4 Audit records | Evidence for regulators and incidents |
| A5 Cluster shared tenancy | Blast radius of one compromised pod |

## 2. Trust boundaries
1. Internet/CloudFront/WAF → ALB → pod (untrusted client input).
2. Pod ↔ other namespaces in a shared cluster (semi-trusted tenants).
3. Pod → AWS APIs (IAM boundary) and → RDS (data boundary).
4. Pod ↔ third-party KYC provider (untrusted external party, both directions).
5. GitHub (40 committers) → AWS accounts (CI trust boundary).
6. Workload accounts → log-archive account (audit trust boundary).

## 3. Threat register
Likelihood (L) and Impact (I): H/M/L. Rating = qualitative combination. "Residual" is the rating after the controls described in `DECISIONS.md`.

| ID | STRIDE | Threat | L | I | Inherent | Key mitigations (control IDs → DECISIONS.md) | Residual |
|---|---|---|---|---|---|---|---|
| T01 | I | Customer data disclosure via API flaws, over-broad queries, or PII in logs/responses | M | H | High | D03 field allow-list logging, D09 KMS/RDS encryption, SG-scoped RDS, WAF | Medium: app-layer authz flaws are outside this repo |
| T02 | E, T | Compromised workload (RCE) escalates privileges or escapes container | M | H | High | D01 hardened pod + admission policy, PSA `restricted`, no K8s token, D05 IRSA least privilege, runtime detection | Medium: kernel/runtime 0-days |
| T03 | E, T | Lateral movement to/from other services in the shared cluster | M | H | High | D02 default-deny NetworkPolicy, dedicated SA, no token, namespace isolation | Medium: CIDR-level rules are coarse; shared nodes |
| T04 | T | Supply-chain attack: malicious dependency/base image/tag re-pointing | M | H | High | D07 digest pinning, immutable ECR tags, scan on push, CI vuln scan | Medium-High: signing/verification is **not yet implemented** |
| T05 | S, E | Compromised CI credentials or abuse of GitHub OIDC trust | M | H | High | D06 OIDC (no stored keys), trust scoped to repo+environment, short sessions, CODEOWNERS | Medium |
| T06 | E | Excessive IAM permissions (workload, CI, cross-account) | H | H | High | D05 resource-scoped policies, conditions, ExternalId, no wildcard actions | Low-Medium |
| T07 | I | Leaked secrets (in repo, images, env, logs) | M | H | High | D04 Secrets Manager at runtime, gitleaks, `.gitignore`, no secrets in manifests | Medium: runtime memory exposure |
| T08 | S, T, I | Malicious/compromised KYC provider: poisoned responses, or exfiltration via egress | L-M | H | Medium-High | D02 egress allow-list at proxy/firewall, strict response schema validation (app), timeouts | Medium: FQDN filtering is not in NetworkPolicy |
| T09 | R, T | Audit log tampering or deletion | L | H | Medium | D08 CloudTrail log validation, separate account, Object Lock, deny-delete, SCP | Low-Medium |
| T10 | T, E | Insecure infrastructure change (Terraform/K8s drift or misconfig merged) | H | M-H | High | D06 CI IaC scan + terraform validate, CODEOWNERS, admission policy, plan-review | Medium |
| T11 | T, R | Security-gate bypass (admin merge, disabled checks, abused/forever waivers) | M | H | High | D10 waiver validator + expiry, CODEOWNERS, branch protection (must be configured), break-glass review | Medium: depends on org settings outside the repo |

## 4. STRIDE walk-through (summary)
- **Spoofing:** forged CI identity (T05), forged workload identity (T02, T06), spoofed KYC responses (T08).
- **Tampering:** images/tags (T04), IaC (T10), audit log (T09), gate configuration (T11).
- **Repudiation:** missing or alterable audit trail (T09), unattributed waivers (T11).
- **Information disclosure:** PII leaks (T01), secrets (T07), egress exfiltration (T08).
- **Denial of service:** resource exhaustion by one pod affecting neighbours; mitigated by CPU/memory limits (WS-06) and replicas. Not given a T-ID; rated Medium, partly out of scope (WAF rate limiting).
- **Elevation of privilege:** container escape (T02), lateral movement (T03), IAM (T06).

## 5. Residual risks accepted for the take-home scope
See `DECISIONS.md` §Deferred. The most significant: unsigned images (T04), coarse egress control for KYC (T08), and gate bypass relying on correctly configured GitHub branch protection (T11).
