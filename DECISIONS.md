# Engineering Decisions

Audience: a 2-person platform team supporting ~40 committers. Preference order: (1) preventative controls that need no per-team effort, (2) controls that fail loudly in CI, (3) documented process only where tooling is not feasible.

## 1. Threat → control traceability
| Threat | Decisions | Implemented in this repo | Not implemented / deferred |
|---|---|---|---|
| T01 | D03, D09 | `docs/LOGGING_AND_IR.md` (spec), Terraform KMS keys | RDS/SG Terraform, app-level authz, log pipeline code |
| T02 | D01, D05 | `k8s/accounts-api.yaml`, Kyverno policy, `policy_check.py`, IRSA role | Runtime sensor deployment (GuardDuty feature declared only) |
| T03 | D01, D02 | `k8s/network-policy.yaml`, dedicated SA, no token | Per-service mesh authn, node isolation |
| T04 | D07 | Digest pin (placeholder), immutable ECR, scan on push, CI Trivy | **Signing, provenance, admission verification** |
| T05 | D06 | OIDC trust Terraform, `permissions: contents: read`, CODEOWNERS | Org-level SCPs, GitHub org settings |
| T06 | D05 | Resource-scoped IAM, conditions, ExternalId | IAM Access Analyzer, permission boundaries |
| T07 | D04 | No secrets in manifests, Secrets Manager policy, `.gitignore`, gitleaks job | Secret rotation Terraform |
| T08 | D02 | Egress limited to proxy CIDR (documented limits) | Network Firewall/proxy FQDN allow-list |
| T09 | D08 | CloudTrail validation + bucket policy Terraform | Object Lock, SCPs (described only) |
| T10 | D06 | CI Trivy config + terraform validate, admission policy | Drift detection, plan-review automation |
| T11 | D10 | `waiver_check.py` + tests, CODEOWNERS | Branch-protection/ruleset configuration (org-side) |

## 2. Decisions

**D01 Hardened pod + one preventative admission policy (T02, T03, T10).** Non-root, no privilege escalation, `drop: ALL`, seccomp `RuntimeDefault`, read-only rootfs, CPU/memory requests+limits, dedicated SA, no token mount, digest-pinned image. *Why:* with 12 other services, a compromised pod must not gain host or API power. *Policy choice:* a single Kyverno `Enforce` policy (YAML, readable by non-experts) beats many advisory policies for a small team. *Rejected:* OPA Gatekeeper (Rego learning curve for a 2-person team); PSA alone (cannot require digests/limits; kept as a second layer on the namespace). *Local enforcement:* `scripts/policy_check.py` mirrors the rules because Kyverno is not installed here; it is a pre-merge check, not the enforcement point.

**D02 Default-deny NetworkPolicy with explicit allows (T03, T08).** Allows: ALB subnet ingress on 8080; CoreDNS; RDS subnet 5432; VPC-endpoint subnet 443; egress-proxy subnet 443 for KYC. *Limits, stated plainly:* standard NetworkPolicy has no FQDN support, so the KYC rule restricts only the *next hop*; the domain allow-list must live in AWS Network Firewall or a proxy (or Cilium FQDN policies if Cilium is adopted). DNS tunnelling is not prevented (use Route 53 Resolver DNS Firewall). RDS is selected by subnet CIDR, so also enforce at the RDS security group. Ingress is CIDR-level; CloudFront-only access belongs on the ALB SG via the CloudFront managed prefix list plus a secret header/WAF. *Requires* a CNI that enforces policy; on EKS this means enabling the VPC CNI network-policy feature or using Calico/Cilium. *Rejected:* service mesh mTLS now (operational cost; deferred).

**D03 Structured, allow-listed logging (T01).** See `docs/LOGGING_AND_IR.md`. Allow-list fields at the logger rather than redact after the fact; regex redaction is a backstop only.

**D04 Runtime secrets from Secrets Manager via IRSA (T07).** No secret in Git, image, env value, or manifest. Rejected: Kubernetes Secrets as source of truth (base64, broad RBAC exposure). Deferred: rotation lambdas, External Secrets Operator.

**D05 Least-privilege IAM (T02, T06).** IRSA role bound to exactly `system:serviceaccount:accounts:accounts-api` with `aud` check; policies list specific ARNs; `kms:Decrypt` restricted with `kms:ViaService`. Rejected: node instance role sharing (every pod inherits it). Note: EKS Pod Identity is a viable modern alternative; IRSA was chosen for its explicit trust-policy conditions being easy to review.

**D06 CI/CD trust (T05, T10).** GitHub OIDC, no stored AWS keys; trust pinned to `repo:<org/repo>:environment:production`, so PRs and forks cannot assume the role; workflow `permissions: contents: read`; CODEOWNERS on `.github/`, `terraform/`, `k8s/policies/`, `waivers/`. Cross-account deploy via chained role with ExternalId. *Reality check:* CODEOWNERS and the `production` environment's required reviewers only work if branch protection/rulesets are enabled; this cannot be proven from files. *Preferred direction:* GitOps pull (Argo CD/Flux) so CI holds no cluster credentials (deferred). Action refs are version tags here, **not SHA pins**; pinning by commit SHA (via Dependabot) is deferred and listed under residual risk for T04/T05.

**D07 Supply chain: digests now, signing later (T04).** Implemented: digest-pinned image reference (all-zero **placeholder** until the release pipeline substitutes the real digest; `--strict` rejects it), immutable ECR tags, scan-on-push, Trivy in CI. *Not implemented:* image signing (cosign keyless via GitHub OIDC), SLSA-style provenance attestations, SBOM publication, and Kyverno `verifyImages` admission verification. The design intent: release job builds, pushes by digest, signs, attests; admission verifies signer identity = the release workflow. Until that exists, a digest only proves *immutability*, not *origin*.

**D08 Audit integrity (T09).** CloudTrail log-file validation, delivery to a separate log-archive account, bucket policy denying deletion and non-TLS. Production adds S3 Object Lock and SCPs preventing `StopLogging`/`DeleteTrail` (described, not coded). Application audit records ship to the same locked destination with a separate writer role that has no read/delete.

**D09 Encryption (T01).** Customer-managed KMS keys with rotation for secrets/ECR; RDS encryption at rest and TLS enforcement are assumed existing and out of scope.

**D10 Waiver mechanism (T11)** — see §3.

## 3. Waiver mechanism (critical)
**Principle:** exceptions are allowed but must be visible, owned, compensated, and temporary.

**A waiver entry** (`waivers/waivers.yaml`, template in `waivers/WAIVER_TEMPLATE.yaml`) must contain: threat ID (T01–T11), affected resource, business justification, evidence link, requester, independent approver, accountable owner, ≥1 compensating control, created and expiry dates.

**Rules enforced by `scripts/waiver_check.py` (runs in CI, tested in `policy-tests/test_policy.py`):**
- All required fields present; threat ID known.
- Validity ≤ 30 days (break-glass ≤ 7 days); `expires` after `created`.
- Approver ≠ requester and ≠ owner (string comparison of handles).
- **Expired waiver ⇒ CI exits non-zero**, blocking every PR until the waiver is renewed through review or removed (automatic gate failure).
- Break-glass waiver requires `incident: INC-…` and `retro_review_due`.
- Same threat+resource waived 3 times ⇒ `permanent_fix_ticket` required (recurring exceptions must become a funded fix).

**What the script can NOT do (be honest):** a YAML file cannot prove that a real, independent human approved. Real enforcement requires, in GitHub/the org: branch protection or rulesets requiring PR review from CODEOWNERS (`/waivers/` → security team), "dismiss stale approvals", no admin bypass, required status check `security`, and the author unable to approve their own PR. An approval system (Jira/ServiceNow) or signed commits would add attribution. Waivers also do not *apply* to any scanner automatically here: they are a record plus an expiry gate; wiring each scanner's ignore list to waiver IDs is deferred.

**Review cadence:** weekly review of waivers expiring within 7 days; owner confirms fix or requests renewal (new entry, new approval; never an in-place date edit by the requester).

**Emergency break-glass:** declared incident; one approver (on-call security lead) may approve immediately via PR with `break_glass: true`; max 7 days; retrospective review within 5 business days, results recorded; if the same break-glass recurs, a permanent fix is mandatory.

## 4. Deferred work (ordered)
1. Image signing + provenance + Kyverno `verifyImages` (T04).
2. Branch-protection/ruleset as code (T11, T05) and SHA-pinned actions (T04/T05).
3. Network Firewall or proxy domain allow-list for KYC (T08).
4. Runtime detection rollout and alert routing (T02).
5. Secret rotation, Object Lock/SCP Terraform (T07, T09).
6. Waiver-aware scanner ignore lists; hash-pinned Python deps.

## 5. Assumptions
Cluster uses a policy-enforcing CNI; Kyverno is (or will be) installed; RDS, VPC, and EKS already exist; CIDRs and account IDs in files are placeholders; the KYC provider is reachable only over public HTTPS; a single `production` GitHub environment has required reviewers.

## 6. Realistic trade-offs for a 2-person team
One policy engine, one waiver file, one workflow; controls that need ongoing manual review (waivers) are minimized and time-boxed; heavy items (mesh, GitOps, SIEM tuning) are explicitly deferred rather than half-built.
