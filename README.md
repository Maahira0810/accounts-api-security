# accounts-api-security

Security take-home submission for a hypothetical regulated bank's `accounts-api` (EKS `ap-south-1`, RDS PostgreSQL, KYC provider). **Nothing here was deployed.** No cloud resources, accounts, or credentials exist; all AWS IDs and CIDRs are placeholders.

## Architecture
```
Client → CloudFront/WAF → ALB ─(10.0.0.0/24)→ [ns: accounts] accounts-api pods (x3)
                                                  ├→ CoreDNS (kube-system)
                                                  ├→ RDS PostgreSQL (DB subnet, 5432)
                                                  ├→ AWS APIs via VPC endpoints (Secrets Manager, KMS, STS, stream)
                                                  └→ Egress proxy/Network Firewall (443) → KYC provider
GitHub Actions ─OIDC→ ci-release role ─chain→ deploy role (per account) → EKS (namespace-scoped)
CloudTrail/app audit → log-archive account (validated, delete-denied)
```

## Layout
| Path | Purpose |
|---|---|
| `THREAT_MODEL.md` | Assets, boundaries, STRIDE, threats T01–T11 |
| `DECISIONS.md` | Controls, traceability, trade-offs, deferred work, **waiver mechanism** |
| `SECURITY.md` | Reporting/handling |
| `docs/LOGGING_AND_IR.md` | Logging, audit integrity, detection, incident response |
| `k8s/accounts-api.yaml`, `k8s/network-policy.yaml` | Hardened workload; default-deny network policy |
| `k8s/policies/require-workload-security.yaml` | Kyverno preventative policy (not executed locally) |
| `scripts/policy_check.py` | Dependency-light mirror of the policy (rules WS-01..12, NP-01) |
| `scripts/waiver_check.py`, `waivers/` | Waiver validator, empty register, template |
| `policy-tests/` | Passing/failing fixtures + unittest suite |
| `terraform/` | IRSA, GitHub OIDC, cross-account, ECR, KMS, CloudTrail, GuardDuty |
| `.github/workflows/security.yml`, `.github/CODEOWNERS` | CI gates; review ownership |
| `evidence/VALIDATION.md` | Real local results and what was **not** run |

## Prerequisites
`python3` (3.9+) and `PyYAML` (`pip install -r requirements.txt` if not present). Optional, auto-used only if already installed: `terraform`, `kyverno`, `gitleaks`, `trivy`.

## Test commands
```bash
bash scripts/validate.sh                                   # everything below + sanity checks
python3 -m unittest discover -s policy-tests -v            # fixtures, real manifest, waivers
python3 scripts/policy_check.py k8s/accounts-api.yaml      # PASS with WS-08 placeholder WARN
python3 scripts/policy_check.py --strict k8s/accounts-api.yaml   # EXPECTED FAIL until a real digest is set
python3 scripts/policy_check.py policy-tests/fail/root-user.yaml # EXPECTED FAIL (WS-01)
python3 scripts/policy_check.py --netpol k8s/network-policy.yaml
python3 scripts/waiver_check.py [--today YYYY-MM-DD]
```

## Reviewer guide
1. Read `THREAT_MODEL.md`, then the traceability table in `DECISIONS.md`.
2. Run `bash scripts/validate.sh`; open `policy-tests/fail/*.yaml` (each declares its expected rule on line 1).
3. Check the honest gaps: placeholder digest, unsigned images, NetworkPolicy FQDN limits, waiver approval enforced only by org settings.

## Validator limitations
`policy_check.py` is a pre-merge check, not an admission controller: it validates static YAML for Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob, does not resolve Helm/Kustomize output, mutating webhooks, or defaults applied by the cluster, and does not evaluate the Kyverno YAML itself (the two are kept aligned by hand and by shared rule IDs). Enforcement in production is Kyverno (+ PSA `restricted` on the namespace).

## Not implemented (see DECISIONS.md §4)
Image signing/provenance/admission verification; FQDN egress filtering; branch protection as code; runtime sensor rollout; SHA-pinned actions.
