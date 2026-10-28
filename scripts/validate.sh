#!/usr/bin/env bash
# Local validation. Installs nothing. Optional tools are used only if already present.
set -u
cd "$(dirname "$0")/.."
rc=0; skipped=()
step() { echo; echo "== $*"; }

step "1. Unit + fixture tests (python3 unittest)"
python3 -m unittest discover -s policy-tests -v 2>&1 | tail -40 || rc=1
python3 -m unittest discover -s policy-tests >/dev/null 2>&1 || rc=1

step "2. Real workload vs policy (non-strict; placeholder digest = WARN)"
python3 scripts/policy_check.py k8s/accounts-api.yaml || rc=1

step "3. NetworkPolicy default-deny present"
python3 scripts/policy_check.py --netpol k8s/network-policy.yaml || rc=1

step "4. Waiver file"
python3 scripts/waiver_check.py || rc=1

step "5. YAML syntax (workflow, k8s)"
python3 - <<'PY' || rc=1
import glob, yaml, sys
bad = 0
for p in glob.glob(".github/workflows/*.yml") + glob.glob("k8s/**/*.yaml", recursive=True) + glob.glob("waivers/*.yaml"):
    try: list(yaml.safe_load_all(open(p))); print("ok", p)
    except Exception as e: print("BAD", p, e); bad = 1
sys.exit(bad)
PY

step "6. Simple secret/ID heuristics (NOT a substitute for gitleaks)"
if grep -rInE --exclude-dir=.git --exclude=validate.sh --exclude=security.yml -e 'AKIA[0-9A-Z]{16}' -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' -e 'ghp_[A-Za-z0-9]{30,}' -e 'xox[baprs]-[A-Za-z0-9-]{10,}' . ; then echo "FAIL: possible secret"; rc=1; else echo "no obvious secret patterns"; fi

step "6b. Terraform static sanity (brace balance, no wildcard Action, no hardcoded 12-digit IDs)"
python3 - <<'PY' || rc=1
import glob, re, sys
bad = 0
for p in glob.glob("terraform/*.tf"):
    t = open(p).read()
    if t.count("{") != t.count("}") or t.count("(") != t.count(")") or t.count("[") != t.count("]"):
        print("BAD brackets", p); bad = 1
    if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', t): print("BAD wildcard action", p); bad = 1
    if re.search(r'(?<![0-9])[0-9]{12}(?![0-9])', t): print("BAD hardcoded 12-digit ID", p); bad = 1
print("terraform static sanity:", "FAIL" if bad else "ok (NOT a substitute for terraform validate)")
sys.exit(bad)
PY

step "7. Optional tools (only if already installed)"
if command -v terraform >/dev/null; then (cd terraform && terraform init -backend=false -input=false >/dev/null && terraform validate) || rc=1; else skipped+=("terraform validate"); fi
if command -v kyverno >/dev/null; then kyverno apply k8s/policies/require-workload-security.yaml --resource k8s/accounts-api.yaml || rc=1; else skipped+=("kyverno apply"); fi
if command -v gitleaks >/dev/null; then gitleaks detect --no-banner || rc=1; else skipped+=("gitleaks"); fi
if command -v trivy >/dev/null; then trivy config --exit-code 1 . || rc=1; else skipped+=("trivy config"); fi
[ ${#skipped[@]} -gt 0 ] && echo "SKIPPED (tool not installed): ${skipped[*]}"

echo; [ $rc -eq 0 ] && echo "VALIDATION PASSED" || echo "VALIDATION FAILED"
exit $rc
