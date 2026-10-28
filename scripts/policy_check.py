#!/usr/bin/env python3
"""Dependency-light workload security validator (needs only Python 3 + PyYAML).

Mirrors the Kyverno ClusterPolicy in k8s/policies/require-workload-security.yaml.
It is a LOCAL/CI pre-check, NOT the production enforcement point (that is the
admission controller). See README "Validator limitations".

Usage: policy_check.py [--strict] [--netpol] FILE [FILE...]
Exit 0 = no failures, 1 = failures, 2 = usage/parse error.
--strict additionally fails placeholder (all-zero) image digests.
"""
import re
import sys

import yaml

DIGEST_RE = re.compile(r"@sha256:([0-9a-f]{64})$")
POD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
RULES = {
    "WS-01": "runAsNonRoot must be true and runAsUser must not be 0",
    "WS-02": "allowPrivilegeEscalation must be false",
    "WS-03": "capabilities.drop must include ALL and nothing may be added",
    "WS-04": "seccompProfile must be RuntimeDefault or Localhost",
    "WS-05": "readOnlyRootFilesystem must be true",
    "WS-06": "cpu+memory requests and limits are required",
    "WS-07": "privileged containers are forbidden",
    "WS-08": "image must be pinned by @sha256 digest (no tags)",
    "WS-09": "automountServiceAccountToken must be false",
    "WS-10": "a dedicated serviceAccountName (not 'default') is required",
    "WS-11": "hostNetwork/hostPID/hostIPC are forbidden",
    "WS-12": "hostPath volumes are forbidden",
    "NP-01": "namespace needs a default-deny NetworkPolicy (empty podSelector, Ingress+Egress)",
}


def pod_spec(doc):
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return (spec.get("template") or {}).get("spec")


def check_document(doc, strict=False):
    """Return list of (rule_id, message, severity) for one manifest."""
    out = []
    if not isinstance(doc, dict) or doc.get("kind") not in POD_KINDS:
        return out
    ps = pod_spec(doc)
    if not isinstance(ps, dict):
        return [("WS-01", "cannot locate pod spec", "FAIL")]
    psc = ps.get("securityContext") or {}
    if ps.get("automountServiceAccountToken") is not False:
        out.append(("WS-09", RULES["WS-09"], "FAIL"))
    if ps.get("serviceAccountName") in (None, "", "default"):
        out.append(("WS-10", RULES["WS-10"], "FAIL"))
    if any(ps.get(k) is True for k in ("hostNetwork", "hostPID", "hostIPC")):
        out.append(("WS-11", RULES["WS-11"], "FAIL"))
    if any("hostPath" in (v or {}) for v in ps.get("volumes") or []):
        out.append(("WS-12", RULES["WS-12"], "FAIL"))
    ctrs = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        ctrs += ps.get(key) or []
    if not ps.get("containers"):
        out.append(("WS-01", "no containers defined", "FAIL"))
    for c in ctrs:
        n = c.get("name", "?")
        sc = c.get("securityContext") or {}

        def f(rule, extra=""):
            out.append((rule, f"container '{n}': {RULES[rule]}{extra}", "FAIL"))

        run_user = sc.get("runAsUser", psc.get("runAsUser"))
        if not (sc.get("runAsNonRoot", psc.get("runAsNonRoot")) is True) or run_user == 0:
            f("WS-01")
        if sc.get("allowPrivilegeEscalation") is not False:
            f("WS-02")
        caps = sc.get("capabilities") or {}
        if "ALL" not in [str(x).upper() for x in caps.get("drop") or []] or caps.get("add"):
            f("WS-03")
        sp = sc.get("seccompProfile") or psc.get("seccompProfile") or {}
        if sp.get("type") not in ("RuntimeDefault", "Localhost"):
            f("WS-04")
        if sc.get("readOnlyRootFilesystem") is not True:
            f("WS-05")
        res = c.get("resources") or {}
        lim, req = res.get("limits") or {}, res.get("requests") or {}
        if not all(k in lim and k in req for k in ("cpu", "memory")):
            f("WS-06")
        if sc.get("privileged") is True:
            f("WS-07")
        m = DIGEST_RE.search(str(c.get("image", "")))
        if not m:
            f("WS-08")
        elif set(m.group(1)) == {"0"}:
            sev = "FAIL" if strict else "WARN"
            out.append(("WS-08", f"container '{n}': placeholder all-zero digest - replace in release pipeline", sev))
    return out


def check_netpol(docs):
    for d in docs:
        if isinstance(d, dict) and d.get("kind") == "NetworkPolicy":
            s = d.get("spec") or {}
            if s.get("podSelector") == {} and {"Ingress", "Egress"} <= set(s.get("policyTypes") or []) \
                    and not s.get("ingress") and not s.get("egress"):
                return []
    return [("NP-01", RULES["NP-01"], "FAIL")]


def load(path):
    with open(path) as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def main(argv):
    strict = "--strict" in argv
    netpol = "--netpol" in argv
    files = [a for a in argv if not a.startswith("--")]
    if not files:
        print(__doc__)
        return 2
    failed = False
    for p in files:
        try:
            docs = load(p)
        except Exception as e:  # noqa: BLE001
            print(f"ERROR {p}: {e}")
            return 2
        res = []
        for d in docs:
            res += check_document(d, strict)
        if netpol:
            res += check_netpol(docs)
        for rule, msg, sev in res:
            print(f"{sev} {p} [{rule}] {msg}")
            failed |= sev == "FAIL"
        if not any(s == "FAIL" for _, _, s in res):
            print(f"PASS {p}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
