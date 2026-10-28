"""Dependency-free tests (unittest + PyYAML). Run: python3 -m unittest discover -s policy-tests -v"""
import copy
import datetime as dt
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import policy_check as pc  # noqa: E402
import waiver_check as wc  # noqa: E402


def rules(docs, strict=False, netpol=False):
    out = []
    for d in docs:
        out += pc.check_document(d, strict)
    if netpol:
        out += pc.check_netpol(docs)
    return {r for r, _, s in out if s == "FAIL"}


class FixtureTests(unittest.TestCase):
    def test_compliant_fixture_passes_even_strict(self):
        for p in glob.glob(os.path.join(ROOT, "policy-tests/pass/*.yaml")):
            self.assertEqual(rules(pc.load(p), strict=True), set(), p)

    def test_each_insecure_fixture_fails_expected_rules(self):
        files = sorted(glob.glob(os.path.join(ROOT, "policy-tests/fail/*.yaml")))
        self.assertGreaterEqual(len(files), 13)
        for p in files:
            expected = set(open(p).readline().split("expect:")[1].split("(")[0].split())
            got = rules(pc.load(p), netpol=p.endswith("netpol.yaml"))
            self.assertTrue(expected <= got, f"{p}: expected {expected}, got {got}")


class RealManifestTests(unittest.TestCase):
    def setUp(self):
        self.docs = pc.load(os.path.join(ROOT, "k8s/accounts-api.yaml"))
        self.dep = next(d for d in self.docs if d["kind"] == "Deployment")

    def test_actual_workload_passes_non_strict(self):
        self.assertEqual(rules(self.docs), set())

    def test_actual_workload_fails_strict_due_to_placeholder_digest(self):
        self.assertEqual(rules(self.docs, strict=True), {"WS-08"})

    def test_actual_netpol_has_default_deny(self):
        docs = pc.load(os.path.join(ROOT, "k8s/network-policy.yaml"))
        self.assertEqual(rules(docs, netpol=True), set())

    def test_mutating_real_workload_triggers_each_control(self):
        def spec(d): return d["spec"]["template"]["spec"]
        def ctr(d): return spec(d)["containers"][0]
        muts = {
            "WS-01": lambda d: ctr(d)["securityContext"].__setitem__("runAsNonRoot", False),
            "WS-02": lambda d: ctr(d)["securityContext"].__setitem__("allowPrivilegeEscalation", True),
            "WS-03": lambda d: ctr(d)["securityContext"].pop("capabilities"),
            "WS-05": lambda d: ctr(d)["securityContext"].__setitem__("readOnlyRootFilesystem", False),
            "WS-06": lambda d: ctr(d)["resources"]["limits"].pop("memory"),
            "WS-08": lambda d: ctr(d).__setitem__("image", "x:latest"),
            "WS-09": lambda d: spec(d).pop("automountServiceAccountToken"),
            "WS-10": lambda d: spec(d).pop("serviceAccountName"),
        }
        for rule, fn in muts.items():
            d = copy.deepcopy(self.dep)
            fn(d)
            self.assertIn(rule, rules([d]), rule)


class WaiverTests(unittest.TestCase):
    TODAY = dt.date(2026, 6, 15)

    def good(self, **kw):
        w = dict(id="W-1", threat_id="T03", resource="k8s/x", justification="j", evidence="e",
                 requester="alice", approver="bob", owner="carol", compensating_controls=["alert"],
                 created=dt.date(2026, 6, 1), expires=dt.date(2026, 6, 25))
        w.update(kw)
        return w

    def errs(self, ws): return wc.validate(ws, self.TODAY)

    def test_valid_waiver_passes(self): self.assertEqual(self.errs([self.good()]), [])
    def test_empty_list_passes(self): self.assertEqual(self.errs([]), [])

    def test_missing_fields_fail(self):
        for k in wc.REQUIRED:
            w = self.good(); w.pop(k)
            self.assertTrue(any(k in e for e in self.errs([w])), k)

    def test_expired_fails(self):
        e = self.errs([self.good(created=dt.date(2026, 5, 1), expires=dt.date(2026, 5, 20))])
        self.assertTrue(any("EXPIRED" in x for x in e))

    def test_excessive_duration_fails(self):
        e = self.errs([self.good(expires=dt.date(2026, 8, 1))])
        self.assertTrue(any("exceeds maximum 30d" in x for x in e))

    def test_no_compensating_controls_fails(self):
        self.assertTrue(self.errs([self.good(compensating_controls=[])]))

    def test_self_approval_fails(self):
        self.assertTrue(any("independent" in x for x in self.errs([self.good(approver="alice")])))

    def test_unknown_threat_fails(self):
        self.assertTrue(self.errs([self.good(threat_id="T99")]))

    def test_break_glass_needs_incident_review_and_short_window(self):
        e = self.errs([self.good(break_glass=True)])
        self.assertTrue(any("retro_review_due" in x for x in e) and any("INC-" in x for x in e)
                        and any("7d" in x for x in e))
        ok = self.good(break_glass=True, incident="INC-1", retro_review_due=dt.date(2026, 6, 20),
                       created=dt.date(2026, 6, 12), expires=dt.date(2026, 6, 18))
        self.assertEqual(self.errs([ok]), [])

    def test_recurring_requires_permanent_fix(self):
        ws = [self.good(id=f"W-{i}") for i in range(3)]
        self.assertTrue(any("permanent_fix_ticket" in x for x in self.errs(ws)))
        ws[2]["permanent_fix_ticket"] = "SEC-1"
        self.assertEqual(self.errs(ws), [])

    def test_shipped_waiver_file_is_valid(self):
        import yaml
        with open(os.path.join(ROOT, "waivers/waivers.yaml")) as fh:
            data = yaml.safe_load(fh)
        self.assertEqual(wc.validate(data.get("waivers"), dt.date.today()), [])


if __name__ == "__main__":
    unittest.main()
