#!/usr/bin/env python3
"""Waiver validator (Python 3 + PyYAML). Fails CI on invalid or expired waivers.

Usage: waiver_check.py [--today YYYY-MM-DD] [FILE]   (default waivers/waivers.yaml)

IMPORTANT: this checks FORMAT and DATES only. It cannot prove the approver is a
real, independent human. Production must enforce that via CODEOWNERS + branch
protection + required reviews (see DECISIONS.md, section "Waiver mechanism").
"""
import datetime as dt
import re
import sys

import yaml

MAX_DAYS, MAX_BREAK_GLASS_DAYS, RECURRENCE_LIMIT = 30, 7, 3
REQUIRED = ["id", "threat_id", "resource", "justification", "evidence", "requester",
            "approver", "owner", "compensating_controls", "created", "expires"]
THREATS = {f"T{i:02d}" for i in range(1, 12)}


def _d(v):
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def validate(waivers, today):
    errs, seen = [], {}
    for i, w in enumerate(waivers or []):
        wid = w.get("id", f"#{i}") if isinstance(w, dict) else f"#{i}"
        e = lambda m: errs.append(f"{wid}: {m}")  # noqa: E731
        if not isinstance(w, dict):
            e("not a mapping")
            continue
        for k in REQUIRED:
            if w.get(k) in (None, "", [], {}):
                e(f"missing required field '{k}'")
        if w.get("threat_id") and w["threat_id"] not in THREATS:
            e(f"unknown threat_id '{w['threat_id']}' (expected T01-T11)")
        if w.get("requester") and w.get("requester") == w.get("approver"):
            e("approver must be independent of requester")
        if w.get("owner") and w.get("owner") == w.get("approver"):
            e("approver must be independent of accountable owner")
        if w.get("created") and w.get("expires"):
            try:
                c, x = _d(w["created"]), _d(w["expires"])
            except ValueError:
                e("created/expires must be ISO dates")
                continue
            limit = MAX_BREAK_GLASS_DAYS if w.get("break_glass") else MAX_DAYS
            if (x - c).days > limit:
                e(f"validity {(x - c).days}d exceeds maximum {limit}d")
            if x <= c:
                e("expires must be after created")
            if x < today:
                e(f"EXPIRED on {x}; gate fails until removed or re-approved")
        if w.get("break_glass"):
            if not w.get("retro_review_due"):
                e("break_glass requires retro_review_due")
            if not re.match(r"^INC-", str(w.get("incident", ""))):
                e("break_glass requires incident reference 'INC-...'")
        key = (w.get("threat_id"), w.get("resource"))
        seen[key] = seen.get(key, 0) + 1
        if seen[key] >= RECURRENCE_LIMIT and not w.get("permanent_fix_ticket"):
            e(f"recurring waiver ({seen[key]}x) requires permanent_fix_ticket")
    return errs


def main(argv):
    today, path = dt.date.today(), "waivers/waivers.yaml"
    if "--today" in argv:
        i = argv.index("--today")
        today = dt.date.fromisoformat(argv[i + 1])
        del argv[i:i + 2]
    if argv:
        path = argv[0]
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    errs = validate(data.get("waivers"), today)
    for m in errs:
        print("FAIL", m)
    print(f"{'FAIL' if errs else 'PASS'} {path}: {len(data.get('waivers') or [])} waiver(s) checked as of {today}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
