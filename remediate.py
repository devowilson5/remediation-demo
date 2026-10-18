"""
Automated remediation demo (DRY RUN ONLY).

Reads a CSV of fake findings, decides what to do with each one,
and writes an audit log, owner notifications, and a summary.
No real systems are touched. All data is fake.

Usage:  python remediate.py findings.csv
"""
import csv
import sys
from collections import Counter
from datetime import datetime, timezone

# ---------- Step 1: the rules (edit these to tune behavior) ----------
SENSITIVE_DATA = {"PII", "PHI", "PCI"}   # data types we treat as sensitive
CONFIDENCE_THRESHOLD = 0.90              # below this, a human must review
EXCEPTIONS = {"F-1005"}                  # approved exceptions: never touch
DRY_RUN = True                           # keep True: log only, change nothing

REQUIRED_COLUMNS = [
    "finding_id", "resource", "environment", "exposure",
    "data_type", "confidence", "owner", "critical",
]


def load_findings(path):
    """Step 2: read the input file and check it has the columns we need."""
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"Input file is missing columns: {', '.join(missing)}")
        return list(reader)


def decide(f):
    """Step 3: apply the rules in order. First matching rule wins."""
    if f["finding_id"] in EXCEPTIONS:
        return "SKIP", "on approved-exceptions list"
    if f["exposure"].strip().lower() != "public":
        return "IGNORE", "not publicly exposed"
    if f["data_type"].strip().upper() not in SENSITIVE_DATA:
        return "IGNORE", "data type is not sensitive"
    try:
        confidence = float(f["confidence"])
    except ValueError:
        return "NEEDS_APPROVAL", "confidence value is invalid"
    if confidence < CONFIDENCE_THRESHOLD:
        return "NEEDS_APPROVAL", f"low confidence ({confidence:.2f})"
    if f["critical"].strip().lower() == "yes":
        return "NEEDS_APPROVAL", "resource is marked critical"
    return "AUTO_REMEDIATE", "public + sensitive + high confidence + not critical"


def remove_public_access(f):
    """Step 4: the action. In a real tool, an API call to the cloud provider
    goes here. It stays a stub on purpose so nothing real can change."""
    if DRY_RUN:
        return f"DRY RUN: would remove public access on {f['resource']}"
    raise NotImplementedError("Connect a real cloud API here, with approval.")


def verify(f):
    """Step 5: re-check that the exposure is gone. Stub for the demo."""
    if DRY_RUN:
        return "verification skipped (dry run)"
    raise NotImplementedError("Re-query the resource and confirm it is private.")


def build_notification(f, action, reason):
    """Step 6: message the owner so nothing changes silently."""
    return (
        f"To: {f['owner']}\n"
        f"Re: {f['finding_id']} on {f['resource']} ({f['environment']})\n"
        f"Action: {action}. Reason: {reason}.\n"
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "findings.csv"
    findings = load_findings(path)

    audit_rows, notices, counts, review_list = [], [], Counter(), []

    for f in findings:
        action, reason = decide(f)
        counts[action] += 1
        result = ""

        if action == "AUTO_REMEDIATE":
            result = remove_public_access(f) + "; " + verify(f)
            notices.append(build_notification(f, action, reason))
        elif action == "NEEDS_APPROVAL":
            result = "ticket needed: waiting for human approval"
            review_list.append(f"{f['finding_id']} ({f['resource']}): {reason}")
            notices.append(build_notification(f, action, reason))
        else:
            result = "no action"

        # Step 7: audit log row for every finding, whatever the outcome
        audit_rows.append({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "finding_id": f["finding_id"],
            "resource": f["resource"],
            "action": action,
            "reason": reason,
            "result": result,
            "dry_run": DRY_RUN,
        })

    with open("audit_log.csv", "w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(audit_rows[0].keys()))
        writer.writeheader()
        writer.writerows(audit_rows)

    with open("notifications.txt", "w") as out:
        out.write("\n".join(notices))

    # Step 8: a short summary a human can read in 30 seconds
    lines = [f"Findings processed: {len(findings)}", ""]
    for name in ["AUTO_REMEDIATE", "NEEDS_APPROVAL", "SKIP", "IGNORE"]:
        lines.append(f"{name}: {counts.get(name, 0)}")
    if review_list:
        lines += ["", "Needs human review:"] + [f"- {item}" for item in review_list]
    lines += ["", f"Mode: {'DRY RUN (no changes made)' if DRY_RUN else 'LIVE'}"]
    summary = "\n".join(lines)

    with open("summary.txt", "w") as out:
        out.write(summary)
    print(summary)


if __name__ == "__main__":
    main()
