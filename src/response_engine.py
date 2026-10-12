#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def severity_label(value: int) -> str:
    return {1: "High", 2: "Medium", 3: "Low"}.get(value, "Unknown")


def recommended_action(signature: str, severity: int, repeats: int) -> tuple[str, str]:
    text = signature.lower()
    if severity == 1:
        return "Immediate investigation", "Validate the alert and isolate affected assets if compromise is confirmed."
    if "repeated" in text or repeats >= 5:
        return "Investigate repeated activity", "Validate the source; consider temporary rate limiting or blocking only after analyst review."
    if "icmp" in text or "probe" in text or "syn" in text:
        return "Reconnaissance review", "Confirm whether the source is an approved scanner or administrator; escalate unexpected reconnaissance."
    if severity == 2:
        return "Priority review", "Correlate with endpoint, firewall, authentication and application logs before taking action."
    return "Monitor and document", "Confirm context, record the event and continue monitoring for repetition or escalation."


def main() -> int:
    parser = argparse.ArgumentParser(description="Create defensive response recommendations from Suricata alerts.")
    parser.add_argument("eve_json", type=Path)
    parser.add_argument("--csv", type=Path, default=Path("output/response_queue.csv"))
    args = parser.parse_args()
    events = []
    with args.eve_json.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert" and isinstance(event.get("alert"), dict):
                events.append(event)
    pairs = Counter((e.get("src_ip", "-"), e["alert"].get("signature", "Unknown")) for e in events)
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    with args.csv.open("w", newline="", encoding="utf-8") as fh:
        fields = ["timestamp","severity","signature","source_ip","destination_ip","repeat_count","recommended_action","analyst_guidance"]
        writer = csv.DictWriter(fh, fieldnames=fields); writer.writeheader()
        for e in events:
            alert = e["alert"]
            signature = str(alert.get("signature", "Unknown"))
            try: sev = int(alert.get("severity", 0))
            except (TypeError, ValueError): sev = 0
            repeat_count = pairs[(e.get("src_ip", "-"), signature)]
            action, guidance = recommended_action(signature, sev, repeat_count)
            writer.writerow({"timestamp":e.get("timestamp", ""),"severity":severity_label(sev),"signature":signature,"source_ip":e.get("src_ip", "-"),"destination_ip":e.get("dest_ip", "-"),"repeat_count":repeat_count,"recommended_action":action,"analyst_guidance":guidance})
    print(f"Response queue written to: {args.csv}")
    print("No firewall or system changes were performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
