#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class AlertRecord:
    timestamp: str
    signature_id: int
    signature: str
    severity: int
    category: str
    action: str
    proto: str
    src_ip: str
    src_port: Optional[int]
    dest_ip: str
    dest_port: Optional[int]


def iter_eve(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[WARN] Skipping malformed JSON at line {line_no}: {exc}")


def extract_alert(event: dict) -> Optional[AlertRecord]:
    if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
        return None
    alert = event["alert"]
    try:
        signature_id = int(alert.get("signature_id", 0))
        severity = int(alert.get("severity", 0))
    except (TypeError, ValueError):
        signature_id = 0
        severity = 0
    return AlertRecord(
        timestamp=str(event.get("timestamp", "")),
        signature_id=signature_id,
        signature=str(alert.get("signature", "Unknown signature")),
        severity=severity,
        category=str(alert.get("category", "Unknown")),
        action=str(alert.get("action", "unknown")),
        proto=str(event.get("proto", "UNKNOWN")),
        src_ip=str(event.get("src_ip", "-")),
        src_port=event.get("src_port"),
        dest_ip=str(event.get("dest_ip", "-")),
        dest_port=event.get("dest_port"),
    )


def load_alerts(path: Path) -> list[AlertRecord]:
    records = []
    for event in iter_eve(path):
        record = extract_alert(event)
        if record:
            records.append(record)
    return records


def severity_label(value: int) -> str:
    return {1: "High", 2: "Medium", 3: "Low"}.get(value, f"Priority {value}" if value else "Unknown")


def print_summary(records: list[AlertRecord]) -> None:
    print("=" * 76)
    print("CodeAlpha NIDS - Suricata Alert Summary")
    print("=" * 76)
    print(f"Total alerts: {len(records)}")
    if not records:
        print("No alert events found.")
        return
    sigs = Counter(r.signature for r in records)
    protos = Counter(r.proto for r in records)
    srcs = Counter(r.src_ip for r in records)
    severities = Counter(severity_label(r.severity) for r in records)
    print("\nBy severity:")
    for name, count in severities.most_common():
        print(f"  {name:<12} {count}")
    print("\nBy protocol:")
    for name, count in protos.most_common():
        print(f"  {name:<12} {count}")
    print("\nTop signatures:")
    for name, count in sigs.most_common(10):
        print(f"  {count:>4}  {name}")
    print("\nTop source IPs:")
    for name, count in srcs.most_common(10):
        print(f"  {count:>4}  {name}")


def export_csv(records: list[AlertRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(AlertRecord.__dataclass_fields__.keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))


def export_json(records: list[AlertRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in records], fh, indent=2)


def bar_rows(counter: Counter, total: int, limit: int = 10) -> str:
    rows = []
    for name, count in counter.most_common(limit):
        pct = (count / total * 100) if total else 0
        rows.append(f'<div class="bar-row"><div class="bar-label">{html.escape(str(name))}</div><div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%"></div></div><div class="bar-value">{count}</div></div>')
    return "\n".join(rows) or "<p>No data</p>"


def export_html(records: list[AlertRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    total = len(records)
    sigs = Counter(r.signature for r in records)
    protos = Counter(r.proto for r in records)
    srcs = Counter(r.src_ip for r in records)
    severities = Counter(severity_label(r.severity) for r in records)
    table_rows = "\n".join(
        f'<tr><td>{html.escape(r.timestamp)}</td><td>{r.signature_id}</td><td>{html.escape(r.signature)}</td><td>{html.escape(severity_label(r.severity))}</td><td>{html.escape(r.proto)}</td><td>{html.escape(r.src_ip)}{":" + str(r.src_port) if r.src_port is not None else ""}</td><td>{html.escape(r.dest_ip)}{":" + str(r.dest_port) if r.dest_port is not None else ""}</td></tr>'
        for r in records[-100:]
    )
    doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CodeAlpha NIDS Dashboard</title>
<style>
:root{{--bg:#07111f;--card:#0e1c2e;--border:#1c3856;--text:#eaf2ff;--muted:#9db0c9;--accent:#4da3ff;--accent2:#5be7c4}}*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(135deg,#07111f,#0c1830);color:var(--text);font-family:Segoe UI,Arial,sans-serif}}.wrap{{max-width:1200px;margin:0 auto;padding:32px 20px 56px}}h1{{margin:0 0 6px;font-size:32px}}.sub{{color:var(--muted);margin-bottom:24px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}}.card{{background:rgba(14,28,46,.92);border:1px solid var(--border);border-radius:16px;padding:18px;box-shadow:0 10px 28px rgba(0,0,0,.18)}}.metric{{font-size:34px;font-weight:700;margin-top:6px}}.label{{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}@media(max-width:800px){{.grid{{grid-template-columns:1fr}}}}h2{{font-size:18px;margin:0 0 16px}}.bar-row{{display:grid;grid-template-columns:minmax(120px,1fr) 3fr 40px;gap:10px;align-items:center;margin:10px 0}}.bar-label{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.bar-track{{height:10px;background:#152941;border-radius:999px;overflow:hidden}}.bar-fill{{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:999px}}.bar-value{{text-align:right;color:var(--muted)}}.table-card{{margin-top:18px;overflow:auto}}table{{width:100%;border-collapse:collapse;min-width:900px}}th,td{{padding:11px 10px;border-bottom:1px solid #18314e;text-align:left;font-size:13px}}th{{color:#b8cbe3;background:#0e1c2e}}.footer{{margin-top:18px;color:var(--muted);font-size:12px}}
</style></head><body><div class="wrap"><h1>CodeAlpha Network IDS Dashboard</h1><div class="sub">Suricata EVE alert analysis - defensive monitoring view</div>
<div class="cards"><div class="card"><div class="label">Total Alerts</div><div class="metric">{total}</div></div><div class="card"><div class="label">Unique Signatures</div><div class="metric">{len(sigs)}</div></div><div class="card"><div class="label">Unique Sources</div><div class="metric">{len(srcs)}</div></div><div class="card"><div class="label">Protocols</div><div class="metric">{len(protos)}</div></div></div>
<div class="grid"><div class="card"><h2>Alert Severity</h2>{bar_rows(severities,total)}</div><div class="card"><h2>Protocol Distribution</h2>{bar_rows(protos,total)}</div><div class="card"><h2>Top Signatures</h2>{bar_rows(sigs,total)}</div><div class="card"><h2>Top Source IPs</h2>{bar_rows(srcs,total)}</div></div>
<div class="card table-card"><h2>Recent Alerts</h2><table><thead><tr><th>Timestamp</th><th>SID</th><th>Signature</th><th>Severity</th><th>Protocol</th><th>Source</th><th>Destination</th></tr></thead><tbody>{table_rows}</tbody></table></div><div class="footer">Generated locally from Suricata EVE JSON. Do not publish sensitive production log data.</div></div></body></html>'''
    path.write_text(doc, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Suricata EVE JSON alerts.")
    parser.add_argument("eve_json", type=Path)
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--html", type=Path)
    args = parser.parse_args()
    if not args.eve_json.exists():
        parser.error(f"Input file not found: {args.eve_json}")
    records = load_alerts(args.eve_json)
    print_summary(records)
    if args.csv:
        export_csv(records, args.csv); print(f"\nCSV exported  : {args.csv}")
    if args.json:
        export_json(records, args.json); print(f"JSON exported : {args.json}")
    if args.html:
        export_html(records, args.html); print(f"HTML dashboard: {args.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
