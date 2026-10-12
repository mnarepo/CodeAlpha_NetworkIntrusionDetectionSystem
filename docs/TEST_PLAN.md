# Task 4 Test Plan

## Phase 1 — Offline validation

```bash
python -m unittest discover -s tests -v
```

Analyze the provided synthetic Suricata EVE sample:

```bash
python src/eve_analyzer.py sample_data/eve_sample.json --csv output/sample_alerts.csv --json output/sample_alerts.json --html output/sample_dashboard.html
python src/response_engine.py sample_data/eve_sample.json --csv output/sample_response_queue.csv
```

Open `output/sample_dashboard.html`.

## Phase 2 — Suricata validation
After installing Suricata:

```text
suricata -T -c <path-to-suricata.yaml>
```

Confirm `codealpha.rules` loads without syntax errors.

## Phase 3 — Authorized live monitoring
Monitor only your own/authorized interface. Generate normal traffic such as web browsing and DNS lookups. Confirm `eve.json` is being populated.

## Phase 4 — Harmless lab rule tests
Use only your own machine or a controlled lab host.

```bash
python src/test_traffic.py --mode udp
python src/test_traffic.py --mode tcp4444
python src/test_traffic.py --mode repeated8080
```

For ICMP, use a normal ping to an authorized host. For the HTTP marker rule, send a request to a local/lab HTTP service with the `User-Agent: CodeAlpha-NIDS-Test` header.

Loopback visibility depends on the capture driver/interface. If localhost is not visible to Suricata, use your own host's LAN address or a second authorized lab machine.

## Evidence screenshots
1. Suricata build/version output
2. Suricata `-T` validation success
3. Custom rule file
4. Live EVE alert output
5. Analyzer terminal summary
6. HTML dashboard
7. Response queue CSV
8. Unit tests passing

Never publish credentials, tokens, private payloads or sensitive production logs.
