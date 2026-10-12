# CodeAlpha — Network Intrusion Detection System

**Cyber Security Internship — Task 4**

A Suricata-based defensive Network Intrusion Detection System (NIDS) project featuring custom rules, EVE JSON analysis, alert visualization, controlled test traffic and analyst-oriented response recommendations.

> **Authorized use only:** Monitor and test only systems/networks you own or have explicit permission to inspect.

## What This Project Implements

- Suricata NIDS configuration guidance
- Five custom detection rules
- Continuous EVE JSON event logging
- Alert parsing and normalization
- CSV and JSON exports
- Local HTML alert dashboard
- Defensive response recommendation engine
- Harmless lab traffic generator
- Synthetic sample alerts for offline demonstration
- Unit tests
- Windows and Linux setup guides

## CodeAlpha Task Coverage

### Set up a network IDS
Suricata is used as the network sensor.

### Configure rules and alerts
`suricata/rules/codealpha.rules` contains five custom training rules.

### Monitor network traffic
Suricata continuously inspects an authorized interface and logs EVE events.

### Implement response mechanisms
`src/response_engine.py` creates analyst-reviewed response recommendations without making automatic firewall changes.

### Visualize detected activity
`src/eve_analyzer.py` can generate a static local HTML dashboard.

## Architecture

```text
Authorized Traffic
       |
       v
Suricata Sensor
       |
Custom + Built-in Rules
       |
       v
    eve.json
    /      \
   v        v
Analyzer   Response Engine
 |            |
CSV/JSON      Response Queue
HTML Dashboard
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Repository Structure

```text
CodeAlpha_NetworkIntrusionDetectionSystem/
├── suricata/
│   ├── rules/
│   │   └── codealpha.rules
│   └── suricata-config-snippet.yaml
├── src/
│   ├── eve_analyzer.py
│   ├── response_engine.py
│   └── test_traffic.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── WINDOWS_SETUP.md
│   ├── LINUX_SETUP.md
│   ├── TEST_PLAN.md
│   └── PROJECT_REPORT.md
├── tests/
│   └── test_eve_analyzer.py
├── sample_data/
│   └── eve_sample.json
├── output/
├── README.md
├── .gitignore
└── LICENSE
```

## Quick Offline Demo

No Suricata installation is required to verify the Python analysis layer against the synthetic sample data:

```bash
python -m unittest discover -s tests -v
```

```bash
python src/eve_analyzer.py sample_data/eve_sample.json --csv output/sample_alerts.csv --json output/sample_alerts.json --html output/sample_dashboard.html
```

```bash
python src/response_engine.py sample_data/eve_sample.json --csv output/sample_response_queue.csv
```

Open:

```text
output/sample_dashboard.html
```

## Live Suricata Setup

Windows: [`docs/WINDOWS_SETUP.md`](docs/WINDOWS_SETUP.md)  
Linux: [`docs/LINUX_SETUP.md`](docs/LINUX_SETUP.md)

## Custom Rules

| SID | Detection |
|---|---|
| 1000001 | ICMP echo request into HOME_NET |
| 1000002 | TCP SYN to training port 4444 |
| 1000003 | HTTP `CodeAlpha-NIDS-Test` User-Agent |
| 1000004 | UDP probe to training port 9999 |
| 1000005 | Thresholded repeated TCP attempts to port 8080 |

These rules are deliberately simple and transparent for a controlled internship lab.

## Safe Test Traffic

The included generator defaults to localhost:

```bash
python src/test_traffic.py --mode udp
python src/test_traffic.py --mode tcp4444
python src/test_traffic.py --mode repeated8080
```

Use another target only when it is your own or an authorized lab host.

## Alert Analysis

```bash
python src/eve_analyzer.py PATH_TO_EVE_JSON --csv output/alerts.csv --json output/alerts.json --html output/dashboard.html
```

## Response Recommendations

```bash
python src/response_engine.py PATH_TO_EVE_JSON --csv output/response_queue.csv
```

The response engine does **not** automatically modify firewall rules. It creates recommendations for analyst review.

## Internship

**Organization:** CodeAlpha  
**Domain:** Cyber Security  
**Task:** Task 4 — Network Intrusion Detection System
