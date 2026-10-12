# Project Report — Network Intrusion Detection System

## Objective
This project implements a network-based intrusion detection workflow using Suricata. It demonstrates rule-based detection, continuous traffic monitoring, alert generation, event analysis, defensive response recommendations and visualization.

## Components

### Suricata Sensor
Inspects traffic on an authorized interface and evaluates built-in/custom rules.

### Custom Rules
The project includes transparent lab rules for:
- ICMP echo requests;
- TCP SYN attempts to training port 4444;
- HTTP `CodeAlpha-NIDS-Test` user-agent marker;
- UDP traffic to training port 9999;
- thresholded repeated TCP attempts to port 8080.

### EVE Analyzer
Normalizes Suricata alert events and produces terminal summaries, CSV, JSON and an HTML dashboard.

### Response Engine
Creates analyst-oriented response recommendations without automatically blocking hosts or changing firewall rules.

## Workflow
1. Configure `HOME_NET`.
2. Load `codealpha.rules`.
3. Validate Suricata configuration.
4. Monitor an authorized interface.
5. Review `eve.json`.
6. Analyze alerts.
7. Generate response recommendations.
8. Review the dashboard and evidence.

## Response Mechanism
The response workflow categorizes events into immediate investigation, priority review, reconnaissance review, repeated-activity investigation, or monitor/document actions. Enforcement remains analyst-reviewed.

## Visualization
The local HTML dashboard shows total alerts, unique signatures, unique sources, protocol count, severity distribution, top signatures, top sources and a recent-alert table.

## Security and Privacy
NIDS logs can contain sensitive infrastructure information. Public evidence should use synthetic or sanitized lab data instead of production traffic.

## Learning Outcomes
- Suricata rule syntax and SIDs
- HOME_NET configuration
- EVE JSON logging
- alert triage
- signature-based intrusion detection
- thresholding/noise reduction
- defensive response workflow
- alert visualization and reporting

## Conclusion
The project goes beyond basic Suricata setup by connecting detection, event normalization, visualization and analyst response into a coherent defensive NIDS workflow for an authorized lab.
