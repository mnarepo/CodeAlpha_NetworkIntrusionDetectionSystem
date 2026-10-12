# Architecture

```text
Authorized Network/Lab Traffic
            |
            v
     Suricata NIDS Sensor
    packet inspection/rules
            |
            v
        EVE JSON Log
        /          \
       v            v
 EVE Analyzer   Response Engine
 CSV / JSON     Analyst guidance
 HTML Dashboard No auto-blocking
```

The response engine intentionally produces analyst recommendations instead of automatically modifying firewall rules. This keeps the project safe, auditable and appropriate for an internship lab.
