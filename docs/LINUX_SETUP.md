# Linux Setup Guide — Suricata

Install Suricata from your distribution or the official OISF-recommended source, then verify:

```bash
suricata --build-info
```

Copy `suricata/rules/codealpha.rules` into your rules directory or reference it from `suricata.yaml`.

Set `HOME_NET` to your authorized lab subnet and enable EVE JSON.

Validate:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Analyze alerts:

```bash
python src/eve_analyzer.py /var/log/suricata/eve.json \
  --csv output/alerts.csv \
  --json output/alerts.json \
  --html output/dashboard.html

python src/response_engine.py /var/log/suricata/eve.json \
  --csv output/response_queue.csv
```
