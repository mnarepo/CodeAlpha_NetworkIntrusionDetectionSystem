# Windows Setup Guide — Suricata

## 1. Install Suricata
Install the current Windows build of Suricata from the official Suricata/OISF distribution source. If Npcap is already installed from Task 1, keep it available.

Open **PowerShell as Administrator** and verify:

```powershell
suricata --build-info
```

If Suricata is not in PATH, use the full executable path from your installation.

## 2. Back up your configuration
Locate `suricata.yaml` in your installation and make a backup before editing it.

## 3. Set HOME_NET
Use your own authorized local subnet. Example only:

```yaml
HOME_NET: "[192.168.100.0/24]"
```

Check your IPv4 network with:

```powershell
ipconfig
```

Do not blindly copy the example if your subnet is different.

## 4. Add the custom rule file
Copy `suricata\rules\codealpha.rules` into your Suricata rules directory, or reference its full path in `suricata.yaml`.

Ensure `rule-files` includes:

```yaml
- codealpha.rules
```

## 5. Enable EVE JSON
Ensure EVE JSON output is enabled. See `suricata/suricata-config-snippet.yaml` for the required logging fields.

## 6. Validate configuration
Run Suricata test mode:

```powershell
suricata -T -c "PATH\TO\suricata.yaml"
```

Fix any rule/configuration errors before live capture.

## 7. Select your authorized capture interface
Use the interface-listing/help options supported by your installed Suricata build. Monitor only an interface you own or are explicitly authorized to inspect.

## 8. Start monitoring
Run Suricata with your validated configuration and authorized interface. Confirm `eve.json` is being updated.

## 9. Analyze live alerts

```powershell
python src\eve_analyzer.py "PATH\TO\eve.json" `
  --csv output\alerts.csv `
  --json output\alerts.json `
  --html output\dashboard.html
```

Then:

```powershell
python src\response_engine.py "PATH\TO\eve.json" --csv output\response_queue.csv
```

Open `output\dashboard.html` in your browser.

## Safety
Only monitor systems/networks you own or have explicit permission to inspect. The included custom rules and traffic generator are for harmless local/lab demonstrations.
