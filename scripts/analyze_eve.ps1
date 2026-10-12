$ErrorActionPreference = "Stop"
$EvePath = if ($args.Count -ge 1) { $args[0] } else { "sample_data\eve_sample.json" }
Write-Host "Analyzing: $EvePath"
python src\eve_analyzer.py $EvePath --csv output\alerts.csv --json output\alerts.json --html output\dashboard.html
python src\response_engine.py $EvePath --csv output\response_queue.csv
Write-Host "Generated output files under output\."
