# aegoria-rust

the core telemetry engine of the aegoria platform. this is where raw system logs become structured security intelligence.

aegoria-rust reads logs from the operating system, parses them into normalized telemetry events, runs behavioral analysis, correlates suspicious patterns, scores risk, and outputs a structured security report. it's the foundation that everything else in aegoria builds on.

---

## what this does

at its core, this is a detection pipeline:

```
system logs
  → collectors (syslog, auth logs)
  → parsers (structured telemetry events)
  → threat intelligence enrichment
  → behavioral analysis
  → correlation engine
  → risk scoring
  → security report
  → REST API / CLI output
```

it takes messy, unstructured log data and turns it into something you can actually reason about — a JSON report with detected threats, an attack timeline, risk scores, and recommended actions.

---

## how it fits into aegoria

this repository is the first stage of the pipeline. it produces the `SecurityReport` JSON that feeds into everything downstream:

- the **ai-model** consumes this report and runs deeper ML-based threat analysis
- the **monitoring dashboard** stores and visualizes the results
- the **pipeline orchestrator** coordinates all three

the rust engine doesn't know about the AI layer or the dashboard. it just does its job — collect, parse, analyze, report — and exposes the results through a clean API.

---

## key components

| directory | what it does |
|---|---|
| `src/collector/` | reads raw logs from syslog and auth.log |
| `src/parser/` | converts log lines into `TelemetryEvent` structs |
| `src/threat_intel/` | enriches events with known threat indicators and MITRE mappings |
| `src/analyzer/` | behavioral anomaly detection — login bursts, privilege escalation, suspicious processes |
| `src/risk/` | weighted risk scoring engine |
| `src/reports/` | builds the final `SecurityReport` with recommendations |
| `src/api/` | Axum REST server exposing `/scan`, `/report`, `/timeline` |
| `src/streaming/` | real-time log file monitoring |
| `testdata/` | synthetic datasets (~2,400 events across linux and macos logs) |

---

## API

| endpoint | method | description |
|---|---|---|
| `/health` | GET | service status |
| `/scan` | POST | run the full telemetry pipeline |
| `/report` | GET | retrieve the latest security report |
| `/timeline` | GET | attack timeline from the latest scan |
| `/stream/start` | POST | start real-time log streaming |
| `/stream/stop` | POST | stop streaming |

---

## quick start

```bash
# build
cargo build --release

# start the API server (port 3000)
cargo run

# run against the included test dataset
cargo run -- demo

# run tests
cargo test

# benchmarks
cargo bench
```

the demo mode processes the synthetic dataset in `testdata/` and prints a full security report to stdout. useful for seeing what the engine produces without needing live system logs.

---

## tech

- Rust, Tokio, Axum
- ~2,400 test events across 150 synthetic log files
- full pipeline processes 10k events in ~3ms
- 73 passing tests
