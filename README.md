## Aegoria Telemetry Engine
**observe. detect. protect.**

Aegoria is a lightweight telemetry engine that turns raw system logs into structured security intelligence.

Instead of manually digging through thousands of log lines, Aegoria collects logs, parses them into structured events, analyzes behavioral patterns, correlates suspicious activity, and generates a clear security report through a simple API.

The goal of this project is to demonstrate a complete **security telemetry pipeline** — from log ingestion to threat analysis and reporting.

---

## What Aegoria Does

At a high level, Aegoria converts messy log data into actionable insights.

Pipeline overview:

System Logs > Collectors > Parsers > Telemetry Events > Threat Intelligence Enrichment > Behavioral Analysis > Correlation Engine > Risk Scoring > Security Report > API / CLI Output


The result is a structured report describing system activity, potential threats, and recommended actions.

---

## Core Capabilities

### Log Ingestion
Reads logs from system sources such as:

- syslog
- authentication logs

### Structured Telemetry Events
Every log entry is normalized into a consistent `TelemetryEvent` structure.

### Behavioral Anomaly Detection
Detects suspicious activity patterns such as:

- repeated login failures
- privilege escalation
- suspicious process execution
- abnormal network behavior

### Threat Intelligence Enrichment
Events are enriched with known malicious indicators such as suspicious IP addresses.

### Attack Timeline Reconstruction
Events are reconstructed chronologically to help understand how an attack unfolded.

### Risk Scoring
Security risk is calculated using a weighted scoring system.

### Security Reporting
The system produces a structured JSON report containing:

- detected threats
- risk level
- attack timeline
- recommendations

---

## Architecture

built as a modular pipeline.

logs
  │
collector
  │
parser
  │
telemetry events
  │
behavior engine
  │
correlation engine
  │
risk scoring
  │
report builder
  │
api / cli

--- 

## Project Structure

src/
  core/           core data structures
  collector/      log ingestion
  parser/         log parsing
  analyzer/       anomaly detection and correlation
  risk/           risk scoring engine
  reports/        report generation
  threat_intel/   threat enrichment
  streaming/      real-time log monitoring
  api/            REST API server
  utils/          configuration and helpers
  cli/            command line tools

tests/
  integration and dataset tests

testdata/
  synthetic log datasets

benches/
  performance benchmarks

---

## API Endpoints

| Endpoint        | Method | Description                     |
| --------------- | ------ | ------------------------------- |
| `/health`       | GET    | service information             |
| `/docs`         | GET    | API documentation               |
| `/scan`         | POST   | run full telemetry pipeline     |
| `/report`       | GET    | retrieve latest security report |
| `/timeline`     | GET    | attack timeline                 |
| `/stream/start` | POST   | start real-time log streaming   |
| `/stream/stop`  | POST   | stop streaming                  |

---

## Quick Start

Clone this repository
```
git clone https://github.com/Aegoria/aegoria-rust.git
cd aegoria-rust
```

Build the project: 
```
cargo build
```

Run the telemetry engine:
```
cargo run
```

The API Server witll start at: 
```
http://localhost:3000
```

---

## Example Commands

Check service health:
```
curl http://localhost:3000/health | jq
```

View API documentation:
```
curl http://localhost:3000/docs | jq
```

Run a security scan:
```
curl -X POST http://localhost:3000/scan | jq
```

Retrieve the latest report:
```
curl http://localhost:3000/report | jq
```

View attack timeline:
```
curl http://localhost:3000/timeline | jq
```

Start real-time log monitoring:
```
curl -X POST http://localhost:3000/stream/start
```

Stop streaming:
```
curl -X POST http://localhost:3000/stream/stop
```

--- 

## Demo Mode

You can run the pipeline against the included synthetic dataset.
```
cargo run -- demo
```

This loads test logs, processes them through the full pipeline, and prints a formatted security report.

--- 

## Running Tests

Run all tests:
```
cargo test
```

Dataset pipeline tests:
```
cargo test --test dataset_pipeline_test
```

Code quality check:
```
cargo clippy --all-targets --all-features -- -D warnings
```

Format code:
```
cargo fmt
```

--- 

## Performance

Benchmark the pipeline:
```
cargo bench
```

Example benchmark results:
```
Full pipeline (10k events): ~3 ms
Analysis only: ~0.28 ms
Threat enrichment: ~1.6 ms
Throughput: ~54k events/sec
```

## Synthetic Dataset

The repository includes generated datasets for testing.

```
testdata/
  linux/
  macos/
  windows/
```

The dataset includes:
- SSH brute force attempts
- privilege escalation events
- suspicious process execution
- network reconnaissance
- system operations

Total coverage:
150 files
~2,400 log events


## Tech Stack
Core engine
- Rust
- Tokio
- Axum

Testing and benchmarking
- Criterion
- Rust test framework

Data format
- JSON telemetry events

## Current Status

The telemetry engine currently supports:

- full pipeline processing
- real-time log streaming
- threat intelligence enrichment
- attack timeline reconstruction
- structured security reporting
- CLI testing tools
- performance benchmarking

--- 

## Improvements

Planned extensions include:
- machine learning anomaly detection
- distributed log ingestion
- external threat intelligence feeds
- real-time alerting
- advanced visualization dashboards

thanks. please feel free to contact in case of doubt related to any steps or the pipeline.