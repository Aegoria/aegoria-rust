# aegoria-rust

aegoria is a lightweight telemetry and security analysis engine written in rust. the goal of the project is to turn raw system logs into structured security insights that can help identify suspicious behavior, correlate events, and produce actionable reports.

the system ingests logs, parses them into normalized telemetry events, analyzes patterns such as authentication failures or unusual processes, and then builds a report describing potential threats and overall system risk.

the project was built with a modular architecture so that collectors, parsers, and analysis components can evolve independently.

## current capabilities

- log ingestion from system sources
- parsing into structured telemetry events
- behavioral anomaly detection
- correlation of related security events
- risk scoring and report generation
- json api for retrieving scan results
- automated tests covering the analysis pipeline

## goals

the long term goal is to evolve aegoria into a lightweight telemetry platform that can analyze system activity in near real time and reconstruct security-relevant events.

future work focuses on:

- real-time log streaming
- attack timeline reconstruction
- threat intelligence enrichment
- expanded cross-platform log support

## development

the project is written entirely in rust and follows a modular architecture. the codebase is organized so that each stage of the telemetry pipeline remains isolated and testable.

tests can be run with:
```
cargo test
```

and the development server can be started with:
```
cargo run
```

---

this project is currently under active development.
