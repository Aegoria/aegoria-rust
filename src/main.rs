use axum::Router;
use axum::routing::{get, post};
use tracing::info;

use aegoria_rust::api::routes;
use aegoria_rust::api::server::AppState;
use aegoria_rust::utils;

mod cli;

const BANNER: &str = r#"
     _    _____ ____ ___  ____  ___    _
    / \  | ____/ ___/ _ \|  _ \|_ _|  / \
   / _ \ |  _|| |  | | | | |_) || |  / _ \
  / ___ \| |__| |__| |_| |  _ < | | / ___ \
 /_/   \_|_____\____\___/|_| \_|___/_/   \_\

 Observe. Detect. Protect.
 Telemetry Engine v0.1.0
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("aegoria_rust=info")
        .init();

    // check for cli subcommand
    if let Some(result) = cli::try_run()? {
        return result;
    }

    println!("{}", BANNER);

    let config = utils::config::Config::default();
    let addr = format!("{}:{}", config.api_host, config.api_port);
    let state = AppState::new(config);

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/docs", get(routes::docs))
        .route("/report", get(routes::get_report))
        .route("/scan", post(routes::post_scan))
        .route("/stream/start", post(routes::post_stream_start))
        .route("/stream/stop", post(routes::post_stream_stop))
        .route("/timeline", get(routes::get_timeline))
        .with_state(state);

    info!("aegoria telemetry engine starting on {addr}");
    info!("endpoints: /health /docs /scan /report /timeline /stream/start /stream/stop");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
