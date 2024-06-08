use anyhow::Result;
use chat::{get_router, AppConfig};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{
    filter::LevelFilter, fmt::Layer, layer::SubscriberExt, util::SubscriberInitExt, Layer as _,
};

#[tokio::main]
async fn main() -> Result<()> {
    let layer = Layer::new().with_filter(LevelFilter::INFO);
    tracing_subscriber::registry().with(layer).init();

    let config = AppConfig::load()?;
    let addr = format!("0.0.0.0:{}", config.server.port);

    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on: {}", addr);

    let app = get_router(config);

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
