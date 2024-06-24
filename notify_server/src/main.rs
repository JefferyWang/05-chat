use anyhow::Result;
use notify_server::{get_router, setup_pg_listener};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{
    filter::LevelFilter, fmt::Layer, layer::SubscriberExt, util::SubscriberInitExt, Layer as _,
};

#[tokio::main]
async fn main() -> Result<()> {
    let layer = Layer::new().with_filter(LevelFilter::INFO);
    tracing_subscriber::registry().with(layer).init();

    let addr = "0.0.0.0:6687";

    setup_pg_listener().await?;

    let listener = TcpListener::bind(&addr).await?;
    info!("Listening on: {}", addr);

    let app = get_router();

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
