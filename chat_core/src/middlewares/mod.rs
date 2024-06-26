mod auth;
mod request_id;
pub mod server_time;

use std::fmt::Debug;

pub use auth::verify_token;
use axum::middleware::from_fn;
pub use request_id::set_request_id;
pub use server_time::ServerTimeLayer;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::Level;

use crate::User;

pub trait TokenVerify {
    type Error: Debug;
    fn verify(&self, token: &str) -> Result<User, Self::Error>;
}

pub const REQUEST_ID_HEADER: &str = "x-request-id";
pub const SERVER_TIME_HEADER: &str = "x-server-time";

pub fn set_layer(app: axum::Router) -> axum::Router {
    app.layer(
        ServiceBuilder::new()
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().include_headers(true))
                    .on_request(DefaultOnRequest::new().level(Level::INFO))
                    .on_response(
                        DefaultOnResponse::new()
                            .level(Level::INFO)
                            .latency_unit(LatencyUnit::Micros),
                    ),
            )
            .layer(CompressionLayer::new().gzip(true).br(true).deflate(true))
            .layer(from_fn(set_request_id))
            .layer(ServerTimeLayer),
    )
}
