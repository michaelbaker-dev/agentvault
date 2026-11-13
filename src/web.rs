//! The web interface: static files compiled into the binary.

use axum::{http::header, response::IntoResponse};

const INDEX: &str = include_str!("../web/index.html");
const SCRIPT: &str = include_str!("../web/app.js");
const STYLE: &str = include_str!("../web/app.css");
const FAVICON: &str = include_str!("../web/favicon.svg");

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "no-cache")], body)
}

pub async fn index() -> impl IntoResponse {
    asset("text/html; charset=utf-8", INDEX)
}
pub async fn script() -> impl IntoResponse {
    asset("text/javascript; charset=utf-8", SCRIPT)
}
pub async fn style() -> impl IntoResponse {
    asset("text/css; charset=utf-8", STYLE)
}
pub async fn favicon() -> impl IntoResponse {
    asset("image/svg+xml", FAVICON)
}
