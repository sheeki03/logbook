//! Embedded static assets and the static-file / SPA-fallback handler.
//!
//! The built React/Vite bundle in `ui/dist` is compiled into the binary via
//! [`rust_embed`] (plan §1: "serves embedded static assets via rust-embed from
//! `ui/dist`"). `ui/dist` lives at the workspace root, two directories up from
//! this crate, so the embed path is relative to `CARGO_MANIFEST_DIR`.
//!
//! `ui/dist` is gitignored (it is generated build output), so nothing under it
//! is committed: a `vite build` (`npm install && npm run build` in `ui/`) must
//! run before this crate will compile, since the `#[folder = "../../ui/dist"]`
//! attribute requires that directory to exist at compile time. If the bundle is
//! present but a requested asset is missing, [`static_handler`] returns a 404
//! with a build hint.

use axum::body::Body;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

/// All files under `ui/dist`, embedded at compile time.
#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
pub struct Assets;

/// Serve an embedded asset by request path, falling back to `index.html` for
/// client-side routes (single-page-app behavior).
///
/// - `/` and unknown non-asset paths → `index.html` (so the SPA router handles
///   them), 200.
/// - Known asset paths (`/assets/app-*.js`, `/favicon.ico`, …) → the file with a
///   guessed `Content-Type`, 200.
/// - If `index.html` itself is missing (dist never built) → a 404 with a hint.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let candidate = if path.is_empty() { "index.html" } else { path };

    if let Some(resp) = serve_asset(candidate) {
        return resp;
    }

    // Not a real file: treat as an SPA route and serve the app shell. The
    // browser-side router renders the right view from the URL.
    if let Some(resp) = serve_asset("index.html") {
        return resp;
    }

    (
        StatusCode::NOT_FOUND,
        "logbook UI assets not built — run `npm install && npm run build` in ui/\n",
    )
        .into_response()
}

/// Look up `path` in the embedded bundle and render it as an HTTP response with
/// a guessed content type. Returns `None` if the file is not embedded.
fn serve_asset(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(Body::from(file.data.into_owned()))
            .expect("static response builds"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_embedded() {
        // A `vite build` must have populated `ui/dist` before compilation, so the
        // bundle always carries an `index.html` (it is the SPA fallback target).
        assert!(Assets::get("index.html").is_some(), "index.html must be embedded");
    }

    #[test]
    fn serve_asset_sets_html_content_type() {
        let resp = serve_asset("index.html").expect("index served");
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(ct.contains("text/html"), "expected html content type, got {ct}");
    }

    #[test]
    fn serve_asset_missing_returns_none() {
        assert!(serve_asset("definitely-not-here.xyz").is_none());
    }
}
