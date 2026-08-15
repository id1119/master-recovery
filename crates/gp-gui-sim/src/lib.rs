//! Local browser gateway for the guided protocol simulator.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS},
    },
    response::Html,
    routing::{get, post},
};
use gp_ipc::{Command, IPC_VERSION, Response, execute};
use gp_sim::{DemoOptions, RotationDemoOptions, RotationDemoResult, run_rotation_demo};
use serde::{Deserialize, Serialize};

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/api/demo", post(run_demo_post))
        .route("/api/rotation", post(run_rotation_post))
        .route("/api/signer-keys", post(signer_keys_post))
        .route("/api/health", get(health))
        .layer(DefaultBodyLimit::max(1280 * 1024));
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Guardian Protocol simulator: http://{address}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
enum RotationApiResponse {
    Complete(Box<RotationDemoResult>),
    Error(String),
}

async fn run_rotation_post(
    Json(options): Json<RotationDemoOptions>,
) -> (StatusCode, HeaderMap, Json<RotationApiResponse>) {
    match run_rotation_demo(&options) {
        Ok(result) => (
            StatusCode::OK,
            security_headers(),
            Json(RotationApiResponse::Complete(Box::new(result))),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            security_headers(),
            Json(RotationApiResponse::Error(error.to_string())),
        ),
    }
}

async fn index() -> (HeaderMap, Html<&'static str>) {
    (security_headers(), Html(INDEX_HTML))
}

async fn health() -> (HeaderMap, Json<Response>) {
    (security_headers(), Json(execute(Command::Ping)))
}

async fn run_demo_post(
    Json(options): Json<DemoOptions>,
) -> (StatusCode, HeaderMap, Json<Response>) {
    let response = execute_demo(options);
    let status = if matches!(response, Response::Error { .. }) {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, security_headers(), Json(response))
}

#[derive(Deserialize)]
struct SignerKeysRequest {
    seed: u64,
    signer_count: u16,
}

#[derive(Serialize)]
struct SignerKeysResponse {
    signer_public_keys: Vec<String>,
    error: Option<String>,
}

async fn signer_keys_post(
    Json(request): Json<SignerKeysRequest>,
) -> (StatusCode, HeaderMap, Json<SignerKeysResponse>) {
    match gp_sim::simulator_signer_public_keys(request.seed, request.signer_count, 1) {
        Ok(signer_public_keys) => (
            StatusCode::OK,
            security_headers(),
            Json(SignerKeysResponse {
                signer_public_keys,
                error: None,
            }),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            security_headers(),
            Json(SignerKeysResponse {
                signer_public_keys: vec![],
                error: Some(error.to_string()),
            }),
        ),
    }
}

fn execute_demo(options: DemoOptions) -> Response {
    execute(Command::RunDemo {
        version: IPC_VERSION,
        options,
    })
}

fn security_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers
}

const INDEX_HTML: &str = include_str!("index.html");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_contains_guided_flow_and_every_required_control() {
        for required in [
            "guidedSteps",
            "signerCount",
            "signerThreshold",
            "signerKeys",
            "signerKeyStatus",
            "guardianCount",
            "guardianThreshold",
            "recoveryOutcome",
            "delaySeconds",
            "metadataMode",
            "fileInput",
            "compareButton",
            "copyCardButton",
            "downloadCardButton",
            "networkSignerValue",
            "networkGuardianValue",
            "requestBindingFact",
            "graphBackup",
            "graphRecovery",
            "observedMetric",
            "packetChart",
            "comparisonPanel",
            "rotationButton",
            "rotationStatus",
            "rotationEpoch",
            "rotationGuardians",
        ] {
            assert!(
                INDEX_HTML.contains(required),
                "missing UI control {required}"
            );
        }
        assert!(INDEX_HTML.contains("method: 'POST'"));
        assert!(!INDEX_HTML.contains("/api/demo?"));
        assert!(INDEX_HTML.contains("not a production anonymity network"));
        assert!(INDEX_HTML.contains("Ed25519 is classical/non-PQ"));
        assert!(!INDEX_HTML.contains("cancelThreshold"));
        for removed in [
            "Recommended recovery plan",
            "offlineSigner",
            "offlineGuardian",
            "corruptGuardian",
            "replaySeed",
            "latencyMs",
            "packetLoss",
            "packetDuplication",
            "mixDrop",
            "coverRate",
        ] {
            assert!(
                !INDEX_HTML.contains(removed),
                "obsolete UI element {removed}"
            );
        }
    }

    #[test]
    fn secret_responses_are_not_cacheable_or_cross_origin_embeddable() {
        let headers = security_headers();
        assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(headers.get(REFERRER_POLICY).unwrap(), "no-referrer");
        assert!(
            headers
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }
}
