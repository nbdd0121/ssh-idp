use anyhow::Result;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use base64ct::Encoding;
use jsonwebtoken::jwk::{self, Jwk, JwkSet};
use rsa::traits::PublicKeyParts;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;

use crate::OPTIONS;

#[derive(serde::Serialize)]
struct OpenIdConfiguration {
    issuer: &'static str,
    // authorization_endpoint is technically REQUIRED, but we doesn't provide a way for user to login over HTTP.
    // GitHub OIDC configuration also doesn't contain it.
    jwks_uri: String,
    scopes_supported: &'static [&'static str],
    response_types_supported: &'static [&'static str],
    subject_types_supported: &'static [&'static str],
    id_token_signing_alg_values_supported: &'static [&'static str],
    claims_supported: &'static [&'static str],
}

async fn openid_configuration() -> Json<OpenIdConfiguration> {
    Json(OpenIdConfiguration {
        issuer: &OPTIONS.jwt_issuer,
        jwks_uri: format!("{}/jwks", OPTIONS.jwt_issuer),
        scopes_supported: &["openid"],
        response_types_supported: &["id_token"],
        subject_types_supported: &["public"],
        id_token_signing_alg_values_supported: &["RS256"],
        claims_supported: &["iss", "aud", "exp", "iat", "sub", "sans"],
    })
}

async fn jwks() -> Json<JwkSet> {
    let key = crate::SIGNING_KEY.get().unwrap().to_public_key();
    Json(JwkSet {
        keys: vec![Jwk {
            common: jwk::CommonParameters {
                public_key_use: Some(jwk::PublicKeyUse::Signature),
                key_algorithm: Some(jwk::KeyAlgorithm::RS256),
                key_id: None,
                ..Default::default()
            },
            algorithm: jwk::AlgorithmParameters::RSA(jwk::RSAKeyParameters {
                key_type: jwk::RSAKeyType::RSA,
                n: base64ct::Base64UrlUnpadded::encode_string(&key.n().to_bytes_be()),
                e: base64ct::Base64UrlUnpadded::encode_string(&key.e().to_bytes_be()),
            }),
        }],
    })
}

async fn not_found() -> (StatusCode, &'static str) {
    tracing::info!("not found");
    (StatusCode::NOT_FOUND, "Not Found")
}

async fn wrong_method() -> (StatusCode, &'static str) {
    tracing::info!("wrong method");
    (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

pub async fn listen(listen_addr: &str, port: u16) -> Result<()> {
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration).fallback(wrong_method),
        )
        .route("/jwks", get(jwks).fallback(wrong_method))
        .fallback(not_found)
        .layer(
            TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().level(Level::INFO)),
        );

    let listener = tokio::net::TcpListener::bind((listen_addr, port)).await?;
    tracing::info!("Serving HTTP on {listen_addr}:{port}");
    axum::serve(listener, app).await?;

    Ok(())
}
