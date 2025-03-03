mod http;
mod util;

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use jsonwebtoken::EncodingKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use russh::keys::PublicKeyBase64;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{ChannelId, CryptoVec};
use ssh_key::public::Ed25519PublicKey;
use tracing_subscriber::layer::SubscriberExt;

static SIGNING_KEY: OnceLock<RsaPrivateKey> = OnceLock::new();

#[derive(Parser)]
struct Options {
    /// JWT signing private key of the server.
    #[arg(long)]
    jwt_signing_key: PathBuf,

    /// Issuer URL for the JWT.
    #[arg(long)]
    jwt_issuer: String,

    /// Valid duration of the JWT token.
    ///
    /// Should not be longer than 24 hours.
    #[arg(long, default_value = "12hr", value_parser = humantime::parse_duration)]
    jwt_valid_duration: Duration,

    /// SSH host private key of the server.
    #[arg(long)]
    ssh_host_key: PathBuf,

    /// Path to the known hosts file.
    #[arg(long)]
    known_hosts: PathBuf,

    /// Listening address of the server.
    #[arg(long, default_value = "0.0.0.0")]
    listen_addr: String,

    /// Listening port of SSH server.
    #[arg(long, default_value = "2222")]
    ssh_port: u16,

    /// Listening port of the HTTP server.
    #[arg(long, default_value = "8080")]
    http_port: u16,
}

static OPTIONS: LazyLock<Options> = LazyLock::new(Options::parse);

fn tracing_init() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let layer = tracing_tree::HierarchicalLayer::default()
        .with_indent_lines(true)
        .with_ansi(true)
        .with_targets(true)
        .with_indent_amount(2);
    let subscriber = tracing_subscriber::Registry::default()
        .with(filter)
        .with(layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_init();
    LazyLock::force(&OPTIONS);

    // Read JWT signing key
    {
        let signing_key_pem = std::fs::read_to_string(&OPTIONS.jwt_signing_key)
            .context("Cannot read JWT signing key")?;
        let signing_key = RsaPrivateKey::from_pkcs8_pem(&signing_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&signing_key_pem))?;
        SIGNING_KEY.set(signing_key).map_err(|_| ()).unwrap();
    }

    // Read SSH host key.
    let ssh_keypair = russh::keys::load_secret_key(&OPTIONS.ssh_host_key, None)?;

    let config = russh::server::Config {
        methods: russh::MethodSet::PUBLICKEY,
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![ssh_keypair],
        ..Default::default()
    };

    let http = async {
        http::listen(OPTIONS.listen_addr.as_str(), OPTIONS.http_port)
            .await
            .context("HTTP server error")
    };

    let ssh = async {
        Server
            .run_on_address(
                Arc::new(config),
                (OPTIONS.listen_addr.as_str(), OPTIONS.ssh_port),
            )
            .await
            .context("Cannot start SSH server")
    };

    tokio::try_join!(http, ssh)?;

    Ok(())
}

struct Server;

impl russh::server::Server for Server {
    type Handler = Handler;
    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Handler {
        let span = tracing::info_span!("client", ?addr);
        Handler {
            span,
            pubkey: None,
            hosts: Vec::new(),
        }
    }

    fn handle_session_error(&mut self, err: <Self::Handler as russh::server::Handler>::Error) {
        tracing::debug!(%err, "session error");
    }
}

struct Handler {
    span: tracing::Span,
    pubkey: Option<Ed25519PublicKey>,
    hosts: Vec<String>,
}

fn check_key(key: &Ed25519PublicKey) -> Vec<String> {
    // This is read everything instead of at start-up allow hot updating.
    let entries = ssh_key::KnownHosts::read_file(&OPTIONS.known_hosts).unwrap_or_else(|err| {
        tracing::error!(?err, "cannot read known_hosts");
        Vec::new()
    });

    let mut hosts = Vec::new();
    for entry in entries {
        let ssh_key::known_hosts::HostPatterns::Patterns(host_name) = entry.host_patterns() else {
            continue;
        };
        let Some(host_key) = entry.public_key().key_data().ed25519() else {
            continue;
        };
        if key == host_key {
            hosts.extend_from_slice(&host_name);
        }
    }

    hosts
}

fn pubkey_to_ed25519(public_key: &russh::keys::key::PublicKey) -> Option<Ed25519PublicKey> {
    // No public method exposed from pubkey to check algorithm, so we need to use byte form.
    // The bytes have format <u32 BE length><type><u32 BE length><key>
    let public_key_bytes = public_key.public_key_bytes();

    // Check if starts with "<11 as u32 BE>ssh-ed25519"
    if !public_key_bytes.starts_with(b"\0\0\0\x0Bssh-ed25519") {
        tracing::debug!("reject non-ED25519 keys");
        return None;
    }

    // Get the key part.
    // The ED25519 must be 32 bytes long, so unwrap here is okay.
    Some(public_key_bytes[4 + 11 + 4..].try_into().unwrap())
}

#[async_trait]
impl russh::server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &russh::keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let _enter = self.span.enter();
        let span = tracing::debug_span!("public key offered", public_key = ?public_key.public_key_base64());
        let _enter = span.enter();

        let Some(key) = pubkey_to_ed25519(public_key) else {
            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        };

        // Returns matched host names
        let hosts = check_key(&key);
        if hosts.is_empty() {
            tracing::debug!("unknown keys");

            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        };

        tracing::debug!(?hosts, "host recognised");

        self.pubkey = Some(key);
        self.hosts = hosts;

        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        public_key: &russh::keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let _enter = self.span.enter();

        // Double check that this is the expected public key.
        // This is defense-in-depth.
        if pubkey_to_ed25519(public_key) != self.pubkey {
            tracing::error!("authenticated public key differs from offered public key");
            return Ok(Auth::Reject {
                proceed_with_methods: None,
            });
        }

        tracing::info!(public_key = ?public_key.public_key_base64(), "authenticated");

        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _enter = self.span.enter();
        tracing::info!("deny shell requests");

        // We get this if client side just does SSH without any command.
        // Reject because we want client to explicitly give us an audience.
        session.data(
            channel,
            CryptoVec::from("Error: no audience is specified.\r\n".to_owned()),
        );
        session.exit_status_request(channel, 1);
        session.close(channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _enter = self.span.enter();
        let span = tracing::info_span!("JWT signing request");
        let _enter = span.enter();

        // When the client sends a command, this is treated as OIDC signing request
        // for this specific targeted audience.

        let Ok(audience) = std::str::from_utf8(data) else {
            tracing::info!("audience is not UTF-8");
            session.data(
                channel,
                CryptoVec::from("Error: audience is not UTF-8.\r\n".to_owned()),
            );
            session.exit_status_request(channel, 1);
            return Ok(());
        };

        let issue_time = SystemTime::now();
        let expiration = issue_time + OPTIONS.jwt_valid_duration;

        fn serialize_timestamp<S: serde::Serializer>(
            time: &SystemTime,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            let time = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            s.serialize_u64(time)
        }

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            aud: &'a str,
            #[serde(serialize_with = "serialize_timestamp")]
            exp: SystemTime,
            #[serde(serialize_with = "serialize_timestamp")]
            iat: SystemTime,
            sub: &'a str,

            // Custom claim for permitted host names.
            // Only use this if multiple hosts are associated are associated with this public key.
            #[serde(skip_serializing_if = "Option::is_none")]
            sans: Option<&'a [String]>,
        }

        impl std::fmt::Debug for Claims<'_> {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut fmt = formatter.debug_struct("Claims");
                fmt.field("iss", &self.iss)
                    .field("aud", &self.aud)
                    .field(
                        "exp",
                        &util::FmtAsDisplay(humantime::format_rfc3339_seconds(self.exp)),
                    )
                    .field(
                        "iat",
                        &util::FmtAsDisplay(humantime::format_rfc3339_seconds(self.iat)),
                    )
                    .field("sub", &self.sub);
                if let Some(sans) = self.sans {
                    fmt.field("sans", &sans);
                }
                fmt.finish()
            }
        }

        let claims = Claims {
            iss: &OPTIONS.jwt_issuer,
            aud: audience,
            exp: expiration,
            iat: issue_time,
            sub: &self.hosts[0],
            sans: if self.hosts.len() == 1 {
                None
            } else {
                Some(&self.hosts)
            },
        };

        tracing::info!(?claims);

        let key = SIGNING_KEY.get().unwrap().to_pkcs1_der()?;
        let key = EncodingKey::from_rsa_der(key.as_bytes());

        let token = match jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        ) {
            Ok(v) => v,
            Err(err) => {
                tracing::info!(?err, "signing failed");
                session.data(
                    channel,
                    CryptoVec::from(format!("Error: cannot sign JWT: {:?}\r\n", err)),
                );
                session.exit_status_request(channel, 1);
                return Ok(());
            }
        };

        let data = CryptoVec::from(format!("{token}\n", token = token.to_string()));
        session.data(channel, data);
        session.exit_status_request(channel, 0);
        session.close(channel);
        Ok(())
    }
}
