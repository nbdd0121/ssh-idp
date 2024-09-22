mod util;

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use jsonwebtoken::EncodingKey;
use russh::keys::PublicKeyBase64;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{ChannelId, CryptoVec};
use ssh_key::public::Ed25519PublicKey;
use tracing_subscriber::layer::SubscriberExt;

static SIGNING_KEY: OnceLock<EncodingKey> = OnceLock::new();

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

    /// Listening address of SSH server.
    #[arg(long, default_value = "0.0.0.0")]
    ssh_addr: String,

    /// Listening port of SSH server.
    #[arg(long, default_value = "2222")]
    ssh_port: u16,
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
    let signing_key = EncodingKey::from_rsa_pem(
        &std::fs::read(&OPTIONS.jwt_signing_key).context("Cannot read JWT signing key")?,
    )
    .map_err(|err| anyhow::anyhow!(err))?;
    SIGNING_KEY.set(signing_key).map_err(|_| ()).unwrap();

    // Read SSH host key.
    let ssh_keypair = russh::keys::load_secret_key(&OPTIONS.ssh_host_key, None)?;

    let config = russh::server::Config {
        methods: russh::MethodSet::PUBLICKEY,
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![ssh_keypair],
        ..Default::default()
    };

    Server
        .run_on_address(
            Arc::new(config),
            (OPTIONS.ssh_addr.as_str(), OPTIONS.ssh_port),
        )
        .await
        .context("Cannot start SSH server")?;

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
        tracing::debug!(name: "session error", ?err);
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
        tracing::error!(name: "cannot read known_hosts", ?err);
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
    type Error = russh::Error;

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

        tracing::debug!(name: "host recognised", ?hosts);

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

        tracing::info!(name: "authenticated", public_key = ?public_key.public_key_base64());

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

        let token = match jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            SIGNING_KEY.get().unwrap(),
        ) {
            Ok(v) => v,
            Err(err) => {
                tracing::info!(name: "signing failed", ?err);
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
        session.close(channel);
        Ok(())
    }
}
