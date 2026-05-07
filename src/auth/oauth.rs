use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use ring::digest::{Context, SHA256};
use serde::Deserialize;
use serde_json::Value;

use crate::error::ViaError;
use crate::redaction::Redactor;
use crate::secrets::SecretValue;

const CACHE_EXPIRY_SKEW_SECONDS: i64 = 60;
const SERVICE_OAUTH_TYPE: &str = "service_oauth";

pub fn access_token(credential: &SecretValue, redactor: &mut Redactor) -> Result<String, ViaError> {
    access_token_with_mode(credential, redactor, crate::daemon::OAuthTokenMode::Cached)
}

pub fn refresh_access_token(
    credential: &SecretValue,
    redactor: &mut Redactor,
) -> Result<String, ViaError> {
    access_token_with_mode(credential, redactor, crate::daemon::OAuthTokenMode::Refresh)
}

fn access_token_with_mode(
    credential: &SecretValue,
    redactor: &mut Redactor,
    mode: crate::daemon::OAuthTokenMode,
) -> Result<String, ViaError> {
    redactor.add(credential.expose());
    let bundle = CredentialBundle::parse(credential.expose())?;
    register_bundle_secrets(&bundle, redactor);

    let token = crate::daemon::oauth_access_token(credential.expose(), mode)?;
    redactor.add(token.expose());
    Ok(token.expose().to_owned())
}

pub fn validate_credential_bundle(raw: &str) -> Result<(), ViaError> {
    CredentialBundle::parse(raw).map(|_| ())
}

pub(crate) fn exchange_access_token(
    client: &Client,
    bundle: &CredentialBundle,
    cached: Option<&CachedOAuthToken>,
    redactor: &mut Redactor,
) -> Result<OAuthAccessToken, ViaError> {
    match &bundle.grant {
        OAuthGrant::RefreshToken { refresh_token } => {
            let cached_refresh_token = cached.and_then(|cached| cached.refresh_token.as_deref());
            let refresh_token_for_request = cached_refresh_token.unwrap_or(refresh_token);
            match exchange_refresh_token(client, bundle, refresh_token_for_request, redactor) {
                Ok(token) => Ok(token),
                Err(_error)
                    if cached_refresh_token.is_some_and(|cached| cached != refresh_token) =>
                {
                    crate::timing::event(
                        "oauth refresh token fallback",
                        "cached_refresh_token_failed",
                    );
                    exchange_refresh_token(client, bundle, refresh_token, redactor)
                }
                Err(error) => Err(error),
            }
        }
        OAuthGrant::ClientCredentials { .. } => {
            exchange_client_credentials(client, bundle, redactor)
        }
    }
}

fn exchange_refresh_token(
    client: &Client,
    bundle: &CredentialBundle,
    refresh_token: &str,
    redactor: &mut Redactor,
) -> Result<OAuthAccessToken, ViaError> {
    redactor.add(refresh_token);
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", bundle.client_id.as_str()),
    ];
    if let Some(client_secret) = bundle.client_secret.as_deref() {
        form.push(("client_secret", client_secret));
    }

    exchange_token_form(
        client,
        bundle,
        &form,
        TokenResponseRefreshMode::PreserveRefreshToken(refresh_token),
        redactor,
    )
}

fn exchange_client_credentials(
    client: &Client,
    bundle: &CredentialBundle,
    redactor: &mut Redactor,
) -> Result<OAuthAccessToken, ViaError> {
    let OAuthGrant::ClientCredentials { scope } = &bundle.grant else {
        unreachable!("caller only passes client_credentials grants");
    };
    let client_secret = bundle.client_secret.as_deref().ok_or_else(|| {
        ViaError::InvalidConfig(
            "oauth client_credentials credential bundle must include `client_secret`".to_owned(),
        )
    })?;

    let form = vec![
        ("grant_type", "client_credentials"),
        ("scope", scope.as_str()),
        ("client_id", bundle.client_id.as_str()),
        ("client_secret", client_secret),
    ];

    exchange_token_form(
        client,
        bundle,
        &form,
        TokenResponseRefreshMode::NoRefreshToken,
        redactor,
    )
}

fn exchange_token_form(
    client: &Client,
    bundle: &CredentialBundle,
    form: &[(&str, &str)],
    refresh_mode: TokenResponseRefreshMode<'_>,
    redactor: &mut Redactor,
) -> Result<OAuthAccessToken, ViaError> {
    let body = form_encode(form);
    let exchange_span = crate::timing::span("oauth token exchange");
    let response = match client
        .post(&bundle.token_url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
    {
        Ok(response) => {
            let status = response.status();
            exchange_span.finish(format!("status={status}"));
            response
        }
        Err(error) => {
            exchange_span.finish("failed");
            return Err(error.into());
        }
    };
    let status = response.status();
    let body_span = crate::timing::span("oauth token body");
    let body = match response.text() {
        Ok(body) => {
            body_span.finish(format!("bytes={}", body.len()));
            body
        }
        Err(error) => {
            body_span.finish("failed");
            return Err(error.into());
        }
    };

    if !status.is_success() {
        let body = redactor.redact(&body);
        return Err(ViaError::InvalidArgument(format!(
            "OAuth token exchange failed with status {status}: {body}"
        )));
    }

    parse_token_response(&body, refresh_mode, redactor)
}

fn parse_token_response(
    body: &str,
    refresh_mode: TokenResponseRefreshMode<'_>,
    redactor: &mut Redactor,
) -> Result<OAuthAccessToken, ViaError> {
    let response: TokenResponse = serde_json::from_str(body)?;
    if let Some(token_type) = &response.token_type {
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(ViaError::InvalidArgument(format!(
                "OAuth token response had unsupported token_type `{token_type}`"
            )));
        }
    }

    let refresh_token = match refresh_mode {
        TokenResponseRefreshMode::PreserveRefreshToken(refresh_token) => Some(
            response
                .refresh_token
                .unwrap_or_else(|| refresh_token.to_owned()),
        ),
        TokenResponseRefreshMode::NoRefreshToken => response.refresh_token,
    };
    let expires_at = expires_at(response.expires_in)?;

    redactor.add(&response.access_token);
    if let Some(refresh_token) = &refresh_token {
        redactor.add(refresh_token);
    }

    Ok(OAuthAccessToken {
        access_token: response.access_token,
        refresh_token,
        expires_at,
    })
}

fn expires_at(expires_in: u64) -> Result<i64, ViaError> {
    let now = unix_timestamp()?;
    let expires_in = i64::try_from(expires_in).map_err(|_| {
        ViaError::InvalidArgument("OAuth token response expires_in is too large".to_owned())
    })?;
    now.checked_add(expires_in).ok_or_else(|| {
        ViaError::InvalidArgument("OAuth token response expires_at is too large".to_owned())
    })
}

pub(crate) fn register_bundle_secrets(bundle: &CredentialBundle, redactor: &mut Redactor) {
    if let Some(client_secret) = &bundle.client_secret {
        redactor.add(client_secret);
    }
    match &bundle.grant {
        OAuthGrant::RefreshToken { refresh_token } => redactor.add(refresh_token),
        OAuthGrant::ClientCredentials { .. } => {}
    }
}

pub(crate) fn register_cached_secrets(cached: Option<&CachedOAuthToken>, redactor: &mut Redactor) {
    if let Some(cached) = cached {
        redactor.add(&cached.access_token);
        if let Some(refresh_token) = &cached.refresh_token {
            redactor.add(refresh_token);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CredentialBundle {
    credential_type: String,
    pub(crate) token_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    grant: OAuthGrant,
}

impl CredentialBundle {
    pub(crate) fn parse(raw: &str) -> Result<Self, ViaError> {
        let value: Value = serde_json::from_str(raw).map_err(credential_json_error)?;
        let credential_type = required_string(&value, "type")?;
        validate_credential_type(&credential_type)?;
        let token_url = required_string(&value, "token_url")?;
        let client_id = required_string(&value, "client_id")?;
        let client_secret = optional_string(&value, "client_secret")?;
        let configured_grant_type = optional_string(&value, "grant_type")?;
        let configured_refresh_token = optional_string(&value, "refresh_token")?;
        let grant = match configured_grant_type.as_deref() {
            Some("refresh_token") => OAuthGrant::RefreshToken {
                refresh_token: configured_refresh_token.ok_or_else(|| {
                    ViaError::InvalidConfig(
                        "oauth refresh_token credential bundle must include `refresh_token`"
                            .to_owned(),
                    )
                })?,
            },
            Some("client_credentials") => OAuthGrant::ClientCredentials {
                scope: required_string(&value, "scope")?,
            },
            Some(grant_type) => {
                return Err(ViaError::InvalidConfig(format!(
                    "unsupported oauth grant_type `{grant_type}`"
                )));
            }
            None => match configured_refresh_token {
                Some(refresh_token) => OAuthGrant::RefreshToken { refresh_token },
                None => {
                    return Err(ViaError::InvalidConfig(
                        "oauth credential bundle must include `grant_type`".to_owned(),
                    ));
                }
            },
        };

        Ok(Self {
            credential_type,
            token_url,
            client_id,
            client_secret,
            grant,
        })
    }
}

fn validate_credential_type(value: &str) -> Result<(), ViaError> {
    if value == SERVICE_OAUTH_TYPE {
        return Ok(());
    }

    Err(ViaError::InvalidConfig(format!(
        "unsupported oauth credential type `{value}`; expected `{SERVICE_OAUTH_TYPE}`"
    )))
}

#[derive(Debug, PartialEq, Eq)]
enum OAuthGrant {
    RefreshToken { refresh_token: String },
    ClientCredentials { scope: String },
}

#[derive(Clone, Copy)]
enum TokenResponseRefreshMode<'a> {
    PreserveRefreshToken(&'a str),
    NoRefreshToken,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug)]
pub(crate) struct OAuthAccessToken {
    pub(crate) access_token: String,
    pub(crate) refresh_token: Option<String>,
    pub(crate) expires_at: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct CachedOAuthToken {
    pub(crate) access_token: String,
    pub(crate) expires_at: i64,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
}

pub(crate) fn cache_key(bundle: &CredentialBundle) -> String {
    let mut context = Context::new(&SHA256);
    context.update(bundle.credential_type.as_bytes());
    context.update(b"\0");
    context.update(bundle.token_url.as_bytes());
    context.update(b"\0");
    context.update(bundle.client_id.as_bytes());
    context.update(b"\0");
    match &bundle.grant {
        OAuthGrant::RefreshToken { refresh_token } => {
            context.update(b"refresh_token\0");
            context.update(refresh_token.as_bytes());
        }
        OAuthGrant::ClientCredentials { scope } => {
            context.update(b"client_credentials\0");
            context.update(scope.as_bytes());
        }
    }
    hex_encode(context.finish().as_ref())
}

pub(crate) fn cached_access_token(cached: Option<&CachedOAuthToken>, now: i64) -> Option<String> {
    let cached = cached?;
    if cached.expires_at <= now + CACHE_EXPIRY_SKEW_SECONDS {
        return None;
    }
    Some(cached.access_token.clone())
}

pub(crate) fn unix_timestamp() -> Result<i64, ViaError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ViaError::InvalidConfig("system clock is before UNIX epoch".to_owned()))?;
    i64::try_from(duration.as_secs())
        .map_err(|_| ViaError::InvalidConfig("system clock timestamp is too large".to_owned()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                form_percent_encode(name),
                form_percent_encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn form_percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn credential_json_error(error: serde_json::Error) -> ViaError {
    ViaError::InvalidConfig(format!(
        "oauth credential bundle must be valid JSON: {error}"
    ))
}

fn required_string(value: &Value, field: &str) -> Result<String, ViaError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ViaError::InvalidConfig(format!(
                "oauth credential bundle must include non-empty `{field}`"
            ))
        })
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, ViaError> {
    match value.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.to_owned())),
        Some(Value::String(_)) | None => Ok(None),
        Some(_) => Err(ViaError::InvalidConfig(format!(
            "oauth credential bundle `{field}` must be a string"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const LINEAR_TOKEN_URL: &str = "https://api.linear.app/oauth/token";

    #[test]
    fn parses_service_refresh_token_bundle() {
        let bundle = CredentialBundle::parse(
            &serde_json::json!({
                "type": "service_oauth",
                "token_url": LINEAR_TOKEN_URL,
                "grant_type": "refresh_token",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "refresh-token",
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(bundle.credential_type, SERVICE_OAUTH_TYPE);
        assert_eq!(bundle.token_url, LINEAR_TOKEN_URL);
        assert_eq!(bundle.client_id, "client-id");
        assert_eq!(bundle.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(
            bundle.grant,
            OAuthGrant::RefreshToken {
                refresh_token: "refresh-token".to_owned()
            }
        );
    }

    #[test]
    fn parses_service_client_credentials_bundle() {
        let bundle = CredentialBundle::parse(
            &serde_json::json!({
                "type": "service_oauth",
                "token_url": LINEAR_TOKEN_URL,
                "grant_type": "client_credentials",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "scope": "read,issues:create",
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            bundle.grant,
            OAuthGrant::ClientCredentials {
                scope: "read,issues:create".to_owned()
            }
        );
    }

    #[test]
    fn rejects_unsupported_oauth_credential_type() {
        let error = CredentialBundle::parse(
            &serde_json::json!({
                "type": "example_oauth",
                "token_url": LINEAR_TOKEN_URL,
                "grant_type": "refresh_token",
                "client_id": "client-id",
                "refresh_token": "refresh-token",
            })
            .to_string(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::InvalidConfig(message) if message.contains("unsupported oauth credential type")
        ));
    }

    #[test]
    fn validates_credential_bundle() {
        validate_credential_bundle(
            &serde_json::json!({
                "type": "service_oauth",
                "token_url": LINEAR_TOKEN_URL,
                "client_id": "client-id",
                "refresh_token": "refresh-token",
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn returns_unexpired_cached_oauth_token() {
        let cached = CachedOAuthToken {
            access_token: "cached-access-token".to_owned(),
            expires_at: unix_timestamp().unwrap() + 3_600,
            refresh_token: Some("cached-refresh-token".to_owned()),
        };

        let token = cached_access_token(Some(&cached), unix_timestamp().unwrap()).unwrap();

        assert_eq!(token, "cached-access-token");
    }

    #[test]
    fn refreshes_and_returns_rotated_refresh_token() {
        let response_body = serde_json::json!({
            "access_token": "fresh-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rotated-refresh-token",
            "scope": "read write",
        })
        .to_string();
        let (token_url, server) = token_server(response_body);
        let bundle = test_refresh_bundle(&token_url);

        let client = Client::new();
        let mut redactor = Redactor::new();
        let token = exchange_access_token(&client, &bundle, None, &mut redactor).unwrap();
        let request = server.join().unwrap();

        assert_eq!(token.access_token, "fresh-access-token");
        assert!(request.starts_with("POST /oauth/token "));
        assert!(request.contains("content-type: application/x-www-form-urlencoded"));
        assert!(request.contains("grant_type=refresh_token"));
        assert!(request.contains("refresh_token=configured-refresh-token"));
        assert_eq!(
            token.refresh_token.as_deref(),
            Some("rotated-refresh-token")
        );
        assert_eq!(
            redactor.redact("fresh-access-token rotated-refresh-token configured-refresh-token"),
            "[REDACTED] [REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn refreshes_and_preserves_current_refresh_token_when_response_omits_rotation() {
        let response_body = serde_json::json!({
            "access_token": "fresh-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })
        .to_string();
        let (token_url, server) = token_server(response_body);
        let bundle = test_refresh_bundle(&token_url);

        let client = Client::new();
        let mut redactor = Redactor::new();
        let token = exchange_access_token(&client, &bundle, None, &mut redactor).unwrap();
        let request = server.join().unwrap();

        assert_eq!(token.access_token, "fresh-access-token");
        assert!(request.contains("grant_type=refresh_token"));
        assert_eq!(
            token.refresh_token.as_deref(),
            Some("configured-refresh-token")
        );
    }

    #[test]
    fn exchanges_client_credentials_and_returns_access_token() {
        let response_body = serde_json::json!({
            "access_token": "client-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read issues:create",
        })
        .to_string();
        let (token_url, server) = token_server(response_body);
        let bundle = CredentialBundle {
            credential_type: SERVICE_OAUTH_TYPE.to_owned(),
            token_url,
            client_id: "client-id".to_owned(),
            client_secret: Some("client-secret".to_owned()),
            grant: OAuthGrant::ClientCredentials {
                scope: "read,issues:create".to_owned(),
            },
        };

        let client = Client::new();
        let mut redactor = Redactor::new();
        let token = exchange_access_token(&client, &bundle, None, &mut redactor).unwrap();
        let request = server.join().unwrap();

        assert_eq!(token.access_token, "client-access-token");
        assert!(request.contains("grant_type=client_credentials"));
        assert!(request.contains("scope=read%2Cissues%3Acreate"));
        assert!(request.contains("client_secret=client-secret"));
    }

    #[test]
    fn rejects_non_bearer_token_response() {
        let mut redactor = Redactor::new();
        let error = parse_token_response(
            &serde_json::json!({
                "access_token": "access-token",
                "token_type": "mac",
                "expires_in": 3600,
                "refresh_token": "refresh-token",
            })
            .to_string(),
            TokenResponseRefreshMode::PreserveRefreshToken("refresh-token"),
            &mut redactor,
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidArgument(message) if message.contains("token_type"))
        );
    }

    fn test_refresh_bundle(token_url: &str) -> CredentialBundle {
        CredentialBundle {
            credential_type: SERVICE_OAUTH_TYPE.to_owned(),
            token_url: token_url.to_owned(),
            client_id: "client-id".to_owned(),
            client_secret: Some("client-secret".to_owned()),
            grant: OAuthGrant::RefreshToken {
                refresh_token: "configured-refresh-token".to_owned(),
            },
        }
    }

    fn token_server(response_body: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });

        (format!("http://{address}/oauth/token"), handle)
    }
}
