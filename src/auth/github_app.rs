use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::auth::jwt;
use crate::error::ViaError;
use crate::redaction::Redactor;
use crate::secrets::SecretValue;

const CACHE_EXPIRY_SKEW_SECONDS: i64 = 60;
const CACHE_LOCK_WAIT: Duration = Duration::from_secs(10);
const CACHE_LOCK_POLL: Duration = Duration::from_millis(50);
const CACHE_LOCK_STALE_AFTER: Duration = Duration::from_secs(60);

pub fn installation_access_token(
    client: &Client,
    api_base_url: &str,
    credential: &SecretValue,
    private_key: Option<&SecretValue>,
    redactor: &mut Redactor,
) -> Result<String, ViaError> {
    redactor.add(credential.expose());
    if let Some(private_key) = private_key {
        redactor.add(private_key.expose());
    }

    let bundle =
        CredentialBundle::parse(credential.expose(), private_key.map(SecretValue::expose))?;
    bundle.validate_kind()?;

    if let Some(cache_dir) = default_cache_dir() {
        return installation_access_token_with_cache_dir(
            client,
            api_base_url,
            &bundle,
            redactor,
            &cache_dir,
        );
    }

    crate::timing::event("github_app token cache", "disabled");
    exchange_installation_access_token(client, api_base_url, &bundle, redactor)
        .map(|token| token.token)
}

fn installation_access_token_with_cache_dir(
    client: &Client,
    api_base_url: &str,
    bundle: &CredentialBundle,
    redactor: &mut Redactor,
    cache_dir: &Path,
) -> Result<String, ViaError> {
    let now = unix_timestamp()?;
    let key = cache_key(api_base_url, bundle);
    let cache_path = token_cache_path(cache_dir, &key);

    let cache_span = crate::timing::span("github_app token cache read");
    if let Some(token) = read_cached_token(&cache_path, now) {
        cache_span.finish("hit");
        redactor.add(&token);
        return Ok(token);
    }
    cache_span.finish("miss");

    let lock_path = token_lock_path(cache_dir, &key);
    let lock_span = crate::timing::span("github_app token cache lock");
    if let Some(_lock) = CacheLock::acquire(&lock_path) {
        lock_span.finish("acquired");
        let now = unix_timestamp()?;
        let cache_span = crate::timing::span("github_app token cache read_after_lock");
        if let Some(token) = read_cached_token(&cache_path, now) {
            cache_span.finish("hit");
            redactor.add(&token);
            return Ok(token);
        }
        cache_span.finish("miss");

        let token = exchange_installation_access_token(client, api_base_url, bundle, redactor)?;
        let write_span = crate::timing::span("github_app token cache write");
        match write_cached_token(
            &cache_path,
            &CachedInstallationToken {
                token: token.token.clone(),
                expires_at: token.expires_at,
            },
        ) {
            Ok(()) => write_span.finish("ok"),
            Err(_) => write_span.finish("failed"),
        };
        return Ok(token.token);
    }

    lock_span.finish("unavailable");
    exchange_installation_access_token(client, api_base_url, bundle, redactor)
        .map(|token| token.token)
}

fn exchange_installation_access_token(
    client: &Client,
    api_base_url: &str,
    bundle: &CredentialBundle,
    redactor: &mut Redactor,
) -> Result<InstallationAccessToken, ViaError> {
    redactor.add(&bundle.private_key);
    let jwt_span = crate::timing::span("github_app jwt sign");
    let jwt = app_jwt(bundle)?;
    jwt_span.finish("ok");
    redactor.add(&jwt);

    let url = format!(
        "{}/app/installations/{}/access_tokens",
        api_base_url.trim_end_matches('/'),
        bundle.installation_id
    );
    let exchange_span = crate::timing::span("github_app installation token exchange");
    let response = match client
        .post(url)
        .headers(token_exchange_headers(&jwt)?)
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
    let body_span = crate::timing::span("github_app installation token body");
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
            "GitHub App token exchange failed with status {status}: {body}"
        )));
    }

    let response: InstallationTokenResponse = serde_json::from_str(&body)?;
    let expires_at = parse_github_expires_at(&response.expires_at)?;
    redactor.add(&response.token);
    Ok(InstallationAccessToken {
        token: response.token,
        expires_at,
    })
}

pub fn validate_credential_bundle(raw: &str, private_key: Option<&str>) -> Result<(), ViaError> {
    let bundle = CredentialBundle::parse(raw, private_key)?;
    bundle.validate_kind()?;
    app_jwt(&bundle)?;
    Ok(())
}

fn app_jwt(bundle: &CredentialBundle) -> Result<String, ViaError> {
    let now = unix_timestamp()?;
    let claims = serde_json::json!({
        "iat": now - 60,
        "exp": now + 540,
        "iss": bundle.issuer,
    });
    jwt::sign_rs256(&claims, &bundle.private_key)
}

fn token_exchange_headers(jwt: &str) -> Result<HeaderMap, ViaError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("via-cli"));
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2022-11-28"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {jwt}"))
            .map_err(|_| ViaError::InvalidConfig("invalid GitHub App JWT".to_owned()))?,
    );
    Ok(headers)
}

fn unix_timestamp() -> Result<i64, ViaError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ViaError::InvalidConfig("system clock is before UNIX epoch".to_owned()))?;
    i64::try_from(duration.as_secs())
        .map_err(|_| ViaError::InvalidConfig("system clock timestamp is too large".to_owned()))
}

#[derive(Debug, PartialEq, Eq)]
struct CredentialBundle {
    kind: String,
    issuer: String,
    installation_id: String,
    private_key: String,
}

impl CredentialBundle {
    fn parse(raw: &str, private_key: Option<&str>) -> Result<Self, ViaError> {
        let value: Value = serde_json::from_str(raw).map_err(credential_json_error)?;

        Ok(Self {
            kind: required_string(&value, "type")?,
            issuer: required_app_id(&value)?,
            installation_id: required_string_or_number(&value, "installation_id")?,
            private_key: match private_key {
                Some(private_key) => private_key.to_owned(),
                None => required_string(&value, "private_key")?,
            },
        })
    }

    fn validate_kind(&self) -> Result<(), ViaError> {
        if self.kind == "github_app" {
            return Ok(());
        }

        Err(ViaError::InvalidConfig(
            "GitHub App credential bundle must set type = \"github_app\"".to_owned(),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

struct InstallationAccessToken {
    token: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct CachedInstallationToken {
    token: String,
    expires_at: i64,
}

struct CacheLock {
    path: PathBuf,
}

impl CacheLock {
    fn acquire(path: &Path) -> Option<Self> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent).ok()?;
        }

        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    let _ = set_private_file_permissions(path);
                    let _ = writeln!(file, "{}", std::process::id());
                    return Some(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path) {
                        let _ = fs::remove_file(path);
                        continue;
                    }

                    if started.elapsed() >= CACHE_LOCK_WAIT {
                        return None;
                    }

                    thread::sleep(CACHE_LOCK_POLL);
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn default_cache_dir() -> Option<PathBuf> {
    env_path("VIA_CACHE_DIR")
        .or_else(|| env_path("XDG_CACHE_HOME").map(|path| path.join("via")))
        .or_else(|| env_path("HOME").map(|path| path.join(".cache").join("via")))
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.as_os_str().is_empty())
        .map(PathBuf::from)
}

fn token_cache_path(cache_dir: &Path, key: &str) -> PathBuf {
    cache_dir.join("github-app").join(format!("{key}.json"))
}

fn token_lock_path(cache_dir: &Path, key: &str) -> PathBuf {
    cache_dir.join("github-app").join(format!("{key}.lock"))
}

fn cache_key(api_base_url: &str, bundle: &CredentialBundle) -> String {
    let mut context = Context::new(&SHA256);
    context.update(api_base_url.trim_end_matches('/').as_bytes());
    context.update(b"\0");
    context.update(bundle.issuer.as_bytes());
    context.update(b"\0");
    context.update(bundle.installation_id.as_bytes());
    hex_encode(context.finish().as_ref())
}

fn read_cached_token(path: &Path, now: i64) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let cached: CachedInstallationToken = serde_json::from_str(&raw).ok()?;
    if cached.expires_at <= now + CACHE_EXPIRY_SKEW_SECONDS {
        return None;
    }
    Some(cached.token)
}

fn write_cached_token(path: &Path, token: &CachedInstallationToken) -> Result<(), ViaError> {
    let parent = path
        .parent()
        .ok_or_else(|| ViaError::InvalidConfig("cache path has no parent".to_owned()))?;
    create_private_dir(parent)?;

    let temp_path = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("token"),
        std::process::id()
    ));
    let raw = serde_json::to_vec(token)?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        let _ = set_private_file_permissions(&temp_path);
        file.write_all(&raw)?;
        file.sync_all()?;
    }

    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            if error.kind() == io::ErrorKind::AlreadyExists {
                fs::remove_file(path)?;
                fs::rename(&temp_path, path)?;
                Ok(())
            } else {
                let _ = fs::remove_file(&temp_path);
                Err(error.into())
            }
        }
    }
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_dir_permissions(path)
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn lock_is_stale(path: &Path) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(io::Error::other))
        .is_ok_and(|age| age >= CACHE_LOCK_STALE_AFTER)
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

fn parse_github_expires_at(value: &str) -> Result<i64, ViaError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|error| {
            ViaError::InvalidArgument(format!(
                "GitHub App token response had invalid `expires_at` `{value}`: {error}"
            ))
        })
}

fn credential_json_error(error: serde_json::Error) -> ViaError {
    let mut message = format!("GitHub App credential bundle must be valid JSON: {error}");
    if error.to_string().contains("control character") {
        message.push_str(
            "; private_key must escape PEM newlines as `\\n`, not contain raw line breaks inside the JSON string",
        );
    }
    ViaError::InvalidConfig(message)
}

fn required_string(value: &Value, field: &str) -> Result<String, ViaError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ViaError::InvalidConfig(format!(
                "GitHub App credential bundle must include non-empty `{field}`"
            ))
        })
}

fn required_app_id(value: &Value) -> Result<String, ViaError> {
    if let Some(number) = value.get("app_id").and_then(Value::as_u64) {
        return Ok(number.to_string());
    }
    if let Some(app_id) = value
        .get("app_id")
        .and_then(Value::as_str)
        .filter(|value| value.chars().all(|character| character.is_ascii_digit()))
    {
        return Ok(app_id.to_owned());
    }

    if value.get("client_id").is_some() {
        return Err(ViaError::InvalidConfig(
            "GitHub App credential bundle must include numeric `app_id`; `client_id` is metadata only and is not used for this token exchange".to_owned(),
        ));
    }

    Err(ViaError::InvalidConfig(
        "GitHub App credential bundle must include numeric `app_id`".to_owned(),
    ))
}

fn required_string_or_number(value: &Value, field: &str) -> Result<String, ViaError> {
    if let Some(value) = value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(value.to_owned());
    }
    if let Some(number) = value.get(field).and_then(Value::as_u64) {
        return Ok(number.to_string());
    }

    Err(ViaError::InvalidConfig(format!(
        "GitHub App credential bundle must include non-empty `{field}`"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    const PRIVATE_KEY: &str = include_str!("../../tests/fixtures/rsa-private-key.pkcs1.pem");

    #[test]
    fn parses_bundle_with_app_id_string() {
        let bundle = CredentialBundle::parse(
            &serde_json::json!({
                "type": "github_app",
                "app_id": "42",
                "installation_id": "123",
                "private_key": PRIVATE_KEY,
            })
            .to_string(),
            None,
        )
        .unwrap();

        assert_eq!(
            bundle,
            CredentialBundle {
                kind: "github_app".to_owned(),
                issuer: "42".to_owned(),
                installation_id: "123".to_owned(),
                private_key: PRIVATE_KEY.to_owned(),
            }
        );
    }

    #[test]
    fn parses_numeric_app_and_installation_ids() {
        let bundle = CredentialBundle::parse(
            &serde_json::json!({
                "type": "github_app",
                "app_id": 42,
                "installation_id": 123,
                "private_key": PRIVATE_KEY,
            })
            .to_string(),
            None,
        )
        .unwrap();

        assert_eq!(bundle.issuer, "42");
        assert_eq!(bundle.installation_id, "123");
    }

    #[test]
    fn rejects_missing_private_key() {
        let error = CredentialBundle::parse(
            &serde_json::json!({
                "type": "github_app",
                "app_id": 42,
                "installation_id": "123",
            })
            .to_string(),
            None,
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("private_key"))
        );
    }

    #[test]
    fn explains_raw_newlines_inside_private_key_json() {
        let error = CredentialBundle::parse(
            r#"{
  "type": "github_app",
  "app_id": 42,
  "installation_id": "123",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----
abc
-----END RSA PRIVATE KEY-----"
}"#,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("escape PEM newlines"))
        );
    }

    #[test]
    fn validates_bundle_and_private_key() {
        validate_credential_bundle(
            &serde_json::json!({
                "type": "github_app",
                "app_id": 42,
                "installation_id": "123",
                "private_key": PRIVATE_KEY,
            })
            .to_string(),
            None,
        )
        .unwrap();
    }

    #[test]
    fn validates_split_metadata_and_private_key() {
        validate_credential_bundle(
            &serde_json::json!({
                "type": "github_app",
                "app_id": 42,
                "installation_id": "123",
            })
            .to_string(),
            Some(PRIVATE_KEY),
        )
        .unwrap();
    }

    #[test]
    fn creates_app_jwt() {
        let bundle = CredentialBundle {
            kind: "github_app".to_owned(),
            issuer: "42".to_owned(),
            installation_id: "123".to_owned(),
            private_key: PRIVATE_KEY.to_owned(),
        };

        let token = app_jwt(&bundle).unwrap();

        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn rejects_client_id_without_app_id() {
        let error = CredentialBundle::parse(
            &serde_json::json!({
                "type": "github_app",
                "client_id": "Iv1.client",
                "installation_id": "123",
                "private_key": PRIVATE_KEY,
            })
            .to_string(),
            None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::InvalidConfig(message)
                if message.contains("numeric `app_id`") && message.contains("client_id")
        ));
    }

    #[test]
    fn parses_github_token_expiry() {
        assert_eq!(parse_github_expires_at("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_github_expires_at("2026-05-02T12:34:56Z").unwrap(),
            1_777_725_296
        );
        assert_eq!(
            parse_github_expires_at("2026-05-02T12:34:56.789Z").unwrap(),
            1_777_725_296
        );
        assert_eq!(
            parse_github_expires_at("2026-05-02T08:34:56-04:00").unwrap(),
            1_777_725_296
        );
    }

    #[test]
    fn rejects_invalid_github_token_expiry() {
        assert!(parse_github_expires_at("2026-02-29T12:34:56Z").is_err());
        assert!(parse_github_expires_at("not-a-date").is_err());
    }

    #[test]
    fn returns_unexpired_cached_installation_token() {
        let cache_dir = temp_cache_dir("hit");
        let bundle = test_bundle();
        let key = cache_key("https://api.github.com", &bundle);
        let cache_path = token_cache_path(&cache_dir, &key);
        let now = unix_timestamp().unwrap();
        write_cached_token(
            &cache_path,
            &CachedInstallationToken {
                token: "cached-token".to_owned(),
                expires_at: now + 3_600,
            },
        )
        .unwrap();

        let client = Client::new();
        let mut redactor = Redactor::new();
        let token = installation_access_token_with_cache_dir(
            &client,
            "https://api.github.com",
            &bundle,
            &mut redactor,
            &cache_dir,
        )
        .unwrap();

        assert_eq!(token, "cached-token");
        assert_eq!(redactor.redact("cached-token"), "[REDACTED]");
        let _ = fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn exchanges_and_caches_expired_installation_token() {
        crate::tls::install_crypto_provider();

        let cache_dir = temp_cache_dir("refresh");
        let bundle = test_bundle();

        let response_body = serde_json::json!({
            "token": "fresh-token",
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string();
        let (api_base_url, server) = token_server(response_body);
        let key = cache_key(&api_base_url, &bundle);
        let cache_path = token_cache_path(&cache_dir, &key);
        write_cached_token(
            &cache_path,
            &CachedInstallationToken {
                token: "expired-token".to_owned(),
                expires_at: 0,
            },
        )
        .unwrap();

        let client = Client::new();
        let mut redactor = Redactor::new();
        let token = installation_access_token_with_cache_dir(
            &client,
            &api_base_url,
            &bundle,
            &mut redactor,
            &cache_dir,
        )
        .unwrap();
        let request = server.join().unwrap();

        assert_eq!(token, "fresh-token");
        assert!(request.starts_with("POST /app/installations/123/access_tokens "));
        assert_eq!(
            read_cached_token(&cache_path, unix_timestamp().unwrap()).as_deref(),
            Some("fresh-token")
        );
        let _ = fs::remove_dir_all(cache_dir);
    }

    fn test_bundle() -> CredentialBundle {
        CredentialBundle {
            kind: "github_app".to_owned(),
            issuer: "42".to_owned(),
            installation_id: "123".to_owned(),
            private_key: PRIVATE_KEY.to_owned(),
        }
    }

    fn temp_cache_dir(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!(
            "via-github-app-cache-test-{name}-{}-{}",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let _ = fs::remove_dir_all(&path);
        path
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
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });

        (format!("http://{address}"), handle)
    }
}
