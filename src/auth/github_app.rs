use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use serde_json::Value;

use crate::auth::jwt;
use crate::error::ViaError;
use crate::redaction::Redactor;
use crate::secrets::SecretValue;

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

    redactor.add(&bundle.private_key);
    let jwt = app_jwt(&bundle)?;
    redactor.add(&jwt);

    let url = format!(
        "{}/app/installations/{}/access_tokens",
        api_base_url.trim_end_matches('/'),
        bundle.installation_id
    );
    let response = client
        .post(url)
        .headers(token_exchange_headers(&jwt)?)
        .send()?;
    let status = response.status();
    let body = response.text()?;
    let body = redactor.redact(&body);

    if !status.is_success() {
        return Err(ViaError::InvalidArgument(format!(
            "GitHub App token exchange failed with status {status}: {body}"
        )));
    }

    let response: InstallationTokenResponse = serde_json::from_str(&body)?;
    redactor.add(&response.token);
    Ok(response.token)
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
}
