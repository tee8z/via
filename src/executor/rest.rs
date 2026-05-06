use std::io::{self, Read};

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT,
};
use reqwest::Method;

use crate::config::{AuthConfig, RestCommandConfig, SecretHeaderConfig, ServiceConfig};
use crate::error::ViaError;
use crate::providers::SecretProvider;
use crate::redaction::Redactor;

pub fn execute(
    service_name: &str,
    service: &ServiceConfig,
    config: &RestCommandConfig,
    provider: &dyn SecretProvider,
    args: Vec<String>,
) -> Result<(), ViaError> {
    let request = RestInvocation::parse(config, args)?;
    let mut redactor = Redactor::new();
    let client = Client::new();
    let builder = build_authenticated_request(
        &client,
        config,
        service_name,
        service,
        provider,
        &request,
        &mut redactor,
    )?;
    let response = send_rest_request(builder, &request.method, &request.path)?;
    let body = redactor.redact(&response.body);

    ensure_success(response.status, &response.headers, &body)?;
    println!("{body}");
    Ok(())
}

struct RestResponse {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: String,
}

fn build_authenticated_request(
    client: &Client,
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    request: &RestInvocation,
    redactor: &mut Redactor,
) -> Result<RequestBuilder, ViaError> {
    let url = build_url(&config.base_url, &request.path, &request.query)?;
    let builder = client.request(request.method.clone(), url);
    let builder = with_auth_headers(
        builder,
        client,
        config,
        service_name,
        service,
        provider,
        redactor,
    )?;
    Ok(with_body(builder, request.body.as_deref()))
}

fn with_auth_headers(
    builder: RequestBuilder,
    client: &Client,
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    redactor: &mut Redactor,
) -> Result<RequestBuilder, ViaError> {
    let auth_span = crate::timing::span("rest auth headers");
    let headers = match build_headers(
        Some(client),
        config,
        service_name,
        service,
        provider,
        redactor,
    ) {
        Ok(headers) => {
            auth_span.finish("ok");
            headers
        }
        Err(error) => {
            auth_span.finish("failed");
            return Err(error);
        }
    };
    Ok(builder.headers(headers))
}

fn with_body(builder: RequestBuilder, body: Option<&str>) -> RequestBuilder {
    match body {
        Some(body) => builder
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_owned()),
        None => builder,
    }
}

fn send_rest_request(
    builder: RequestBuilder,
    method: &Method,
    path: &str,
) -> Result<RestResponse, ViaError> {
    let request_span = crate::timing::span(format!("rest request {method} {path}"));
    let response = match builder.send() {
        Ok(response) => {
            let status = response.status();
            request_span.finish(format!("status={status}"));
            response
        }
        Err(error) => {
            request_span.finish("failed");
            return Err(error.into());
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = read_response_body(response)?;

    Ok(RestResponse {
        status,
        headers,
        body,
    })
}

fn read_response_body(response: reqwest::blocking::Response) -> Result<String, ViaError> {
    let body_span = crate::timing::span("rest response body");
    match response.text() {
        Ok(body) => {
            body_span.finish(format!("bytes={}", body.len()));
            Ok(body)
        }
        Err(error) => {
            body_span.finish("failed");
            Err(error.into())
        }
    }
}

fn ensure_success(
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    body: &str,
) -> Result<(), ViaError> {
    if status.is_success() {
        return Ok(());
    }

    let request_id = headers
        .get("x-github-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let mut message = format!("request failed with status {status}; request id {request_id}");
    if let Some(body) = error_body_summary(body) {
        message.push_str("; response body: ");
        message.push_str(&body);
    }
    Err(ViaError::InvalidArgument(message))
}

fn error_body_summary(body: &str) -> Option<String> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
            return Some(truncate_error_body(message));
        }
    }

    Some(truncate_error_body(body))
}

fn truncate_error_body(body: &str) -> String {
    const MAX_CHARS: usize = 500;
    let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = normalized.chars();
    let truncated = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

struct RestInvocation {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    body: Option<String>,
}

impl RestInvocation {
    fn parse(config: &RestCommandConfig, args: Vec<String>) -> Result<Self, ViaError> {
        let mut args = args.into_iter().peekable();
        let first = args
            .next()
            .ok_or_else(|| ViaError::MissingArgument("path".to_owned()))?;

        let (method, path) = if first.starts_with('/') {
            (parse_method(&config.method_default)?, first)
        } else {
            let path = args
                .next()
                .ok_or_else(|| ViaError::MissingArgument("path".to_owned()))?;
            (parse_method(&first)?, path)
        };

        let mut query = Vec::new();
        let mut body = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--query" | "-q" => {
                    let pair = args
                        .next()
                        .ok_or_else(|| ViaError::MissingArgument("--query value".to_owned()))?;
                    let (name, value) = pair.split_once('=').ok_or_else(|| {
                        ViaError::InvalidArgument("--query expects key=value".to_owned())
                    })?;
                    query.push((name.to_owned(), value.to_owned()));
                }
                "--json" => {
                    let value = args
                        .next()
                        .ok_or_else(|| ViaError::MissingArgument("--json value".to_owned()))?;
                    body = Some(read_body_arg(&value)?);
                }
                "--data" | "-d" => {
                    let value = args
                        .next()
                        .ok_or_else(|| ViaError::MissingArgument("--data value".to_owned()))?;
                    body = Some(read_body_arg(&value)?);
                }
                other => {
                    return Err(ViaError::InvalidArgument(format!(
                        "unknown rest argument `{other}`"
                    )));
                }
            }
        }

        Ok(Self {
            method,
            path,
            query,
            body,
        })
    }
}

fn parse_method(method: &str) -> Result<Method, ViaError> {
    method
        .parse()
        .map_err(|_| ViaError::InvalidArgument(format!("invalid HTTP method `{method}`")))
}

fn build_headers(
    client: Option<&reqwest::blocking::Client>,
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    redactor: &mut Redactor,
) -> Result<HeaderMap, ViaError> {
    let mut headers = build_static_headers(config)?;
    let mut auth_context = AuthHeaderContext {
        client,
        config,
        service_name,
        service,
        provider,
        redactor,
    };
    apply_auth_headers(&mut headers, &mut auth_context)?;
    Ok(headers)
}

struct AuthHeaderContext<'a> {
    client: Option<&'a reqwest::blocking::Client>,
    config: &'a RestCommandConfig,
    service_name: &'a str,
    service: &'a ServiceConfig,
    provider: &'a dyn SecretProvider,
    redactor: &'a mut Redactor,
}

fn build_static_headers(config: &RestCommandConfig) -> Result<HeaderMap, ViaError> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("via-cli"));
    for (name, value) in &config.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ViaError::InvalidConfig(format!("invalid header name `{name}`")))?,
            HeaderValue::from_str(value)
                .map_err(|_| ViaError::InvalidConfig(format!("invalid header value `{name}`")))?,
        );
    }

    Ok(headers)
}

fn apply_auth_headers(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
) -> Result<(), ViaError> {
    match &context.config.auth {
        Some(AuthConfig::Bearer { secret }) => {
            apply_bearer_auth(headers, context, secret)?;
        }
        Some(AuthConfig::Headers {
            headers: secret_headers,
        }) => {
            apply_secret_headers(headers, context, secret_headers)?;
        }
        Some(auth @ AuthConfig::GitHubApp { .. }) => {
            apply_github_app_auth(headers, context, auth)?;
        }
        Some(AuthConfig::OAuth { credential }) => {
            apply_oauth_auth(headers, context, credential)?;
        }
        None => {}
    }

    Ok(())
}

fn apply_bearer_auth(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
    secret: &str,
) -> Result<(), ViaError> {
    let secret = resolve_service_secret(
        context.service_name,
        context.service,
        context.provider,
        secret,
    )?;
    context.redactor.add(secret.expose());
    insert_bearer_header(headers, secret.expose(), "invalid bearer token")
}

fn apply_secret_headers(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
    secret_headers: &std::collections::BTreeMap<String, SecretHeaderConfig>,
) -> Result<(), ViaError> {
    for (name, secret_header) in secret_headers {
        apply_secret_header(headers, context, name, secret_header)?;
    }
    Ok(())
}

fn apply_secret_header(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
    name: &str,
    secret_header: &SecretHeaderConfig,
) -> Result<(), ViaError> {
    let secret = resolve_service_secret(
        context.service_name,
        context.service,
        context.provider,
        &secret_header.secret,
    )?;
    context.redactor.add(secret.expose());
    let value = format!(
        "{}{}{}",
        secret_header.prefix,
        secret.expose(),
        secret_header.suffix
    );
    headers.insert(
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ViaError::InvalidConfig(format!("invalid header name `{name}`")))?,
        HeaderValue::from_str(&value).map_err(|_| {
            ViaError::InvalidConfig(format!("invalid secret header value `{name}`"))
        })?,
    );
    Ok(())
}

fn apply_github_app_auth(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
    auth: &AuthConfig,
) -> Result<(), ViaError> {
    let (credential, private_key) = resolve_github_app_secrets(
        context.service_name,
        context.service,
        context.provider,
        auth,
    )?;
    let client = context.client.ok_or_else(|| {
        ViaError::InvalidConfig("github_app auth requires an HTTP client".to_owned())
    })?;
    let token = crate::auth::github_app::installation_access_token(
        client,
        &context.config.base_url,
        &credential,
        private_key.as_ref(),
        context.redactor,
    )?;
    insert_bearer_header(headers, &token, "invalid GitHub App installation token")
}

fn apply_oauth_auth(
    headers: &mut HeaderMap,
    context: &mut AuthHeaderContext<'_>,
    credential: &str,
) -> Result<(), ViaError> {
    let credential = resolve_service_secret(
        context.service_name,
        context.service,
        context.provider,
        credential,
    )?;
    let client = context
        .client
        .ok_or_else(|| ViaError::InvalidConfig("oauth auth requires an HTTP client".to_owned()))?;
    let token = crate::auth::oauth::access_token(client, &credential, context.redactor)?;
    insert_bearer_header(headers, &token, "invalid OAuth access token")
}

fn resolve_github_app_secrets(
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    auth: &AuthConfig,
) -> Result<
    (
        crate::secrets::SecretValue,
        Option<crate::secrets::SecretValue>,
    ),
    ViaError,
> {
    let AuthConfig::GitHubApp {
        secret,
        credential,
        private_key,
    } = auth
    else {
        unreachable!("caller only passes github_app auth");
    };

    match (secret, credential, private_key) {
        (Some(secret), None, None) => {
            let credential = resolve_service_secret(service_name, service, provider, secret)?;
            Ok((credential, None))
        }
        (None, Some(credential), Some(private_key)) => {
            let credential = resolve_service_secret(service_name, service, provider, credential)?;
            let private_key = resolve_service_secret(service_name, service, provider, private_key)?;
            Ok((credential, Some(private_key)))
        }
        _ => Err(ViaError::InvalidConfig(
            "github_app auth must set either `secret` or both `credential` and `private_key`"
                .to_owned(),
        )),
    }
}

fn resolve_service_secret(
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    secret: &str,
) -> Result<crate::secrets::SecretValue, ViaError> {
    let reference = service
        .secrets
        .get(secret)
        .ok_or_else(|| ViaError::UnknownSecret {
            service: service_name.to_owned(),
            secret: secret.to_owned(),
        })?;
    let span = crate::timing::span(format!("secret resolve {service_name}.{secret}"));
    match provider.resolve(reference) {
        Ok(value) => {
            span.finish("ok");
            Ok(value)
        }
        Err(error) => {
            span.finish("failed");
            Err(error)
        }
    }
}

fn insert_bearer_header(headers: &mut HeaderMap, token: &str, error: &str) -> Result<(), ViaError> {
    let value = format!("Bearer {token}");
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&value).map_err(|_| ViaError::InvalidConfig(error.to_owned()))?,
    );
    Ok(())
}

fn build_url(base_url: &str, path: &str, query: &[(String, String)]) -> Result<String, ViaError> {
    if path.starts_with("http://") || path.starts_with("https://") {
        return Err(ViaError::InvalidArgument(
            "REST capabilities only accept paths; absolute URLs are not allowed".to_owned(),
        ));
    }

    if !path.starts_with('/') {
        return Err(ViaError::InvalidArgument(
            "REST path must start with `/`".to_owned(),
        ));
    }

    let mut url = format!("{}{}", base_url.trim_end_matches('/'), path);
    if !query.is_empty() {
        let separator = if url.contains('?') { '&' } else { '?' };
        url.push(separator);
        for (index, (name, value)) in query.iter().enumerate() {
            if index > 0 {
                url.push('&');
            }
            url.push_str(&percent_encode(name));
            url.push('=');
            url.push_str(&percent_encode(value));
        }
    }

    Ok(url)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }

    encoded
}

fn read_body_arg(value: &str) -> Result<String, ViaError> {
    if value == "@-" {
        let mut body = String::new();
        io::stdin().read_to_string(&mut body)?;
        return Ok(body);
    }

    if let Some(path) = value.strip_prefix('@') {
        return Ok(std::fs::read_to_string(path)?);
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rest_config() -> RestCommandConfig {
        toml::from_str(
            r#"
description = "REST access"
base_url = "https://api.github.com"
method_default = "GET"

[auth]
type = "bearer"
secret = "token"

[headers]
Accept = "application/vnd.github+json"
"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_default_method_and_path() {
        let invocation = RestInvocation::parse(&rest_config(), vec!["/user".to_owned()]).unwrap();

        assert_eq!(invocation.method, Method::GET);
        assert_eq!(invocation.path, "/user");
    }

    #[test]
    fn parses_explicit_method_query_and_body() {
        let invocation = RestInvocation::parse(
            &rest_config(),
            vec![
                "POST".to_owned(),
                "/repos/o/r/pulls".to_owned(),
                "--query".to_owned(),
                "state=open".to_owned(),
                "--json".to_owned(),
                "{\"title\":\"x\"}".to_owned(),
            ],
        )
        .unwrap();

        assert_eq!(invocation.method, Method::POST);
        assert_eq!(invocation.path, "/repos/o/r/pulls");
        assert_eq!(invocation.query, [("state".to_owned(), "open".to_owned())]);
        assert_eq!(invocation.body.as_deref(), Some("{\"title\":\"x\"}"));
    }

    #[test]
    fn rejects_bad_query_pair() {
        let error = match RestInvocation::parse(
            &rest_config(),
            vec!["/user".to_owned(), "--query".to_owned(), "state".to_owned()],
        ) {
            Ok(_) => panic!("expected bad query error"),
            Err(error) => error,
        };

        assert!(
            matches!(error, ViaError::InvalidArgument(message) if message.contains("key=value"))
        );
    }

    #[test]
    fn rejects_absolute_urls() {
        let error = build_url("https://api.github.com", "https://evil.test", &[]).unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidArgument(message) if message.contains("absolute URLs"))
        );
    }

    #[test]
    fn builds_url_with_percent_encoded_query() {
        let url = build_url(
            "https://api.github.com/",
            "/search/issues",
            &[("q".to_owned(), "repo:owner/name bug fix".to_owned())],
        )
        .unwrap();

        assert_eq!(
            url,
            "https://api.github.com/search/issues?q=repo%3Aowner%2Fname%20bug%20fix"
        );
    }

    #[test]
    fn success_status_accepts_response_body_without_error() {
        let headers = HeaderMap::new();

        assert!(ensure_success(reqwest::StatusCode::OK, &headers, "{\"ok\":true}").is_ok());
    }

    #[test]
    fn failure_status_includes_request_id_and_error_message() {
        let mut headers = HeaderMap::new();
        headers.insert("x-github-request-id", HeaderValue::from_static("ABC123"));

        let error = ensure_success(
            reqwest::StatusCode::GATEWAY_TIMEOUT,
            &headers,
            r#"{"message":"Endpoint request timed out","secret":"[REDACTED]"}"#,
        )
        .unwrap_err();

        assert!(matches!(error, ViaError::InvalidArgument(message)
                if message.contains("504 Gateway Timeout")
                    && message.contains("ABC123")
                    && message.contains("Endpoint request timed out")
                    && !message.contains("secret")));
    }

    #[test]
    fn reads_inline_body_arg() {
        assert_eq!(read_body_arg("{\"ok\":true}").unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn builds_auth_headers_and_registers_secret_for_redaction() {
        struct FakeProvider;

        impl SecretProvider for FakeProvider {
            fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
                assert_eq!(reference, "op://Private/GitHub/token");
                Ok(SecretValue::new("secret-token".to_owned()))
            }
        }

        use std::collections::BTreeMap;

        use crate::config::CommandConfig;
        use crate::secrets::SecretValue;

        let service = ServiceConfig {
            description: None,
            provider: "onepassword".to_owned(),
            secrets: BTreeMap::from([("token".to_owned(), "op://Private/GitHub/token".to_owned())]),
            commands: BTreeMap::<String, CommandConfig>::new(),
        };
        let mut redactor = Redactor::new();
        let headers = build_headers(
            None,
            &rest_config(),
            "github",
            &service,
            &FakeProvider,
            &mut redactor,
        )
        .unwrap();

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer secret-token");
        assert_eq!(redactor.redact("secret-token"), "[REDACTED]");
    }

    #[test]
    fn builds_multiple_secret_headers_and_registers_redaction() {
        struct FakeProvider;

        impl SecretProvider for FakeProvider {
            fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
                match reference {
                    "op://Private/API/key" => Ok(SecretValue::new("api-key".to_owned())),
                    "op://Private/API/tenant" => Ok(SecretValue::new("tenant-id".to_owned())),
                    other => panic!("unexpected secret reference {other}"),
                }
            }
        }

        use std::collections::BTreeMap;

        use crate::config::CommandConfig;
        use crate::secrets::SecretValue;

        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.example.com"

[auth]
type = "headers"

[auth.headers.Authorization]
secret = "api_key"
prefix = "Token "

[auth.headers.X-Tenant]
secret = "tenant"
"#,
        )
        .unwrap();
        let service = ServiceConfig {
            description: None,
            provider: "onepassword".to_owned(),
            secrets: BTreeMap::from([
                ("api_key".to_owned(), "op://Private/API/key".to_owned()),
                ("tenant".to_owned(), "op://Private/API/tenant".to_owned()),
            ]),
            commands: BTreeMap::<String, CommandConfig>::new(),
        };
        let mut redactor = Redactor::new();
        let headers =
            build_headers(None, &config, "api", &service, &FakeProvider, &mut redactor).unwrap();

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Token api-key");
        assert_eq!(headers.get("X-Tenant").unwrap(), "tenant-id");
        assert_eq!(
            redactor.redact("api-key tenant-id"),
            "[REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn oauth_auth_requires_http_client() {
        struct FakeProvider;

        impl SecretProvider for FakeProvider {
            fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
                assert_eq!(reference, "op://Private/Linear/oauth");
                Ok(SecretValue::new(
                    serde_json::json!({
                        "type": "service_oauth",
                        "token_url": "https://api.linear.app/oauth/token",
                        "grant_type": "refresh_token",
                        "client_id": "client-id",
                        "refresh_token": "refresh-token",
                    })
                    .to_string(),
                ))
            }
        }

        use std::collections::BTreeMap;

        use crate::config::CommandConfig;
        use crate::secrets::SecretValue;

        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.linear.app"

[auth]
type = "oauth"
credential = "oauth"
"#,
        )
        .unwrap();
        let service = ServiceConfig {
            description: None,
            provider: "onepassword".to_owned(),
            secrets: BTreeMap::from([("oauth".to_owned(), "op://Private/Linear/oauth".to_owned())]),
            commands: BTreeMap::<String, CommandConfig>::new(),
        };
        let mut redactor = Redactor::new();
        let error = build_headers(
            None,
            &config,
            "linear",
            &service,
            &FakeProvider,
            &mut redactor,
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("HTTP client"))
        );
    }

    #[test]
    fn github_app_auth_requires_http_client() {
        struct FakeProvider;

        impl SecretProvider for FakeProvider {
            fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
                match reference {
                    "op://Private/GitHub/app" => Ok(SecretValue::new(
                        serde_json::json!({
                            "type": "github_app",
                            "app_id": 42,
                            "installation_id": 123,
                        })
                        .to_string(),
                    )),
                    "op://Private/GitHub/private_key" => {
                        Ok(SecretValue::new("private-key".to_owned()))
                    }
                    other => panic!("unexpected secret reference {other}"),
                }
            }
        }

        use std::collections::BTreeMap;

        use crate::config::CommandConfig;
        use crate::secrets::SecretValue;

        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.github.com"

[auth]
type = "github_app"
credential = "app"
private_key = "private_key"
"#,
        )
        .unwrap();
        let service = ServiceConfig {
            description: None,
            provider: "onepassword".to_owned(),
            secrets: BTreeMap::from([
                ("app".to_owned(), "op://Private/GitHub/app".to_owned()),
                (
                    "private_key".to_owned(),
                    "op://Private/GitHub/private_key".to_owned(),
                ),
            ]),
            commands: BTreeMap::<String, CommandConfig>::new(),
        };
        let mut redactor = Redactor::new();
        let error = build_headers(
            None,
            &config,
            "github",
            &service,
            &FakeProvider,
            &mut redactor,
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("HTTP client"))
        );
    }
}
