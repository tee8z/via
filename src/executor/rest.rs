use std::io::{self, Read};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;

use crate::config::{AuthConfig, RestCommandConfig, ServiceConfig};
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
    let client = reqwest::blocking::Client::new();
    let url = build_url(&config.base_url, &request.path, &request.query)?;
    let mut builder = client.request(request.method, url);

    let headers = build_headers(config, service_name, service, provider, &mut redactor)?;
    builder = builder.headers(headers);

    if let Some(body) = request.body {
        builder = builder.header(CONTENT_TYPE, "application/json").body(body);
    }

    let response = builder.send()?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text()?;
    let body = redactor.redact(&body);

    println!("{body}");

    if status.is_success() {
        return Ok(());
    }

    let request_id = headers
        .get("x-github-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    Err(ViaError::InvalidArgument(format!(
        "request failed with status {status}; request id {request_id}"
    )))
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
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    redactor: &mut Redactor,
) -> Result<HeaderMap, ViaError> {
    let mut headers = HeaderMap::new();
    for (name, value) in &config.headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ViaError::InvalidConfig(format!("invalid header name `{name}`")))?,
            HeaderValue::from_str(value)
                .map_err(|_| ViaError::InvalidConfig(format!("invalid header value `{name}`")))?,
        );
    }

    if let Some(AuthConfig::Bearer { secret }) = &config.auth {
        let reference = service
            .secrets
            .get(secret)
            .ok_or_else(|| ViaError::UnknownSecret {
                service: service_name.to_owned(),
                secret: secret.clone(),
            })?;
        let secret = provider.resolve(reference)?;
        redactor.add(secret.expose());
        let value = format!("Bearer {}", secret.expose());
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&value)
                .map_err(|_| ViaError::InvalidConfig("invalid bearer token".to_owned()))?,
        );
    }

    Ok(headers)
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
}
