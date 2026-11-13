use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, LOCATION, USER_AGENT,
};
use reqwest::{Method, Url};

use crate::config::{AuthConfig, RestCommandConfig, SecretHeaderConfig, ServiceConfig};
use crate::error::ViaError;
use crate::executor::{ExecutionContext, InvocationTrace};
use crate::providers::SecretProvider;
use crate::redaction::Redactor;
use crate::rules::{self, RestRules};

const MAX_BROKER_BODY_BYTES: u64 = 8 * 1024 * 1024;
const BROKER_BODY_TIMEOUT: Duration = Duration::from_secs(30);

pub fn execute(
    context: &ExecutionContext,
    service_name: &str,
    service: &ServiceConfig,
    config: &RestCommandConfig,
    provider: &dyn SecretProvider,
    args: Vec<String>,
    trace: &mut InvocationTrace,
) -> Result<(), ViaError> {
    let request = prepare_request(context, config, args, trace)?;

    let client = http_client(context, config, &request)?;
    let target = RestTarget {
        service_name,
        service,
        config,
        provider,
    };
    let builder = authenticated_request(
        &target,
        &client,
        &request,
        &mut trace.redactor,
        OAuthTokenMode::Cached,
    )?;
    let mut response = send_rest_request(builder, &request.method, &request.path)?;
    if should_retry_with_fresh_oauth(config, response.status) {
        crate::timing::event("rest oauth retry", "status=401");
        let builder = authenticated_request(
            &target,
            &client,
            &request,
            &mut trace.redactor,
            OAuthTokenMode::Refresh,
        )?;
        response = send_rest_request(builder, &request.method, &request.path)?;
    }
    trace.status = Some(i64::from(response.status.as_u16()));

    if !response.status.is_success() {
        if let Some(error) = unfollowed_redirect_error(&response, &trace.redactor) {
            return Err(error);
        }
        let body = trace
            .redactor
            .redact(&String::from_utf8_lossy(&response.body));
        ensure_success(response.status, &response.headers, &body, &trace.redactor)?;
    }

    match &request.output {
        Some(OutputTarget::File(path)) => write_response_body(path, &response.body)?,
        Some(OutputTarget::Stdout) => {
            crate::output::write_stdout(&trace.redactor.redact_bytes(&response.body))?;
        }
        None => {
            let body = trace
                .redactor
                .redact(&String::from_utf8_lossy(&response.body));
            crate::output::write_stdout(format!("{body}\n").as_bytes())?;
        }
    }
    Ok(())
}

// Complete caller-input validation before credentials or network operations.
// Body I/O is deliberately last, after all target and option restrictions.
fn prepare_request(
    context: &ExecutionContext,
    config: &RestCommandConfig,
    args: Vec<String>,
    trace: &mut InvocationTrace,
) -> Result<RestInvocation, ViaError> {
    record_request_target(config, &args, trace);
    let mut request = RestInvocation::parse(context, config, args)?;
    if request.absolute_url {
        if let Err(error) = validate_asset_url(config, &request.path) {
            trace.denied = Some("asset_host_not_allowed");
            return Err(error);
        }
        if context.is_broker() {
            validate_broker_asset_origin(config, &request.path)?;
        }
    }
    enforce_rules(config, &request)?;
    // Validate the URL even without rules, before consuming caller input.
    build_url(config, &request.path, &request.query)?;
    request.body = request
        .body
        .as_deref()
        .map(|value| read_body_arg(context, value))
        .transpose()?;

    Ok(request)
}

struct RestTarget<'a> {
    service_name: &'a str,
    service: &'a ServiceConfig,
    config: &'a RestCommandConfig,
    provider: &'a dyn SecretProvider,
}

fn authenticated_request(
    target: &RestTarget<'_>,
    client: &Client,
    request: &RestInvocation,
    redactor: &mut Redactor,
    oauth_token_mode: OAuthTokenMode,
) -> Result<RequestBuilder, ViaError> {
    let mut context = RestRequestBuildContext {
        client,
        config: target.config,
        service_name: target.service_name,
        service: target.service,
        provider: target.provider,
        redactor,
        oauth_token_mode,
    };
    build_authenticated_request(&mut context, request)
}

// Records the method, host and path before any option is parsed, so that a
// refused request can still be attributed. The query string is left out.
fn record_request_target(config: &RestCommandConfig, args: &[String], trace: &mut InvocationTrace) {
    let Ok((method, target, _)) = request_target(config, args) else {
        return;
    };

    trace.method = Some(method.as_str().to_owned());
    trace.path = Some(target_path(target).to_owned());
    let url = if is_absolute_http_url(target) {
        Url::parse(target)
    } else {
        Url::parse(&config.base_url)
    };
    trace.host = url.ok().and_then(|url| url.host_str().map(str::to_owned));
}

struct RestResponse {
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct RestRequestBuildContext<'a> {
    client: &'a Client,
    config: &'a RestCommandConfig,
    service_name: &'a str,
    service: &'a ServiceConfig,
    provider: &'a dyn SecretProvider,
    redactor: &'a mut Redactor,
    oauth_token_mode: OAuthTokenMode,
}

fn build_authenticated_request(
    context: &mut RestRequestBuildContext<'_>,
    request: &RestInvocation,
) -> Result<RequestBuilder, ViaError> {
    let url = build_url(context.config, &request.path, &request.query)?;
    let builder = context.client.request(request.method.clone(), url);
    let mut headers = authenticated_headers(context)?;
    apply_body_content_type(&mut headers, request.body.as_deref());
    let builder = builder.headers(headers);
    Ok(with_body(builder, request.body.as_deref()))
}

fn authenticated_headers(context: &mut RestRequestBuildContext<'_>) -> Result<HeaderMap, ViaError> {
    let auth_span = crate::timing::span("rest auth headers");
    let headers = match build_headers_with_oauth_mode(
        Some(context.client),
        context.config,
        context.service_name,
        context.service,
        context.provider,
        context.redactor,
        context.oauth_token_mode,
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
    Ok(headers)
}

fn apply_body_content_type(headers: &mut HeaderMap, body: Option<&str>) {
    if body.is_some() && !headers.contains_key(CONTENT_TYPE) {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
}

fn with_body(builder: RequestBuilder, body: Option<&str>) -> RequestBuilder {
    match body {
        Some(body) => builder.body(body.to_owned()),
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

fn http_client(
    context: &ExecutionContext,
    config: &RestCommandConfig,
    request: &RestInvocation,
) -> Result<Client, ViaError> {
    // A redirect could lead to a host or path outside the capability
    // boundary, so it is never followed where that boundary is restricted
    // or the caller is untrusted.
    if request.absolute_url || config.has_rules() || context.is_broker() {
        return Ok(Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?);
    }

    Ok(Client::new())
}

// Reports where an unfollowed redirect pointed so the caller can decide
// whether to make a new request.
fn unfollowed_redirect_error(response: &RestResponse, redactor: &Redactor) -> Option<ViaError> {
    if !response.status.is_redirection() {
        return None;
    }
    let location = response.headers.get(LOCATION)?.to_str().ok()?;

    Some(ViaError::InvalidArgument(format!(
        "request was redirected with status {}; via did not follow the redirect to {}",
        response.status,
        redactor.redact(location)
    )))
}

fn enforce_rules(config: &RestCommandConfig, request: &RestInvocation) -> Result<(), ViaError> {
    let Some(rest_rules) = RestRules::from_config(config)
        .map_err(|problem| ViaError::InvalidConfig(format!("REST capability {problem}")))?
    else {
        return Ok(());
    };

    rules::check_raw_target(&request.path)
        .map_err(|problem| rules::refused("path_not_normalized", problem))?;
    let raw_path = target_path(&request.path);
    rest_rules.check(request.method.as_str(), raw_path)?;
    ensure_sent_path_is_checked_path(config, request, raw_path)
}

// The rules were evaluated against `raw_path`. Refuse the request unless the
// URL parser sends exactly that path to the expected host.
fn ensure_sent_path_is_checked_path(
    config: &RestCommandConfig,
    request: &RestInvocation,
    raw_path: &str,
) -> Result<(), ViaError> {
    let changed = || {
        rules::refused(
            "path_not_normalized",
            "the request URL does not preserve the checked path",
        )
    };
    let url = build_url(config, &request.path, &request.query)?;
    let sent = Url::parse(&url).map_err(|_| changed())?;
    let mut expected = Vec::new();
    if !request.absolute_url {
        let base = Url::parse(config.base_url.trim_end_matches('/')).map_err(|_| changed())?;
        if base.host_str() != sent.host_str() {
            return Err(changed());
        }
        expected.extend(rules::percent_decode_lenient(
            base.path().trim_end_matches('/'),
        ));
    }
    expected.extend(rules::percent_decode_lenient(raw_path));

    if rules::percent_decode_lenient(sent.path()) == expected {
        Ok(())
    } else {
        Err(changed())
    }
}

// The path component of a request target: no query string and no fragment.
fn target_path(target: &str) -> &str {
    let end = target.find(['?', '#']).unwrap_or(target.len());
    let target = &target[..end];
    if !is_absolute_http_url(target) {
        return target;
    }

    let authority_and_path = target.split_once("://").map_or(target, |(_, rest)| rest);
    match authority_and_path.find('/') {
        Some(index) => &authority_and_path[index..],
        None => "/",
    }
}

#[derive(Clone, Copy)]
enum OAuthTokenMode {
    Cached,
    Refresh,
}

fn should_retry_with_fresh_oauth(config: &RestCommandConfig, status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED
        && matches!(config.auth, Some(AuthConfig::OAuth { .. }))
}

fn read_response_body(response: reqwest::blocking::Response) -> Result<Vec<u8>, ViaError> {
    let body_span = crate::timing::span("rest response body");
    match response.bytes() {
        Ok(body) => {
            body_span.finish(format!("bytes={}", body.len()));
            Ok(body.to_vec())
        }
        Err(error) => {
            body_span.finish("failed");
            Err(error.into())
        }
    }
}

fn write_response_body(path: &Path, body: &[u8]) -> Result<(), ViaError> {
    let mut file = File::create(path)?;
    file.write_all(body)?;
    Ok(())
}

fn ensure_success(
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    body: &str,
    redactor: &Redactor,
) -> Result<(), ViaError> {
    if status.is_success() {
        return Ok(());
    }

    let request_id = headers
        .get("x-github-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let mut message = format!("request failed with status {status}; request id {request_id}");
    if let Some(body) = error_body_summary(body, redactor) {
        message.push_str("; response body: ");
        message.push_str(&body);
    }
    Err(ViaError::InvalidArgument(message))
}

// `body` is already redacted. Decoding a JSON string can still restore a
// secret that the service escaped, such as `\/` for `/`, so the decoded
// message is redacted again before any of it is printed.
fn error_body_summary(body: &str, redactor: &Redactor) -> Option<String> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
            return Some(truncate_error_body(&redactor.redact(message)));
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

#[derive(Debug)]
struct RestInvocation {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    body: Option<String>,
    output: Option<OutputTarget>,
    absolute_url: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum OutputTarget {
    Stdout,
    File(PathBuf),
}

impl RestInvocation {
    fn parse(
        context: &ExecutionContext,
        config: &RestCommandConfig,
        args: Vec<String>,
    ) -> Result<Self, ViaError> {
        let (method, path, consumed) = request_target(config, &args)?;
        let path = path.to_owned();
        let mut args = args.into_iter().skip(consumed);

        let mut query = Vec::new();
        let mut body = None;
        let mut output = None;

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
                "--json" | "--data" | "-d" => {
                    let value = args
                        .next()
                        .ok_or_else(|| ViaError::MissingArgument(format!("{arg} value")))?;
                    // Classify without reading: authorization precedes body I/O.
                    body_source(context, &value)?;
                    body = Some(value);
                }
                "--output" | "-o" => {
                    let value = args
                        .next()
                        .ok_or_else(|| ViaError::MissingArgument("--output path".to_owned()))?;
                    output = Some(output_target(context, value)?);
                }
                other => {
                    return Err(ViaError::InvalidArgument(format!(
                        "unknown rest argument `{other}`"
                    )));
                }
            }
        }

        let absolute_url = is_absolute_http_url(&path);
        if absolute_url && output.is_none() {
            return Err(ViaError::InvalidArgument(
                "absolute URL requests must use --output <path>, or --output - for standard output"
                    .to_owned(),
            ));
        }

        Ok(Self {
            method,
            path,
            query,
            body,
            output,
            absolute_url,
        })
    }
}

// The method and request target at the start of the arguments, and how many
// arguments they use.
fn request_target<'a>(
    config: &RestCommandConfig,
    args: &'a [String],
) -> Result<(Method, &'a str, usize), ViaError> {
    let first = args
        .first()
        .ok_or_else(|| ViaError::MissingArgument("path".to_owned()))?;
    if is_request_target(first) {
        return Ok((parse_method(&config.method_default)?, first.as_str(), 1));
    }

    let path = args
        .get(1)
        .ok_or_else(|| ViaError::MissingArgument("path".to_owned()))?;
    Ok((parse_method(first)?, path.as_str(), 2))
}

// `-` writes the raw response to standard output. A broker caller may not
// name a file on the broker host.
fn output_target(context: &ExecutionContext, value: String) -> Result<OutputTarget, ViaError> {
    if value == "-" {
        return Ok(OutputTarget::Stdout);
    }
    if context.is_broker() {
        return Err(ViaError::denied(
            "local_file_output",
            "broker mode refuses `--output <path>`; use `--output -` to write the response to standard output",
        ));
    }

    Ok(OutputTarget::File(PathBuf::from(value)))
}

fn is_request_target(value: &str) -> bool {
    value.starts_with('/') || is_absolute_http_url(value)
}

fn is_absolute_http_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

// Method names are case-sensitive on the wire, and rules and audit records
// use upper case. Send the same spelling that they describe.
fn parse_method(method: &str) -> Result<Method, ViaError> {
    method
        .to_ascii_uppercase()
        .parse()
        .map_err(|_| ViaError::InvalidArgument(format!("invalid HTTP method `{method}`")))
}

#[cfg(test)]
fn build_headers(
    client: Option<&reqwest::blocking::Client>,
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    redactor: &mut Redactor,
) -> Result<HeaderMap, ViaError> {
    build_headers_with_oauth_mode(
        client,
        config,
        service_name,
        service,
        provider,
        redactor,
        OAuthTokenMode::Cached,
    )
}

fn build_headers_with_oauth_mode(
    client: Option<&reqwest::blocking::Client>,
    config: &RestCommandConfig,
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn SecretProvider,
    redactor: &mut Redactor,
    oauth_token_mode: OAuthTokenMode,
) -> Result<HeaderMap, ViaError> {
    let mut headers = build_static_headers(config)?;
    let mut auth_context = AuthHeaderContext {
        client,
        config,
        service_name,
        service,
        provider,
        redactor,
        oauth_token_mode,
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
    oauth_token_mode: OAuthTokenMode,
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
    let token = match context.oauth_token_mode {
        OAuthTokenMode::Cached => crate::auth::oauth::access_token(&credential, context.redactor)?,
        OAuthTokenMode::Refresh => {
            crate::auth::oauth::refresh_access_token(&credential, context.redactor)?
        }
    };
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

fn build_url(
    config: &RestCommandConfig,
    path: &str,
    query: &[(String, String)],
) -> Result<String, ViaError> {
    if path.starts_with("http://") || path.starts_with("https://") {
        validate_asset_url(config, path)?;
        return Ok(append_query(path.to_owned(), query));
    }

    if !path.starts_with('/') {
        return Err(ViaError::InvalidArgument(
            "REST path must start with `/`".to_owned(),
        ));
    }

    Ok(append_query(
        format!("{}{}", config.base_url.trim_end_matches('/'), path),
        query,
    ))
}

fn validate_asset_url(config: &RestCommandConfig, url: &str) -> Result<(), ViaError> {
    let parsed = Url::parse(url).map_err(|error| {
        ViaError::InvalidArgument(format!("absolute REST URL is invalid: {error}"))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        ViaError::InvalidArgument("absolute REST URL must include a host".to_owned())
    })?;

    if config.asset_hosts.iter().any(|allowed| allowed == host) {
        return Ok(());
    }

    Err(ViaError::InvalidArgument(format!(
        "REST absolute URL host `{host}` is not in this capability's asset_hosts allowlist"
    )))
}

fn validate_broker_asset_origin(config: &RestCommandConfig, target: &str) -> Result<(), ViaError> {
    let url = Url::parse(target)
        .map_err(|_| ViaError::InvalidArgument("invalid absolute REST URL".to_owned()))?;
    let configured_origin =
        Url::parse(&config.base_url).is_ok_and(|base| base.origin() == url.origin());
    if url.scheme() != "https"
        || (url.port_or_known_default() != Some(443) && !configured_origin)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ViaError::denied(
            "asset_origin_not_allowed",
            "broker asset URLs require HTTPS without user information and port 443, or the exact HTTPS origin configured in base_url",
        ));
    }
    Ok(())
}

fn append_query(mut url: String, query: &[(String, String)]) -> String {
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

    url
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

#[derive(Debug, PartialEq, Eq)]
enum BodySource<'a> {
    Inline(&'a str),
    Stdin,
    File(&'a str),
}

// `@-` reads standard input and `@path` reads a local file. A broker caller
// may not read a file on the broker host.
fn body_source<'a>(context: &ExecutionContext, value: &'a str) -> Result<BodySource<'a>, ViaError> {
    if value == "@-" {
        return Ok(BodySource::Stdin);
    }
    let Some(path) = value.strip_prefix('@') else {
        return Ok(BodySource::Inline(value));
    };
    if context.is_broker() {
        return Err(ViaError::denied(
            "local_file_input",
            "broker mode refuses `@file` request bodies; pass the body inline or use `@-` to read standard input",
        ));
    }

    Ok(BodySource::File(path))
}

fn read_body_arg(context: &ExecutionContext, value: &str) -> Result<String, ViaError> {
    match body_source(context, value)? {
        BodySource::Inline(body) => Ok(body.to_owned()),
        BodySource::Stdin => {
            if context.is_broker() {
                return read_broker_body(io::stdin(), BROKER_BODY_TIMEOUT);
            }
            let mut body = String::new();
            io::stdin().read_to_string(&mut body)?;
            Ok(body)
        }
        BodySource::File(path) => Ok(std::fs::read_to_string(path)?),
    }
}

fn read_broker_body(
    reader: impl Read + Send + 'static,
    timeout: Duration,
) -> Result<String, ViaError> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    // A broker process handles one request. On timeout it exits, releasing
    // stdin and this bounded reader even if the caller never sends EOF.
    std::thread::Builder::new()
        .name("broker-body".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = reader
                .take(MAX_BROKER_BODY_BYTES + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = send.send(result);
        })?;
    let bytes = receive
        .recv_timeout(timeout)
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => ViaError::denied(
                "body_timeout",
                "broker request body was not received within 30 seconds",
            ),
            std::sync::mpsc::RecvTimeoutError::Disconnected => {
                ViaError::Io(io::Error::other("broker body reader stopped"))
            }
        })??;
    if bytes.len() as u64 > MAX_BROKER_BODY_BYTES {
        return Err(ViaError::denied(
            "body_too_large",
            "broker request bodies must not exceed 8 MiB",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| ViaError::InvalidArgument("request body is not valid UTF-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::thread;

    use crate::config::CommandConfig;
    use crate::secrets::SecretValue;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const JSON_BODY: &str = r#"{"query":"query { viewer { id } }"}"#;

    #[test]
    fn broker_assets_reject_downgrades_ports_and_user_information() {
        let config: RestCommandConfig = toml::from_str(
            "base_url = 'https://api.example.com:8443'\nasset_hosts = ['assets.example.com', 'api.example.com']",
        ).unwrap();
        for target in [
            "http://assets.example.com/file",
            "https://assets.example.com:8443/file",
            "https://assets.example.com:22/file",
            "https://user:pass@assets.example.com/file",
            "https://user@assets.example.com/file",
        ] {
            assert!(
                matches!(
                    validate_broker_asset_origin(&config, target),
                    Err(ViaError::Denied {
                        reason: "asset_origin_not_allowed",
                        ..
                    })
                ),
                "{target}"
            );
        }
        for target in [
            "https://assets.example.com/file",
            "https://assets.example.com:443/file",
            "https://api.example.com:8443/file",
        ] {
            validate_broker_asset_origin(&config, target).unwrap();
        }
    }

    #[test]
    fn broker_body_enforces_size_and_utf8() {
        let limit = MAX_BROKER_BODY_BYTES as usize;
        assert_eq!(
            read_broker_body(io::Cursor::new(vec![b'x'; limit]), Duration::from_secs(5))
                .unwrap()
                .len(),
            limit
        );
        assert!(matches!(
            read_broker_body(
                io::Cursor::new(vec![b'x'; limit + 1]),
                Duration::from_secs(5)
            ),
            Err(ViaError::Denied {
                reason: "body_too_large",
                ..
            })
        ));
        assert!(matches!(
            read_broker_body(io::Cursor::new(vec![0xff]), Duration::from_secs(5)),
            Err(ViaError::InvalidArgument(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn broker_body_deadline_does_not_wait_for_eof() {
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let result = read_broker_body(reader, Duration::from_millis(20));
        drop(writer);
        assert!(matches!(
            result,
            Err(ViaError::Denied {
                reason: "body_timeout",
                ..
            })
        ));
    }

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
        let invocation = RestInvocation::parse(
            &ExecutionContext::direct(),
            &rest_config(),
            vec!["/user".to_owned()],
        )
        .unwrap();

        assert_eq!(invocation.method, Method::GET);
        assert_eq!(invocation.path, "/user");
    }

    #[test]
    fn parses_explicit_method_query_and_body() {
        let invocation = RestInvocation::parse(
            &ExecutionContext::direct(),
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
        assert_eq!(invocation.output, None);
        assert!(!invocation.absolute_url);
    }

    #[test]
    fn parses_absolute_url_with_output() {
        let invocation = RestInvocation::parse(
            &ExecutionContext::direct(),
            &rest_config(),
            vec![
                "GET".to_owned(),
                "https://uploads.linear.app/workspace/object/file".to_owned(),
                "--output".to_owned(),
                "/tmp/hero.jpg".to_owned(),
            ],
        )
        .unwrap();

        assert_eq!(invocation.method, Method::GET);
        assert_eq!(
            invocation.path,
            "https://uploads.linear.app/workspace/object/file"
        );
        assert_eq!(
            invocation.output,
            Some(OutputTarget::File(PathBuf::from("/tmp/hero.jpg")))
        );
        assert!(invocation.absolute_url);
    }

    #[test]
    fn rejects_absolute_url_without_output() {
        let error = RestInvocation::parse(
            &ExecutionContext::direct(),
            &rest_config(),
            vec!["https://uploads.linear.app/workspace/object/file".to_owned()],
        )
        .unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidArgument(message) if message.contains("--output"))
        );
    }

    #[test]
    fn rejects_bad_query_pair() {
        let error = match RestInvocation::parse(
            &ExecutionContext::direct(),
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
    fn rejects_unallowlisted_absolute_urls() {
        let error = build_url(&rest_config(), "https://evil.test", &[]).unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidArgument(message) if message.contains("asset_hosts"))
        );
    }

    #[test]
    fn builds_allowlisted_absolute_url_with_percent_encoded_query() {
        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.linear.app"
asset_hosts = ["uploads.linear.app"]
"#,
        )
        .unwrap();

        let url = build_url(
            &config,
            "https://uploads.linear.app/workspace/object/file",
            &[("name".to_owned(), "hero image.jpg".to_owned())],
        )
        .unwrap();

        assert_eq!(
            url,
            "https://uploads.linear.app/workspace/object/file?name=hero%20image.jpg"
        );
    }

    #[test]
    fn builds_url_with_percent_encoded_query() {
        let url = build_url(
            &rest_config(),
            "/search/issues",
            &[("q".to_owned(), "repo:owner/name bug fix".to_owned())],
        )
        .unwrap();

        assert_eq!(
            url,
            "https://api.github.com/search/issues?q=repo%3Aowner%2Fname%20bug%20fix"
        );
    }

    fn execute_direct(
        service_name: &str,
        service: &ServiceConfig,
        config: &RestCommandConfig,
        provider: &dyn SecretProvider,
        args: Vec<String>,
    ) -> Result<(), ViaError> {
        execute(
            &ExecutionContext::direct(),
            service_name,
            service,
            config,
            provider,
            args,
            &mut InvocationTrace::default(),
        )
    }

    fn parse_in_broker(args: &[&str]) -> Result<RestInvocation, ViaError> {
        let config: RestCommandConfig = toml::from_str(
            "base_url = \"https://api.example.com\"\nasset_hosts = [\"assets.example.com\"]",
        )
        .unwrap();
        RestInvocation::parse(
            &ExecutionContext::broker(),
            &config,
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        )
    }

    fn broker_denial(args: &[&str]) -> &'static str {
        match parse_in_broker(args) {
            Err(ViaError::Denied { reason, .. }) => reason,
            Err(error) => panic!("expected a denial for {args:?}, got {error}"),
            Ok(_) => panic!("expected a denial for {args:?}"),
        }
    }

    #[test]
    fn broker_refuses_request_bodies_read_from_local_files() {
        for option in ["--json", "--data", "-d"] {
            assert_eq!(
                broker_denial(&["POST", "/items", option, "@/etc/hostname"]),
                "local_file_input",
                "option `{option}`"
            );
            assert_eq!(
                broker_denial(&["POST", "/items", option, "@relative.json"]),
                "local_file_input",
                "option `{option}`"
            );
        }

        let inline = parse_in_broker(&["POST", "/items", "--json", "{\"name\":\"x\"}"]).unwrap();
        assert_eq!(inline.body.as_deref(), Some("{\"name\":\"x\"}"));
    }

    #[test]
    fn body_sources_keep_standard_input_available_to_broker_callers() {
        let broker = ExecutionContext::broker();
        let direct = ExecutionContext::direct();

        assert_eq!(body_source(&broker, "@-").unwrap(), BodySource::Stdin);
        assert_eq!(body_source(&direct, "@-").unwrap(), BodySource::Stdin);
        assert_eq!(
            body_source(&broker, "{}").unwrap(),
            BodySource::Inline("{}")
        );
        assert_eq!(
            body_source(&direct, "@body.json").unwrap(),
            BodySource::File("body.json")
        );
        assert!(matches!(
            body_source(&broker, "@body.json"),
            Err(ViaError::Denied { reason, .. }) if reason == "local_file_input"
        ));
        assert!(matches!(
            body_source(&broker, "@"),
            Err(ViaError::Denied { reason, .. }) if reason == "local_file_input"
        ));
    }

    #[test]
    fn broker_refuses_output_paths_and_allows_standard_output() {
        for option in ["--output", "-o"] {
            assert_eq!(
                broker_denial(&["/items", option, "/tmp/via-broker-output"]),
                "local_file_output",
                "option `{option}`"
            );
            assert_eq!(
                broker_denial(&["/items", option, "relative-output"]),
                "local_file_output",
                "option `{option}`"
            );

            let stdout = parse_in_broker(&["/items", option, "-"]).unwrap();
            assert_eq!(stdout.output, Some(OutputTarget::Stdout));
        }

        let direct = RestInvocation::parse(
            &ExecutionContext::direct(),
            &rest_config(),
            vec!["/items".to_owned(), "--output".to_owned(), "-".to_owned()],
        )
        .unwrap();
        assert_eq!(direct.output, Some(OutputTarget::Stdout));
    }

    #[test]
    fn broker_asset_downloads_require_standard_output() {
        let asset = "https://assets.example.com/files/a.png";

        let stdout = parse_in_broker(&[asset, "--output", "-"]).unwrap();
        assert!(stdout.absolute_url);
        assert_eq!(stdout.output, Some(OutputTarget::Stdout));
        assert!(matches!(
            parse_in_broker(&[asset]),
            Err(ViaError::InvalidArgument(message)) if message.contains("--output")
        ));
        assert_eq!(
            broker_denial(&[asset, "--output", "/tmp/a.png"]),
            "local_file_output"
        );
    }

    #[test]
    fn records_the_request_target_without_the_query_for_refused_requests() {
        let config: RestCommandConfig =
            toml::from_str("base_url = \"https://api.example.com/v1\"").unwrap();
        let service = service_with_secrets([]);
        let mut trace = InvocationTrace::default();

        let error = execute(
            &ExecutionContext::broker(),
            "example",
            &service,
            &config,
            &FakeProvider::empty(),
            vec![
                "post".to_owned(),
                "/items/1?token=query-secret".to_owned(),
                "--json".to_owned(),
                "@/etc/hostname".to_owned(),
            ],
            &mut trace,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::Denied { reason, .. } if reason == "local_file_input"
        ));
        assert_eq!(trace.method.as_deref(), Some("POST"));
        assert_eq!(trace.host.as_deref(), Some("api.example.com"));
        assert_eq!(trace.path.as_deref(), Some("/items/1"));
        assert_eq!(trace.status, None);
        assert_eq!(trace.denied, None);
    }

    #[test]
    fn marks_unlisted_asset_hosts_as_denied_in_the_trace() {
        let config: RestCommandConfig = toml::from_str(
            "base_url = \"https://api.example.com\"\nasset_hosts = [\"assets.example.com\"]",
        )
        .unwrap();
        let service = service_with_secrets([]);
        let mut trace = InvocationTrace::default();

        let error = execute(
            &ExecutionContext::broker(),
            "example",
            &service,
            &config,
            &FakeProvider::empty(),
            vec![
                "https://evil.example/files/a.png?x=1".to_owned(),
                "--output".to_owned(),
                "-".to_owned(),
            ],
            &mut trace,
        )
        .unwrap_err();

        assert!(matches!(error, ViaError::InvalidArgument(_)));
        assert_eq!(trace.denied, Some("asset_host_not_allowed"));
        assert_eq!(trace.host.as_deref(), Some("evil.example"));
        assert_eq!(trace.path.as_deref(), Some("/files/a.png"));
    }

    #[test]
    fn records_status_and_secrets_in_the_trace() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = request_server(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found"
                .to_owned(),
        ]);
        let config: RestCommandConfig = toml::from_str(&format!(
            "base_url = \"{base_url}\"\n\n[auth]\ntype = \"bearer\"\nsecret = \"token\""
        ))
        .unwrap();
        let service = service_with_secrets([("token", "op://Private/API/token")]);
        let provider = FakeProvider::new([("op://Private/API/token", "bearer-token")]);
        let mut trace = InvocationTrace::default();

        let error = execute(
            &ExecutionContext::direct(),
            "example",
            &service,
            &config,
            &provider,
            vec![
                "/items/1".to_owned(),
                "--query".to_owned(),
                "a=b".to_owned(),
            ],
            &mut trace,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::InvalidArgument(message) if message.contains("404")
        ));
        assert_eq!(trace.method.as_deref(), Some("GET"));
        assert_eq!(trace.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(trace.path.as_deref(), Some("/items/1"));
        assert_eq!(trace.status, Some(404));
        assert_eq!(trace.redactor.redact("bearer-token"), "[REDACTED]");
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /items/1?a=b "));
    }

    #[test]
    fn broker_requests_do_not_follow_redirects() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = request_server(vec![
            "HTTP/1.1 301 Moved Permanently\r\nLocation: /items/2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
        ]);
        let config: RestCommandConfig =
            toml::from_str(&format!("base_url = \"{base_url}\"")).unwrap();
        let service = service_with_secrets([]);
        let mut trace = InvocationTrace::default();

        let error = execute(
            &ExecutionContext::broker(),
            "example",
            &service,
            &config,
            &FakeProvider::empty(),
            vec!["/items/1".to_owned()],
            &mut trace,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::InvalidArgument(message)
                if message.contains("did not follow the redirect to /items/2")
        ));
        assert_eq!(trace.status, Some(301));
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn writes_redacted_response_bytes_to_standard_output() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = request_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
        ]);
        let config: RestCommandConfig =
            toml::from_str(&format!("base_url = \"{base_url}\"")).unwrap();
        let service = service_with_secrets([]);
        let mut trace = InvocationTrace::default();

        execute(
            &ExecutionContext::broker(),
            "example",
            &service,
            &config,
            &FakeProvider::empty(),
            vec!["/items/1".to_owned(), "--output".to_owned(), "-".to_owned()],
            &mut trace,
        )
        .unwrap();

        assert_eq!(trace.status, Some(200));
        assert_eq!(server.join().unwrap().len(), 1);
    }

    fn rules_config(base_url: &str, rules: &str) -> RestCommandConfig {
        toml::from_str(&format!("base_url = \"{base_url}\"\n{rules}")).unwrap()
    }

    fn invocation(config: &RestCommandConfig, args: &[&str]) -> RestInvocation {
        RestInvocation::parse(
            &ExecutionContext::direct(),
            config,
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        )
        .unwrap()
    }

    fn rule_denial(config: &RestCommandConfig, args: &[&str]) -> &'static str {
        match enforce_rules(config, &invocation(config, args)) {
            Err(ViaError::Denied { reason, .. }) => reason,
            Err(error) => panic!("expected a denial for {args:?}, got {error}"),
            Ok(()) => panic!("expected a denial for {args:?}"),
        }
    }

    #[test]
    fn extracts_the_path_component_of_a_request_target() {
        assert_eq!(target_path("/user"), "/user");
        assert_eq!(target_path("/user?per_page=1"), "/user");
        assert_eq!(target_path("/user#fragment"), "/user");
        assert_eq!(target_path("/a/b?c=/d/../e"), "/a/b");
        assert_eq!(target_path("https://assets.example.com/a/b?c=d"), "/a/b");
        assert_eq!(target_path("https://assets.example.com"), "/");
        assert_eq!(target_path("https://assets.example.com?c=d"), "/");
        assert_eq!(target_path("https://user@assets.example.com:8443/a"), "/a");
    }

    #[test]
    fn requests_without_rules_are_not_normalized_or_restricted() {
        let config = rest_config();

        for args in [
            &["/user"][..],
            &["DELETE", "/repos/o/r"],
            &["/a/../b"],
            &["/a//b"],
            &["/a b"],
        ] {
            assert!(
                enforce_rules(&config, &invocation(&config, args)).is_ok(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn method_rules_refuse_other_methods() {
        let config = rules_config("https://api.example.com", "methods = [\"GET\", \"POST\"]");

        assert!(enforce_rules(&config, &invocation(&config, &["/user"])).is_ok());
        assert!(enforce_rules(&config, &invocation(&config, &["post", "/user"])).is_ok());
        // The request carries the method that the rules allowed, not the
        // caller's spelling of it.
        assert_eq!(invocation(&config, &["post", "/user"]).method, Method::POST);
        assert_eq!(invocation(&config, &["Get", "/user"]).method, Method::GET);
        assert_eq!(
            rule_denial(&config, &["DELETE", "/user"]),
            "method_not_allowed"
        );
        assert_eq!(
            rule_denial(&config, &["delete", "/user"]),
            "method_not_allowed"
        );
    }

    #[test]
    fn path_rules_apply_to_the_path_without_the_query() {
        let config = rules_config(
            "https://api.example.com/v1/",
            "allow_paths = [\"/repos/owner/**\"]\ndeny_paths = [\"/repos/*/*/secrets/**\"]",
        );

        for args in [
            &["/repos/owner/repo"][..],
            &["/repos/owner/repo?path=/repos/owner/repo/secrets"],
            &["/repos/owner/repo/", "--query", "ref=a/../b"],
            &["/repos/owner/repo/caf%C3%A9"],
            &["/repos/owner/repo/a%20b"],
        ] {
            assert!(
                enforce_rules(&config, &invocation(&config, args)).is_ok(),
                "{args:?}"
            );
        }

        assert_eq!(rule_denial(&config, &["/user"]), "path_not_allowed");
        assert_eq!(
            rule_denial(&config, &["/user?next=/repos/owner/repo"]),
            "path_not_allowed"
        );
        assert_eq!(
            rule_denial(&config, &["/repos/owner/repo/secrets/NAME"]),
            "path_denied"
        );
        assert_eq!(
            rule_denial(&config, &["/repos/owner/repo/%73ecrets"]),
            "path_denied"
        );
    }

    #[test]
    fn path_rules_refuse_bypass_attempts() {
        let config = rules_config(
            "https://api.example.com",
            "allow_paths = [\"/public/**\"]\ndeny_paths = [\"/admin/**\"]",
        );

        for target in [
            "/public/../admin",
            "/public/%2e%2e/admin",
            "/public/%2E%2E/admin",
            "/public/.%2e/admin",
            "/public/./admin",
            "/public//admin",
            "//admin",
            "/public/%2fadmin",
            "/public/..%2Fadmin",
            "/public\\admin",
            "/public/%5cadmin",
            "/public/\tadmin",
            "/public/a\nb",
            "/public/a b",
            "/public/a?b=c d",
            "/public/a?b=c\\d",
            "/public/%zz",
        ] {
            assert_eq!(
                rule_denial(&config, &[target]),
                "path_not_normalized",
                "target `{target}`"
            );
        }
    }

    #[test]
    fn rules_apply_to_absolute_asset_urls() {
        let config = rules_config(
            "https://api.example.com",
            "asset_hosts = [\"assets.example.com\"]\nmethods = [\"GET\"]\nallow_paths = [\"/files/**\"]",
        );
        let output = ["--output", "/tmp/via-rules-test-output"];
        let args = |target: &'static str, method: Option<&'static str>| {
            method
                .into_iter()
                .chain([target])
                .chain(output)
                .collect::<Vec<_>>()
        };

        assert!(enforce_rules(
            &config,
            &invocation(
                &config,
                &args("https://assets.example.com/files/a.png?size=2", None)
            )
        )
        .is_ok());
        assert_eq!(
            rule_denial(
                &config,
                &args("https://assets.example.com/private/a.png", None)
            ),
            "path_not_allowed"
        );
        assert_eq!(
            rule_denial(&config, &args("https://assets.example.com", None)),
            "path_not_allowed"
        );
        assert_eq!(
            rule_denial(
                &config,
                &args("https://assets.example.com/files/a.png", Some("DELETE"))
            ),
            "method_not_allowed"
        );
        for target in [
            "https://assets.example.com/files/../private/a.png",
            "https://assets.example.com/files/%2e%2e/private/a.png",
            "https://assets.example.com/files//a.png",
            "https://assets.example.com\\@evil.example/files/a.png",
        ] {
            assert_eq!(
                rule_denial(&config, &args(target, None)),
                "path_not_normalized",
                "target `{target}`"
            );
        }

        let unlisted = invocation(&config, &args("https://evil.example/files/a.png", None));
        assert!(matches!(
            enforce_rules(&config, &unlisted),
            Err(ViaError::InvalidArgument(message)) if message.contains("asset_hosts")
        ));
    }

    #[test]
    fn invalid_rule_patterns_are_a_config_error_at_execution() {
        let config = rules_config("https://api.example.com", "allow_paths = [\"user\"]");

        assert!(matches!(
            enforce_rules(&config, &invocation(&config, &["/user"])),
            Err(ViaError::InvalidConfig(message)) if message.contains("invalid path pattern")
        ));
    }

    #[test]
    fn capabilities_with_rules_do_not_follow_redirects() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = request_server(vec![
            "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/admin?token=bearer-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
        ]);
        let config = rules_config(
            &base_url,
            "allow_paths = [\"/public/**\"]\n\n[auth]\ntype = \"bearer\"\nsecret = \"token\"",
        );
        let service = service_with_secrets([("token", "op://Private/API/token")]);
        let provider = FakeProvider::new([("op://Private/API/token", "bearer-token")]);

        let error = execute_direct(
            "example",
            &service,
            &config,
            &provider,
            vec!["/public/moved".to_owned()],
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            ViaError::InvalidArgument(message)
                if message.contains("302")
                    && message.contains("did not follow the redirect")
                    && message.contains("https://elsewhere.example/admin?token=[REDACTED]")
        ));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /public/moved "));
    }

    #[test]
    fn rules_refuse_a_request_before_it_is_sent() {
        struct NeverResolveProvider;

        impl SecretProvider for NeverResolveProvider {
            fn resolve(&self, _reference: &str) -> Result<SecretValue, ViaError> {
                panic!("the provider must not run for a refused request")
            }
        }

        let config = rules_config(
            "http://127.0.0.1:9",
            "methods = [\"GET\"]\n\n[auth]\ntype = \"bearer\"\nsecret = \"token\"",
        );
        let service = service_with_secrets([("token", "op://Private/API/token")]);

        let error = execute_direct(
            "example",
            &service,
            &config,
            &NeverResolveProvider,
            vec!["DELETE".to_owned(), "/user".to_owned()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::Denied { reason, .. } if reason == "method_not_allowed"
        ));
    }

    #[test]
    fn success_status_accepts_response_body_without_error() {
        let headers = HeaderMap::new();

        assert!(ensure_success(
            reqwest::StatusCode::OK,
            &headers,
            "{\"ok\":true}",
            &Redactor::new()
        )
        .is_ok());
    }

    #[test]
    fn failure_status_includes_request_id_and_error_message() {
        let mut headers = HeaderMap::new();
        headers.insert("x-github-request-id", HeaderValue::from_static("ABC123"));

        let error = ensure_success(
            reqwest::StatusCode::GATEWAY_TIMEOUT,
            &headers,
            r#"{"message":"Endpoint request timed out","secret":"[REDACTED]"}"#,
            &Redactor::new(),
        )
        .unwrap_err();

        assert!(matches!(error, ViaError::InvalidArgument(message)
                if message.contains("504 Gateway Timeout")
                    && message.contains("ABC123")
                    && message.contains("Endpoint request timed out")
                    && !message.contains("secret")));
    }

    #[test]
    fn failure_status_redacts_a_secret_that_json_decoding_restores() {
        let mut redactor = Redactor::new();
        redactor.add("abc/def+ghi");
        // The service echoes the key with JSON escapes, so the raw body does
        // not contain the secret but the decoded message does.
        let raw = r#"{"message":"bad key abc\/def\u002Bghi"}"#;
        let body = redactor.redact(raw);
        assert_eq!(body, raw);

        let error = ensure_success(
            reqwest::StatusCode::UNAUTHORIZED,
            &HeaderMap::new(),
            &body,
            &redactor,
        )
        .unwrap_err();

        assert!(matches!(error, ViaError::InvalidArgument(message)
                if message.contains("response body: bad key [REDACTED]")
                    && !message.contains("abc/def")));
    }

    #[test]
    fn retries_oauth_requests_after_unauthorized_response() {
        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.linear.app"

[auth]
type = "oauth"
credential = "oauth"
"#,
        )
        .unwrap();
        let bearer_config = rest_config();

        assert!(should_retry_with_fresh_oauth(
            &config,
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!should_retry_with_fresh_oauth(
            &config,
            reqwest::StatusCode::FORBIDDEN
        ));
        assert!(!should_retry_with_fresh_oauth(
            &bearer_config,
            reqwest::StatusCode::UNAUTHORIZED
        ));
    }

    #[test]
    fn sends_json_body_with_default_content_type_header() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = single_request_server();
        let config: RestCommandConfig = toml::from_str(&format!(
            r#"
base_url = "{base_url}"
"#
        ))
        .unwrap();

        let raw_request = send_json_request(
            config,
            service_with_secrets([]),
            &FakeProvider::empty(),
            server,
        );

        assert_json_request_body(&raw_request);
        assert_single_header(
            &raw_request,
            "content-type:",
            Some("content-type: application/json"),
        );
    }

    #[test]
    fn sends_json_body_with_configured_content_type_without_duplicate() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = single_request_server();
        let config: RestCommandConfig = toml::from_str(&format!(
            r#"
base_url = "{base_url}"

[headers]
Content-Type = "application/json"
"#
        ))
        .unwrap();

        let raw_request = send_json_request(
            config,
            service_with_secrets([]),
            &FakeProvider::empty(),
            server,
        );

        assert_json_request_body(&raw_request);
        assert_single_header(
            &raw_request,
            "content-type:",
            Some("content-type: application/json"),
        );
    }

    #[test]
    fn sends_json_body_with_bearer_auth() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = single_request_server();
        let config: RestCommandConfig = toml::from_str(&format!(
            r#"
base_url = "{base_url}"

[auth]
type = "bearer"
secret = "token"

[headers]
Content-Type = "application/json"
"#
        ))
        .unwrap();
        let service = service_with_secrets([("token", "op://Private/API/token")]);
        let provider = FakeProvider::new([("op://Private/API/token", "bearer-token")]);

        let raw_request = send_json_request(config, service, &provider, server);

        assert_json_request_body(&raw_request);
        assert_single_header(
            &raw_request,
            "authorization:",
            Some("authorization: Bearer bearer-token"),
        );
        assert_single_header(
            &raw_request,
            "content-type:",
            Some("content-type: application/json"),
        );
    }

    #[test]
    fn writes_allowlisted_absolute_url_response_to_output_with_auth() {
        crate::tls::install_crypto_provider();

        let body = vec![0xff, 0xd8, 0xff, 0x00, 0x41, 0x42];
        let (asset_base_url, server) = binary_request_server(body.clone());
        let output = temp_path("linear-asset-output");
        let config: RestCommandConfig = toml::from_str(
            r#"
base_url = "https://api.linear.app"
asset_hosts = ["127.0.0.1"]

[auth]
type = "bearer"
secret = "token"
"#,
        )
        .unwrap();
        let service = service_with_secrets([("token", "op://Private/API/token")]);
        let provider = FakeProvider::new([("op://Private/API/token", "bearer-token")]);

        execute_direct(
            "linear",
            &service,
            &config,
            &provider,
            vec![
                "GET".to_owned(),
                format!("{asset_base_url}/workspace/object/file"),
                "--output".to_owned(),
                output.display().to_string(),
            ],
        )
        .unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), body);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /workspace/object/file "));
        assert_single_header(
            &requests[0],
            "authorization:",
            Some("authorization: Bearer bearer-token"),
        );

        let _ = std::fs::remove_file(output);
    }

    #[test]
    fn sends_json_body_with_secret_header_auth() {
        crate::tls::install_crypto_provider();

        let (base_url, server) = single_request_server();
        let config: RestCommandConfig = toml::from_str(&format!(
            r#"
base_url = "{base_url}"

[auth]
type = "headers"

[auth.headers.Authorization]
secret = "api_key"
prefix = "Token "

[headers]
Content-Type = "application/json"
"#
        ))
        .unwrap();
        let service = service_with_secrets([("api_key", "op://Private/API/key")]);
        let provider = FakeProvider::new([("op://Private/API/key", "api-key")]);

        let raw_request = send_json_request(config, service, &provider, server);

        assert_json_request_body(&raw_request);
        assert_single_header(
            &raw_request,
            "authorization:",
            Some("authorization: Token api-key"),
        );
        assert_single_header(
            &raw_request,
            "content-type:",
            Some("content-type: application/json"),
        );
    }

    #[test]
    fn sends_json_body_with_github_app_auth() {
        crate::tls::install_crypto_provider();

        let _env_lock = ENV_LOCK.lock().unwrap();
        let cache_dir = temp_path("github-app-json-cache");
        let _cache_env = EnvVarGuard::set("VIA_CACHE_DIR", cache_dir.as_os_str());
        let (base_url, server) = github_app_request_server();
        let config: RestCommandConfig = toml::from_str(&format!(
            r#"
base_url = "{base_url}"

[auth]
type = "github_app"
credential = "app"
private_key = "private_key"

[headers]
Content-Type = "application/json"
"#
        ))
        .unwrap();
        let service = service_with_secrets([
            ("app", "op://Private/GitHub/app"),
            ("private_key", "op://Private/GitHub/private_key"),
        ]);
        let github_app_metadata = serde_json::json!({
            "type": "github_app",
            "app_id": 42,
            "installation_id": 123,
        })
        .to_string();
        let provider = FakeProvider::new([
            ("op://Private/GitHub/app", github_app_metadata.as_str()),
            (
                "op://Private/GitHub/private_key",
                include_str!("../../tests/fixtures/rsa-private-key.pkcs1.pem"),
            ),
        ]);

        let requests = send_json_request_collecting_all(config, service, &provider, server);
        let api_request = requests.last().unwrap();

        assert!(requests[0].starts_with("POST /app/installations/123/access_tokens "));
        assert_json_request_body(api_request);
        assert_single_header(
            api_request,
            "authorization:",
            Some("authorization: Bearer github-app-token"),
        );
        assert_single_header(
            api_request,
            "content-type:",
            Some("content-type: application/json"),
        );
        let _ = std::fs::remove_dir_all(cache_dir);
    }

    #[test]
    fn json_content_type_merge_preserves_oauth_authorization_header() {
        let mut headers = HeaderMap::new();
        insert_bearer_header(&mut headers, "oauth-access-token", "invalid oauth token").unwrap();

        apply_body_content_type(&mut headers, Some(JSON_BODY));

        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "Bearer oauth-access-token"
        );
        assert_eq!(headers.get(CONTENT_TYPE).unwrap(), "application/json");
    }

    #[test]
    fn reads_file_body_arg() {
        let path = temp_path("json-body");
        std::fs::write(&path, JSON_BODY).unwrap();

        assert_eq!(
            read_body_arg(&ExecutionContext::direct(), &format!("@{}", path.display())).unwrap(),
            JSON_BODY
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reads_inline_body_arg() {
        assert_eq!(
            read_body_arg(&ExecutionContext::direct(), "{\"ok\":true}").unwrap(),
            "{\"ok\":true}"
        );
        assert_eq!(
            read_body_arg(&ExecutionContext::broker(), "{\"ok\":true}").unwrap(),
            "{\"ok\":true}"
        );
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
            hint: None,
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
            hint: None,
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
    fn oauth_auth_validates_credential_before_daemon_request() {
        struct FakeProvider;

        impl SecretProvider for FakeProvider {
            fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
                assert_eq!(reference, "op://Private/Linear/oauth");
                Ok(SecretValue::new(
                    serde_json::json!({
                        "type": "wrong_oauth",
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
            hint: None,
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
            matches!(error, ViaError::InvalidConfig(message) if message.contains("unsupported oauth credential type"))
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
            hint: None,
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

    struct FakeProvider {
        values: BTreeMap<String, String>,
    }

    impl FakeProvider {
        fn empty() -> Self {
            Self {
                values: BTreeMap::new(),
            }
        }

        fn new<K, V>(values: impl IntoIterator<Item = (K, V)>) -> Self
        where
            K: AsRef<str>,
            V: AsRef<str>,
        {
            Self {
                values: values
                    .into_iter()
                    .map(|(reference, value)| {
                        (reference.as_ref().to_owned(), value.as_ref().to_owned())
                    })
                    .collect(),
            }
        }
    }

    impl SecretProvider for FakeProvider {
        fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
            self.values
                .get(reference)
                .cloned()
                .map(SecretValue::new)
                .ok_or_else(|| {
                    ViaError::InvalidConfig(format!("unexpected secret resolve {reference}"))
                })
        }
    }

    struct EnvVarGuard {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: &std::ffi::OsStr) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    fn service_with_secrets(
        secrets: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> ServiceConfig {
        ServiceConfig {
            description: None,
            hint: None,
            provider: "onepassword".to_owned(),
            secrets: secrets
                .into_iter()
                .map(|(name, reference)| (name.to_owned(), reference.to_owned()))
                .collect(),
            commands: BTreeMap::<String, CommandConfig>::new(),
        }
    }

    fn json_invocation() -> RestInvocation {
        RestInvocation {
            method: Method::POST,
            path: "/graphql".to_owned(),
            query: Vec::new(),
            body: Some(JSON_BODY.to_owned()),
            output: None,
            absolute_url: false,
        }
    }

    fn send_json_request(
        config: RestCommandConfig,
        service: ServiceConfig,
        provider: &dyn SecretProvider,
        server: thread::JoinHandle<Vec<String>>,
    ) -> String {
        send_json_request_collecting_all(config, service, provider, server)
            .into_iter()
            .next()
            .unwrap()
    }

    fn send_json_request_collecting_all(
        config: RestCommandConfig,
        service: ServiceConfig,
        provider: &dyn SecretProvider,
        server: thread::JoinHandle<Vec<String>>,
    ) -> Vec<String> {
        let request = json_invocation();
        let client = Client::new();
        let mut redactor = Redactor::new();
        let mut context = RestRequestBuildContext {
            client: &client,
            config: &config,
            service_name: "linear",
            service: &service,
            provider,
            redactor: &mut redactor,
            oauth_token_mode: OAuthTokenMode::Cached,
        };

        let builder = build_authenticated_request(&mut context, &request).unwrap();
        let response = send_rest_request(builder, &request.method, &request.path).unwrap();
        assert!(response.status.is_success());

        server.join().unwrap()
    }

    fn single_request_server() -> (String, thread::JoinHandle<Vec<String>>) {
        request_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
        ])
    }

    fn github_app_request_server() -> (String, thread::JoinHandle<Vec<String>>) {
        let token_body = serde_json::json!({
            "token": "github-app-token",
            "expires_at": "2099-01-01T00:00:00Z",
        })
        .to_string();
        request_server(vec![
            format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                token_body.len(),
                token_body
            ),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned(),
        ])
    }

    fn request_server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });

        (format!("http://{address}"), handle)
    }

    fn binary_request_server(body: Vec<u8>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            stream.write_all(&response).unwrap();
            vec![request]
        });

        (format!("http://{address}"), handle)
    }

    fn assert_json_request_body(raw_request: &str) {
        assert!(raw_request.starts_with("POST /graphql "));
        assert!(raw_request.contains(JSON_BODY));
    }

    fn assert_single_header(raw_request: &str, prefix: &str, expected: Option<&str>) {
        let prefix = prefix.to_ascii_lowercase();
        let matching_headers = raw_request
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with(&prefix))
            .collect::<Vec<_>>();
        assert_eq!(matching_headers.len(), 1);
        if let Some(expected) = expected {
            assert_eq!(matching_headers[0], expected);
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "via-rest-{name}-{}-{}",
            std::process::id(),
            crate::auth::oauth::unix_timestamp().unwrap()
        ))
    }
}
