use std::collections::BTreeMap;
use std::process::Command;

use crate::config::{
    AuthConfig, CommandConfig, Config, OnePasswordCacheMode, ProviderConfig, RestCommandConfig,
    ServiceConfig,
};
use crate::error::ViaError;
use crate::providers::ProviderRegistry;

pub fn run(config: &Config, only_service: Option<&str>) -> Result<(), ViaError> {
    validate_requested_service(config, only_service)?;

    let mut status = DoctorStatus::default();
    let provider_ready = check_providers(config, &mut status);
    let providers = ProviderRegistry::from_config(config)?;

    for (service_name, service) in &config.services {
        if should_check_service(service_name, only_service) {
            check_service(
                service_name,
                service,
                &provider_ready,
                &providers,
                &mut status,
            )?;
        }
    }

    status.into_result()
}

fn validate_requested_service(config: &Config, only_service: Option<&str>) -> Result<(), ViaError> {
    if let Some(service_name) = only_service {
        if !config.services.contains_key(service_name) {
            return Err(ViaError::UnknownService(service_name.to_owned()));
        }
    }

    Ok(())
}

fn should_check_service(service_name: &str, only_service: Option<&str>) -> bool {
    only_service.is_none_or(|only| only == service_name)
}

fn check_service(
    service_name: &str,
    service: &ServiceConfig,
    provider_ready: &BTreeMap<String, bool>,
    providers: &ProviderRegistry,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    println!("service {service_name}: checking");
    let service_provider_ready = provider_ready
        .get(&service.provider)
        .copied()
        .unwrap_or(false);

    check_service_secrets(
        service_name,
        service,
        service_provider_ready,
        providers,
        status,
    )?;
    check_service_commands(
        service_name,
        service,
        service_provider_ready,
        providers,
        status,
    )
}

fn check_service_secrets(
    service_name: &str,
    service: &ServiceConfig,
    service_provider_ready: bool,
    providers: &ProviderRegistry,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    if service.secrets.is_empty() {
        println!("  secrets: none configured");
        return Ok(());
    }

    if !service_provider_ready {
        status.fail();
        println!(
            "  secrets: skipped because provider `{}` is not ready",
            service.provider
        );
        print_agent_guidance(
            "Ask the user to complete secret provider setup, then rerun `via config doctor`.",
        );
        return Ok(());
    }

    let provider = providers.get(&service.provider)?;
    for (secret_name, reference) in &service.secrets {
        match provider.resolve(reference) {
            Ok(_) => println!("  secret {secret_name}: readable by via"),
            Err(error) => {
                status.fail();
                print_secret_failure(service_name, secret_name, &error);
            }
        }
    }

    Ok(())
}

fn check_service_commands(
    service_name: &str,
    service: &ServiceConfig,
    service_provider_ready: bool,
    providers: &ProviderRegistry,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    for (command_name, command) in &service.commands {
        check_service_command(
            service_name,
            command_name,
            service,
            command,
            service_provider_ready,
            providers,
            status,
        )?;
    }

    Ok(())
}

fn check_service_command(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    command: &CommandConfig,
    service_provider_ready: bool,
    providers: &ProviderRegistry,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    match command {
        CommandConfig::Rest(rest) => {
            println!("  capability {command_name}: rest");
            if service_provider_ready {
                check_rest_auth(service_name, command_name, service, rest, providers, status)?;
            }
        }
        CommandConfig::Delegated(delegated) => {
            check_delegated_command(command_name, &delegated.program, &delegated.check, status);
        }
    }

    Ok(())
}

fn check_delegated_command(
    command_name: &str,
    program: &str,
    check: &[String],
    status: &mut DoctorStatus,
) {
    match check_program(program, check) {
        Ok(()) => println!("  capability {command_name}: delegated {program}"),
        Err(error) => {
            status.fail();
            print_delegated_failure(command_name, program, &error);
        }
    }
}

fn check_rest_auth(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    rest: &RestCommandConfig,
    providers: &ProviderRegistry,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    let Some(auth) = &rest.auth else {
        return Ok(());
    };

    let provider = providers.get(&service.provider)?;
    check_rest_auth_config(service_name, command_name, service, provider, auth, status)
}

fn check_rest_auth_config(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    provider: &dyn crate::providers::SecretProvider,
    auth: &AuthConfig,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    match auth {
        AuthConfig::GitHubApp { .. } => {
            check_github_app_auth(service_name, command_name, service, provider, auth, status)
        }
        AuthConfig::OAuth { credential } => check_oauth_auth(
            service_name,
            command_name,
            service,
            provider,
            credential,
            status,
        ),
        AuthConfig::Bearer { .. } | AuthConfig::Headers { .. } => Ok(()),
    }
}

fn check_github_app_auth(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    provider: &dyn crate::providers::SecretProvider,
    auth: &AuthConfig,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    match resolve_github_app_doctor_secrets(service_name, service, provider, auth).and_then(
        |(credential, private_key)| {
            crate::auth::github_app::validate_credential_bundle(
                credential.expose(),
                private_key.as_deref(),
            )
        },
    ) {
        Ok(()) => println!("  auth {command_name}: GitHub App credential bundle valid"),
        Err(error) => {
            status.fail();
            println!("  auth {command_name}: GitHub App credential bundle invalid");
            println!("  reason: {error}");
            print_human_setup(&[
                "Edit the configured 1Password metadata field for this GitHub App credential bundle.",
                "The metadata field must contain valid JSON with `type`, numeric `app_id`, and `installation_id`.",
                "The private key should be a separate 1Password file attachment referenced by the `private_key` auth setting.",
                "If using the legacy single-field bundle, replace raw PEM line breaks with escaped `\\n` newlines inside `private_key`.",
                "Do not paste the real private key into an online validator.",
                &format!(
                    "Rerun `via config doctor {service_name}` after updating the 1Password field."
                ),
            ]);
            print_agent_guidance(
                "Ask the user to fix the GitHub App credential bundle in 1Password; do not ask for the private key value.",
            );
        }
    }

    Ok(())
}

fn check_oauth_auth(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    provider: &dyn crate::providers::SecretProvider,
    credential: &str,
    status: &mut DoctorStatus,
) -> Result<(), ViaError> {
    match resolve_doctor_secret(service_name, service, provider, credential)
        .and_then(|credential| crate::auth::oauth::validate_credential_bundle(credential.expose()))
    {
        Ok(()) => println!("  auth {command_name}: OAuth credential bundle valid"),
        Err(error) => {
            status.fail();
            println!("  auth {command_name}: OAuth credential bundle invalid");
            println!("  reason: {error}");
            print_human_setup(&[
                "Edit the configured 1Password field for this OAuth credential bundle.",
                "The field must contain valid JSON with `\"type\":\"service_oauth\"`, `token_url`, `client_id`, and either a refresh-token or client-credentials grant.",
                "Prefer `\"grant_type\":\"client_credentials\"` with `scope` for bot, agent, service-account, or app-actor access.",
                "Use `\"grant_type\":\"refresh_token\"` with `refresh_token` only when the service must act as a specific user.",
                "Store `client_secret` in the same 1Password field unless the OAuth service intentionally uses a public PKCE client.",
                &format!(
                    "Rerun `via config doctor {service_name}` after updating the 1Password field."
                ),
            ]);
            print_agent_guidance(
                "Ask the user to fix the OAuth credential bundle in 1Password; do not ask for OAuth token or client secret values.",
            );
        }
    }

    Ok(())
}

fn resolve_github_app_doctor_secrets(
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn crate::providers::SecretProvider,
    auth: &AuthConfig,
) -> Result<(crate::secrets::SecretValue, Option<String>), ViaError> {
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
            let credential = resolve_doctor_secret(service_name, service, provider, secret)?;
            Ok((credential, None))
        }
        (None, Some(credential), Some(private_key)) => {
            let credential = resolve_doctor_secret(service_name, service, provider, credential)?;
            let private_key = resolve_doctor_secret(service_name, service, provider, private_key)?;
            Ok((credential, Some(private_key.expose().to_owned())))
        }
        _ => Err(ViaError::InvalidConfig(
            "github_app auth must set either `secret` or both `credential` and `private_key`"
                .to_owned(),
        )),
    }
}

fn resolve_doctor_secret(
    service_name: &str,
    service: &ServiceConfig,
    provider: &dyn crate::providers::SecretProvider,
    secret: &str,
) -> Result<crate::secrets::SecretValue, ViaError> {
    let reference = service
        .secrets
        .get(secret)
        .ok_or_else(|| ViaError::UnknownSecret {
            service: service_name.to_owned(),
            secret: secret.to_owned(),
        })?;
    provider.resolve(reference)
}

#[derive(Default)]
struct DoctorStatus {
    failed: bool,
}

impl DoctorStatus {
    fn fail(&mut self) {
        self.failed = true;
    }

    fn into_result(self) -> Result<(), ViaError> {
        if self.failed {
            Err(ViaError::DoctorFailed)
        } else {
            Ok(())
        }
    }
}

fn check_program(program: &str, check: &[String]) -> Result<(), ViaError> {
    let args = if check.is_empty() {
        vec!["--version".to_owned()]
    } else {
        check.to_owned()
    };

    run_command(program, &args).map(|_| ())
}

fn check_providers(config: &Config, status: &mut DoctorStatus) -> BTreeMap<String, bool> {
    let mut ready = BTreeMap::new();

    for (provider_name, provider) in &config.providers {
        let provider_ready = match provider {
            ProviderConfig::OnePassword {
                account,
                cache,
                cache_ttl_seconds,
            } => check_onepassword_provider(
                provider_name,
                account.as_deref(),
                *cache,
                *cache_ttl_seconds,
                status,
            ),
        };
        ready.insert(provider_name.clone(), provider_ready);
    }

    ready
}

fn check_onepassword_provider(
    provider_name: &str,
    account: Option<&str>,
    cache: OnePasswordCacheMode,
    cache_ttl_seconds: u64,
    status: &mut DoctorStatus,
) -> bool {
    println!("provider {provider_name} (1Password): checking");
    print_onepassword_cache(cache, cache_ttl_seconds);

    if !check_onepassword_cli_installed(status) {
        return false;
    }
    if !check_onepassword_account(account, status) {
        return false;
    }

    check_onepassword_authentication(account, status)
}

fn print_onepassword_cache(cache: OnePasswordCacheMode, cache_ttl_seconds: u64) {
    match cache {
        OnePasswordCacheMode::Daemon => {
            println!("  cache: daemon enabled (ttl {cache_ttl_seconds}s)");
            println!(
                "  config reload: automatic on each via invocation; use `via daemon clear` to drop cached secret and OAuth state"
            );
        }
        OnePasswordCacheMode::Off => println!("  cache: off"),
    }
}

fn check_onepassword_cli_installed(status: &mut DoctorStatus) -> bool {
    match run_command("op", &["--version".to_owned()]) {
        Ok(output) => {
            print_onepassword_version(&output.stdout);
            true
        }
        Err(error) => {
            status.fail();
            print_onepassword_cli_failure(&error);
            false
        }
    }
}

fn print_onepassword_version(version: &str) {
    if version.is_empty() {
        println!("  1Password CLI: installed");
    } else {
        println!("  1Password CLI: installed ({version})");
    }
}

fn print_onepassword_cli_failure(error: &ViaError) {
    println!("  1Password CLI: not ready");
    print_error_hint(error);
    print_human_setup(&[
        "Install the 1Password CLI.",
        "macOS/Homebrew: `brew install --cask 1password-cli`.",
        "Windows/winget: `winget install -e --id AgileBits.1Password.CLI`.",
        "Linux: follow the official APT/YUM/Alpine/Nix/manual steps at https://developer.1password.com/docs/cli/get-started/.",
        "Verify the CLI is available with `op --version`.",
        "Install the 1Password desktop app if it is not already installed.",
        "Open and unlock the 1Password desktop app.",
        "Enable the 1Password CLI integration in the desktop app: Settings > Developer > Integrate with 1Password CLI.",
        "Rerun `via config doctor` after setup.",
    ]);
    print_agent_guidance(
        "Ask the user to install the secret provider, run `via login`, then rerun `via config doctor`.",
    );
}

fn check_onepassword_account(account: Option<&str>, status: &mut DoctorStatus) -> bool {
    let Some(account) = account else {
        return true;
    };

    let args = vec!["account".to_owned(), "get".to_owned(), account.to_owned()];
    match run_command("op", &args) {
        Ok(_) => {
            println!("  account {account}: configured");
            true
        }
        Err(error) => {
            status.fail();
            print_onepassword_account_failure(account, &error);
            false
        }
    }
}

fn print_onepassword_account_failure(account: &str, error: &ViaError) {
    println!("  account {account}: not ready");
    print_error_hint(error);
    print_human_setup(&[
        "Add this 1Password account to the desktop app or CLI.",
        "Confirm the provider account in `via.toml` matches a configured account ID or sign-in address.",
        "Rerun `via config doctor` after the account is available.",
    ]);
    print_agent_guidance(
        "Ask the user to fix the configured 1Password account, then rerun `via config doctor`.",
    );
}

fn check_onepassword_authentication(account: Option<&str>, status: &mut DoctorStatus) -> bool {
    let mut args = vec!["whoami".to_owned()];
    if let Some(account) = account {
        args.push("--account".to_owned());
        args.push(account.to_owned());
    }

    match run_command("op", &args) {
        Ok(_) => {
            println!("  authentication: ready");
            true
        }
        Err(error) => {
            status.fail();
            print_onepassword_auth_failure(&error);
            false
        }
    }
}

fn print_onepassword_auth_failure(error: &ViaError) {
    println!("  authentication: not ready");
    print_error_hint(error);
    print_onepassword_auth_setup(error);
    print_agent_guidance("Ask the user to run `via login`, then rerun `via config doctor`.");
}

fn print_onepassword_auth_setup(error: &ViaError) {
    if is_onepassword_not_signed_in(error) {
        print_onepassword_signed_out_setup();
    } else if is_onepassword_account_missing(error) {
        print_onepassword_missing_account_setup();
    } else {
        print_onepassword_desktop_setup();
    }
}

fn print_onepassword_signed_out_setup() {
    print_human_setup(&[
        "The 1Password CLI can see an account, but it is not signed in.",
        "Run `via login` from your terminal and choose the account that contains the configured vault.",
        "Approve the sign-in from the 1Password desktop app if prompted.",
        "Run `via config doctor` to confirm the CLI session is active.",
        "If multiple accounts are visible, set `[providers.onepassword] account = \"<account-id-or-sign-in-address>\"` in the via config.",
        "Rerun `via login` after pinning the account if needed.",
    ]);
}

fn print_onepassword_missing_account_setup() {
    print_human_setup(&[
        "The 1Password CLI is installed, but it cannot find a signed-in account.",
        "Open the 1Password desktop app and confirm the account containing the configured vault is added and unlocked.",
        "Enable the 1Password CLI integration in the desktop app: Settings > Developer > Integrate with 1Password CLI.",
        "Run `op account list` in your terminal to confirm the account is visible to the CLI.",
        "Run `via login` after the account is visible.",
        "If multiple accounts are visible, set `[providers.onepassword] account = \"<account-id-or-sign-in-address>\"` in the via config.",
        "Rerun `via config doctor` after authentication succeeds.",
    ]);
}

fn print_onepassword_desktop_setup() {
    print_human_setup(&[
        "Install the 1Password desktop app if it is not already installed.",
        "macOS/Homebrew: `brew install --cask 1password`.",
        "Windows/winget: `winget install -e --id AgileBits.1Password`.",
        "Linux: follow the official desktop app install steps at https://support.1password.com/install-linux/.",
        "Add your 1Password account to the desktop app.",
        "Open and unlock the 1Password desktop app.",
        "Enable the 1Password CLI integration in the desktop app: Settings > Developer > Integrate with 1Password CLI.",
        "Run `via login` from your terminal.",
        "Rerun `via config doctor` after authentication succeeds.",
    ]);
}

struct CommandOutput {
    stdout: String,
}

fn run_command(program: &str, args: &[String]) -> Result<CommandOutput, ViaError> {
    let output = Command::new(program).args(args).output();
    match output {
        Ok(output) if output.status.success() => Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        }),
        Ok(output) => Err(ViaError::ExternalCommandFailed {
            program: program.to_owned(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
        Err(source) => Err(ViaError::MissingProgram {
            program: program.to_owned(),
            source,
        }),
    }
}

fn print_secret_failure(service_name: &str, secret_name: &str, error: &ViaError) {
    println!("  secret {secret_name}: not readable by via");
    print_secret_error_hint(error);
    print_human_setup(&[
        &format!(
            "Confirm the configured 1Password reference for `{service_name}.{secret_name}` exists."
        ),
        "Confirm your signed-in account has permission to read it.",
        "Update `via.toml` with the correct secret reference if needed.",
        &format!("Rerun `via config doctor {service_name}` after fixing the secret."),
    ]);
    print_agent_guidance(
        "Do not ask for the token value. Ask the user to fix the configured secret reference or 1Password permissions.",
    );
}

fn print_secret_error_hint(error: &ViaError) {
    match error {
        ViaError::MissingProgram { .. } => {
            println!("  reason: secret provider command was not found on PATH");
        }
        ViaError::ExternalCommandFailed { status, .. } => {
            println!("  reason: secret provider could not read the configured reference; status {status:?}");
        }
        _ => println!("  reason: secret provider could not read the configured reference"),
    }
}

fn print_delegated_failure(command_name: &str, program: &str, error: &ViaError) {
    println!("  capability {command_name}: delegated {program} not ready");
    print_error_hint(error);
    print_human_setup(&[
        &format!("Install `{program}` or make sure it is available on PATH."),
        "Run `via config doctor` again after the delegated tool is available.",
    ]);
    print_agent_guidance(
        "Ask the user to install or fix the delegated tool, then rerun `via config doctor`.",
    );
}

fn print_error_hint(error: &ViaError) {
    match error {
        ViaError::MissingProgram { program, .. } => {
            println!("  reason: `{program}` was not found on PATH");
        }
        ViaError::ExternalCommandFailed { status, stderr, .. } => {
            println!("  reason: command exited with status {status:?}");
            if !stderr.is_empty() {
                println!("  detail: {stderr}");
            }
        }
        _ => println!("  reason: {error}"),
    }
}

fn is_onepassword_account_missing(error: &ViaError) -> bool {
    matches!(
        error,
        ViaError::ExternalCommandFailed { stderr, .. }
            if stderr.contains("no account found for filter")
    )
}

fn is_onepassword_not_signed_in(error: &ViaError) -> bool {
    matches!(
        error,
        ViaError::ExternalCommandFailed { stderr, .. }
            if stderr.contains("account is not signed in")
    )
}

fn print_human_setup(steps: &[&str]) {
    println!("  Human setup:");
    for step in steps {
        println!("    - {step}");
    }
}

fn print_agent_guidance(message: &str) {
    println!("  Agent guidance:");
    println!("    - {message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const PRIVATE_KEY: &str = include_str!("../tests/fixtures/rsa-private-key.pkcs1.pem");

    fn config() -> Config {
        Config::from_toml_str(
            r#"
version = 1

[providers.onepassword]
type = "1password"

[services.github]
provider = "onepassword"

[services.github.secrets]
token = "op://Private/GitHub/token"

[services.github.commands.api]
mode = "rest"
base_url = "https://api.github.com"
"#,
        )
        .unwrap()
    }

    fn auth_config() -> Config {
        Config::from_toml_str(
            r#"
version = 1

[providers.onepassword]
type = "1password"

[services.example]
provider = "onepassword"

[services.example.secrets]
oauth = "op://Private/OAuth/credential"
github_metadata = "op://Private/GitHub App/metadata"
github_private_key = "op://Private/GitHub App/private key"

[services.example.commands.api]
mode = "rest"
base_url = "https://api.example.com"
"#,
        )
        .unwrap()
    }

    #[derive(Default)]
    struct FakeProvider {
        values: BTreeMap<String, String>,
    }

    impl FakeProvider {
        fn with(reference: &str, value: String) -> Self {
            let mut values = BTreeMap::new();
            values.insert(reference.to_owned(), value);
            Self { values }
        }

        fn insert(&mut self, reference: &str, value: String) {
            self.values.insert(reference.to_owned(), value);
        }
    }

    impl crate::providers::SecretProvider for FakeProvider {
        fn resolve(&self, reference: &str) -> Result<crate::secrets::SecretValue, ViaError> {
            self.values
                .get(reference)
                .cloned()
                .map(crate::secrets::SecretValue::new)
                .ok_or_else(|| ViaError::InvalidConfig(format!("missing test secret {reference}")))
        }
    }

    #[test]
    fn rejects_unknown_service_before_provider_checks() {
        let error = run(&config(), Some("missing")).unwrap_err();

        assert!(matches!(error, ViaError::UnknownService(service) if service == "missing"));
    }

    #[test]
    fn check_program_accepts_successful_check_command() {
        check_program("sh", &["-c".to_owned(), "exit 0".to_owned()]).unwrap();
    }

    #[test]
    fn check_program_reports_failed_check_command() {
        let error = check_program("sh", &["-c".to_owned(), "exit 9".to_owned()]).unwrap_err();

        assert!(matches!(
            error,
            ViaError::ExternalCommandFailed {
                program,
                status: Some(9),
                ..
            } if program == "sh"
        ));
    }

    #[test]
    fn run_command_captures_stdout_without_newline() {
        let output = run_command("sh", &["-c".to_owned(), "printf 'ready\\n'".to_owned()]).unwrap();

        assert_eq!(output.stdout, "ready");
    }

    #[test]
    fn check_rest_auth_accepts_oauth_bundle() {
        let config = auth_config();
        let service = config.services.get("example").unwrap();
        let provider = FakeProvider::with(
            "op://Private/OAuth/credential",
            serde_json::json!({
                "type": "service_oauth",
                "token_url": "https://api.example.com/oauth/token",
                "grant_type": "refresh_token",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "refresh-token",
            })
            .to_string(),
        );
        let auth = AuthConfig::OAuth {
            credential: "oauth".to_owned(),
        };
        let mut status = DoctorStatus::default();

        check_rest_auth_config("example", "api", service, &provider, &auth, &mut status).unwrap();

        assert!(status.into_result().is_ok());
    }

    #[test]
    fn check_rest_auth_reports_invalid_oauth_bundle() {
        let config = auth_config();
        let service = config.services.get("example").unwrap();
        let provider = FakeProvider::with(
            "op://Private/OAuth/credential",
            serde_json::json!({
                "type": "service_oauth",
                "grant_type": "refresh_token",
                "client_id": "client-id",
                "refresh_token": "refresh-token",
            })
            .to_string(),
        );
        let auth = AuthConfig::OAuth {
            credential: "oauth".to_owned(),
        };
        let mut status = DoctorStatus::default();

        check_rest_auth_config("example", "api", service, &provider, &auth, &mut status).unwrap();

        assert!(matches!(status.into_result(), Err(ViaError::DoctorFailed)));
    }

    #[test]
    fn check_rest_auth_accepts_github_app_bundle() {
        let config = auth_config();
        let service = config.services.get("example").unwrap();
        let mut provider = FakeProvider::with(
            "op://Private/GitHub App/metadata",
            serde_json::json!({
                "type": "github_app",
                "app_id": 42,
                "installation_id": "123",
            })
            .to_string(),
        );
        provider.insert(
            "op://Private/GitHub App/private key",
            PRIVATE_KEY.to_owned(),
        );
        let auth = AuthConfig::GitHubApp {
            secret: None,
            credential: Some("github_metadata".to_owned()),
            private_key: Some("github_private_key".to_owned()),
        };
        let mut status = DoctorStatus::default();

        check_rest_auth_config("example", "api", service, &provider, &auth, &mut status).unwrap();

        assert!(status.into_result().is_ok());
    }

    #[test]
    fn detects_onepassword_missing_account_error() {
        let error = ViaError::ExternalCommandFailed {
            program: "op".to_owned(),
            status: Some(1),
            stderr: "[ERROR] no account found for filter".to_owned(),
        };

        assert!(is_onepassword_account_missing(&error));
    }

    #[test]
    fn detects_onepassword_signed_out_error() {
        let error = ViaError::ExternalCommandFailed {
            program: "op".to_owned(),
            status: Some(1),
            stderr: "[ERROR] account is not signed in".to_owned(),
        };

        assert!(is_onepassword_not_signed_in(&error));
    }
}
