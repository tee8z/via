use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ViaError;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConfig>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "1password")]
    OnePassword {
        #[serde(default)]
        account: Option<String>,
        #[serde(default)]
        cache: OnePasswordCacheMode,
        #[serde(default = "default_onepassword_cache_ttl_seconds")]
        cache_ttl_seconds: u64,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnePasswordCacheMode {
    Off,
    Daemon,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
    pub provider: String,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode")]
pub enum CommandConfig {
    #[serde(rename = "rest")]
    Rest(RestCommandConfig),
    #[serde(rename = "delegated")]
    Delegated(DelegatedCommandConfig),
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityMode {
    Rest,
    Delegated,
}

#[derive(Debug, Deserialize)]
pub struct RestCommandConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub base_url: String,
    #[serde(default = "default_method")]
    pub method_default: String,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    #[serde(rename = "bearer")]
    Bearer { secret: String },
    #[serde(rename = "headers")]
    Headers {
        #[serde(default)]
        headers: BTreeMap<String, SecretHeaderConfig>,
    },
    #[serde(rename = "github_app")]
    GitHubApp {
        #[serde(default)]
        secret: Option<String>,
        #[serde(default)]
        credential: Option<String>,
        #[serde(default)]
        private_key: Option<String>,
    },
    #[serde(rename = "oauth")]
    OAuth { credential: String },
}

#[derive(Debug, Deserialize)]
pub struct SecretHeaderConfig {
    pub secret: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub suffix: String,
}

#[derive(Debug, Deserialize)]
pub struct DelegatedCommandConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub program: String,
    #[serde(default)]
    pub args_prefix: Vec<String>,
    #[serde(default)]
    pub inject: InjectConfig,
    #[serde(default)]
    pub check: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct InjectConfig {
    #[serde(default)]
    pub env: BTreeMap<String, SecretBinding>,
}

#[derive(Debug, Deserialize)]
pub struct SecretBinding {
    pub secret: String,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ViaError> {
        let path = resolve_path(path)?;

        let raw = fs::read_to_string(&path).map_err(|source| ViaError::ReadConfig {
            path: path.clone(),
            source,
        })?;
        Self::from_toml_str(&raw)
    }

    pub(crate) fn from_toml_str(raw: &str) -> Result<Self, ViaError> {
        let config: Self = toml::from_str(raw)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ViaError> {
        if self.version != 1 {
            return Err(ViaError::InvalidConfig(format!(
                "unsupported config version {}; expected 1",
                self.version
            )));
        }

        for (service_name, service) in &self.services {
            if !self.providers.contains_key(&service.provider) {
                return Err(ViaError::InvalidConfig(format!(
                    "service `{service_name}` references unknown provider `{}`",
                    service.provider
                )));
            }

            for (secret_name, reference) in &service.secrets {
                if !reference.starts_with("op://") {
                    return Err(ViaError::InvalidConfig(format!(
                        "secret `{service_name}.{secret_name}` must be an op:// reference"
                    )));
                }
            }

            for (command_name, command) in &service.commands {
                command.validate(service_name, command_name, service)?;
            }
        }

        Ok(())
    }
}

pub fn resolve_path(path: Option<&Path>) -> Result<PathBuf, ViaError> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => default_config_path(),
    }
}

impl CommandConfig {
    pub fn description(&self) -> Option<&String> {
        match self {
            CommandConfig::Rest(config) => config.description.as_ref(),
            CommandConfig::Delegated(config) => config.description.as_ref(),
        }
    }

    pub fn mode(&self) -> CapabilityMode {
        match self {
            CommandConfig::Rest(_) => CapabilityMode::Rest,
            CommandConfig::Delegated(_) => CapabilityMode::Delegated,
        }
    }

    fn validate(
        &self,
        service_name: &str,
        command_name: &str,
        service: &ServiceConfig,
    ) -> Result<(), ViaError> {
        match self {
            CommandConfig::Rest(rest) => {
                if rest.base_url.trim().is_empty() {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` must set rest base_url"
                    )));
                }

                if let Some(auth) = &rest.auth {
                    match auth {
                        AuthConfig::Bearer { secret } => {
                            validate_secret_name(service_name, command_name, service, secret)?;
                        }
                        AuthConfig::Headers { headers } => {
                            if headers.is_empty() {
                                return Err(ViaError::InvalidConfig(format!(
                                    "command `{service_name}.{command_name}` headers auth must configure at least one header"
                                )));
                            }
                            for secret_header in headers.values() {
                                validate_secret_name(
                                    service_name,
                                    command_name,
                                    service,
                                    &secret_header.secret,
                                )?;
                            }
                        }
                        AuthConfig::GitHubApp {
                            secret,
                            credential,
                            private_key,
                        } => validate_github_app_auth(
                            service_name,
                            command_name,
                            service,
                            secret.as_deref(),
                            credential.as_deref(),
                            private_key.as_deref(),
                        )?,
                        AuthConfig::OAuth { credential } => {
                            validate_secret_name(service_name, command_name, service, credential)?;
                        }
                    }
                }
            }
            CommandConfig::Delegated(delegated) => {
                if delegated.program.trim().is_empty() {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` must set delegated program"
                    )));
                }

                for binding in delegated.inject.env.values() {
                    validate_secret_name(service_name, command_name, service, &binding.secret)?;
                }
            }
        }

        Ok(())
    }
}

fn validate_secret_name(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    secret: &str,
) -> Result<(), ViaError> {
    if service.secrets.contains_key(secret) {
        return Ok(());
    }

    Err(ViaError::InvalidConfig(format!(
        "command `{service_name}.{command_name}` references unknown secret `{secret}`"
    )))
}

fn validate_github_app_auth(
    service_name: &str,
    command_name: &str,
    service: &ServiceConfig,
    secret: Option<&str>,
    credential: Option<&str>,
    private_key: Option<&str>,
) -> Result<(), ViaError> {
    match (secret, credential, private_key) {
        (Some(secret), None, None) => {
            validate_secret_name(service_name, command_name, service, secret)
        }
        (None, Some(credential), Some(private_key)) => {
            validate_secret_name(service_name, command_name, service, credential)?;
            validate_secret_name(service_name, command_name, service, private_key)
        }
        _ => Err(ViaError::InvalidConfig(format!(
            "command `{service_name}.{command_name}` github_app auth must set either `secret` or both `credential` and `private_key`"
        ))),
    }
}

fn default_method() -> String {
    "GET".to_owned()
}

impl Default for OnePasswordCacheMode {
    fn default() -> Self {
        if cfg!(unix) {
            Self::Daemon
        } else {
            Self::Off
        }
    }
}

fn default_onepassword_cache_ttl_seconds() -> u64 {
    300
}

fn default_config_path() -> Result<PathBuf, ViaError> {
    if let Ok(path) = env::var("VIA_CONFIG") {
        return Ok(PathBuf::from(path));
    }

    let local = PathBuf::from("via.toml");
    if local.exists() {
        return Ok(local);
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| ViaError::ConfigNotFound("HOME is not set".to_owned()))?;
    Ok(home.join(".config").join("via").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version = 1

[providers.onepassword]
type = "1password"

[services.github]
description = "GitHub access"
hint = "via github api /user"
provider = "onepassword"

[services.github.secrets]
token = "op://Private/GitHub/token"

[services.github.commands.api]
description = "REST access"
mode = "rest"
base_url = "https://api.github.com"

[services.github.commands.api.auth]
type = "bearer"
secret = "token"

[services.github.commands.gh]
description = "GitHub CLI access"
mode = "delegated"
program = "gh"
check = ["--version"]

[services.github.commands.gh.inject.env.GH_TOKEN]
secret = "token"
"#;

    #[test]
    fn parses_valid_config() {
        let config = Config::from_toml_str(VALID).unwrap();

        assert_eq!(config.version, 1);
        assert_eq!(
            config.services["github"].hint.as_deref(),
            Some("via github api /user")
        );
        assert!(config.services["github"].commands.contains_key("api"));
        assert!(config.services["github"].commands.contains_key("gh"));
    }

    #[test]
    fn rejects_unknown_provider() {
        let raw = VALID.replace("provider = \"onepassword\"", "provider = \"missing\"");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("unknown provider")
        ));
    }

    #[test]
    fn rejects_plaintext_secret_values() {
        let raw = VALID.replace("op://Private/GitHub/token", "ghp_plaintext");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("must be an op:// reference")
        ));
    }

    #[test]
    fn rejects_unknown_rest_secret() {
        let raw = VALID.replace("secret = \"token\"", "secret = \"missing\"");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("unknown secret")
        ));
    }

    #[test]
    fn accepts_github_app_rest_auth() {
        let raw = VALID.replace(
            r#"[services.github.commands.api.auth]
type = "bearer"
secret = "token""#,
            r#"[services.github.commands.api.auth]
type = "github_app"
credential = "token"
private_key = "token""#,
        );

        assert!(Config::from_toml_str(&raw).is_ok());
    }

    #[test]
    fn accepts_oauth_rest_auth() {
        let raw = VALID.replace(
            r#"[services.github.commands.api.auth]
type = "bearer"
secret = "token""#,
            r#"[services.github.commands.api.auth]
type = "oauth"
credential = "token""#,
        );

        assert!(Config::from_toml_str(&raw).is_ok());
    }

    #[test]
    fn accepts_onepassword_daemon_cache() {
        let raw = VALID.replace(
            r#"[providers.onepassword]
type = "1password""#,
            r#"[providers.onepassword]
type = "1password"
cache = "daemon"
cache_ttl_seconds = 600"#,
        );
        let config = Config::from_toml_str(&raw).unwrap();

        match &config.providers["onepassword"] {
            ProviderConfig::OnePassword {
                cache,
                cache_ttl_seconds,
                ..
            } => {
                assert_eq!(*cache, OnePasswordCacheMode::Daemon);
                assert_eq!(*cache_ttl_seconds, 600);
            }
        }
    }

    #[test]
    fn defaults_onepassword_cache_for_platform() {
        let config = Config::from_toml_str(VALID).unwrap();

        match &config.providers["onepassword"] {
            ProviderConfig::OnePassword {
                cache,
                cache_ttl_seconds,
                ..
            } => {
                #[cfg(unix)]
                assert_eq!(*cache, OnePasswordCacheMode::Daemon);
                #[cfg(not(unix))]
                assert_eq!(*cache, OnePasswordCacheMode::Off);
                assert_eq!(*cache_ttl_seconds, 300);
            }
        }
    }

    #[test]
    fn accepts_secret_header_rest_auth() {
        let raw = VALID.replace(
            r#"[services.github.commands.api.auth]
type = "bearer"
secret = "token""#,
            r#"[services.github.commands.api.auth]
type = "headers"

[services.github.commands.api.auth.headers.Authorization]
secret = "token"
prefix = "Token "

[services.github.commands.api.auth.headers.X-Api-Key]
secret = "token""#,
        );

        assert!(Config::from_toml_str(&raw).is_ok());
    }

    #[test]
    fn rejects_empty_secret_header_rest_auth() {
        let raw = VALID.replace(
            r#"[services.github.commands.api.auth]
type = "bearer"
secret = "token""#,
            r#"[services.github.commands.api.auth]
type = "headers""#,
        );

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("at least one header")
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let raw = VALID.replace("version = 1", "version = 2");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("unsupported config version")
        ));
    }

    #[test]
    fn rejects_empty_rest_base_url() {
        let raw = VALID.replace("base_url = \"https://api.github.com\"", "base_url = \"\"");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("base_url")
        ));
    }

    #[test]
    fn rejects_empty_delegated_program() {
        let raw = VALID.replace("program = \"gh\"", "program = \"\"");

        assert!(matches!(
            Config::from_toml_str(&raw),
            Err(ViaError::InvalidConfig(message)) if message.contains("delegated program")
        ));
    }
}
