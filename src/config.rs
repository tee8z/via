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
    pub ssh_profiles: BTreeMap<String, SshProfileConfig>,
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
    #[serde(rename = "ssh")]
    Ssh(SshCommandConfig),
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityMode {
    Rest,
    Delegated,
    Ssh,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshProfileConfig {
    pub provider: String,
    pub public_key: String,
    #[serde(default)]
    pub agent_socket: Option<PathBuf>,
    #[serde(default)]
    pub ssh_program: Option<PathBuf>,
    #[serde(default)]
    pub ssh_add_program: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshCommandConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub profile: String,
    pub user: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct RestCommandConfig {
    #[serde(default)]
    pub description: Option<String>,
    pub base_url: String,
    #[serde(default)]
    pub asset_hosts: Vec<String>,
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

        for (profile_name, profile) in &self.ssh_profiles {
            validate_ssh_profile(profile_name, profile, &self.providers)?;
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
                command.validate(service_name, command_name, service, &self.ssh_profiles)?;
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
            CommandConfig::Ssh(config) => config.description.as_ref(),
        }
    }

    pub fn mode(&self) -> CapabilityMode {
        match self {
            CommandConfig::Rest(_) => CapabilityMode::Rest,
            CommandConfig::Delegated(_) => CapabilityMode::Delegated,
            CommandConfig::Ssh(_) => CapabilityMode::Ssh,
        }
    }

    fn validate(
        &self,
        service_name: &str,
        command_name: &str,
        service: &ServiceConfig,
        ssh_profiles: &BTreeMap<String, SshProfileConfig>,
    ) -> Result<(), ViaError> {
        match self {
            CommandConfig::Rest(rest) => {
                if rest.base_url.trim().is_empty() {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` must set rest base_url"
                    )));
                }
                validate_asset_hosts(service_name, command_name, &rest.asset_hosts)?;

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
            CommandConfig::Ssh(ssh) => {
                if !ssh_profiles.contains_key(&ssh.profile) {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` references unknown SSH profile `{}`",
                        ssh.profile
                    )));
                }
                validate_ssh_user(service_name, command_name, &ssh.user)?;
                if ssh.hosts.is_empty() {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` must allow at least one SSH host pattern"
                    )));
                }
                for pattern in &ssh.hosts {
                    validate_ssh_host_pattern(service_name, command_name, pattern)?;
                }
                if ssh.port == Some(0) {
                    return Err(ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` SSH port must be between 1 and 65535"
                    )));
                }
            }
        }

        Ok(())
    }
}

fn validate_ssh_profile(
    profile_name: &str,
    profile: &SshProfileConfig,
    providers: &BTreeMap<String, ProviderConfig>,
) -> Result<(), ViaError> {
    if profile_name.trim().is_empty() || profile_name.trim() != profile_name {
        return Err(ViaError::InvalidConfig(
            "SSH profile names must be non-empty and may not start or end with whitespace"
                .to_owned(),
        ));
    }
    if !providers.contains_key(&profile.provider) {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile `{profile_name}` references unknown provider `{}`",
            profile.provider
        )));
    }
    if !profile.public_key.starts_with("op://") {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile `{profile_name}` public_key must be an op:// reference"
        )));
    }
    if let Some(agent_socket) = &profile.agent_socket {
        if !agent_socket.is_absolute() {
            return Err(ViaError::InvalidConfig(format!(
                "SSH profile `{profile_name}` agent_socket must be an absolute path"
            )));
        }
        #[cfg(windows)]
        if agent_socket != Path::new(r"\\.\pipe\openssh-ssh-agent") {
            return Err(ViaError::InvalidConfig(format!(
                "SSH profile `{profile_name}` agent_socket must use the Windows OpenSSH agent pipe"
            )));
        }
    }
    for (field, program) in [
        ("ssh_program", profile.ssh_program.as_ref()),
        ("ssh_add_program", profile.ssh_add_program.as_ref()),
    ] {
        if program.is_some_and(|program| !program.is_absolute()) {
            return Err(ViaError::InvalidConfig(format!(
                "SSH profile `{profile_name}` {field} must be an absolute path"
            )));
        }
    }
    if profile.ssh_program.is_some() != profile.ssh_add_program.is_some() {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile `{profile_name}` must configure ssh_program and ssh_add_program together"
        )));
    }
    if let (Some(ssh), Some(ssh_add)) = (&profile.ssh_program, &profile.ssh_add_program) {
        if ssh.parent() != ssh_add.parent() {
            return Err(ViaError::InvalidConfig(format!(
                "SSH profile `{profile_name}` ssh_program and ssh_add_program must use the same directory"
            )));
        }
    }

    Ok(())
}

fn validate_ssh_user(service_name: &str, command_name: &str, user: &str) -> Result<(), ViaError> {
    let valid = !user.is_empty()
        && user.len() <= 255
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        return Ok(());
    }

    Err(ViaError::InvalidConfig(format!(
        "command `{service_name}.{command_name}` SSH user must contain only letters, digits, `.`, `_`, or `-` and may not start with `-`"
    )))
}

fn validate_ssh_host_pattern(
    service_name: &str,
    command_name: &str,
    pattern: &str,
) -> Result<(), ViaError> {
    if valid_ssh_host_value(pattern, true) {
        return Ok(());
    }

    Err(ViaError::InvalidConfig(format!(
        "command `{service_name}.{command_name}` has invalid SSH host pattern `{pattern}`"
    )))
}

pub(crate) fn valid_ssh_host_value(value: &str, allow_wildcards: bool) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || value.trim() != value
        || value.starts_with('-')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains('/')
        || value.contains('@')
        || value.contains('[')
        || value.contains(']')
        || (!allow_wildcards && (value.contains('*') || value.contains('?')))
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b':' | b'%')
                || (allow_wildcards && matches!(byte, b'*' | b'?'))
        })
    {
        return false;
    }

    // A single colon is host:port syntax, not an IPv6 literal. Ports are fixed by
    // the SSH capability instead of being accepted from the invocation.
    value.bytes().filter(|byte| *byte == b':').count() != 1
}

fn validate_asset_hosts(
    service_name: &str,
    command_name: &str,
    asset_hosts: &[String],
) -> Result<(), ViaError> {
    for host in asset_hosts {
        let trimmed = host.trim();
        if trimmed.is_empty()
            || trimmed != host
            || trimmed.contains('/')
            || trimmed.contains(':')
            || trimmed.contains('*')
            || trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
        {
            return Err(ViaError::InvalidConfig(format!(
                "command `{service_name}.{command_name}` asset host `{host}` must be an exact hostname without scheme, path, port, or wildcard"
            )));
        }
    }

    Ok(())
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

    #[cfg(windows)]
    let home = windows_config_home(
        env::var_os("HOME").map(PathBuf::from),
        env::var_os("USERPROFILE").map(PathBuf::from),
        env::var_os("HOMEDRIVE").map(PathBuf::from),
        env::var_os("HOMEPATH").map(PathBuf::from),
    )
    .ok_or_else(|| {
        ViaError::ConfigNotFound(
            "HOME or USERPROFILE must be set, or HOMEDRIVE and HOMEPATH must identify an absolute path"
                .to_owned(),
        )
    })?;

    #[cfg(not(windows))]
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| ViaError::ConfigNotFound("HOME is not set".to_owned()))?;

    Ok(home.join(".config").join("via").join("config.toml"))
}

#[cfg(windows)]
fn windows_config_home(
    home: Option<PathBuf>,
    user_profile: Option<PathBuf>,
    home_drive: Option<PathBuf>,
    home_path: Option<PathBuf>,
) -> Option<PathBuf> {
    nonempty_path(home)
        .or_else(|| nonempty_path(user_profile))
        .or_else(|| {
            let combined = nonempty_path(home_drive)?.join(nonempty_path(home_path)?);
            combined.is_absolute().then_some(combined)
        })
}

#[cfg(windows)]
fn nonempty_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|path| !path.as_os_str().is_empty())
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

    const SSH_VALID: &str = r#"
version = 1

[providers.onepassword]
type = "1password"

[ssh_profiles.production]
provider = "onepassword"
public_key = "op://Private/Production SSH/public key"

[services.nodes]
provider = "onepassword"

[services.nodes.commands.connect]
description = "Connect to a production node"
mode = "ssh"
profile = "production"
user = "volt"
hosts = ["btcd-*.internal", "2001:db8::*"]
port = 22
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
    fn parses_valid_ssh_profile_and_command() {
        let config = Config::from_toml_str(SSH_VALID).unwrap();

        let profile = &config.ssh_profiles["production"];
        assert_eq!(profile.provider, "onepassword");
        assert_eq!(profile.public_key, "op://Private/Production SSH/public key");
        assert!(profile.agent_socket.is_none());
        match &config.services["nodes"].commands["connect"] {
            CommandConfig::Ssh(ssh) => {
                assert_eq!(ssh.user, "volt");
                assert_eq!(ssh.port, Some(22));
                assert_eq!(ssh.hosts, ["btcd-*.internal", "2001:db8::*"]);
            }
            _ => panic!("expected SSH command"),
        }
    }

    #[test]
    fn rejects_unknown_ssh_profile_provider_and_command_profile() {
        let unknown_provider = SSH_VALID.replace(
            "[ssh_profiles.production]\nprovider = \"onepassword\"",
            "[ssh_profiles.production]\nprovider = \"missing\"",
        );
        assert!(matches!(
            Config::from_toml_str(&unknown_provider),
            Err(ViaError::InvalidConfig(message)) if message.contains("unknown provider")
        ));

        let unknown_profile =
            SSH_VALID.replace("profile = \"production\"", "profile = \"missing\"");
        assert!(matches!(
            Config::from_toml_str(&unknown_profile),
            Err(ViaError::InvalidConfig(message)) if message.contains("unknown SSH profile")
        ));
    }

    #[test]
    fn rejects_plaintext_ssh_public_key_and_relative_agent_socket() {
        let plaintext =
            SSH_VALID.replace("op://Private/Production SSH/public key", "ssh-ed25519 AAAA");
        assert!(matches!(
            Config::from_toml_str(&plaintext),
            Err(ViaError::InvalidConfig(message)) if message.contains("public_key must be an op://")
        ));

        let relative_socket = SSH_VALID.replace(
            "public_key = \"op://Private/Production SSH/public key\"",
            "public_key = \"op://Private/Production SSH/public key\"\nagent_socket = \"agent.sock\"",
        );
        assert!(matches!(
            Config::from_toml_str(&relative_socket),
            Err(ViaError::InvalidConfig(message)) if message.contains("agent_socket must be an absolute path")
        ));

        for field in ["ssh_program", "ssh_add_program"] {
            let relative_program = SSH_VALID.replace(
                "public_key = \"op://Private/Production SSH/public key\"",
                &format!(
                    "public_key = \"op://Private/Production SSH/public key\"\n{field} = \"ssh\""
                ),
            );
            assert!(matches!(
                Config::from_toml_str(&relative_program),
                Err(ViaError::InvalidConfig(message)) if message.contains(&format!("{field} must be an absolute path"))
            ));
        }

        #[cfg(windows)]
        let absolute_ssh = r"'C:\OpenSSH\ssh.exe'";
        #[cfg(not(windows))]
        let absolute_ssh = r#""/usr/bin/ssh""#;
        let incomplete_programs = SSH_VALID.replace(
            "public_key = \"op://Private/Production SSH/public key\"",
            &format!(
                "public_key = \"op://Private/Production SSH/public key\"\nssh_program = {absolute_ssh}"
            ),
        );
        assert!(matches!(
            Config::from_toml_str(&incomplete_programs),
            Err(ViaError::InvalidConfig(message)) if message.contains("ssh_program and ssh_add_program together")
        ));
    }

    #[test]
    fn rejects_invalid_ssh_user_hosts_and_port() {
        for (old, new, expected) in [
            ("user = \"volt\"", "user = \"-oProxyCommand=x\"", "SSH user"),
            (
                "hosts = [\"btcd-*.internal\", \"2001:db8::*\"]",
                "hosts = []",
                "at least one SSH host pattern",
            ),
            (
                "hosts = [\"btcd-*.internal\", \"2001:db8::*\"]",
                "hosts = [\"user@host\"]",
                "invalid SSH host pattern",
            ),
            ("port = 22", "port = 0", "SSH port"),
            (
                "hosts = [\"btcd-*.internal\", \"2001:db8::*\"]",
                "hosts = [\"host;unexpected\"]",
                "invalid SSH host pattern",
            ),
        ] {
            let raw = SSH_VALID.replace(old, new);
            assert!(
                matches!(
                    Config::from_toml_str(&raw),
                    Err(ViaError::InvalidConfig(message)) if message.contains(expected)
                ),
                "expected `{expected}` rejection"
            );
        }
    }

    #[test]
    fn ssh_security_fields_reject_typos() {
        let profile_typo = SSH_VALID.replace(
            "public_key = \"op://Private/Production SSH/public key\"",
            "public_key = \"op://Private/Production SSH/public key\"\nagent_soket = \"/tmp/agent.sock\"",
        );
        assert!(matches!(
            Config::from_toml_str(&profile_typo),
            Err(ViaError::ParseConfig(message)) if message.to_string().contains("unknown field")
        ));

        let command_typo = SSH_VALID.replace("port = 22", "port = 22\nporrt = 2222");
        assert!(matches!(
            Config::from_toml_str(&command_typo),
            Err(ViaError::ParseConfig(message)) if message.to_string().contains("unknown field")
        ));
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
    fn accepts_rest_asset_hosts() {
        let raw = VALID.replace(
            "base_url = \"https://api.github.com\"",
            "base_url = \"https://api.github.com\"\nasset_hosts = [\"uploads.linear.app\"]",
        );

        assert!(Config::from_toml_str(&raw).is_ok());
    }

    #[test]
    fn rejects_invalid_rest_asset_hosts() {
        for asset_hosts in [
            "[\"https://uploads.linear.app\"]",
            "[\"uploads.linear.app/path\"]",
            "[\"uploads.linear.app:443\"]",
            "[\"*.linear.app\"]",
        ] {
            let raw = VALID.replace(
                "base_url = \"https://api.github.com\"",
                &format!("base_url = \"https://api.github.com\"\nasset_hosts = {asset_hosts}"),
            );

            assert!(
                matches!(
                    Config::from_toml_str(&raw),
                    Err(ViaError::InvalidConfig(message)) if message.contains("asset host")
                ),
                "expected invalid asset_hosts rejection for {asset_hosts}"
            );
        }
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

    #[cfg(windows)]
    #[test]
    fn windows_config_home_prefers_home_then_user_profile() {
        assert_eq!(
            windows_config_home(
                Some(PathBuf::from(r"C:\home")),
                Some(PathBuf::from(r"C:\Users\via")),
                Some(PathBuf::from("D:")),
                Some(PathBuf::from(r"\Users\via")),
            ),
            Some(PathBuf::from(r"C:\home"))
        );
        assert_eq!(
            windows_config_home(
                Some(PathBuf::new()),
                Some(PathBuf::from(r"C:\Users\via")),
                Some(PathBuf::from("D:")),
                Some(PathBuf::from(r"\Users\via")),
            ),
            Some(PathBuf::from(r"C:\Users\via"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_home_combines_home_drive_and_home_path() {
        assert_eq!(
            windows_config_home(
                None,
                Some(PathBuf::new()),
                Some(PathBuf::from("D:")),
                Some(PathBuf::from(r"\Users\via")),
            ),
            Some(PathBuf::from(r"D:\Users\via"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_config_home_rejects_incomplete_or_relative_fallbacks() {
        assert_eq!(
            windows_config_home(None, None, Some(PathBuf::from("D:")), None),
            None
        );
        assert_eq!(
            windows_config_home(
                None,
                None,
                Some(PathBuf::from("D:")),
                Some(PathBuf::from(r"Users\via")),
            ),
            None
        );
    }
}
