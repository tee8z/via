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
    // `broker` and `audit` are only consulted by `via broker exec`.
    #[serde(default)]
    pub broker: Option<BrokerConfig>,
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    #[serde(default)]
    pub disable_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub sink: AuditSinkKind,
    #[serde(default)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditSinkKind {
    Journald,
    File,
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
    #[serde(rename = "directory")]
    Directory {
        #[serde(default)]
        path: Option<PathBuf>,
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
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RestRuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestRuleConfig {
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: Option<Vec<String>>,
    pub path: String,
    pub effect: RuleEffect,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Deny,
}

impl RestCommandConfig {
    pub fn has_rules(&self) -> bool {
        self.methods.is_some()
            || !self.allow_paths.is_empty()
            || !self.deny_paths.is_empty()
            || !self.rules.is_empty()
    }
}

// HTTP methods in rules are stored in upper case.
fn deserialize_methods<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let methods = Option::<Vec<String>>::deserialize(deserializer)?;
    Ok(methods.map(|methods| {
        methods
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect()
    }))
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

        if let Some(broker) = &self.broker {
            broker.validate()?;
        }
        if let Some(audit) = &self.audit {
            audit.validate()?;
        }

        for (provider_name, provider) in &self.providers {
            provider.validate(provider_name)?;
        }

        for (profile_name, profile) in &self.ssh_profiles {
            validate_ssh_profile(profile_name, profile, &self.providers)?;
        }

        for (service_name, service) in &self.services {
            let provider = self.providers.get(&service.provider).ok_or_else(|| {
                ViaError::InvalidConfig(format!(
                    "service `{service_name}` references unknown provider `{}`",
                    service.provider
                ))
            })?;

            for (secret_name, reference) in &service.secrets {
                if let Err(problem) = provider.validate_reference(reference) {
                    return Err(ViaError::InvalidConfig(format!(
                        "secret `{service_name}.{secret_name}` {problem}"
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

impl BrokerConfig {
    fn validate(&self) -> Result<(), ViaError> {
        if self
            .disable_dir
            .as_deref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ViaError::InvalidConfig(
                "broker disable_dir must be an absolute path".to_owned(),
            ));
        }

        Ok(())
    }
}

impl AuditConfig {
    fn validate(&self) -> Result<(), ViaError> {
        match (self.sink, self.path.as_deref()) {
            (AuditSinkKind::File, None) => Err(ViaError::InvalidConfig(
                "audit sink `file` requires an absolute `path`".to_owned(),
            )),
            (AuditSinkKind::File, Some(path)) if !path.is_absolute() => Err(
                ViaError::InvalidConfig("audit path must be an absolute path".to_owned()),
            ),
            (AuditSinkKind::Journald, Some(_)) => Err(ViaError::InvalidConfig(
                "audit sink `journald` does not take a `path`".to_owned(),
            )),
            (AuditSinkKind::File, Some(_)) | (AuditSinkKind::Journald, None) => Ok(()),
        }
    }
}

const ONEPASSWORD_REFERENCE_SCHEME: &str = "op://";
const DIRECTORY_REFERENCE_SCHEME: &str = "cred://";

impl ProviderConfig {
    fn validate(&self, provider_name: &str) -> Result<(), ViaError> {
        match self {
            ProviderConfig::OnePassword { .. } => Ok(()),
            ProviderConfig::Directory { path } => {
                if path.as_deref().is_some_and(|path| !path.is_absolute()) {
                    return Err(ViaError::InvalidConfig(format!(
                        "provider `{provider_name}` directory path must be an absolute path"
                    )));
                }
                Ok(())
            }
        }
    }

    // A reference must use the scheme of the provider that resolves it. The
    // returned problem completes a sentence that names the offending field.
    fn validate_reference(&self, reference: &str) -> Result<(), &'static str> {
        match self {
            ProviderConfig::OnePassword { .. } => {
                if reference.starts_with(ONEPASSWORD_REFERENCE_SCHEME) {
                    Ok(())
                } else {
                    Err("must be an op:// reference")
                }
            }
            ProviderConfig::Directory { .. } => {
                if !reference.starts_with(DIRECTORY_REFERENCE_SCHEME) {
                    Err("must be a cred:// reference")
                } else if directory_credential_name(reference).is_none() {
                    Err("must be a cred://<name> reference that names a single file")
                } else {
                    Ok(())
                }
            }
        }
    }
}

pub(crate) fn directory_credential_name(reference: &str) -> Option<&str> {
    let name = reference.strip_prefix(DIRECTORY_REFERENCE_SCHEME)?;
    valid_path_component(name).then_some(name)
}

pub(crate) fn valid_path_component(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\', '\0'])
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
                crate::rules::RestRules::from_config(rest).map_err(|problem| {
                    ViaError::InvalidConfig(format!(
                        "command `{service_name}.{command_name}` {problem}"
                    ))
                })?;

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
    let Some(provider) = providers.get(&profile.provider) else {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile `{profile_name}` references unknown provider `{}`",
            profile.provider
        )));
    };
    if let Err(problem) = provider.validate_reference(&profile.public_key) {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile `{profile_name}` public_key {problem}"
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
user = "deploy"
hosts = ["server-*.example.com", "2001:db8::*"]
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
                assert_eq!(ssh.user, "deploy");
                assert_eq!(ssh.port, Some(22));
                assert_eq!(ssh.hosts, ["server-*.example.com", "2001:db8::*"]);
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
            (
                "user = \"deploy\"",
                "user = \"-oProxyCommand=x\"",
                "SSH user",
            ),
            (
                "hosts = [\"server-*.example.com\", \"2001:db8::*\"]",
                "hosts = []",
                "at least one SSH host pattern",
            ),
            (
                "hosts = [\"server-*.example.com\", \"2001:db8::*\"]",
                "hosts = [\"user@host\"]",
                "invalid SSH host pattern",
            ),
            ("port = 22", "port = 0", "SSH port"),
            (
                "hosts = [\"server-*.example.com\", \"2001:db8::*\"]",
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
            other => panic!("expected a 1Password provider, got {other:?}"),
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
            other => panic!("expected a 1Password provider, got {other:?}"),
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

    #[test]
    fn parses_rest_rules_and_stores_methods_in_upper_case() {
        let raw = VALID.replace(
            "base_url = \"https://api.github.com\"",
            r#"base_url = "https://api.github.com"
methods = ["get", "Post"]
allow_paths = ["/repos/OWNER/**", "/user"]
deny_paths = ["/repos/*/*/actions/secrets/**"]

[[services.github.commands.api.rules]]
methods = ["patch"]
path = "/repos/OWNER/REPO/issues/*"
effect = "allow"
"#,
        );
        let config = Config::from_toml_str(&raw).unwrap();

        match &config.services["github"].commands["api"] {
            CommandConfig::Rest(rest) => {
                assert!(rest.has_rules());
                assert_eq!(
                    rest.methods.as_deref(),
                    Some(&["GET".to_owned(), "POST".to_owned()][..])
                );
                assert_eq!(rest.allow_paths, ["/repos/OWNER/**", "/user"]);
                assert_eq!(rest.deny_paths, ["/repos/*/*/actions/secrets/**"]);
                assert_eq!(rest.rules.len(), 1);
                assert_eq!(
                    rest.rules[0].methods.as_deref(),
                    Some(&["PATCH".to_owned()][..])
                );
                assert_eq!(rest.rules[0].path, "/repos/OWNER/REPO/issues/*");
                assert_eq!(rest.rules[0].effect, RuleEffect::Allow);
            }
            _ => panic!("expected REST command"),
        }
    }

    #[test]
    fn rest_commands_without_rule_fields_have_no_rules() {
        let config = Config::from_toml_str(VALID).unwrap();

        match &config.services["github"].commands["api"] {
            CommandConfig::Rest(rest) => assert!(!rest.has_rules()),
            _ => panic!("expected REST command"),
        }
    }

    #[test]
    fn rejects_invalid_rest_rules() {
        for (rules, expected) in [
            ("methods = []", "at least one HTTP method"),
            ("methods = [\"GE T\"]", "invalid HTTP method"),
            (
                "allow_paths = [\"repos\"]",
                "invalid path pattern `repos` in allow_paths",
            ),
            (
                "deny_paths = [\"/a/**/b\"]",
                "invalid path pattern `/a/**/b` in deny_paths",
            ),
            ("allow_paths = [\"/a/../b\"]", "invalid path pattern"),
        ] {
            let raw = VALID.replace(
                "base_url = \"https://api.github.com\"",
                &format!("base_url = \"https://api.github.com\"\n{rules}"),
            );

            assert!(
                matches!(
                    Config::from_toml_str(&raw),
                    Err(ViaError::InvalidConfig(message))
                        if message.contains("command `github.api`") && message.contains(expected)
                ),
                "expected `{rules}` to be rejected"
            );
        }
    }

    #[test]
    fn rest_rule_tables_reject_unknown_fields_and_effects() {
        let rule = |body: &str| {
            VALID.replace(
                "base_url = \"https://api.github.com\"",
                &format!(
                    "base_url = \"https://api.github.com\"\n\n[[services.github.commands.api.rules]]\n{body}\n"
                ),
            )
        };

        assert!(Config::from_toml_str(&rule("path = \"/user\"\neffect = \"allow\"")).is_ok());
        assert!(matches!(
            Config::from_toml_str(&rule("path = \"/user\"\neffect = \"permit\"")),
            Err(ViaError::ParseConfig(_))
        ));
        assert!(matches!(
            Config::from_toml_str(&rule(
                "path = \"/user\"\neffect = \"allow\"\nmethod = \"GET\""
            )),
            Err(ViaError::ParseConfig(_))
        ));
        assert!(matches!(
            Config::from_toml_str(&rule("effect = \"allow\"")),
            Err(ViaError::ParseConfig(_))
        ));
    }

    #[cfg(windows)]
    const ABSOLUTE_DIRECTORY: &str = r"'C:\via\state'";
    #[cfg(not(windows))]
    const ABSOLUTE_DIRECTORY: &str = r#""/var/lib/via""#;

    #[cfg(unix)]
    #[test]
    fn broker_example_is_a_valid_config() {
        let config = Config::from_toml_str(include_str!("../examples/broker.toml")).unwrap();

        assert!(matches!(
            &config.providers["files"],
            ProviderConfig::Directory { path: Some(_) }
        ));
        assert!(config.broker.as_ref().unwrap().disable_dir.is_some());
        assert_eq!(config.audit.as_ref().unwrap().sink, AuditSinkKind::Journald);
        match &config.services["github"].commands["api"] {
            CommandConfig::Rest(rest) => {
                assert!(rest.has_rules());
                assert_eq!(rest.rules.len(), 4);
                assert!(rest.allow_paths.is_empty());
                assert!(!rest.deny_paths.is_empty());
            }
            _ => panic!("expected REST command"),
        }
        assert!(matches!(
            &config.services["servers"].commands["shell"],
            CommandConfig::Ssh(_)
        ));
    }

    #[test]
    fn configs_without_broker_tables_leave_them_unset() {
        let config = Config::from_toml_str(VALID).unwrap();

        assert!(config.broker.is_none());
        assert!(config.audit.is_none());
    }

    #[test]
    fn parses_broker_and_audit_tables() {
        let raw = format!(
            "{VALID}\n[broker]\ndisable_dir = {ABSOLUTE_DIRECTORY}\n\n[audit]\nsink = \"file\"\npath = {ABSOLUTE_DIRECTORY}\n"
        );
        let config = Config::from_toml_str(&raw).unwrap();

        assert!(config
            .broker
            .as_ref()
            .and_then(|broker| broker.disable_dir.as_deref())
            .is_some_and(Path::is_absolute));
        let audit = config.audit.as_ref().unwrap();
        assert_eq!(audit.sink, AuditSinkKind::File);
        assert!(audit.path.as_deref().is_some_and(Path::is_absolute));

        let journald = format!("{VALID}\n[audit]\nsink = \"journald\"\n");
        let config = Config::from_toml_str(&journald).unwrap();
        assert_eq!(config.audit.as_ref().unwrap().sink, AuditSinkKind::Journald);
        assert!(config.broker.is_none());
    }

    #[test]
    fn rejects_invalid_broker_and_audit_tables() {
        for (tables, expected) in [
            (
                "[broker]\ndisable_dir = \"disabled\"".to_owned(),
                "disable_dir must be an absolute path",
            ),
            (
                "[audit]\nsink = \"file\"".to_owned(),
                "requires an absolute `path`",
            ),
            (
                "[audit]\nsink = \"file\"\npath = \"audit.jsonl\"".to_owned(),
                "audit path must be an absolute path",
            ),
            (
                format!("[audit]\nsink = \"journald\"\npath = {ABSOLUTE_DIRECTORY}"),
                "does not take a `path`",
            ),
        ] {
            let raw = format!("{VALID}\n{tables}\n");

            assert!(
                matches!(
                    Config::from_toml_str(&raw),
                    Err(ViaError::InvalidConfig(message)) if message.contains(expected)
                ),
                "expected `{expected}` rejection"
            );
        }

        for tables in [
            "[audit]\nsink = \"syslog\"",
            "[audit]\npath = \"/var/log/via.jsonl\"",
            "[audit]\nsink = \"journald\"\nidentifier = \"via\"",
            "[broker]\ndisable_directory = \"/var/lib/via/disabled\"",
        ] {
            let raw = format!("{VALID}\n{tables}\n");

            assert!(
                matches!(Config::from_toml_str(&raw), Err(ViaError::ParseConfig(_))),
                "expected `{tables}` to fail to parse"
            );
        }
    }

    const DIRECTORY_VALID: &str = r#"
version = 1

[providers.files]
type = "directory"

[ssh_profiles.deploy]
provider = "files"
public_key = "cred://deploy-ssh-public-key"

[services.github]
provider = "files"

[services.github.secrets]
token = "cred://github-token"

[services.github.commands.api]
mode = "rest"
base_url = "https://api.github.com"

[services.github.commands.api.auth]
type = "bearer"
secret = "token"
"#;

    #[test]
    fn parses_directory_provider_with_cred_references() {
        let config = Config::from_toml_str(DIRECTORY_VALID).unwrap();

        assert!(matches!(
            &config.providers["files"],
            ProviderConfig::Directory { path: None }
        ));
        assert_eq!(
            config.services["github"].secrets["token"],
            "cred://github-token"
        );
        assert_eq!(
            config.ssh_profiles["deploy"].public_key,
            "cred://deploy-ssh-public-key"
        );
    }

    #[test]
    fn directory_provider_path_must_be_absolute() {
        #[cfg(windows)]
        let absolute = r"path = 'C:\via\credentials'";
        #[cfg(not(windows))]
        let absolute = r#"path = "/run/credentials/via""#;
        let with_path = |path: &str| {
            DIRECTORY_VALID.replace(
                "type = \"directory\"",
                &format!("type = \"directory\"\n{path}"),
            )
        };

        let config = Config::from_toml_str(&with_path(absolute)).unwrap();
        assert!(matches!(
            &config.providers["files"],
            ProviderConfig::Directory { path: Some(path) } if path.is_absolute()
        ));

        assert!(matches!(
            Config::from_toml_str(&with_path("path = \"credentials\"")),
            Err(ViaError::InvalidConfig(message)) if message.contains("must be an absolute path")
        ));
    }

    #[test]
    fn rejects_references_that_do_not_match_the_provider_type() {
        let op_secret_for_directory =
            DIRECTORY_VALID.replace("cred://github-token", "op://Private/GitHub/token");
        assert!(matches!(
            Config::from_toml_str(&op_secret_for_directory),
            Err(ViaError::InvalidConfig(message))
                if message.contains("secret `github.token` must be a cred:// reference")
        ));

        let op_public_key_for_directory = DIRECTORY_VALID.replace(
            "cred://deploy-ssh-public-key",
            "op://Private/Deploy SSH/public key",
        );
        assert!(matches!(
            Config::from_toml_str(&op_public_key_for_directory),
            Err(ViaError::InvalidConfig(message))
                if message.contains("public_key must be a cred:// reference")
        ));

        let cred_secret_for_onepassword =
            VALID.replace("op://Private/GitHub/token", "cred://github-token");
        assert!(matches!(
            Config::from_toml_str(&cred_secret_for_onepassword),
            Err(ViaError::InvalidConfig(message)) if message.contains("must be an op:// reference")
        ));

        let cred_public_key_for_onepassword = SSH_VALID.replace(
            "op://Private/Production SSH/public key",
            "cred://deploy-ssh-public-key",
        );
        assert!(matches!(
            Config::from_toml_str(&cred_public_key_for_onepassword),
            Err(ViaError::InvalidConfig(message)) if message.contains("public_key must be an op://")
        ));
    }

    #[test]
    fn rejects_directory_references_that_are_not_a_single_file_name() {
        for name in [
            "",
            ".",
            "..",
            "nested/token",
            "../token",
            "/etc/passwd",
            r"a\b",
        ] {
            let raw =
                DIRECTORY_VALID.replace("\"cred://github-token\"", &format!("'cred://{name}'"));

            assert!(
                matches!(
                    Config::from_toml_str(&raw),
                    Err(ViaError::InvalidConfig(message)) if message.contains("names a single file")
                ),
                "expected `cred://{name}` to be rejected"
            );
        }

        assert_eq!(
            directory_credential_name("cred://github-token"),
            Some("github-token")
        );
        assert_eq!(directory_credential_name("cred://a\0b"), None);
        assert_eq!(directory_credential_name("op://Private/GitHub/token"), None);
        assert_eq!(directory_credential_name("github-token"), None);
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
