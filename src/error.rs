use std::io;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ViaError {
    #[error("{0}")]
    InvalidCli(String),

    #[error(transparent)]
    Clap(#[from] clap::Error),

    #[error("could not determine config path: {0}")]
    ConfigNotFound(String),

    #[error("failed to read config `{path}`: {source}")]
    ReadConfig { path: PathBuf, source: io::Error },

    #[error("failed to parse config: {0}")]
    ParseConfig(#[from] toml::de::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("unknown service `{0}`")]
    UnknownService(String),

    #[error("unknown capability `{capability}` for service `{service}`")]
    UnknownCapability { service: String, capability: String },

    #[error("missing required argument: {0}")]
    MissingArgument(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("program `{program}` was not found: {source}")]
    MissingProgram { program: String, source: io::Error },

    #[error("program `{program}` failed with status {status:?}: {stderr}")]
    ExternalCommandFailed {
        program: String,
        status: Option<i32>,
        stderr: String,
    },

    #[error("SSH command failed with status {status:?}")]
    SshCommandFailed { status: Option<i32> },

    #[error("SSH agent socket `{path}` is unavailable: {reason}")]
    SshAgentUnavailable { path: PathBuf, reason: String },

    #[error("resolved SSH public key is invalid: {0}")]
    InvalidSshPublicKey(String),

    #[error("configured SSH identity is not available from the selected agent")]
    SshIdentityUnavailable,

    #[error("SSH identity path cannot be passed safely to OpenSSH: {0}")]
    InvalidSshIdentityPath(String),

    #[error("secret `{secret}` is not configured for service `{service}`")]
    UnknownSecret { service: String, secret: String },

    #[error("credential `{name}` is unavailable: {reason}")]
    SecretUnavailable { name: String, reason: String },

    #[error("{message}")]
    Denied {
        reason: &'static str,
        message: String,
    },

    #[error("doctor checks failed; see output above for setup guidance")]
    DoctorFailed,

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

impl ViaError {
    pub fn denied(reason: &'static str, message: impl Into<String>) -> Self {
        ViaError::Denied {
            reason,
            message: message.into(),
        }
    }

    // A short, stable, machine-readable name for audit records. It never
    // contains caller input or secret material.
    pub fn kind(&self) -> &'static str {
        match self {
            ViaError::InvalidCli(_) | ViaError::Clap(_) => "invalid_cli",
            ViaError::ConfigNotFound(_) => "config_not_found",
            ViaError::ReadConfig { .. } => "config_unreadable",
            ViaError::ParseConfig(_) => "config_parse_failed",
            ViaError::InvalidConfig(_) => "invalid_config",
            ViaError::UnknownService(_) => "unknown_service",
            ViaError::UnknownCapability { .. } => "unknown_capability",
            ViaError::MissingArgument(_) => "missing_argument",
            ViaError::InvalidArgument(_) => "invalid_argument",
            ViaError::MissingProgram { .. } => "missing_program",
            ViaError::ExternalCommandFailed { .. } => "command_failed",
            ViaError::SshCommandFailed { .. } => "ssh_command_failed",
            ViaError::SshAgentUnavailable { .. } => "ssh_agent_unavailable",
            ViaError::InvalidSshPublicKey(_) => "invalid_ssh_public_key",
            ViaError::SshIdentityUnavailable => "ssh_identity_unavailable",
            ViaError::InvalidSshIdentityPath(_) => "invalid_ssh_identity_path",
            ViaError::UnknownSecret { .. } => "unknown_secret",
            ViaError::SecretUnavailable { .. } => "secret_unavailable",
            ViaError::Denied { reason, .. } => *reason,
            ViaError::DoctorFailed => "doctor_failed",
            ViaError::Http(_) => "http_error",
            ViaError::Json(_) => "json_error",
            ViaError::Io(_) => "io_error",
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            ViaError::Clap(error) => {
                if error.use_stderr() {
                    2
                } else {
                    0
                }
            }
            ViaError::SshCommandFailed { status: Some(code) } if (1..=255).contains(code) => {
                *code as u8
            }
            ViaError::InvalidCli(_)
            | ViaError::InvalidConfig(_)
            | ViaError::UnknownService(_)
            | ViaError::UnknownCapability { .. }
            | ViaError::MissingArgument(_)
            | ViaError::InvalidArgument(_)
            | ViaError::UnknownSecret { .. }
            | ViaError::Denied { .. } => 2,
            ViaError::ConfigNotFound(_)
            | ViaError::ReadConfig { .. }
            | ViaError::ParseConfig(_)
            | ViaError::MissingProgram { .. }
            | ViaError::ExternalCommandFailed { .. }
            | ViaError::SshCommandFailed { .. }
            | ViaError::SshAgentUnavailable { .. }
            | ViaError::InvalidSshPublicKey(_)
            | ViaError::SshIdentityUnavailable
            | ViaError::InvalidSshIdentityPath(_)
            | ViaError::SecretUnavailable { .. }
            | ViaError::DoctorFailed
            | ViaError::Http(_)
            | ViaError::Json(_)
            | ViaError::Io(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_and_usage_errors_exit_two() {
        assert_eq!(ViaError::InvalidConfig("bad".to_owned()).exit_code(), 2);
        assert_eq!(ViaError::UnknownService("github".to_owned()).exit_code(), 2);
    }

    #[test]
    fn runtime_errors_exit_one() {
        let error = ViaError::ConfigNotFound("missing".to_owned());

        assert_eq!(error.exit_code(), 1);
        assert_eq!(
            ViaError::InvalidSshIdentityPath("unsafe path".to_owned()).exit_code(),
            1
        );
    }

    #[test]
    fn denied_errors_exit_two_and_report_their_reason() {
        let error = ViaError::denied("method_not_allowed", "method `DELETE` is not allowed");

        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.kind(), "method_not_allowed");
        assert_eq!(error.to_string(), "method `DELETE` is not allowed");
    }

    #[test]
    fn unavailable_credentials_exit_one_without_a_value() {
        let error = ViaError::SecretUnavailable {
            name: "github-token".to_owned(),
            reason: "the credential file does not exist or is not accessible".to_owned(),
        };

        assert_eq!(error.exit_code(), 1);
        assert_eq!(error.kind(), "secret_unavailable");
        assert!(error.to_string().contains("credential `github-token`"));
    }

    #[test]
    fn ssh_errors_preserve_valid_child_exit_codes() {
        assert_eq!(
            ViaError::SshCommandFailed { status: Some(42) }.exit_code(),
            42
        );
        assert_eq!(
            ViaError::SshCommandFailed { status: Some(255) }.exit_code(),
            255
        );
        assert_eq!(ViaError::SshCommandFailed { status: None }.exit_code(), 1);
    }
}
