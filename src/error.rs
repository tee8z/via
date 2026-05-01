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

    #[error("secret `{secret}` is not configured for service `{service}`")]
    UnknownSecret { service: String, secret: String },

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

impl ViaError {
    pub fn exit_code(&self) -> u8 {
        match self {
            ViaError::Clap(error) => {
                if error.use_stderr() {
                    2
                } else {
                    0
                }
            }
            ViaError::InvalidCli(_)
            | ViaError::InvalidConfig(_)
            | ViaError::UnknownService(_)
            | ViaError::UnknownCapability { .. }
            | ViaError::MissingArgument(_)
            | ViaError::InvalidArgument(_)
            | ViaError::UnknownSecret { .. } => 2,
            ViaError::ConfigNotFound(_)
            | ViaError::ReadConfig { .. }
            | ViaError::ParseConfig(_)
            | ViaError::MissingProgram { .. }
            | ViaError::ExternalCommandFailed { .. }
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
    }
}
