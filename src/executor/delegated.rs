use std::process::{Command, Stdio};

use crate::config::{DelegatedCommandConfig, ServiceConfig};
use crate::error::ViaError;
use crate::providers::SecretProvider;
use crate::redaction::Redactor;

pub fn execute(
    service_name: &str,
    service: &ServiceConfig,
    config: &DelegatedCommandConfig,
    provider: &dyn SecretProvider,
    args: Vec<String>,
) -> Result<(), ViaError> {
    let mut command = Command::new(&config.program);
    command.args(&config.args_prefix);
    command.args(args);
    command.env_clear();
    pass_safe_env(&mut command);

    let mut redactor = Redactor::new();
    for (name, binding) in &config.inject.env {
        let reference =
            service
                .secrets
                .get(&binding.secret)
                .ok_or_else(|| ViaError::UnknownSecret {
                    service: service_name.to_owned(),
                    secret: binding.secret.clone(),
                })?;
        let secret = provider.resolve(reference)?;
        redactor.add(secret.expose());
        command.env(name, secret.expose());
    }

    let output = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let stdout = redactor.redact(&String::from_utf8_lossy(&output.stdout));
    let stderr = redactor.redact(&String::from_utf8_lossy(&output.stderr));

    print!("{stdout}");
    eprint!("{stderr}");

    if output.status.success() {
        return Ok(());
    }

    Err(ViaError::ExternalCommandFailed {
        program: config.program.clone(),
        status: output.status.code(),
        stderr: stderr.trim().to_owned(),
    })
}

fn pass_safe_env(command: &mut Command) {
    for key in [
        "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::{InjectConfig, SecretBinding};
    use crate::secrets::SecretValue;

    use super::*;

    struct FakeProvider;

    impl SecretProvider for FakeProvider {
        fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
            assert_eq!(reference, "op://Private/GitHub/token");
            Ok(SecretValue::new("secret-token".to_owned()))
        }
    }

    fn service() -> ServiceConfig {
        ServiceConfig {
            description: None,
            provider: "onepassword".to_owned(),
            secrets: BTreeMap::from([("token".to_owned(), "op://Private/GitHub/token".to_owned())]),
            commands: BTreeMap::new(),
        }
    }

    fn delegated(program: &str, args_prefix: Vec<String>) -> DelegatedCommandConfig {
        DelegatedCommandConfig {
            description: None,
            program: program.to_owned(),
            args_prefix,
            inject: InjectConfig {
                env: BTreeMap::from([(
                    "GH_TOKEN".to_owned(),
                    SecretBinding {
                        secret: "token".to_owned(),
                    },
                )]),
            },
            check: Vec::new(),
        }
    }

    #[test]
    fn delegated_command_succeeds_with_injected_secret() {
        execute(
            "github",
            &service(),
            &delegated("sh", vec!["-c".to_owned()]),
            &FakeProvider,
            vec!["test \"$GH_TOKEN\" = secret-token".to_owned()],
        )
        .unwrap();
    }

    #[test]
    fn delegated_command_redacts_secret_from_failure_stderr() {
        let error = execute(
            "github",
            &service(),
            &delegated("sh", vec!["-c".to_owned()]),
            &FakeProvider,
            vec!["printf '%s' \"$GH_TOKEN\" >&2; exit 7".to_owned()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::ExternalCommandFailed {
                status: Some(7),
                stderr,
                ..
            } if stderr == "[REDACTED]"
        ));
    }
}
