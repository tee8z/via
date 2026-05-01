use std::process::Command;

use crate::error::ViaError;
use crate::providers::SecretProvider;
use crate::secrets::SecretValue;

pub struct OnePasswordCliProvider {
    account: Option<String>,
}

impl OnePasswordCliProvider {
    pub fn new(account: Option<String>) -> Self {
        Self { account }
    }
}

impl SecretProvider for OnePasswordCliProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
        let mut command = Command::new("op");
        command.arg("read").arg(reference);
        if let Some(account) = &self.account {
            command.arg("--account").arg(account);
        }

        let output = command
            .output()
            .map_err(|source| ViaError::MissingProgram {
                program: "op".to_owned(),
                source,
            })?;

        if !output.status.success() {
            return Err(ViaError::ExternalCommandFailed {
                program: "op".to_owned(),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }

        let secret = String::from_utf8_lossy(&output.stdout)
            .trim_end_matches(['\r', '\n'])
            .to_owned();
        Ok(SecretValue::new(secret))
    }
}
