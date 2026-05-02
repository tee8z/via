use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::{Config, ProviderConfig};
use crate::error::ViaError;

pub fn run(config_path: Option<&Path>, provider_name: Option<&str>) -> Result<(), ViaError> {
    let providers = login_targets(config_path, provider_name)?;

    if providers.is_empty() {
        return Err(ViaError::InvalidConfig(
            "no login-capable providers are configured".to_owned(),
        ));
    }

    for provider in providers {
        login_onepassword(&provider.name, provider.account.as_deref())?;
    }

    Ok(())
}

fn login_targets(
    config_path: Option<&Path>,
    provider_name: Option<&str>,
) -> Result<Vec<OnePasswordLoginTarget>, ViaError> {
    match Config::load(config_path) {
        Ok(config) => onepassword_login_targets(&config, provider_name),
        Err(ViaError::ConfigNotFound(_)) if config_path.is_none() => {
            default_onepassword_login_targets(provider_name)
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
struct OnePasswordLoginTarget {
    name: String,
    account: Option<String>,
}

fn onepassword_login_targets(
    config: &Config,
    provider_name: Option<&str>,
) -> Result<Vec<OnePasswordLoginTarget>, ViaError> {
    if let Some(provider_name) = provider_name {
        let provider = config.providers.get(provider_name).ok_or_else(|| {
            ViaError::InvalidConfig(format!("provider `{provider_name}` is not configured"))
        })?;
        return Ok(onepassword_target(provider_name, provider)
            .into_iter()
            .collect());
    }

    Ok(config
        .providers
        .iter()
        .filter_map(|(name, provider)| onepassword_target(name, provider))
        .collect())
}

fn default_onepassword_login_targets(
    provider_name: Option<&str>,
) -> Result<Vec<OnePasswordLoginTarget>, ViaError> {
    match provider_name {
        Some("onepassword") | None => Ok(vec![OnePasswordLoginTarget {
            name: "onepassword".to_owned(),
            account: None,
        }]),
        Some(provider_name) => Err(ViaError::InvalidConfig(format!(
            "provider `{provider_name}` is not configured"
        ))),
    }
}

fn onepassword_target(name: &str, provider: &ProviderConfig) -> Option<OnePasswordLoginTarget> {
    match provider {
        ProviderConfig::OnePassword { account, .. } => Some(OnePasswordLoginTarget {
            name: name.to_owned(),
            account: account.clone(),
        }),
    }
}

fn login_onepassword(provider_name: &str, account: Option<&str>) -> Result<(), ViaError> {
    println!("provider {provider_name} (1Password): signing in");

    let args = onepassword_signin_args(account);
    let status = Command::new("op")
        .args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|source| ViaError::MissingProgram {
            program: "op".to_owned(),
            source,
        })?;

    if !status.success() {
        return Err(ViaError::ExternalCommandFailed {
            program: "op".to_owned(),
            status: status.code(),
            stderr: "op signin did not complete successfully".to_owned(),
        });
    }

    println!("provider {provider_name} (1Password): authenticated");
    Ok(())
}

fn onepassword_signin_args(account: Option<&str>) -> Vec<String> {
    let mut args = vec!["signin".to_owned()];
    if let Some(account) = account {
        args.push("--account".to_owned());
        args.push(account.to_owned());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
version = 1

[providers.onepassword]
type = "1password"
account = "example.1password.com"
"#;

    #[test]
    fn builds_plain_onepassword_signin_args() {
        assert_eq!(onepassword_signin_args(None), ["signin"]);
    }

    #[test]
    fn builds_account_scoped_onepassword_signin_args() {
        assert_eq!(
            onepassword_signin_args(Some("example.1password.com")),
            ["signin", "--account", "example.1password.com"]
        );
    }

    #[test]
    fn selects_configured_onepassword_provider() {
        let config = Config::from_toml_str(CONFIG).unwrap();
        let targets = onepassword_login_targets(&config, None).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "onepassword");
        assert_eq!(targets[0].account.as_deref(), Some("example.1password.com"));
    }

    #[test]
    fn rejects_unknown_provider() {
        let config = Config::from_toml_str(CONFIG).unwrap();
        let error = onepassword_login_targets(&config, Some("missing")).unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("provider `missing`"))
        );
    }

    #[test]
    fn defaults_to_onepassword_when_config_is_missing() {
        let targets = default_onepassword_login_targets(None).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "onepassword");
        assert_eq!(targets[0].account, None);
    }

    #[test]
    fn rejects_unknown_provider_when_config_is_missing() {
        let error = default_onepassword_login_targets(Some("missing")).unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("provider `missing`"))
        );
    }
}
