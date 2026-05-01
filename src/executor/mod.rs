use crate::config::{CommandConfig, Config};
use crate::error::ViaError;
use crate::providers::ProviderRegistry;

mod delegated;
mod rest;

pub fn invoke(
    config: &Config,
    providers: &ProviderRegistry,
    service_name: &str,
    capability_name: &str,
    args: Vec<String>,
) -> Result<(), ViaError> {
    let service = config
        .services
        .get(service_name)
        .ok_or_else(|| ViaError::UnknownService(service_name.to_owned()))?;
    let command =
        service
            .commands
            .get(capability_name)
            .ok_or_else(|| ViaError::UnknownCapability {
                service: service_name.to_owned(),
                capability: capability_name.to_owned(),
            })?;
    let provider = providers.get(&service.provider)?;

    match command {
        CommandConfig::Rest(rest) => rest::execute(service_name, service, rest, provider, args),
        CommandConfig::Delegated(delegated) => {
            delegated::execute(service_name, service, delegated, provider, args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn invoke_rejects_unknown_service() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let error = invoke(&config, &providers, "missing", "api", Vec::new()).unwrap_err();

        assert!(matches!(error, ViaError::UnknownService(service) if service == "missing"));
    }

    #[test]
    fn invoke_rejects_unknown_capability() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let error = invoke(&config, &providers, "github", "missing", Vec::new()).unwrap_err();

        assert!(matches!(
            error,
            ViaError::UnknownCapability {
                service,
                capability
            } if service == "github" && capability == "missing"
        ));
    }
}
