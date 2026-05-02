use std::collections::{BTreeMap, BTreeSet};

use crate::config::{Config, ProviderConfig};
use crate::error::ViaError;
use crate::secrets::SecretValue;

mod onepassword;

pub trait SecretProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError>;
}

pub struct ProviderRegistry {
    providers: BTreeMap<String, Box<dyn SecretProvider>>,
}

impl ProviderRegistry {
    pub fn from_config(config: &Config) -> Result<Self, ViaError> {
        let mut providers: BTreeMap<String, Box<dyn SecretProvider>> = BTreeMap::new();
        for (name, provider) in &config.providers {
            match provider {
                ProviderConfig::OnePassword {
                    account,
                    cache,
                    cache_ttl_seconds,
                } => {
                    providers.insert(
                        name.clone(),
                        Box::new(onepassword::OnePasswordCliProvider::new(
                            account.clone(),
                            *cache,
                            *cache_ttl_seconds,
                            provider_secret_references(config, name),
                        )),
                    );
                }
            }
        }

        Ok(Self { providers })
    }

    pub fn get(&self, name: &str) -> Result<&dyn SecretProvider, ViaError> {
        self.providers
            .get(name)
            .map(|provider| provider.as_ref())
            .ok_or_else(|| ViaError::InvalidConfig(format!("unknown provider `{name}`")))
    }
}

fn provider_secret_references(config: &Config, provider_name: &str) -> Vec<String> {
    config
        .services
        .values()
        .filter(|service| service.provider == provider_name)
        .flat_map(|service| service.secrets.values().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
"#,
        )
        .unwrap()
    }

    #[test]
    fn builds_registry_from_config() {
        let registry = ProviderRegistry::from_config(&config()).unwrap();

        assert!(registry.get("onepassword").is_ok());
    }

    #[test]
    fn reports_missing_provider() {
        let registry = ProviderRegistry::from_config(&config()).unwrap();
        let error = match registry.get("missing") {
            Ok(_) => panic!("expected missing provider error"),
            Err(error) => error,
        };

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("unknown provider"))
        );
    }
}
