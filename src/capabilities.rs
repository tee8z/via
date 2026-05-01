use serde::Serialize;

use crate::config::{CapabilityMode, Config};
use crate::error::ViaError;

#[derive(Serialize)]
struct Capabilities<'a> {
    services: Vec<ServiceCapabilities<'a>>,
}

#[derive(Serialize)]
struct ServiceCapabilities<'a> {
    name: &'a str,
    description: Option<&'a str>,
    capabilities: Vec<CapabilitySummary<'a>>,
}

#[derive(Serialize)]
struct CapabilitySummary<'a> {
    name: &'a str,
    description: Option<&'a str>,
    mode: CapabilityMode,
}

pub fn print(config: &Config, json: bool) -> Result<(), ViaError> {
    print!("{}", render(config, json)?);
    Ok(())
}

pub fn render(config: &Config, json: bool) -> Result<String, ViaError> {
    if json {
        let capabilities = Capabilities {
            services: config
                .services
                .iter()
                .map(|(name, service)| ServiceCapabilities {
                    name,
                    description: service.description.as_deref(),
                    capabilities: service
                        .commands
                        .iter()
                        .map(|(command_name, command)| CapabilitySummary {
                            name: command_name,
                            description: command.description().map(String::as_str),
                            mode: command.mode(),
                        })
                        .collect(),
                })
                .collect(),
        };
        return Ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&capabilities)?
        ));
    }

    let mut output = String::new();
    for (service_name, service) in &config.services {
        match &service.description {
            Some(description) => output.push_str(&format!("{service_name}: {description}\n")),
            None => output.push_str(&format!("{service_name}\n")),
        }

        for (command_name, command) in &service.commands {
            match command.description() {
                Some(description) => output.push_str(&format!(
                    "  {command_name} ({:?}): {description}\n",
                    command.mode()
                )),
                None => output.push_str(&format!("  {command_name} ({:?})\n", command.mode())),
            }
        }
    }

    Ok(output)
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
description = "GitHub access"
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
"#,
        )
        .unwrap()
    }

    #[test]
    fn renders_human_capabilities() {
        let output = render(&config(), false).unwrap();

        assert!(output.contains("github: GitHub access"));
        assert!(output.contains("api (Rest): REST access"));
    }

    #[test]
    fn renders_json_capabilities_without_secret_refs() {
        let output = render(&config(), true).unwrap();

        assert!(output.contains("\"name\": \"github\""));
        assert!(output.contains("\"mode\": \"rest\""));
        assert!(!output.contains("op://"));
    }
}
