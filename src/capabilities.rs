use serde::Serialize;

use crate::config::{CapabilityMode, CommandConfig, Config};
use crate::error::ViaError;

#[derive(Serialize)]
struct Capabilities<'a> {
    services: Vec<ServiceCapabilities<'a>>,
}

#[derive(Serialize)]
struct ServiceCapabilities<'a> {
    name: &'a str,
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'a str>,
    capabilities: Vec<CapabilitySummary<'a>>,
}

#[derive(Serialize)]
struct CapabilitySummary<'a> {
    name: &'a str,
    description: Option<&'a str>,
    mode: CapabilityMode,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    asset_hosts: Vec<&'a str>,
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
                    hint: service.hint.as_deref(),
                    capabilities: service
                        .commands
                        .iter()
                        .map(|(command_name, command)| CapabilitySummary {
                            name: command_name,
                            description: command.description().map(String::as_str),
                            mode: command.mode(),
                            asset_hosts: asset_hosts(command),
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
        if let Some(hint) = &service.hint {
            output.push_str(&format!("  hint: {hint}\n"));
        }

        for (command_name, command) in &service.commands {
            match command.description() {
                Some(description) => output.push_str(&format!(
                    "  {command_name} ({:?}): {description}\n",
                    command.mode()
                )),
                None => output.push_str(&format!("  {command_name} ({:?})\n", command.mode())),
            }
            let asset_hosts = asset_hosts(command);
            if !asset_hosts.is_empty() {
                output.push_str(&format!("    asset hosts: {}\n", asset_hosts.join(", ")));
            }
        }
    }

    Ok(output)
}

fn asset_hosts(command: &CommandConfig) -> Vec<&str> {
    match command {
        CommandConfig::Rest(rest) => rest.asset_hosts.iter().map(String::as_str).collect(),
        CommandConfig::Delegated(_) => Vec::new(),
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
description = "GitHub access"
hint = "via github api /user"
provider = "onepassword"

[services.github.secrets]
token = "op://Private/GitHub/token"

[services.github.commands.api]
description = "REST access"
mode = "rest"
base_url = "https://api.github.com"
asset_hosts = ["uploads.linear.app"]

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
        assert!(output.contains("hint: via github api /user"));
        assert!(output.contains("api (Rest): REST access"));
        assert!(output.contains("asset hosts: uploads.linear.app"));
    }

    #[test]
    fn renders_json_capabilities_without_secret_refs() {
        let output = render(&config(), true).unwrap();

        assert!(output.contains("\"name\": \"github\""));
        assert!(output.contains("\"hint\": \"via github api /user\""));
        assert!(output.contains("\"mode\": \"rest\""));
        assert!(output.contains("\"asset_hosts\""));
        assert!(output.contains("\"uploads.linear.app\""));
        assert!(!output.contains("op://"));
    }
}
