use crate::config::{CapabilityMode, Config};

pub fn print(config: &Config) {
    print!("{}", render(config));
}

pub fn render(config: &Config) -> String {
    let mut output = String::new();
    output.push_str("---\n");
    output.push_str("name: via\n");
    output.push_str("description: Use via when a task needs authenticated access to configured services without asking for or handling raw secrets. via resolves credentials from 1Password and runs configured capabilities such as REST API calls or delegated CLIs.\n");
    output.push_str("---\n\n");
    output.push_str("# via\n\n");
    output.push_str("Use `via capabilities --json` before authenticated work to discover configured services and capabilities.\n\n");
    output.push_str("Rules:\n");
    output.push_str("- Never ask the user for tokens or passwords.\n");
    output.push_str("- Never call `op read` directly.\n");
    output.push_str("- Prefer REST capabilities because secrets stay inside `via`.\n");
    output.push_str("- Use delegated capabilities only when the configured binary is trusted and its native behavior is required.\n");
    output.push_str("- Do not print environment variables or credentials.\n");
    output.push_str("- Run `via doctor <service>` when a configured service fails.\n\n");
    output.push_str("Configured capabilities:\n");

    for (service_name, service) in &config.services {
        output.push('\n');
        match &service.description {
            Some(description) => output.push_str(&format!("- `{service_name}`: {description}\n")),
            None => output.push_str(&format!("- `{service_name}`\n")),
        }
        for (command_name, command) in &service.commands {
            let usage = match command.mode() {
                CapabilityMode::Rest => format!("via {service_name} {command_name} <path>"),
                CapabilityMode::Delegated => {
                    format!("via {service_name} {command_name} <tool-args...>")
                }
            };
            match command.description() {
                Some(description) => output.push_str(&format!(
                    "  - `{command_name}`: {description} Use `{usage}`.\n"
                )),
                None => output.push_str(&format!("  - `{command_name}`: use `{usage}`.\n")),
            }
        }
    }

    output
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
description = "REST access."
mode = "rest"
base_url = "https://api.github.com"

[services.github.commands.gh]
description = "CLI access."
mode = "delegated"
program = "gh"
"#,
        )
        .unwrap()
    }

    #[test]
    fn renders_agent_rules_and_configured_capabilities() {
        let output = render(&config());

        assert!(output.contains("Never ask the user for tokens"));
        assert!(output.contains("via github api <path>"));
        assert!(output.contains("via github gh <tool-args...>"));
        assert!(!output.contains("op://Private"));
    }
}
