use crate::config::{CapabilityMode, CommandConfig, Config};

pub fn print(config: &Config) {
    print!("{}", render(config));
}

pub fn render(config: &Config) -> String {
    let mut output = String::new();
    output.push_str("---\n");
    output.push_str("name: via\n");
    output.push_str("description: Use via when a task needs authenticated access to configured services without asking for or handling raw secrets. via resolves credentials from 1Password and runs configured capabilities such as REST API calls, delegated CLIs, or scoped SSH sessions.\n");
    output.push_str("---\n\n");
    output.push_str("# via\n\n");
    output.push_str("Use `via capabilities --json` before authenticated work to discover configured services and capabilities.\n\n");
    output.push_str("Rules:\n");
    output.push_str("- Never ask the user for tokens, passwords, or SSH private keys.\n");
    output.push_str("- Never call the underlying secret provider directly.\n");
    output
        .push_str("- If provider authentication is not ready, ask the user to run `via login`.\n");
    output.push_str("- Prefer REST capabilities because secrets stay inside `via`.\n");
    output.push_str("- Use delegated capabilities only when the configured binary is trusted and its native behavior is required.\n");
    if has_ssh_capabilities(config) {
        output.push_str("- For SSH capabilities, use a listed host. Arguments after the host form the remote command, not local SSH options.\n");
    }
    output.push_str("- Do not print environment variables or credentials.\n");
    output.push_str("- Run `via config doctor <service>` when a configured service fails.\n\n");
    output.push_str("Configured capabilities:\n");

    for (service_name, service) in &config.services {
        output.push('\n');
        match &service.description {
            Some(description) => output.push_str(&format!("- `{service_name}`: {description}\n")),
            None => output.push_str(&format!("- `{service_name}`\n")),
        }
        if let Some(hint) = &service.hint {
            output.push_str(&format!("  - Example: `{hint}`.\n"));
        }
        for (command_name, command) in &service.commands {
            let usage = match command.mode() {
                CapabilityMode::Rest => rest_usage(service_name, command_name, command),
                CapabilityMode::Delegated => {
                    format!("via {service_name} {command_name} <tool-args...>")
                }
                CapabilityMode::Ssh => {
                    format!("via {service_name} {command_name} <host> [remote-command...]")
                }
            };
            let details = ssh_details(command);
            match command.description() {
                Some(description) => output.push_str(&format!(
                    "  - `{command_name}`: {description}{details} Use `{usage}`.\n"
                )),
                None => {
                    output.push_str(&format!("  - `{command_name}`:{details} Use `{usage}`.\n"))
                }
            }
        }
    }

    output
}

fn has_ssh_capabilities(config: &Config) -> bool {
    config
        .services
        .values()
        .flat_map(|service| service.commands.values())
        .any(|command| matches!(command, CommandConfig::Ssh(_)))
}

fn ssh_details(command: &CommandConfig) -> String {
    let CommandConfig::Ssh(ssh) = command else {
        return String::new();
    };

    let port = ssh
        .port
        .map(|port| format!(" on port `{port}`"))
        .unwrap_or_default();
    format!(
        " Connect as `{}`{port}. Allowed hosts: `{}`.",
        ssh.user,
        ssh.hosts.join("`, `")
    )
}

fn rest_usage(service_name: &str, command_name: &str, command: &CommandConfig) -> String {
    match command {
        CommandConfig::Rest(rest) if !rest.asset_hosts.is_empty() => format!(
            "via {service_name} {command_name} <path> or via {service_name} {command_name} GET <asset-url> --output <file>"
        ),
        _ => format!("via {service_name} {command_name} <path>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const SSH_RUNTIME_PATHS: &str = r"agent_socket = '\\.\pipe\openssh-ssh-agent'
ssh_program = 'C:\Windows\System32\OpenSSH\ssh.exe'
ssh_add_program = 'C:\Windows\System32\OpenSSH\ssh-add.exe'";
    #[cfg(not(windows))]
    const SSH_RUNTIME_PATHS: &str = r#"agent_socket = "/tmp/onepassword-agent.sock"
ssh_program = "/trusted/bin/ssh"
ssh_add_program = "/trusted/bin/ssh-add""#;

    fn config() -> Config {
        Config::from_toml_str(&format!(
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
description = "REST access."
mode = "rest"
base_url = "https://api.github.com"
asset_hosts = ["uploads.linear.app"]

[services.github.commands.gh]
description = "CLI access."
mode = "delegated"
program = "gh"

[ssh_profiles.production]
provider = "onepassword"
public_key = "op://Private/SSH/public key"
{}

[services.github.commands.shell]
description = "SSH access."
mode = "ssh"
profile = "production"
user = "volt"
hosts = ["btcd.example.com"]
port = 2222
"#,
            SSH_RUNTIME_PATHS
        ))
        .unwrap()
    }

    #[test]
    fn renders_agent_rules_and_configured_capabilities() {
        let output = render(&config());

        assert!(output.contains("Never ask the user for tokens"));
        assert!(output.contains("Never call the underlying secret provider directly"));
        assert!(output.contains("via login"));
        assert!(output.contains("Example: `via github api /user`."));
        assert!(output.contains("via github api <path>"));
        assert!(output.contains("via github api GET <asset-url> --output <file>"));
        assert!(output.contains("via github gh <tool-args...>"));
        assert!(output.contains("For SSH capabilities, use a listed host"));
        assert!(output.contains("Connect as `volt` on port `2222`"));
        assert!(output.contains("Allowed hosts: `btcd.example.com`"));
        assert!(output.contains("via github shell <host> [remote-command...]"));
        assert!(!output.contains("op://Private"));
        assert!(!output.contains("op read"));
        assert!(!output.contains("onepassword-agent.sock"));
        assert!(!output.contains("public_key"));
        assert!(!output.contains("agent_socket"));
        assert!(!output.contains("ssh_program"));
        assert!(!output.contains("ssh_add_program"));
    }
}
