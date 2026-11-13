use crate::capabilities::visible_services;
use crate::config::{CapabilityMode, CommandConfig, Config};
use crate::executor::ExecutionContext;

pub fn print(config: &Config) {
    print!("{}", render(config));
}

pub fn render(config: &Config) -> String {
    render_with_context(config, &ExecutionContext::direct())
}

pub fn render_with_context(config: &Config, context: &ExecutionContext) -> String {
    let mut output = String::new();
    output.push_str("---\n");
    output.push_str("name: via\n");
    output.push_str("description: Use via when a task needs authenticated access to configured services without asking for or handling raw secrets. via resolves credentials from its configured secret provider and runs configured capabilities such as REST API calls, delegated CLIs, or scoped SSH sessions.\n");
    output.push_str("---\n\n");
    output.push_str("# via\n\n");
    output.push_str("Use `via capabilities --json` before authenticated work to discover configured services and capabilities.\n\n");
    output.push_str("Rules:\n");
    output.push_str("- Never ask the user for tokens, passwords, or SSH private keys.\n");
    output.push_str("- Never call the underlying secret provider directly.\n");
    if context.is_broker() {
        output.push_str("- This `via` runs on a remote broker host. Only `via capabilities`, `via skill print`, and the REST and SSH capabilities listed below are available.\n");
        output.push_str("- Pass a request body inline or with `@-` from standard input. `@file` bodies and `--output <file>` are refused; use `--output -` to receive the raw response on standard output.\n");
        output.push_str("- Standard input bodies must finish within 30 seconds and contain at most 8 MiB. Absolute asset URLs require HTTPS and port 443, or the exact HTTPS origin configured in `base_url`.\n");
        output.push_str(
            "- Redirects are not followed. A redirected request fails and reports its target.\n",
        );
        output.push_str("- Write request paths in normal form: no `.` or `..` segments, `//`, backslashes or plain whitespace. Percent-encode special characters, such as `%20` for a space.\n");
        output.push_str("- If a capability fails with a credential or configuration error, report it to the user instead of retrying.\n");
    } else {
        output.push_str(
            "- If provider authentication is not ready, ask the user to run `via login`.\n",
        );
    }
    output.push_str("- Prefer REST capabilities because secrets stay inside `via`.\n");
    if !context.is_broker() {
        output.push_str("- Use delegated capabilities only when the configured binary is trusted and its native behavior is required.\n");
    }
    if has_ssh_capabilities(config) {
        output.push_str("- For SSH capabilities, use a listed host. Arguments after the host form the remote command, not local SSH options.\n");
    }
    output.push_str("- Do not print environment variables or credentials.\n");
    if !context.is_broker() {
        output.push_str("- Run `via config doctor <service>` when a configured service fails.\n");
    }
    output.push_str("\nConfigured capabilities:\n");

    for visible in visible_services(config, context) {
        let service_name = visible.name;
        output.push('\n');
        match &visible.service.description {
            Some(description) => output.push_str(&format!("- `{service_name}`: {description}\n")),
            None => output.push_str(&format!("- `{service_name}`\n")),
        }
        if let Some(hint) = &visible.service.hint {
            output.push_str(&format!("  - Example: `{hint}`.\n"));
        }
        for (command_name, command) in visible.commands {
            let usage = match command.mode() {
                CapabilityMode::Rest => rest_usage(context, service_name, command_name, command),
                CapabilityMode::Delegated => {
                    format!("via {service_name} {command_name} <tool-args...>")
                }
                CapabilityMode::Ssh => {
                    format!("via {service_name} {command_name} <host> [remote-command...]")
                }
            };
            let details = format!("{}{}", rest_rule_details(command), ssh_details(command));
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

fn rest_rule_details(command: &CommandConfig) -> String {
    let CommandConfig::Rest(rest) = command else {
        return String::new();
    };

    let mut details = String::new();
    if let Some(methods) = &rest.methods {
        details.push_str(&format!(" Allowed methods: `{}`.", methods.join("`, `")));
    }
    if !rest.allow_paths.is_empty() {
        details.push_str(&format!(
            " Allowed paths: `{}`.",
            rest.allow_paths.join("`, `")
        ));
    }
    if !rest.deny_paths.is_empty() {
        details.push_str(&format!(
            " Denied paths: `{}`.",
            rest.deny_paths.join("`, `")
        ));
    }
    if !rest.rules.is_empty() {
        let rules = rest
            .rules
            .iter()
            .map(crate::rules::describe_rule)
            .collect::<Vec<_>>();
        details.push_str(&format!(" Rules: `{}`.", rules.join("`, `")));
    }
    details
}

fn rest_usage(
    context: &ExecutionContext,
    service_name: &str,
    command_name: &str,
    command: &CommandConfig,
) -> String {
    // A broker caller cannot name a file on the broker host.
    let output = if context.is_broker() { "-" } else { "<file>" };
    match command {
        CommandConfig::Rest(rest) if !rest.asset_hosts.is_empty() => format!(
            "via {service_name} {command_name} <path> or via {service_name} {command_name} GET <asset-url> --output {output}"
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
user = "deploy"
hosts = ["server.example.com"]
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
        assert!(output.contains("Connect as `deploy` on port `2222`"));
        assert!(output.contains("Allowed hosts: `server.example.com`"));
        assert!(output.contains("via github shell <host> [remote-command...]"));
        assert!(!output.contains("op://Private"));
        assert!(!output.contains("op read"));
        assert!(!output.contains("onepassword-agent.sock"));
        assert!(!output.contains("public_key"));
        assert!(!output.contains("agent_socket"));
        assert!(!output.contains("ssh_program"));
        assert!(!output.contains("ssh_add_program"));
    }

    #[test]
    fn broker_context_renders_only_what_a_remote_caller_may_use() {
        let output = render_with_context(&config(), &ExecutionContext::broker());

        assert!(output.contains("runs on a remote broker host"));
        assert!(output.contains("`@file` bodies and `--output <file>` are refused"));
        assert!(output.contains("Redirects are not followed"));
        assert!(output.contains("Write request paths in normal form"));
        assert!(output.contains("via github api GET <asset-url> --output -`"));
        assert!(output.contains("via github shell <host> [remote-command...]"));
        assert!(!output.contains("via github gh"));
        assert!(!output.contains("via login"));
        assert!(!output.contains("via config doctor"));
        assert!(!output.contains("Use delegated capabilities"));
        assert!(!output.contains("op://Private"));
    }

    #[test]
    fn direct_context_matches_the_default_rendering() {
        assert_eq!(
            render_with_context(&config(), &ExecutionContext::direct()),
            render(&config())
        );
    }

    #[test]
    fn renders_rest_rules_for_agents() {
        let config = Config::from_toml_str(
            r#"
version = 1

[providers.files]
type = "directory"

[services.github]
provider = "files"

[services.github.commands.api]
description = "REST access."
mode = "rest"
base_url = "https://api.github.com"
methods = ["GET", "post"]
allow_paths = ["/repos/OWNER/**", "/user"]
deny_paths = ["/repos/*/*/actions/secrets/**"]

[[services.github.commands.api.rules]]
methods = ["PATCH"]
path = "/repos/OWNER/REPO/issues/*"
effect = "allow"

[services.github.commands.open]
description = "Unrestricted."
mode = "rest"
base_url = "https://api.github.com"
"#,
        )
        .unwrap();
        let output = render(&config);

        assert!(output.contains(
            "`api`: REST access. Allowed methods: `GET`, `POST`. Allowed paths: `/repos/OWNER/**`, `/user`. Denied paths: `/repos/*/*/actions/secrets/**`. Rules: `allow PATCH /repos/OWNER/REPO/issues/*`. Use `via github api <path>`."
        ));
        assert!(output.contains("`open`: Unrestricted. Use `via github open <path>`."));
    }
}
