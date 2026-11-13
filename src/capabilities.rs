use serde::Serialize;

use crate::config::{CapabilityMode, CommandConfig, Config, RuleEffect};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    rest: Option<RestRulesSummary<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh: Option<SshCapabilitySummary<'a>>,
}

// The method and path rules of a REST capability. Absent when the
// capability configures none.
#[derive(Serialize)]
struct RestRulesSummary<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    methods: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allow_paths: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny_paths: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<RestRuleSummary<'a>>,
}

#[derive(Serialize)]
struct RestRuleSummary<'a> {
    effect: RuleEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    methods: Option<Vec<&'a str>>,
    path: &'a str,
}

#[derive(Serialize)]
struct SshCapabilitySummary<'a> {
    profile: &'a str,
    user: &'a str,
    hosts: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
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
                            rest: rest_rules_summary(command),
                            ssh: ssh_summary(command),
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
            print_rest_rules_summary(&mut output, command);
            print_ssh_summary(&mut output, command);
        }
    }

    Ok(output)
}

fn asset_hosts(command: &CommandConfig) -> Vec<&str> {
    match command {
        CommandConfig::Rest(rest) => rest.asset_hosts.iter().map(String::as_str).collect(),
        CommandConfig::Delegated(_) | CommandConfig::Ssh(_) => Vec::new(),
    }
}

fn rest_rules_summary(command: &CommandConfig) -> Option<RestRulesSummary<'_>> {
    let CommandConfig::Rest(rest) = command else {
        return None;
    };
    if !rest.has_rules() {
        return None;
    }

    Some(RestRulesSummary {
        methods: rest.methods.as_deref().map(str_list),
        allow_paths: str_list(&rest.allow_paths),
        deny_paths: str_list(&rest.deny_paths),
        rules: rest
            .rules
            .iter()
            .map(|rule| RestRuleSummary {
                effect: rule.effect,
                methods: rule.methods.as_deref().map(str_list),
                path: &rule.path,
            })
            .collect(),
    })
}

fn str_list(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

fn print_rest_rules_summary(output: &mut String, command: &CommandConfig) {
    let CommandConfig::Rest(rest) = command else {
        return;
    };

    if let Some(methods) = &rest.methods {
        output.push_str(&format!("    allowed methods: {}\n", methods.join(", ")));
    }
    if !rest.allow_paths.is_empty() {
        output.push_str(&format!(
            "    allowed paths: {}\n",
            rest.allow_paths.join(", ")
        ));
    }
    if !rest.deny_paths.is_empty() {
        output.push_str(&format!(
            "    denied paths: {}\n",
            rest.deny_paths.join(", ")
        ));
    }
    for rule in &rest.rules {
        output.push_str(&format!(
            "    rule: {}\n",
            crate::rules::describe_rule(rule)
        ));
    }
}

fn ssh_summary(command: &CommandConfig) -> Option<SshCapabilitySummary<'_>> {
    let CommandConfig::Ssh(ssh) = command else {
        return None;
    };

    Some(SshCapabilitySummary {
        profile: &ssh.profile,
        user: &ssh.user,
        hosts: ssh.hosts.iter().map(String::as_str).collect(),
        port: ssh.port,
    })
}

fn print_ssh_summary(output: &mut String, command: &CommandConfig) {
    let Some(ssh) = ssh_summary(command) else {
        return;
    };

    output.push_str(&format!("    SSH profile: {}\n", ssh.profile));
    output.push_str(&format!("    SSH user: {}\n", ssh.user));
    output.push_str(&format!("    allowed hosts: {}\n", ssh.hosts.join(", ")));
    if let Some(port) = ssh.port {
        output.push_str(&format!("    SSH port: {port}\n"));
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
description = "REST access"
mode = "rest"
base_url = "https://api.github.com"
asset_hosts = ["uploads.linear.app"]

[services.github.commands.api.auth]
type = "bearer"
secret = "token"

[ssh_profiles.production]
provider = "onepassword"
public_key = "op://Private/SSH/public key"
{}

[services.github.commands.shell]
description = "SSH access"
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
    fn renders_human_capabilities() {
        let output = render(&config(), false).unwrap();

        assert!(output.contains("github: GitHub access"));
        assert!(output.contains("hint: via github api /user"));
        assert!(output.contains("api (Rest): REST access"));
        assert!(output.contains("asset hosts: uploads.linear.app"));
        assert!(output.contains("shell (Ssh): SSH access"));
        assert!(output.contains("SSH profile: production"));
        assert!(output.contains("SSH user: deploy"));
        assert!(output.contains("allowed hosts: server.example.com"));
        assert!(output.contains("SSH port: 2222"));
        assert!(!output.contains("op://Private/SSH"));
        assert!(!output.contains("onepassword-agent.sock"));
        assert!(!output.contains("/trusted/bin"));
    }

    fn config_with_rules() -> Config {
        Config::from_toml_str(
            r#"
version = 1

[providers.files]
type = "directory"

[services.github]
provider = "files"

[services.github.secrets]
token = "cred://github-token"

[services.github.commands.api]
mode = "rest"
base_url = "https://api.github.com"
methods = ["get", "post"]
allow_paths = ["/repos/OWNER/**", "/user"]
deny_paths = ["/repos/*/*/actions/secrets/**"]

[[services.github.commands.api.rules]]
methods = ["PATCH"]
path = "/repos/OWNER/REPO/issues/*"
effect = "allow"

[[services.github.commands.api.rules]]
path = "/repos/OWNER/REPO/keys/**"
effect = "deny"

[services.github.commands.api.auth]
type = "bearer"
secret = "token"
"#,
        )
        .unwrap()
    }

    #[test]
    fn renders_rest_rules_in_human_capabilities() {
        let output = render(&config_with_rules(), false).unwrap();

        assert!(output.contains("    allowed methods: GET, POST\n"));
        assert!(output.contains("    allowed paths: /repos/OWNER/**, /user\n"));
        assert!(output.contains("    denied paths: /repos/*/*/actions/secrets/**\n"));
        assert!(output.contains("    rule: allow PATCH /repos/OWNER/REPO/issues/*\n"));
        assert!(output.contains("    rule: deny ANY /repos/OWNER/REPO/keys/**\n"));
        assert!(!output.contains("cred://"));
    }

    #[test]
    fn renders_rest_rules_in_json_capabilities() {
        let output = render(&config_with_rules(), true).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rest = &json["services"][0]["capabilities"][0]["rest"];

        assert_eq!(rest["methods"], serde_json::json!(["GET", "POST"]));
        assert_eq!(
            rest["allow_paths"],
            serde_json::json!(["/repos/OWNER/**", "/user"])
        );
        assert_eq!(
            rest["deny_paths"],
            serde_json::json!(["/repos/*/*/actions/secrets/**"])
        );
        assert_eq!(
            rest["rules"],
            serde_json::json!([
                {
                    "effect": "allow",
                    "methods": ["PATCH"],
                    "path": "/repos/OWNER/REPO/issues/*"
                },
                { "effect": "deny", "path": "/repos/OWNER/REPO/keys/**" }
            ])
        );
        assert!(!output.contains("cred://"));
    }

    #[test]
    fn omits_the_rest_summary_without_rules() {
        let output = render(&config(), true).unwrap();

        assert!(!output.contains("\"rest\":"));
        assert!(!output.contains("allow_paths"));
    }

    #[test]
    fn renders_json_capabilities_without_secret_refs() {
        let output = render(&config(), true).unwrap();

        assert!(output.contains("\"name\": \"github\""));
        assert!(output.contains("\"hint\": \"via github api /user\""));
        assert!(output.contains("\"mode\": \"rest\""));
        assert!(output.contains("\"asset_hosts\""));
        assert!(output.contains("\"uploads.linear.app\""));
        assert!(output.contains("\"mode\": \"ssh\""));
        assert!(output.contains("\"profile\": \"production\""));
        assert!(output.contains("\"user\": \"deploy\""));
        assert!(output.contains("\"server.example.com\""));
        assert!(output.contains("\"port\": 2222"));
        assert!(!output.contains("op://"));
        assert!(!output.contains("onepassword-agent.sock"));
        assert!(!output.contains("\"public_key\""));
        assert!(!output.contains("\"agent_socket\""));
        assert!(!output.contains("ssh_program"));
        assert!(!output.contains("ssh_add_program"));
    }
}
