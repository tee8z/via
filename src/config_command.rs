use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

use crate::cli::ConfigCommand;
use crate::config::{self, Config};
use crate::doctor;
use crate::error::ViaError;

pub fn run(path_override: Option<&Path>, command: ConfigCommand) -> Result<(), ViaError> {
    let path = config::resolve_path(path_override)?;

    match command {
        ConfigCommand::Configure => configure(&path),
        ConfigCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::Doctor { service } => {
            if !path.exists() {
                print_missing_config(&path);
                return Err(ViaError::ConfigNotFound(
                    "run `via config` in an interactive terminal to create one".to_owned(),
                ));
            }

            let config = Config::load(Some(&path))?;
            doctor::run(&config, service.as_deref())
        }
    }
}

fn configure(path: &Path) -> Result<(), ViaError> {
    if path.exists() {
        println!("via config: {}", path.display());
        println!("Run `via config doctor` to check providers, secrets, and delegated tools.");
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        print_missing_config(path);
        return Err(ViaError::ConfigNotFound(
            "run `via config` in an interactive terminal to create one".to_owned(),
        ));
    }

    println!("No via config found.");
    println!();
    println!("via can create one at:");
    println!("  {}", path.display());
    println!();

    match prompt_choice(
        "What do you want to configure?",
        &[
            "A service with 1Password",
            "Empty config",
            "Print config path only",
        ],
        1,
    )? {
        1 => write_config(path, &build_service_config(prompt_service_setup()?)),
        2 => write_config(path, empty_config()),
        3 => {
            println!("{}", path.display());
            Ok(())
        }
        _ => unreachable!("prompt_choice only returns listed choices"),
    }
}

fn write_config(path: &Path, contents: &str) -> Result<(), ViaError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    println!("created via config: {}", path.display());
    println!("Run `via config doctor` to check the setup.");
    Ok(())
}

struct ServiceSetup {
    service_name: String,
    secret_name: String,
    secret_reference: String,
    private_key_secret_name: Option<String>,
    private_key_secret_reference: Option<String>,
    rest: Option<RestSetup>,
    delegated: Option<DelegatedSetup>,
}

struct RestSetup {
    command_name: String,
    base_url: String,
    method_default: String,
    auth: RestAuthSetup,
}

enum RestAuthSetup {
    Bearer,
    GitHubApp,
    OAuth,
}

struct DelegatedSetup {
    command_name: String,
    program: String,
    env_var: String,
    check_args: Vec<String>,
}

fn prompt_service_setup() -> Result<ServiceSetup, ViaError> {
    let service_name = prompt_required("Service name", None)?;
    let secret_name = prompt_required("Secret name in via config", Some("token"))?;
    let secret_reference = prompt_secret_reference()?;
    let mode = prompt_service_mode()?;
    let rest = prompt_optional_rest_setup(mode)?;
    let (private_key_secret_name, private_key_secret_reference) =
        prompt_optional_private_key(rest.as_ref())?;
    let delegated = prompt_optional_delegated_setup(mode)?;

    Ok(ServiceSetup {
        service_name,
        secret_name,
        secret_reference,
        private_key_secret_name,
        private_key_secret_reference,
        rest,
        delegated,
    })
}

fn prompt_service_mode() -> Result<usize, ViaError> {
    prompt_choice(
        "How should via run this service?",
        &["REST API", "Trusted CLI", "Both"],
        1,
    )
}

fn prompt_optional_rest_setup(mode: usize) -> Result<Option<RestSetup>, ViaError> {
    if mode_uses_rest(mode) {
        Ok(Some(prompt_rest_setup()?))
    } else {
        Ok(None)
    }
}

fn prompt_optional_private_key(
    rest: Option<&RestSetup>,
) -> Result<(Option<String>, Option<String>), ViaError> {
    if rest.is_some_and(rest_uses_github_app) {
        prompt_private_key_secret()
    } else {
        Ok((None, None))
    }
}

fn prompt_optional_delegated_setup(mode: usize) -> Result<Option<DelegatedSetup>, ViaError> {
    if mode_uses_delegated(mode) {
        Ok(Some(prompt_delegated_setup()?))
    } else {
        Ok(None)
    }
}

fn mode_uses_rest(mode: usize) -> bool {
    mode == 1 || mode == 3
}

fn mode_uses_delegated(mode: usize) -> bool {
    mode == 2 || mode == 3
}

fn rest_uses_github_app(rest: &RestSetup) -> bool {
    matches!(rest.auth, RestAuthSetup::GitHubApp)
}

fn prompt_private_key_secret() -> Result<(Option<String>, Option<String>), ViaError> {
    println!();
    println!("GitHub App private key");
    let name = prompt_required("Private key secret name in via config", Some("private_key"))?;
    let reference = prompt_secret_reference()?;
    Ok((Some(name), Some(reference)))
}

fn prompt_secret_reference() -> Result<String, ViaError> {
    loop {
        println!("1Password secret reference:");
        println!("  Example: op://Private/Service/token");
        let value = prompt_required("Reference", None)?;
        if value.starts_with("op://") {
            return Ok(value);
        }
        println!("Secret references must start with `op://`.");
    }
}

fn prompt_rest_setup() -> Result<RestSetup, ViaError> {
    println!();
    println!("REST API capability");
    let (command_name, base_url, method_default) = prompt_rest_fields()?;
    let auth = prompt_rest_auth_setup()?;

    Ok(RestSetup {
        command_name,
        base_url,
        method_default,
        auth,
    })
}

fn prompt_rest_fields() -> Result<(String, String, String), ViaError> {
    Ok((
        prompt_required("Capability name", Some("api"))?,
        prompt_required("Base URL", None)?,
        prompt_required("Default HTTP method", Some("GET"))?,
    ))
}

fn prompt_rest_auth_setup() -> Result<RestAuthSetup, ViaError> {
    rest_auth_setup_from_choice(prompt_choice(
        "How should REST authenticate?",
        &[
            "Bearer token",
            "GitHub App credential bundle",
            "OAuth credential bundle",
        ],
        1,
    )?)
}

fn rest_auth_setup_from_choice(choice: usize) -> Result<RestAuthSetup, ViaError> {
    match choice {
        1 => Ok(RestAuthSetup::Bearer),
        2 => Ok(RestAuthSetup::GitHubApp),
        3 => Ok(RestAuthSetup::OAuth),
        _ => Err(ViaError::InvalidConfig(format!(
            "unsupported REST auth choice {choice}"
        ))),
    }
}

fn prompt_delegated_setup() -> Result<DelegatedSetup, ViaError> {
    println!();
    println!("Trusted CLI capability");
    let program = prompt_required("Program", None)?;
    let default_command = program.clone();
    let command_name = prompt_required("Capability name", Some(&default_command))?;
    let env_var = prompt_required("Environment variable to inject", Some("TOKEN"))?;
    let check = prompt_required("Check command args", Some("--version"))?;

    Ok(DelegatedSetup {
        command_name,
        program,
        env_var,
        check_args: split_args(&check),
    })
}

fn prompt_choice(prompt: &str, choices: &[&str], default: usize) -> Result<usize, ViaError> {
    loop {
        println!("{prompt}");
        for (index, choice) in choices.iter().enumerate() {
            println!("  {}. {choice}", index + 1);
        }

        let raw = prompt_optional(&format!("Choice [{default}]"))?;
        let choice = if raw.is_empty() {
            default
        } else {
            match raw.parse::<usize>() {
                Ok(choice) => choice,
                Err(_) => {
                    println!("Enter a number from 1 to {}.", choices.len());
                    continue;
                }
            }
        };

        if (1..=choices.len()).contains(&choice) {
            return Ok(choice);
        }
        println!("Enter a number from 1 to {}.", choices.len());
    }
}

fn prompt_required(prompt: &str, default: Option<&str>) -> Result<String, ViaError> {
    loop {
        let label = match default {
            Some(default) => format!("{prompt} [{default}]"),
            None => prompt.to_owned(),
        };
        let value = prompt_optional(&label)?;
        if !value.is_empty() {
            return Ok(value);
        }
        if let Some(default) = default {
            return Ok(default.to_owned());
        }
        println!("This value is required.");
    }
}

fn prompt_optional(prompt: &str) -> Result<String, ViaError> {
    print!("{prompt}: ");
    io::stdout().flush()?;

    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn build_service_config(setup: ServiceSetup) -> String {
    let mut output = String::new();
    output.push_str("version = 1\n\n");
    output.push_str("[providers.onepassword]\n");
    output.push_str("type = \"1password\"\n");
    output.push_str("cache = \"daemon\"\n\n");
    output.push_str(&format!("[services.{}]\n", toml_key(&setup.service_name)));
    output.push_str(&format!(
        "description = {}\n",
        toml_string(&format!("{} access", setup.service_name))
    ));
    output.push_str("provider = \"onepassword\"\n\n");
    output.push_str(&format!(
        "[services.{}.secrets]\n",
        toml_key(&setup.service_name)
    ));
    output.push_str(&format!(
        "{} = {}\n\n",
        toml_key(&setup.secret_name),
        toml_string(&setup.secret_reference)
    ));
    if let (Some(name), Some(reference)) = (
        &setup.private_key_secret_name,
        &setup.private_key_secret_reference,
    ) {
        output.truncate(output.trim_end_matches('\n').len());
        output.push('\n');
        output.push_str(&format!(
            "{} = {}\n\n",
            toml_key(name),
            toml_string(reference)
        ));
    }

    if let Some(rest) = setup.rest {
        output.push_str(&format!(
            "[services.{}.commands.{}]\n",
            toml_key(&setup.service_name),
            toml_key(&rest.command_name)
        ));
        output
            .push_str("description = \"Call the configured REST API. Prefer this for agents.\"\n");
        output.push_str("mode = \"rest\"\n");
        output.push_str(&format!("base_url = {}\n", toml_string(&rest.base_url)));
        output.push_str(&format!(
            "method_default = {}\n\n",
            toml_string(&rest.method_default)
        ));
        output.push_str(&format!(
            "[services.{}.commands.{}.auth]\n",
            toml_key(&setup.service_name),
            toml_key(&rest.command_name)
        ));
        match rest.auth {
            RestAuthSetup::Bearer => {
                output.push_str("type = \"bearer\"\n");
                output.push_str(&format!("secret = {}\n\n", toml_string(&setup.secret_name)));
            }
            RestAuthSetup::GitHubApp => {
                let private_key = setup
                    .private_key_secret_name
                    .as_deref()
                    .unwrap_or("private_key");
                output.push_str("type = \"github_app\"\n");
                output.push_str(&format!(
                    "credential = {}\n",
                    toml_string(&setup.secret_name)
                ));
                output.push_str(&format!("private_key = {}\n\n", toml_string(private_key)));
            }
            RestAuthSetup::OAuth => {
                output.push_str("type = \"oauth\"\n");
                output.push_str(&format!(
                    "credential = {}\n\n",
                    toml_string(&setup.secret_name)
                ));
            }
        }
    }

    if let Some(delegated) = setup.delegated {
        output.push_str(&format!(
            "[services.{}.commands.{}]\n",
            toml_key(&setup.service_name),
            toml_key(&delegated.command_name)
        ));
        output
            .push_str("description = \"Run the configured trusted CLI with a secret injected.\"\n");
        output.push_str("mode = \"delegated\"\n");
        output.push_str(&format!("program = {}\n", toml_string(&delegated.program)));
        output.push_str(&format!(
            "check = {}\n\n",
            toml_array(&delegated.check_args)
        ));
        output.push_str(&format!(
            "[services.{}.commands.{}.inject.env.{}]\n",
            toml_key(&setup.service_name),
            toml_key(&delegated.command_name),
            toml_key(&delegated.env_var)
        ));
        output.push_str(&format!("secret = {}\n", toml_string(&setup.secret_name)));
    }

    output
}

fn empty_config() -> &'static str {
    r#"version = 1

[providers.onepassword]
type = "1password"
cache = "daemon"

"#
}

fn split_args(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}

fn toml_key(value: &str) -> String {
    toml_string(value)
}

fn toml_array(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| toml_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{values}]")
}

fn toml_string(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    format!("\"{escaped}\"")
}

fn print_missing_config(path: &Path) {
    println!("No via config found at:");
    println!("  {}", path.display());
    println!();
    println!("Human setup:");
    println!("  Run `via config` in an interactive terminal to create one.");
    println!();
    println!("Agent guidance:");
    println!("  Ask the user to run `via config`, then rerun `via config doctor`.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_generic_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "gitlab".to_owned(),
            secret_name: "token".to_owned(),
            secret_reference: "op://Private/GitLab/token".to_owned(),
            private_key_secret_name: None,
            private_key_secret_reference: None,
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://gitlab.example.com/api/v4".to_owned(),
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::Bearer,
            }),
            delegated: None,
        });

        assert!(config.contains("[services.\"gitlab\"]"));
        assert!(config.contains("cache = \"daemon\""));
        assert!(config.contains("base_url = \"https://gitlab.example.com/api/v4\""));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn builds_github_app_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "github".to_owned(),
            secret_name: "app".to_owned(),
            secret_reference: "op://Private/Example GitHub App/metadata".to_owned(),
            private_key_secret_name: Some("private_key".to_owned()),
            private_key_secret_reference: Some(
                "op://Private/Example GitHub App/github-app.private-key.pem".to_owned(),
            ),
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://api.github.com".to_owned(),
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::GitHubApp,
            }),
            delegated: None,
        });

        assert!(config.contains("type = \"github_app\""));
        assert!(config.contains("cache = \"daemon\""));
        assert!(config.contains("credential = \"app\""));
        assert!(config.contains("private_key = \"private_key\""));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn builds_oauth_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "linear".to_owned(),
            secret_name: "oauth".to_owned(),
            secret_reference: "op://Private/Linear/oauth".to_owned(),
            private_key_secret_name: None,
            private_key_secret_reference: None,
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://api.linear.app".to_owned(),
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::OAuth,
            }),
            delegated: None,
        });

        assert!(config.contains("type = \"oauth\""));
        assert!(config.contains("credential = \"oauth\""));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn maps_rest_auth_setup_choices() {
        assert!(matches!(
            rest_auth_setup_from_choice(1).unwrap(),
            RestAuthSetup::Bearer
        ));
        assert!(matches!(
            rest_auth_setup_from_choice(2).unwrap(),
            RestAuthSetup::GitHubApp
        ));
        assert!(matches!(
            rest_auth_setup_from_choice(3).unwrap(),
            RestAuthSetup::OAuth
        ));
        assert!(rest_auth_setup_from_choice(4).is_err());
    }

    #[test]
    fn builds_generic_delegated_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "deploy tool".to_owned(),
            secret_name: "api token".to_owned(),
            secret_reference: "op://Private/Deploy/token".to_owned(),
            private_key_secret_name: None,
            private_key_secret_reference: None,
            rest: None,
            delegated: Some(DelegatedSetup {
                command_name: "cli".to_owned(),
                program: "deployctl".to_owned(),
                env_var: "DEPLOY_TOKEN".to_owned(),
                check_args: vec!["--version".to_owned()],
            }),
        });

        assert!(config.contains("[services.\"deploy tool\"]"));
        assert!(config
            .contains("[services.\"deploy tool\".commands.\"cli\".inject.env.\"DEPLOY_TOKEN\"]"));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn escapes_toml_strings() {
        assert_eq!(toml_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
}
