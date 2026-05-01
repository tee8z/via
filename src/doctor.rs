use std::process::Command;

use crate::config::{CommandConfig, Config};
use crate::error::ViaError;

pub fn run(config: &Config, only_service: Option<&str>) -> Result<(), ViaError> {
    if let Some(service_name) = only_service {
        if !config.services.contains_key(service_name) {
            return Err(ViaError::UnknownService(service_name.to_owned()));
        }
    }

    check_op()?;

    for (service_name, service) in &config.services {
        if only_service.is_some_and(|only| only != service_name) {
            continue;
        }

        println!("service {service_name}: ok");
        for (command_name, command) in &service.commands {
            match command {
                CommandConfig::Rest(_) => {
                    println!("  {command_name}: rest");
                }
                CommandConfig::Delegated(delegated) => {
                    check_program(&delegated.program, &delegated.check)?;
                    println!("  {command_name}: delegated {}", delegated.program);
                }
            }
        }
    }

    Ok(())
}

fn check_op() -> Result<(), ViaError> {
    let output = Command::new("op").arg("--version").output();
    match output {
        Ok(output) if output.status.success() => {
            println!("1Password CLI op: ok");
            Ok(())
        }
        Ok(output) => Err(ViaError::ExternalCommandFailed {
            program: "op".to_owned(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
        Err(source) => Err(ViaError::MissingProgram {
            program: "op".to_owned(),
            source,
        }),
    }
}

fn check_program(program: &str, check: &[String]) -> Result<(), ViaError> {
    let mut command = Command::new(program);
    if check.is_empty() {
        command.arg("--version");
    } else {
        command.args(check);
    }

    let output = command.output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(ViaError::ExternalCommandFailed {
            program: program.to_owned(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }),
        Err(source) => Err(ViaError::MissingProgram {
            program: program.to_owned(),
            source,
        }),
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
    fn rejects_unknown_service_before_provider_checks() {
        let error = run(&config(), Some("missing")).unwrap_err();

        assert!(matches!(error, ViaError::UnknownService(service) if service == "missing"));
    }

    #[test]
    fn check_program_accepts_successful_check_command() {
        check_program("sh", &["-c".to_owned(), "exit 0".to_owned()]).unwrap();
    }

    #[test]
    fn check_program_reports_failed_check_command() {
        let error = check_program("sh", &["-c".to_owned(), "exit 9".to_owned()]).unwrap_err();

        assert!(matches!(
            error,
            ViaError::ExternalCommandFailed {
                program,
                status: Some(9),
                ..
            } if program == "sh"
        ));
    }
}
