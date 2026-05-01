use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Arg, ArgAction, Command as ClapCommand};

use crate::error::ViaError;

pub struct Cli {
    pub config_path: Option<PathBuf>,
    pub command: Command,
}

pub enum Command {
    Help,
    Capabilities {
        json: bool,
    },
    Doctor {
        service: Option<String>,
    },
    SkillPrint,
    Invoke {
        service: String,
        capability: String,
        args: Vec<String>,
    },
}

pub fn print_help() {
    let _ = command().print_help();
    println!();
}

impl Cli {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, ViaError> {
        let matches = command().try_get_matches_from(args)?;
        let config_path = matches.get_one::<PathBuf>("config").cloned();

        let command = match matches.subcommand() {
            Some(("capabilities", submatches)) => Command::Capabilities {
                json: submatches.get_flag("json"),
            },
            Some(("doctor", submatches)) => Command::Doctor {
                service: submatches.get_one::<String>("service").cloned(),
            },
            Some(("skill", submatches)) => match submatches.subcommand() {
                Some(("print", _)) => Command::SkillPrint,
                _ => {
                    return Err(ViaError::InvalidCli(
                        "expected `via skill print`".to_owned(),
                    ))
                }
            },
            Some((service, submatches)) => {
                let mut args = submatches
                    .get_many::<String>("")
                    .map(|values| values.cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
                    .into_iter();
                let capability = args
                    .next()
                    .ok_or_else(|| ViaError::MissingArgument("capability".to_owned()))?;

                Command::Invoke {
                    service: service.to_owned(),
                    capability,
                    args: args.collect(),
                }
            }
            None => Command::Help,
        };

        Ok(Self {
            config_path,
            command,
        })
    }
}

fn command() -> ClapCommand {
    ClapCommand::new("via")
        .about("Securely run configured capabilities with credentials from 1Password")
        .disable_help_subcommand(true)
        .allow_external_subcommands(true)
        .external_subcommand_value_parser(clap::value_parser!(String))
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .value_name("PATH")
                .value_parser(clap::value_parser!(PathBuf))
                .global(true)
                .help("Path to via.toml"),
        )
        .subcommand(
            ClapCommand::new("capabilities")
                .about("List configured services and capabilities")
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Print machine-readable JSON"),
                ),
        )
        .subcommand(
            ClapCommand::new("doctor")
                .about("Check configuration, providers, and delegated tools")
                .arg(Arg::new("service").help("Only check one service")),
        )
        .subcommand(
            ClapCommand::new("skill")
                .about("Agent skill helpers")
                .subcommand(ClapCommand::new("print").about("Print the via skill instructions")),
        )
        .arg_required_else_help(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse(args.iter().map(OsString::from)).unwrap()
    }

    #[test]
    fn no_args_is_help() {
        let cli = parse(&["via"]);

        assert!(matches!(cli.command, Command::Help));
    }

    #[test]
    fn parses_global_config_before_service_invocation() {
        let cli = parse(&[
            "via",
            "--config",
            "examples/github.toml",
            "github",
            "api",
            "POST",
            "/user",
            "--json",
            "{}",
        ]);

        assert_eq!(
            cli.config_path.unwrap(),
            PathBuf::from("examples/github.toml")
        );
        match cli.command {
            Command::Invoke {
                service,
                capability,
                args,
            } => {
                assert_eq!(service, "github");
                assert_eq!(capability, "api");
                assert_eq!(args, ["POST", "/user", "--json", "{}"]);
            }
            _ => panic!("expected invoke"),
        }
    }

    #[test]
    fn parses_capabilities_json() {
        let cli = parse(&["via", "capabilities", "--json"]);

        assert!(matches!(cli.command, Command::Capabilities { json: true }));
    }

    #[test]
    fn parses_doctor_service() {
        let cli = parse(&["via", "doctor", "github"]);

        assert!(matches!(
            cli.command,
            Command::Doctor {
                service: Some(service)
            } if service == "github"
        ));
    }

    #[test]
    fn parses_skill_print() {
        let cli = parse(&["via", "skill", "print"]);

        assert!(matches!(cli.command, Command::SkillPrint));
    }

    #[test]
    fn rejects_missing_capability() {
        let error = match Cli::parse([OsString::from("via"), OsString::from("github")]) {
            Ok(_) => panic!("expected missing capability error"),
            Err(error) => error,
        };

        assert!(matches!(error, ViaError::MissingArgument(argument) if argument == "capability"));
    }
}
