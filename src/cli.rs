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
    Version,
    Login {
        provider: Option<String>,
    },
    Capabilities {
        json: bool,
    },
    Config(ConfigCommand),
    Daemon(DaemonCommand),
    SkillPrint,
    Invoke {
        service: String,
        capability: String,
        args: Vec<String>,
    },
}

pub enum ConfigCommand {
    Configure,
    Path,
    Doctor { service: Option<String> },
}

pub enum DaemonCommand {
    Status,
    Clear,
    Stop,
    Serve,
}

pub fn print_help() {
    let _ = command().print_help();
    println!();
}

impl Cli {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, ViaError> {
        let matches = command().try_get_matches_from(args)?;
        let config_path = matches.get_one::<PathBuf>("config_path").cloned();

        let command = match matches.subcommand() {
            Some(("version", _)) => Command::Version,
            Some(("login", submatches)) => Command::Login {
                provider: submatches.get_one::<String>("provider").cloned(),
            },
            Some(("capabilities", submatches)) => Command::Capabilities {
                json: submatches.get_flag("json"),
            },
            Some(("config", submatches)) => Command::Config(parse_config_command(submatches)?),
            Some(("daemon", submatches)) => Command::Daemon(parse_daemon_command(submatches)?),
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

fn parse_config_command(matches: &clap::ArgMatches) -> Result<ConfigCommand, ViaError> {
    match matches.subcommand() {
        Some(("path", _)) => Ok(ConfigCommand::Path),
        Some(("doctor", submatches)) => Ok(ConfigCommand::Doctor {
            service: submatches.get_one::<String>("service").cloned(),
        }),
        None => Ok(ConfigCommand::Configure),
        _ => Err(ViaError::InvalidCli(
            "expected `via config`, `via config path`, or `via config doctor`".to_owned(),
        )),
    }
}

fn parse_daemon_command(matches: &clap::ArgMatches) -> Result<DaemonCommand, ViaError> {
    match matches.subcommand() {
        Some(("status", _)) => Ok(DaemonCommand::Status),
        Some(("clear", _)) => Ok(DaemonCommand::Clear),
        Some(("stop", _)) => Ok(DaemonCommand::Stop),
        Some(("serve", _)) => Ok(DaemonCommand::Serve),
        _ => Err(ViaError::InvalidCli(
            "expected `via daemon status`, `via daemon clear`, or `via daemon stop`".to_owned(),
        )),
    }
}

fn command() -> ClapCommand {
    ClapCommand::new("via")
        .about("Run commands and API requests with 1Password-backed credentials without exposing secrets to your shell")
        .version(env!("CARGO_PKG_VERSION"))
        .disable_help_subcommand(true)
        .allow_external_subcommands(true)
        .external_subcommand_value_parser(clap::value_parser!(String))
        .arg(
            Arg::new("config_path")
                .long("config")
                .short('c')
                .value_name("PATH")
                .value_parser(clap::value_parser!(PathBuf))
                .global(true)
                .help("Path to via.toml"),
        )
        .subcommand(
            ClapCommand::new("version").about("Print the via version"),
        )
        .subcommand(
            ClapCommand::new("login")
                .about("Authenticate configured secret providers")
                .arg(Arg::new("provider").help("Only authenticate one provider")),
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
            ClapCommand::new("config")
                .about("Create, locate, and check via configuration")
                .subcommand(ClapCommand::new("path").about("Print the resolved config path"))
                .subcommand(
                    ClapCommand::new("doctor")
                        .about("Check configuration, providers, secrets, and delegated tools")
                        .arg(Arg::new("service").help("Only check one service")),
                ),
        )
        .subcommand(
            ClapCommand::new("daemon")
                .about("Manage the local via secret cache daemon")
                .subcommand(ClapCommand::new("status").about("Show daemon status"))
                .subcommand(ClapCommand::new("clear").about("Clear cached daemon secrets"))
                .subcommand(ClapCommand::new("stop").about("Stop the daemon"))
                .subcommand(ClapCommand::new("serve").hide(true)),
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
    fn parses_version() {
        let cli = parse(&["via", "version"]);

        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn parses_login() {
        let cli = parse(&["via", "login"]);

        assert!(matches!(cli.command, Command::Login { provider: None }));
    }

    #[test]
    fn parses_login_provider() {
        let cli = parse(&["via", "login", "onepassword"]);

        assert!(matches!(
            cli.command,
            Command::Login {
                provider: Some(provider)
            } if provider == "onepassword"
        ));
    }

    #[test]
    fn parses_doctor_service() {
        let cli = parse(&["via", "config", "doctor", "github"]);

        assert!(matches!(
            cli.command,
            Command::Config(ConfigCommand::Doctor {
                service: Some(service)
            }) if service == "github"
        ));
    }

    #[test]
    fn parses_config_path() {
        let cli = parse(&["via", "config", "path"]);

        assert!(matches!(cli.command, Command::Config(ConfigCommand::Path)));
    }

    #[test]
    fn parses_config_configure() {
        let cli = parse(&["via", "config"]);

        assert!(matches!(
            cli.command,
            Command::Config(ConfigCommand::Configure)
        ));
    }

    #[test]
    fn parses_skill_print() {
        let cli = parse(&["via", "skill", "print"]);

        assert!(matches!(cli.command, Command::SkillPrint));
    }

    #[test]
    fn parses_daemon_status() {
        let cli = parse(&["via", "daemon", "status"]);

        assert!(matches!(
            cli.command,
            Command::Daemon(DaemonCommand::Status)
        ));
    }

    #[test]
    fn parses_daemon_clear() {
        let cli = parse(&["via", "daemon", "clear"]);

        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Clear)));
    }

    #[test]
    fn parses_daemon_stop() {
        let cli = parse(&["via", "daemon", "stop"]);

        assert!(matches!(cli.command, Command::Daemon(DaemonCommand::Stop)));
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
