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
    BrokerExec {
        caller: Option<String>,
        request: Vec<String>,
    },
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
        let mut config_path = matches.get_one::<PathBuf>("config_path").cloned();

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
            Some(("broker", submatches)) => match submatches.subcommand() {
                Some(("exec", exec_matches)) => {
                    // The forced command passes `--config` after `exec`.
                    if let Ok(Some(path)) = exec_matches.try_get_one::<PathBuf>("config_path") {
                        config_path = Some(path.clone());
                    }
                    Command::BrokerExec {
                        caller: exec_matches.get_one::<String>("caller").cloned(),
                        request: exec_matches
                            .get_many::<String>("request")
                            .map(|values| values.cloned().collect())
                            .unwrap_or_default(),
                    }
                }
                _ => return Err(ViaError::InvalidCli(BROKER_USAGE.to_owned())),
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

pub const BROKER_USAGE: &str =
    "expected `via broker exec --config <ABSOLUTE_PATH> [--caller <LABEL>] [-- <args>...]`";

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
        .about("Run commands, SSH sessions, and API requests with 1Password-backed credentials without exposing secrets to your shell")
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
                        .about(
                            "Check configuration, providers, secrets, delegated tools, and SSH profiles",
                        )
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
        .subcommand(
            ClapCommand::new("broker")
                .about("Serve capabilities to a remote caller from a trusted host")
                .subcommand(
                    ClapCommand::new("exec")
                        .about(
                            "Run one request from SSH_ORIGINAL_COMMAND, or from arguments after `--`",
                        )
                        .arg(
                            Arg::new("caller")
                                .long("caller")
                                .value_name("LABEL")
                                .help("Label that identifies the caller in audit records"),
                        )
                        .arg(
                            Arg::new("request")
                                .value_name("ARGS")
                                .num_args(1..)
                                .last(true)
                                .help("Request arguments, for local testing"),
                        ),
                ),
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
    fn parses_broker_exec_as_a_forced_command() {
        let cli = parse(&[
            "via",
            "broker",
            "exec",
            "--config",
            "/etc/via/broker.toml",
            "--caller",
            "sandbox-1",
        ]);

        assert_eq!(
            cli.config_path.unwrap(),
            PathBuf::from("/etc/via/broker.toml")
        );
        match cli.command {
            Command::BrokerExec { caller, request } => {
                assert_eq!(caller.as_deref(), Some("sandbox-1"));
                assert!(request.is_empty());
            }
            _ => panic!("expected broker exec"),
        }
    }

    #[test]
    fn parses_broker_exec_request_after_a_separator() {
        let cli = parse(&[
            "via",
            "--config",
            "/etc/via/broker.toml",
            "broker",
            "exec",
            "--",
            "github",
            "api",
            "POST",
            "/user",
            "--json",
            "{}",
            "--config",
            "/tmp/other.toml",
        ]);

        assert_eq!(
            cli.config_path.unwrap(),
            PathBuf::from("/etc/via/broker.toml")
        );
        match cli.command {
            Command::BrokerExec { caller, request } => {
                assert_eq!(caller, None);
                assert_eq!(
                    request,
                    [
                        "github",
                        "api",
                        "POST",
                        "/user",
                        "--json",
                        "{}",
                        "--config",
                        "/tmp/other.toml"
                    ]
                );
            }
            _ => panic!("expected broker exec"),
        }
    }

    #[test]
    fn rejects_broker_without_exec_and_requests_without_a_separator() {
        for args in [
            &["via", "broker"][..],
            &["via", "broker", "serve"],
            &["via", "broker", "exec", "capabilities"],
            &["via", "broker", "exec", "--unknown"],
        ] {
            assert!(
                Cli::parse(args.iter().map(OsString::from)).is_err(),
                "expected {args:?} to be rejected"
            );
        }
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
