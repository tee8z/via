use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::{print_help, Cli, Command, DaemonCommand};
use crate::config::Config;
use crate::error::ViaError;
use crate::executor;
use crate::providers::ProviderRegistry;

pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    crate::tls::install_crypto_provider();
    exit_code_from_result(try_run(args))
}

fn exit_code_from_result(result: Result<ExitCode, ViaError>) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(ViaError::Clap(error)) => {
            let exit_code = if error.use_stderr() { 2 } else { 0 };
            if error.use_stderr() {
                eprint!("{error}");
            } else {
                print!("{error}");
            }
            ExitCode::from(exit_code)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn try_run(args: impl IntoIterator<Item = OsString>) -> Result<ExitCode, ViaError> {
    let cli = Cli::parse(args)?;
    run_cli(cli)
}

fn run_cli(cli: Cli) -> Result<ExitCode, ViaError> {
    let config_path = cli.config_path.as_deref();
    match cli.command {
        Command::Help => run_help_command(),
        Command::Version => run_version_command(),
        Command::Capabilities { json } => run_capabilities_command(config_path, json),
        Command::Config(command) => run_config_command(config_path, command),
        Command::Daemon(command) => run_daemon_cli_command(command),
        Command::SkillPrint => run_skill_print_command(config_path),
        Command::Invoke {
            service,
            capability,
            args,
        } => run_invoke_command(config_path, service, capability, args),
    }
}

fn run_help_command() -> Result<ExitCode, ViaError> {
    print_help();
    Ok(ExitCode::SUCCESS)
}

fn run_version_command() -> Result<ExitCode, ViaError> {
    println!("via {}", env!("CARGO_PKG_VERSION"));
    Ok(ExitCode::SUCCESS)
}

fn run_capabilities_command(config_path: Option<&Path>, json: bool) -> Result<ExitCode, ViaError> {
    let config = Config::load(config_path)?;
    crate::capabilities::print(&config, json)?;
    Ok(ExitCode::SUCCESS)
}

fn run_config_command(
    config_path: Option<&Path>,
    command: crate::cli::ConfigCommand,
) -> Result<ExitCode, ViaError> {
    crate::config_command::run(config_path, command)?;
    Ok(ExitCode::SUCCESS)
}

fn run_daemon_cli_command(command: DaemonCommand) -> Result<ExitCode, ViaError> {
    run_daemon_command(command)?;
    Ok(ExitCode::SUCCESS)
}

fn run_skill_print_command(config_path: Option<&Path>) -> Result<ExitCode, ViaError> {
    let config = Config::load(config_path)?;
    crate::skill::print(&config);
    Ok(ExitCode::SUCCESS)
}

fn run_invoke_command(
    config_path: Option<&Path>,
    service: String,
    capability: String,
    args: Vec<String>,
) -> Result<ExitCode, ViaError> {
    let config = Config::load(config_path)?;
    let providers = ProviderRegistry::from_config(&config)?;
    executor::invoke(&config, &providers, &service, &capability, args)?;
    Ok(ExitCode::SUCCESS)
}

fn run_daemon_command(command: DaemonCommand) -> Result<(), ViaError> {
    match command {
        DaemonCommand::Status => crate::daemon::status(),
        DaemonCommand::Clear => crate::daemon::clear(),
        DaemonCommand::Stop => crate::daemon::stop(),
        DaemonCommand::Serve => crate::daemon::serve(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_command_returns_success() {
        let code = try_run([
            OsString::from("via"),
            OsString::from("--config"),
            OsString::from("examples/github.toml"),
            OsString::from("capabilities"),
        ])
        .unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn version_command_returns_success() {
        let code = try_run([OsString::from("via"), OsString::from("version")]).unwrap();

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn maps_success_result_to_exit_code() {
        let code = exit_code_from_result(Ok(ExitCode::SUCCESS));

        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn run_returns_usage_code_for_cli_error() {
        let code = run([OsString::from("via"), OsString::from("--unknown")]);

        assert_eq!(code, ExitCode::from(2));
    }

    #[test]
    fn run_returns_runtime_code_for_runtime_error() {
        let code = run([
            OsString::from("via"),
            OsString::from("--config"),
            OsString::from("/definitely/missing/via.toml"),
            OsString::from("capabilities"),
        ]);

        assert_eq!(code, ExitCode::from(1));
    }
}
