use std::ffi::OsString;
use std::process::ExitCode;

use crate::cli::{print_help, Cli, Command};
use crate::config::Config;
use crate::error::ViaError;
use crate::executor;
use crate::providers::ProviderRegistry;

pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    crate::tls::install_crypto_provider();

    match try_run(args) {
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

    match cli.command {
        Command::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Command::Capabilities { json } => {
            let config = Config::load(cli.config_path.as_deref())?;
            crate::capabilities::print(&config, json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Config(command) => {
            crate::config_command::run(cli.config_path.as_deref(), command)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::SkillPrint => {
            let config = Config::load(cli.config_path.as_deref())?;
            crate::skill::print(&config);
            Ok(ExitCode::SUCCESS)
        }
        Command::Invoke {
            service,
            capability,
            args,
        } => {
            let config = Config::load(cli.config_path.as_deref())?;
            let providers = ProviderRegistry::from_config(&config)?;
            executor::invoke(&config, &providers, &service, &capability, args)?;
            Ok(ExitCode::SUCCESS)
        }
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
}
