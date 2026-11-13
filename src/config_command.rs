use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

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
        println!(
            "Run `via config doctor` to check providers, secrets, delegated tools, and SSH profiles."
        );
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        print_missing_config(path);
        return Err(ViaError::ConfigNotFound(
            "run `via config` in an interactive terminal to create one".to_owned(),
        ));
    }

    Prompts {
        input: &mut io::stdin().lock(),
        output: &mut io::stdout().lock(),
    }
    .configure(path)
}

// Exclusive creation does not follow a symbolic link. A dotfile manager can
// leave the config path as a link to a file that does not exist yet, so
// create that file instead of failing after every question is answered.
fn creation_path(path: &Path) -> PathBuf {
    match fs::read_link(path) {
        Ok(target) if !path.exists() => match path.parent() {
            Some(parent) => parent.join(target),
            None => target,
        },
        _ => path.to_path_buf(),
    }
}

struct ServiceSetup {
    service_name: String,
    hint: String,
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
    asset_hosts: Vec<String>,
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

struct Prompts<'a> {
    input: &'a mut dyn BufRead,
    output: &'a mut dyn Write,
}

impl Prompts<'_> {
    fn configure(&mut self, path: &Path) -> Result<(), ViaError> {
        writeln!(self.output, "No via config found.")?;
        writeln!(self.output)?;
        writeln!(self.output, "via can create one at:")?;
        writeln!(self.output, "  {}", path.display())?;
        writeln!(self.output)?;

        match self.prompt_choice(
            "What do you want to configure?",
            &[
                "A service with 1Password",
                "Empty config",
                "Print config path only",
            ],
            1,
        )? {
            1 => {
                let config = build_service_config(self.prompt_service_setup()?);
                self.write_config(path, &config)
            }
            2 => self.write_config(path, empty_config()),
            3 => {
                writeln!(self.output, "{}", path.display())?;
                Ok(())
            }
            _ => unreachable!("prompt_choice only returns listed choices"),
        }
    }

    // Creates the config and never replaces a file. A config that appeared
    // while the questions were being answered stays as it is.
    fn write_config(&mut self, path: &Path, contents: &str) -> Result<(), ViaError> {
        let target = creation_path(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|source| match source.kind() {
                io::ErrorKind::AlreadyExists => io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} already exists and was not changed", target.display()),
                ),
                _ => source,
            })?;
        file.write_all(contents.as_bytes())?;
        writeln!(self.output, "created via config: {}", path.display())?;
        writeln!(self.output, "Run `via config doctor` to check the setup.")?;
        Ok(())
    }

    fn prompt_service_setup(&mut self) -> Result<ServiceSetup, ViaError> {
        let service_name = self.prompt_required("Service name", None)?;
        let hint = self.prompt_optional("Example command hint")?;
        let secret_name = self.prompt_required("Secret name in via config", Some("token"))?;
        let secret_reference = self.prompt_secret_reference()?;
        let mode = self.prompt_service_mode()?;
        let rest = self.prompt_optional_rest_setup(mode)?;
        let (private_key_secret_name, private_key_secret_reference) =
            self.prompt_optional_private_key(rest.as_ref())?;
        let delegated = self.prompt_optional_delegated_setup(mode)?;

        Ok(ServiceSetup {
            service_name,
            hint,
            secret_name,
            secret_reference,
            private_key_secret_name,
            private_key_secret_reference,
            rest,
            delegated,
        })
    }

    fn prompt_service_mode(&mut self) -> Result<usize, ViaError> {
        self.prompt_choice(
            "How should via run this service?",
            &["REST API", "Trusted CLI", "Both"],
            1,
        )
    }

    fn prompt_optional_rest_setup(&mut self, mode: usize) -> Result<Option<RestSetup>, ViaError> {
        if mode_uses_rest(mode) {
            Ok(Some(self.prompt_rest_setup()?))
        } else {
            Ok(None)
        }
    }

    fn prompt_optional_private_key(
        &mut self,
        rest: Option<&RestSetup>,
    ) -> Result<(Option<String>, Option<String>), ViaError> {
        if rest.is_some_and(rest_uses_github_app) {
            self.prompt_private_key_secret()
        } else {
            Ok((None, None))
        }
    }

    fn prompt_optional_delegated_setup(
        &mut self,
        mode: usize,
    ) -> Result<Option<DelegatedSetup>, ViaError> {
        if mode_uses_delegated(mode) {
            Ok(Some(self.prompt_delegated_setup()?))
        } else {
            Ok(None)
        }
    }

    fn prompt_private_key_secret(&mut self) -> Result<(Option<String>, Option<String>), ViaError> {
        writeln!(self.output)?;
        writeln!(self.output, "GitHub App private key")?;
        let name =
            self.prompt_required("Private key secret name in via config", Some("private_key"))?;
        let reference = self.prompt_secret_reference()?;
        Ok((Some(name), Some(reference)))
    }

    fn prompt_secret_reference(&mut self) -> Result<String, ViaError> {
        loop {
            writeln!(self.output, "1Password secret reference:")?;
            writeln!(self.output, "  Example: op://Private/Service/token")?;
            let value = self.prompt_required("Reference", None)?;
            if value.starts_with("op://") {
                return Ok(value);
            }
            writeln!(self.output, "Secret references must start with `op://`.")?;
        }
    }

    fn prompt_rest_setup(&mut self) -> Result<RestSetup, ViaError> {
        writeln!(self.output)?;
        writeln!(self.output, "REST API capability")?;
        let (command_name, base_url, method_default) = self.prompt_rest_fields()?;
        let asset_hosts = self.prompt_asset_hosts()?;
        let auth = self.prompt_rest_auth_setup()?;

        Ok(RestSetup {
            command_name,
            base_url,
            asset_hosts,
            method_default,
            auth,
        })
    }

    fn prompt_rest_fields(&mut self) -> Result<(String, String, String), ViaError> {
        Ok((
            self.prompt_required("Capability name", Some("api"))?,
            self.prompt_required("Base URL", None)?,
            self.prompt_required("Default HTTP method", Some("GET"))?,
        ))
    }

    fn prompt_rest_auth_setup(&mut self) -> Result<RestAuthSetup, ViaError> {
        rest_auth_setup_from_choice(self.prompt_choice(
            "How should REST authenticate?",
            &[
                "Bearer token",
                "GitHub App credential bundle",
                "OAuth credential bundle (prefer client_credentials for bots)",
            ],
            1,
        )?)
    }

    fn prompt_asset_hosts(&mut self) -> Result<Vec<String>, ViaError> {
        let raw =
            self.prompt_optional("Asset hosts for authenticated downloads, comma-separated")?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }

        Ok(raw
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn prompt_delegated_setup(&mut self) -> Result<DelegatedSetup, ViaError> {
        writeln!(self.output)?;
        writeln!(self.output, "Trusted CLI capability")?;
        let program = self.prompt_required("Program", None)?;
        let default_command = program.clone();
        let command_name = self.prompt_required("Capability name", Some(&default_command))?;
        let env_var = self.prompt_required("Environment variable to inject", Some("TOKEN"))?;
        let check = self.prompt_required("Check command args", Some("--version"))?;

        Ok(DelegatedSetup {
            command_name,
            program,
            env_var,
            check_args: split_args(&check),
        })
    }

    fn prompt_choice(
        &mut self,
        prompt: &str,
        choices: &[&str],
        default: usize,
    ) -> Result<usize, ViaError> {
        loop {
            writeln!(self.output, "{prompt}")?;
            for (index, choice) in choices.iter().enumerate() {
                writeln!(self.output, "  {}. {choice}", index + 1)?;
            }

            let raw = self.prompt_optional(&format!("Choice [{default}]"))?;
            let choice = if raw.is_empty() {
                default
            } else {
                match raw.parse::<usize>() {
                    Ok(choice) => choice,
                    Err(_) => {
                        writeln!(self.output, "Enter a number from 1 to {}.", choices.len())?;
                        continue;
                    }
                }
            };

            if (1..=choices.len()).contains(&choice) {
                return Ok(choice);
            }
            writeln!(self.output, "Enter a number from 1 to {}.", choices.len())?;
        }
    }

    fn prompt_required(&mut self, prompt: &str, default: Option<&str>) -> Result<String, ViaError> {
        loop {
            let label = match default {
                Some(default) => format!("{prompt} [{default}]"),
                None => prompt.to_owned(),
            };
            let value = self.prompt_optional(&label)?;
            if !value.is_empty() {
                return Ok(value);
            }
            if let Some(default) = default {
                return Ok(default.to_owned());
            }
            writeln!(self.output, "This value is required.")?;
        }
    }

    fn prompt_optional(&mut self, prompt: &str) -> Result<String, ViaError> {
        write!(self.output, "{prompt}: ")?;
        self.output.flush()?;

        let mut value = String::new();
        if self.input.read_line(&mut value)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "configuration input ended before setup was complete",
            )
            .into());
        }
        Ok(value.trim().to_owned())
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

fn build_service_config(setup: ServiceSetup) -> String {
    let mut output = String::new();
    output.push_str("version = 1\n\n");
    output.push_str("[providers.onepassword]\n");
    output.push_str("type = \"1password\"\n\n");
    output.push_str(&format!("[services.{}]\n", toml_key(&setup.service_name)));
    output.push_str(&format!(
        "description = {}\n",
        toml_string(&format!("{} access", setup.service_name))
    ));
    if !setup.hint.is_empty() {
        output.push_str(&format!("hint = {}\n", toml_string(&setup.hint)));
    }
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
        if !rest.asset_hosts.is_empty() {
            output.push_str(&format!(
                "asset_hosts = {}\n",
                toml_array(&rest.asset_hosts)
            ));
        }
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

    fn configure_with_input(path: &Path, input: &str) -> Result<String, ViaError> {
        let mut output = Vec::new();
        Prompts {
            input: &mut io::Cursor::new(input),
            output: &mut output,
        }
        .configure(path)?;
        Ok(String::from_utf8(output).unwrap())
    }

    const REST_INPUT: &str = "\nexample\nvia example api /items\n\nop://Private/Example/token\n\n\nhttps://api.example.com\n\n\n\n";

    #[test]
    fn interactive_setup_creates_a_valid_rest_service_with_defaults() {
        let directory = crate::test_support::TempDir::create("setup-rest");
        let path = directory.join("nested/config.toml");
        let output = configure_with_input(&path, REST_INPUT).unwrap();
        assert!(output.ends_with(&format!(
            "created via config: {}\nRun `via config doctor` to check the setup.\n",
            path.display()
        )));
        let config = Config::load(Some(&path)).unwrap();
        let service = &config.services["example"];
        assert_eq!(service.secrets["token"], "op://Private/Example/token");
        let config::CommandConfig::Rest(rest) = &service.commands["api"] else {
            panic!("expected REST capability");
        };
        assert_eq!(rest.base_url, "https://api.example.com");
        assert_eq!(rest.method_default, "GET");
        assert!(
            matches!(&rest.auth, Some(config::AuthConfig::Bearer { secret }) if secret == "token")
        );
    }

    #[test]
    fn interactive_setup_supports_combined_github_app_and_delegated_access() {
        let directory = crate::test_support::TempDir::create("setup-combined");
        let path = directory.join("config.toml");
        configure_with_input(&path, "1\ngithub\n\napp\nop://Private/App/metadata\n3\napi\nhttps://api.github.com\nGET\n assets.example.com, , downloads.example.com \n2\n\nop://Private/App/key\ngh\ncli\nGH_TOKEN\nversion --verbose\n").unwrap();
        let config = Config::load(Some(&path)).unwrap();
        let service = &config.services["github"];
        assert_eq!(service.secrets["private_key"], "op://Private/App/key");
        let config::CommandConfig::Rest(rest) = &service.commands["api"] else {
            panic!("expected REST capability");
        };
        assert_eq!(
            rest.asset_hosts,
            ["assets.example.com", "downloads.example.com"]
        );
        assert!(
            matches!(&rest.auth, Some(config::AuthConfig::GitHubApp { credential: Some(name), private_key: Some(key), .. }) if name == "app" && key == "private_key")
        );
        let config::CommandConfig::Delegated(cli) = &service.commands["cli"] else {
            panic!("expected delegated capability");
        };
        assert_eq!(cli.program, "gh");
        assert_eq!(cli.check, ["version", "--verbose"]);
        assert_eq!(cli.inject.env["GH_TOKEN"].secret, "app");
    }

    #[test]
    fn interactive_setup_supports_delegated_defaults_and_oauth() {
        let directory = crate::test_support::TempDir::create("setup-modes");
        let path = directory.join("delegated.toml");
        configure_with_input(
            &path,
            "1\ndeploy\n\n\nop://Private/Deploy/token\n2\ndeployctl\n\n\n\n",
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        let service = &config.services["deploy"];
        assert_eq!(service.commands.len(), 1);
        let config::CommandConfig::Delegated(cli) = &service.commands["deployctl"] else {
            panic!("expected delegated capability");
        };
        assert_eq!(cli.check, ["--version"]);
        assert_eq!(cli.inject.env["TOKEN"].secret, "token");

        let path = directory.join("oauth.toml");
        configure_with_input(
            &path,
            &format!("{}3\n", &REST_INPUT[..REST_INPUT.len() - 1]),
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        let config::CommandConfig::Rest(rest) = &config.services["example"].commands["api"] else {
            panic!("expected REST capability");
        };
        assert!(
            matches!(&rest.auth, Some(config::AuthConfig::OAuth { credential }) if credential == "token")
        );
    }

    #[test]
    fn interactive_setup_retries_invalid_choices_required_fields_and_references() {
        let directory = crate::test_support::TempDir::create("setup-retry");
        let path = directory.join("config.toml");
        let input = REST_INPUT
            .replacen("\nexample", "oops\n0\n4\n1\n\nexample", 1)
            .replace(
                "op://Private/Example/token",
                "plaintext\nop://Private/Example/token",
            );
        let output = configure_with_input(&path, &input).unwrap();
        assert!(output.contains("Enter a number from 1 to 3."));
        assert!(output.contains("This value is required."));
        assert!(output.contains("Secret references must start with `op://`."));
        assert!(Config::load(Some(&path)).is_ok());
    }

    #[test]
    fn interrupted_setup_returns_eof_without_creating_a_config() {
        let directory = crate::test_support::TempDir::create("setup-eof");
        let path = directory.join("config.toml");
        for (index, _) in REST_INPUT.match_indices('\n') {
            let error = configure_with_input(&path, &REST_INPUT[..index]).unwrap_err();
            assert!(
                matches!(error, ViaError::Io(ref source) if source.kind() == io::ErrorKind::UnexpectedEof)
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn empty_and_path_only_setup_do_not_require_service_details() {
        let directory = crate::test_support::TempDir::create("setup-empty");
        let path = directory.join("config.toml");
        assert!(configure_with_input(&path, "3\n")
            .unwrap()
            .contains(&path.display().to_string()));
        assert!(!path.exists());
        configure_with_input(&path, "2\n").unwrap();
        assert!(Config::load(Some(&path)).unwrap().services.is_empty());
    }

    #[test]
    fn writing_config_preserves_existing_files_and_reports_parent_errors() {
        let directory = crate::test_support::TempDir::create("setup-write");
        let path = directory.write_private("config.toml", b"existing config");
        let mut output = Vec::new();
        let mut prompts = Prompts {
            input: &mut io::empty(),
            output: &mut output,
        };
        match prompts.write_config(&path, empty_config()) {
            Err(ViaError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
                // The message names the file that was kept.
                assert!(error.to_string().contains(&path.display().to_string()));
            }
            other => panic!("expected the existing config to be kept, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&path).unwrap(), "existing config");
        assert!(prompts
            .write_config(&path.join("child.toml"), empty_config())
            .is_err());
        assert!(output.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn writing_config_creates_the_missing_target_of_a_symbolic_link() {
        let directory = crate::test_support::TempDir::create("setup-link");
        let path = directory.join("config.toml");
        std::os::unix::fs::symlink("dotfiles/via.toml", &path).unwrap();

        configure_with_input(&path, "2\n").unwrap();

        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(
            fs::read_to_string(directory.join("dotfiles/via.toml")).unwrap(),
            empty_config()
        );
        assert!(Config::load(Some(&path)).unwrap().services.is_empty());

        // A link whose own target is a dangling link is not followed further.
        let chained = directory.join("chained.toml");
        std::os::unix::fs::symlink("missing.toml", directory.join("middle.toml")).unwrap();
        std::os::unix::fs::symlink("middle.toml", &chained).unwrap();
        assert!(matches!(
            configure_with_input(&chained, "2\n"),
            Err(ViaError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(!directory.join("missing.toml").exists());
    }

    // Output that fails when written to, or only when a prompt is flushed.
    struct FailedOutput {
        fail_write: bool,
    }

    impl Write for FailedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn setup_stops_before_reading_input_when_output_fails() {
        // A failed write stops at the banner. A failed flush stops at the
        // first prompt, which must not go on to read an answer.
        for fail_write in [true, false] {
            let mut input = io::Cursor::new(REST_INPUT);
            let mut prompts = Prompts {
                input: &mut input,
                output: &mut FailedOutput { fail_write },
            };
            assert!(
                matches!(
                    prompts.configure(Path::new("unused.toml")),
                    Err(ViaError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe
                ),
                "fail_write: {fail_write}"
            );
            assert_eq!(input.position(), 0, "fail_write: {fail_write}");
        }
    }

    #[test]
    fn builds_generic_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "gitlab".to_owned(),
            hint: "via gitlab api /projects".to_owned(),
            secret_name: "token".to_owned(),
            secret_reference: "op://Private/GitLab/token".to_owned(),
            private_key_secret_name: None,
            private_key_secret_reference: None,
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://gitlab.example.com/api/v4".to_owned(),
                asset_hosts: Vec::new(),
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::Bearer,
            }),
            delegated: None,
        });

        assert!(config.contains("[services.\"gitlab\"]"));
        assert!(config.contains("hint = \"via gitlab api /projects\""));
        assert!(!config.contains("cache ="));
        assert!(config.contains("base_url = \"https://gitlab.example.com/api/v4\""));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn builds_github_app_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "github".to_owned(),
            hint: String::new(),
            secret_name: "app".to_owned(),
            secret_reference: "op://Private/Example GitHub App/metadata".to_owned(),
            private_key_secret_name: Some("private_key".to_owned()),
            private_key_secret_reference: Some(
                "op://Private/Example GitHub App/github-app.private-key.pem".to_owned(),
            ),
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://api.github.com".to_owned(),
                asset_hosts: Vec::new(),
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::GitHubApp,
            }),
            delegated: None,
        });

        assert!(config.contains("type = \"github_app\""));
        assert!(!config.contains("cache ="));
        assert!(config.contains("credential = \"app\""));
        assert!(config.contains("private_key = \"private_key\""));
        assert!(Config::from_toml_str(&config).is_ok());
    }

    #[test]
    fn builds_oauth_rest_config() {
        let config = build_service_config(ServiceSetup {
            service_name: "linear".to_owned(),
            hint: "via linear api POST /graphql --json '{\"query\":\"{ viewer { id name } }\"}'"
                .to_owned(),
            secret_name: "oauth".to_owned(),
            secret_reference: "op://Private/Linear/oauth".to_owned(),
            private_key_secret_name: None,
            private_key_secret_reference: None,
            rest: Some(RestSetup {
                command_name: "api".to_owned(),
                base_url: "https://api.linear.app".to_owned(),
                asset_hosts: vec!["uploads.linear.app".to_owned()],
                method_default: "GET".to_owned(),
                auth: RestAuthSetup::OAuth,
            }),
            delegated: None,
        });

        assert!(config.contains("type = \"oauth\""));
        assert!(config.contains(
            "hint = \"via linear api POST /graphql --json '{\\\"query\\\":\\\"{ viewer { id name } }\\\"}'\""
        ));
        assert!(config.contains("credential = \"oauth\""));
        assert!(config.contains("asset_hosts = [\"uploads.linear.app\"]"));
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
            hint: String::new(),
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
