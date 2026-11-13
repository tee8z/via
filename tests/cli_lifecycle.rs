use std::fs;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

// The unit tests own this module. A helper that only they use is not dead code.
#[allow(dead_code)]
#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TempDir;

struct Process(Child);

impl Process {
    fn spawn(command: &mut Command) -> Self {
        Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    fn output(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.0.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "CLI process did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        use std::io::Read;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        Output {
            status: self.0.wait().unwrap(),
            stdout,
            stderr,
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(directory: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_via"));
    command
        .current_dir(directory.path())
        .env_remove("VIA_CONFIG")
        .env_remove("SSH_ORIGINAL_COMMAND")
        // With timing output on, an autostarted daemon keeps the standard
        // error pipe open and the test would wait for the daemon to exit.
        .env_remove("VIA_TIMING")
        .env_remove("VIA_DEBUG_TIMING")
        .env("HOME", directory.path())
        .env("USERPROFILE", directory.path());
    command
}

fn success(command: &mut Command) -> String {
    let output = Process::spawn(command).output();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn config_path_uses_explicit_environment_local_and_home_precedence() {
    let directory = TempDir::create("config-path");
    let expected = directory
        .path()
        .join(".config")
        .join("via")
        .join("config.toml");
    assert_eq!(
        success(command(&directory).args(["config", "path"])).trim(),
        expected.to_str().unwrap()
    );
    directory.write_private("via.toml", b"version = 1\n");
    assert_eq!(
        success(command(&directory).args(["config", "path"])).trim(),
        "via.toml"
    );
    assert_eq!(
        success(
            command(&directory)
                .env("VIA_CONFIG", "environment.toml")
                .args(["config", "path"])
        )
        .trim(),
        "environment.toml"
    );
    assert_eq!(
        success(
            command(&directory)
                .env("VIA_CONFIG", "environment.toml")
                .args(["--config", "explicit.toml", "config", "path"])
        )
        .trim(),
        "explicit.toml"
    );
}

#[test]
fn config_without_terminal_refuses_creation_and_preserves_existing_config() {
    let directory = TempDir::create("config-cli");
    let args = ["--config", "via.toml", "config"];
    let output = Process::spawn(command(&directory).args(args)).output();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
    assert!(!directory.join("via.toml").exists());
    directory.write_private("via.toml", b"version = 1\n");
    assert!(success(command(&directory).args(args)).contains("via config:"));
    assert_eq!(
        fs::read_to_string(directory.join("via.toml")).unwrap(),
        "version = 1\n"
    );
}

#[test]
fn doctor_reports_missing_config_unknown_services_and_valid_empty_config() {
    let directory = TempDir::create("doctor-cli");
    let args = ["--config", "via.toml", "config", "doctor"];
    let output = Process::spawn(command(&directory).args(args)).output();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive terminal"));
    directory.write_private("via.toml", b"version = 1\n");
    success(command(&directory).args(args));
    let output = Process::spawn(command(&directory).args(args).arg("unknown")).output();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown service `unknown`"));
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    struct Environment {
        directory: TempDir,
    }

    impl Environment {
        fn new(cache: &str) -> Self {
            let environment = Self {
                directory: TempDir::create("cli"),
            };
            fs::create_dir(environment.directory.join("bin")).unwrap();
            environment.script("systemd-run", "exit 1");
            environment.script("launchctl", "exit 1");
            environment.script(
                "op",
                r#"
case "$1" in
  --version) printf 'test-op\n' ;;
  account) printf '[{"url":"test.1password.com"}]\n' ;;
  whoami) printf '{"email":"test@example.com"}\n' ;;
  read)
    printf '%s|%s|%s\n' "$2" "$3" "$4" >> "$VIA_TEST_OP_LOG"
    if [ -f "$VIA_TEST_OP_FAIL" ]; then printf 'test provider failure\n' >&2; exit 9; fi
    printf '  secret-for-%s\n' "${2##*/}"
    ;;
  *) exit 2 ;;
esac
"#,
            );
            environment.script(
                "trusted-tool",
                r#"
if [ "$1" = '--version' ]; then printf 'test-tool\n'; exit 0; fi
printf 'token=%s other=%s\n' "$TOKEN" "$OTHER"
"#,
            );
            environment.directory.write_private(
                "via.toml",
                format!(
                    r#"
version = 1
[providers.op]
type = "1password"
account = "test.1password.com"
cache = "{cache}"
[services.test]
provider = "op"
[services.test.secrets]
token = "op://Private/Test/token"
other = "op://Private/Test/other"
[services.test.commands.cli]
mode = "delegated"
program = "trusted-tool"
[services.test.commands.cli.inject.env.TOKEN]
secret = "token"
[services.test.commands.cli.inject.env.OTHER]
secret = "other"
[services.test.commands.api]
mode = "rest"
base_url = "https://api.example.com"
[services.test.commands.api.auth]
type = "bearer"
secret = "token"
"#
                )
                .as_bytes(),
            );
            environment
        }

        fn script(&self, name: &str, body: &str) {
            let path = self.directory.write_private(
                &format!("bin/{name}"),
                format!("#!/bin/sh\n{body}\n").as_bytes(),
            );
            test_support::set_mode(&path, 0o700);
        }

        fn command(&self) -> Command {
            let mut command = command(&self.directory);
            command
                .env("PATH", self.directory.join("bin"))
                // Short, to fit the socket path limit below a long TMPDIR.
                .env("VIA_DAEMON_SOCKET", self.directory.join("s/d.sock"))
                .env("VIA_TEST_OP_LOG", self.directory.join("op.log"))
                .env("VIA_TEST_OP_FAIL", self.directory.join("fail-op"));
            command
        }

        fn reads(&self) -> String {
            fs::read_to_string(self.directory.join("op.log")).unwrap()
        }
    }

    impl Drop for Environment {
        fn drop(&mut self) {
            // Autostart may have detached a child. Stop only this fixture's
            // socket. Do not panic: this also runs while a failed test unwinds.
            let stop = self
                .command()
                .args(["daemon", "stop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            if let Ok(mut stop) = stop {
                let deadline = Instant::now() + Duration::from_secs(15);
                while matches!(stop.try_wait(), Ok(None)) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let _ = stop.kill();
                let _ = stop.wait();
            }
        }
    }

    // The tool prints both injected secrets, and the fake provider returns a
    // different value for each reference. Both must be replaced.
    fn assert_redacted(output: &str) {
        assert_eq!(output.trim_end(), "token=[REDACTED] other=[REDACTED]");
    }

    #[test]
    fn direct_provider_passes_account_redacts_output_and_reports_failures() {
        let environment = Environment::new("off");
        let output = success(environment.command().args(["test", "cli"]));
        assert_redacted(&output);
        assert_eq!(environment.reads().lines().count(), 2);
        assert!(environment
            .reads()
            .contains("op://Private/Test/token|--account|test.1password.com"));
        environment.directory.write_private("fail-op", b"");
        let output = Process::spawn(environment.command().args(["test", "cli"])).output();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("test provider failure"));
        fs::remove_file(environment.directory.join("bin/op")).unwrap();
        let output = Process::spawn(environment.command().args(["test", "cli"])).output();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("program `op` was not found"));
    }

    #[test]
    fn doctor_checks_provider_auth_and_delegated_tools_and_reports_recovery() {
        let environment = Environment::new("off");
        let output = success(environment.command().args(["config", "doctor", "test"]));
        assert!(output.contains("secret token: readable by via"));
        assert!(output.contains("capability api: rest"));
        assert!(output.contains("trusted-tool"));
        fs::rename(
            environment.directory.join("bin/op"),
            environment.directory.join("bin/op-disabled"),
        )
        .unwrap();
        let output = Process::spawn(environment.command().args(["config", "doctor"])).output();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("secrets: skipped"));
        fs::rename(
            environment.directory.join("bin/op-disabled"),
            environment.directory.join("bin/op"),
        )
        .unwrap();
        assert!(success(environment.command().args(["config", "doctor"]))
            .contains("secret token: readable by via"));
    }

    #[test]
    fn daemon_autostart_cache_clear_and_stop_preserve_resolution_and_redaction() {
        let environment = Environment::new("daemon");
        for _ in 0..2 {
            assert_redacted(&success(environment.command().args(["test", "cli"])));
        }
        assert_eq!(environment.reads().lines().count(), 2);
        assert!(
            success(environment.command().args(["daemon", "status"])).contains("cached entries: 2")
        );
        success(environment.command().args(["daemon", "clear"]));
        assert!(
            success(environment.command().args(["daemon", "status"])).contains("cached entries: 0")
        );
        success(environment.command().args(["test", "cli"]));
        assert_eq!(environment.reads().lines().count(), 4);
        success(environment.command().args(["daemon", "stop"]));
        assert!(success(environment.command().args(["daemon", "status"]))
            .contains("via daemon: stopped"));
    }

    #[test]
    fn daemon_provider_failure_is_not_cached_and_can_recover() {
        let environment = Environment::new("daemon");
        environment.directory.write_private("fail-op", b"");
        let output = Process::spawn(environment.command().args(["test", "cli"])).output();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("test provider failure"));
        assert!(
            success(environment.command().args(["daemon", "status"])).contains("cached entries: 0")
        );
        fs::remove_file(environment.directory.join("fail-op")).unwrap();
        success(environment.command().args(["test", "cli"]));
        assert!(
            success(environment.command().args(["daemon", "status"])).contains("cached entries: 2")
        );
    }

    #[test]
    fn daemon_client_reports_empty_and_invalid_responses() {
        let directory = TempDir::create("daemon-wire");
        let path = directory.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        for (response, problem) in [
            ("\n", "daemon returned an empty response"),
            ("not-json\n", "json error"),
        ] {
            let child = Process::spawn(
                command(&directory)
                    .env("VIA_DAEMON_SOCKET", &path)
                    .args(["daemon", "status"]),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "client did not connect");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            // Some platforms hand out a non-blocking stream from a
            // non-blocking listener.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = String::new();
            BufReader::new(&mut stream).read_line(&mut request).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&request).unwrap()["type"],
                "status"
            );
            stream.write_all(response.as_bytes()).unwrap();
            drop(stream);
            let output = child.output();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(problem), "{stderr}");
        }
    }
}
