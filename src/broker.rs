use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

use crate::audit::{rfc3339_utc, AuditOutcome, AuditRecord, AuditSink};
use crate::config::{valid_path_component, CapabilityMode, Config};
use crate::error::ViaError;
use crate::executor::{self, ExecutionContext, InvocationTrace};
use crate::providers::ProviderRegistry;

const ORIGINAL_COMMAND_ENV: &str = "SSH_ORIGINAL_COMMAND";
const CONNECTION_ENV: &str = "SSH_CONNECTION";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ARGS: usize = 256;
const MAX_CALLER_BYTES: usize = 128;

// Names a remote caller may not use as a service, because they select via
// commands that act on the broker host itself.
const RESERVED_REQUESTS: [&str; 7] = [
    "config", "login", "daemon", "doctor", "broker", "version", "help",
];

pub struct BrokerInvocation {
    pub config_path: Option<PathBuf>,
    pub caller: Option<String>,
    // Arguments after `--`, for local testing. Empty when absent.
    pub request: Vec<String>,
}

pub fn run(invocation: BrokerInvocation) -> Result<ExitCode, ViaError> {
    let original_command = env::var_os(ORIGINAL_COMMAND_ENV);
    let connection = env::var_os(CONNECTION_ENV);
    run_request(
        &invocation,
        original_command.as_deref(),
        connection.as_deref(),
    )?;
    Ok(ExitCode::SUCCESS)
}

// Serves one request. The config comes only from `--config`; no environment
// variable, default location or part of the request can select another one.
fn run_request(
    invocation: &BrokerInvocation,
    original_command: Option<&OsStr>,
    connection: Option<&OsStr>,
) -> Result<(), ViaError> {
    let started = Instant::now();
    let config_path = broker_config_path(invocation.config_path.as_deref())?;
    validate_caller(invocation.caller.as_deref())?;
    let config = Config::load(Some(config_path))?;

    // Fail closed: without a writable audit sink no request runs.
    let audit = config.audit.as_ref().ok_or_else(|| {
        ViaError::InvalidConfig(
            "`via broker exec` requires an [audit] table in the broker config".to_owned(),
        )
    })?;
    let mut sink = AuditSink::open(audit)?;

    let mut record = AuditRecord::new(invocation.caller.clone(), client_address(connection));
    let mut trace = InvocationTrace::default();
    // A panic must not skip the audit record, so it becomes a failed request.
    let served = panic::catch_unwind(AssertUnwindSafe(|| {
        serve(
            &config,
            &invocation.request,
            original_command,
            &mut record,
            &mut trace,
            &mut sink,
        )
    }));
    let panicked = served.is_err();
    let result = served.unwrap_or_else(|_| {
        Err(ViaError::Io(io::Error::other(
            "via broker: the request handler stopped unexpectedly",
        )))
    });

    complete_record(&mut record, &result, &trace, started.elapsed());
    if panicked {
        record.reason = Some("internal_error".to_owned());
    }
    sink.write(&record)?;
    result
}

fn broker_config_path(path: Option<&Path>) -> Result<&Path, ViaError> {
    let path = path.ok_or_else(|| ViaError::InvalidCli(crate::cli::BROKER_USAGE.to_owned()))?;
    if !path.is_absolute() {
        return Err(ViaError::InvalidCli(
            "`via broker exec --config` must be an absolute path".to_owned(),
        ));
    }

    Ok(path)
}

fn validate_caller(caller: Option<&str>) -> Result<(), ViaError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.is_empty() || caller.len() > MAX_CALLER_BYTES || caller.chars().any(char::is_control)
    {
        return Err(ViaError::InvalidCli(format!(
            "`--caller` must be 1 to {MAX_CALLER_BYTES} bytes without control characters"
        )));
    }

    Ok(())
}

// The first field of SSH_CONNECTION is the client address.
fn client_address(connection: Option<&OsStr>) -> Option<String> {
    connection?
        .to_str()?
        .split_whitespace()
        .next()
        .map(str::to_owned)
}

fn serve(
    config: &Config,
    cli_request: &[String],
    original_command: Option<&OsStr>,
    record: &mut AuditRecord,
    trace: &mut InvocationTrace,
    sink: &mut AuditSink,
) -> Result<(), ViaError> {
    let args = select_request(cli_request, original_command)?;
    let request = BrokerRequest::parse(args)?;
    record.request = Some(request.kind());
    if let BrokerRequest::Run {
        service,
        capability,
        ..
    } = &request
    {
        record.service = Some(service.clone());
        record.capability = Some(capability.clone());
    }
    check_kill_switch(config, &request)?;

    // Persist admission before any stdin, network, SSH, or output operation
    // can block. The completion record uses the same ID. Do not log raw
    // targets or command arguments before secrets are available for redaction.
    record.ts = rfc3339_utc(SystemTime::now());
    record.outcome = AuditOutcome::Started;
    record.sanitize(&trace.redactor);
    sink.write(record)?;

    let context = ExecutionContext::broker();
    match request {
        BrokerRequest::Capabilities { json } => {
            let output = crate::capabilities::render_with_context(config, json, &context)?;
            crate::output::write_stdout(output.as_bytes())?;
            Ok(())
        }
        BrokerRequest::SkillPrint => {
            let output = crate::skill::render_with_context(config, &context);
            crate::output::write_stdout(output.as_bytes())?;
            Ok(())
        }
        BrokerRequest::Run {
            service,
            capability,
            args,
        } => {
            let providers = ProviderRegistry::from_config(config)?;
            executor::invoke_with_context(
                &context,
                config,
                &providers,
                &service,
                &capability,
                args,
                trace,
            )
        }
    }
}

// The request is the caller's via argument list. It comes from arguments
// after `--`, or from SSH_ORIGINAL_COMMAND as a JSON array of strings.
fn select_request(
    cli_request: &[String],
    original_command: Option<&OsStr>,
) -> Result<Vec<String>, ViaError> {
    match (cli_request.is_empty(), original_command) {
        (false, Some(_)) => Err(invalid_request(
            "pass the request after `--` or in SSH_ORIGINAL_COMMAND, not both",
        )),
        (true, None) => Err(invalid_request(
            "no request; pass it after `--`, or connect over SSH with a command",
        )),
        (false, None) => validate_request_args(cli_request.to_vec()),
        (true, Some(raw)) => parse_original_command(raw),
    }
}

// Strict by design: a shell-word fallback would let quoting decide what the
// broker runs.
fn parse_original_command(raw: &OsStr) -> Result<Vec<String>, ViaError> {
    let raw = raw
        .to_str()
        .ok_or_else(|| invalid_request("SSH_ORIGINAL_COMMAND is not valid UTF-8"))?;
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(invalid_request("the request is larger than 64 KiB"));
    }
    if raw.contains('\0') {
        return Err(invalid_request("the request contains a NUL byte"));
    }
    let args = serde_json::from_str::<Vec<String>>(raw)
        .map_err(|_| invalid_request("SSH_ORIGINAL_COMMAND must be a JSON array of strings"))?;

    validate_request_args(args)
}

fn validate_request_args(args: Vec<String>) -> Result<Vec<String>, ViaError> {
    if args.is_empty() {
        return Err(invalid_request("the request is empty"));
    }
    if args.len() > MAX_REQUEST_ARGS {
        return Err(invalid_request("the request has more than 256 arguments"));
    }
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(invalid_request("the request contains a NUL byte"));
    }

    Ok(args)
}

fn invalid_request(problem: &str) -> ViaError {
    ViaError::denied("invalid_request", format!("via broker: {problem}"))
}

fn not_allowed(problem: &str) -> ViaError {
    ViaError::denied("request_not_allowed", format!("via broker: {problem}"))
}

#[derive(Debug, PartialEq, Eq)]
enum BrokerRequest {
    Capabilities {
        json: bool,
    },
    SkillPrint,
    Run {
        service: String,
        capability: String,
        args: Vec<String>,
    },
}

impl BrokerRequest {
    // Only discovery and capability invocations are served. Everything that
    // configures, authenticates or inspects the broker host is refused.
    fn parse(args: Vec<String>) -> Result<Self, ViaError> {
        let mut args = args.into_iter();
        let Some(first) = args.next() else {
            return Err(invalid_request("the request is empty"));
        };
        let rest = args.collect::<Vec<_>>();

        if first == "capabilities" {
            return match rest.as_slice() {
                [] => Ok(Self::Capabilities { json: false }),
                [flag] if flag == "--json" => Ok(Self::Capabilities { json: true }),
                _ => Err(not_allowed("`capabilities` only accepts `--json`")),
            };
        }
        if first == "skill" {
            return match rest.as_slice() {
                [subcommand] if subcommand == "print" => Ok(Self::SkillPrint),
                _ => Err(not_allowed("only `skill print` is available")),
            };
        }
        if first.starts_with('-') {
            return Err(not_allowed("options are not accepted before a request"));
        }
        if RESERVED_REQUESTS.contains(&first.as_str()) {
            return Err(not_allowed(
                "only `capabilities`, `skill print` and capability invocations are available",
            ));
        }

        let mut rest = rest.into_iter();
        let capability = rest
            .next()
            .ok_or_else(|| invalid_request("a capability name is required after the service"))?;
        Ok(Self::Run {
            service: first,
            capability,
            args: rest.collect(),
        })
    }

    fn kind(&self) -> &'static str {
        match self {
            BrokerRequest::Capabilities { .. } => "capabilities",
            BrokerRequest::SkillPrint => "skill",
            BrokerRequest::Run { .. } => "run",
        }
    }
}

// `<disable_dir>/all` disables every request and `<disable_dir>/<service>`
// disables one service. The refusal does not say which marker exists.
fn check_kill_switch(config: &Config, request: &BrokerRequest) -> Result<(), ViaError> {
    let service = match request {
        BrokerRequest::Run { service, .. } => Some(service.as_str()),
        BrokerRequest::Capabilities { .. } | BrokerRequest::SkillPrint => None,
    };
    // A service name becomes a file name below, so it must be exactly one
    // path component.
    if service.is_some_and(|service| !valid_path_component(service)) {
        return Err(ViaError::denied(
            "invalid_service_name",
            "via broker: the service name is not valid",
        ));
    }

    let Some(disable_dir) = config
        .broker
        .as_ref()
        .and_then(|broker| broker.disable_dir.as_deref())
    else {
        return Ok(());
    };
    let disabled = marker_exists(&disable_dir.join("all"))
        || service.is_some_and(|service| marker_exists(&disable_dir.join(service)));
    if disabled {
        return Err(ViaError::denied(
            "disabled",
            "via broker: access is disabled",
        ));
    }

    Ok(())
}

// Only a clear "not found" means that a marker is absent. Any other answer,
// such as a permission error, disables access.
fn marker_exists(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

fn complete_record(
    record: &mut AuditRecord,
    result: &Result<(), ViaError>,
    trace: &InvocationTrace,
    elapsed: Duration,
) {
    record.mode = trace.mode;
    record.method.clone_from(&trace.method);
    record.host.clone_from(&trace.host);
    record.path.clone_from(&trace.path);
    record.ssh_host.clone_from(&trace.ssh_host);
    record.ssh_command.clone_from(&trace.ssh_command);
    record.status = trace.status;

    let (outcome, reason) = classify(result, trace);
    record.outcome = outcome;
    record.reason = reason.map(str::to_owned);
    record.duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    record.ts = rfc3339_utc(SystemTime::now());
    record.sanitize(&trace.redactor);
}

fn classify(
    result: &Result<(), ViaError>,
    trace: &InvocationTrace,
) -> (AuditOutcome, Option<&'static str>) {
    match result {
        Ok(()) => (AuditOutcome::Ok, None),
        Err(error @ ViaError::Denied { .. }) => (AuditOutcome::Denied, Some(error.kind())),
        Err(_) if trace.denied.is_some() => (AuditOutcome::Denied, trace.denied),
        Err(_) if is_http_failure(trace) => (AuditOutcome::Error, Some("http_status")),
        Err(error) => (AuditOutcome::Error, Some(error.kind())),
    }
}

fn is_http_failure(trace: &InvocationTrace) -> bool {
    matches!(trace.mode, Some(CapabilityMode::Rest))
        && trace
            .status
            .is_some_and(|status| !(200..300).contains(&status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const TOKEN: &str = "broker-test-token";
    const CONNECTION: &str = "198.51.100.7 51234 203.0.113.9 22";
    const UNREACHABLE: &str = "http://127.0.0.1:9";

    struct Harness {
        directory: TempDir,
        config_path: PathBuf,
    }

    impl Harness {
        fn create(label: &str, base_url: &str) -> Self {
            let directory = TempDir::create(label);
            let audit = format!(
                "[audit]\nsink = \"file\"\npath = '{}'\n",
                directory.join("audit.jsonl").display()
            );
            Self::create_in(directory, base_url, &audit)
        }

        fn create_in(directory: TempDir, base_url: &str, audit: &str) -> Self {
            directory.write_private("github-token", format!("{TOKEN}\n").as_bytes());
            let root = directory.path().display();
            let disable_dir = directory.join("disabled");
            let disable_dir = disable_dir.display();
            let config = format!(
                r#"
version = 1

[providers.files]
type = "directory"
path = '{root}'

[broker]
disable_dir = '{disable_dir}'

{audit}

[services.github]
description = "Example API"
provider = "files"

[services.github.secrets]
token = "cred://github-token"

[services.github.commands.api]
mode = "rest"
base_url = "{base_url}"
methods = ["GET", "POST"]
allow_paths = ["/repos/**"]
deny_paths = ["/repos/*/*/secrets/**"]

[services.github.commands.api.auth]
type = "bearer"
secret = "token"

[services.github.commands.gh]
mode = "delegated"
program = "via-test-missing-delegated-program"

[services.other]
provider = "files"

[services.other.commands.api]
mode = "rest"
base_url = "{base_url}"
"#
            );
            let config_path = directory.write_private("broker.toml", config.as_bytes());

            Self {
                directory,
                config_path,
            }
        }

        fn invocation(&self) -> BrokerInvocation {
            BrokerInvocation {
                config_path: Some(self.config_path.clone()),
                caller: Some("sandbox-1".to_owned()),
                request: Vec::new(),
            }
        }

        // Runs one request the way sshd delivers it to a forced command.
        fn run(&self, request: &[&str]) -> Result<(), ViaError> {
            let original_command = serde_json::to_string(request).unwrap();
            self.run_raw(&original_command)
        }

        fn run_raw(&self, original_command: &str) -> Result<(), ViaError> {
            run_request(
                &self.invocation(),
                Some(OsStr::new(original_command)),
                Some(OsStr::new(CONNECTION)),
            )
        }

        fn disable(&self, marker: &str) {
            let disable_dir = self.directory.join("disabled");
            fs::create_dir_all(disable_dir.as_path()).unwrap();
            fs::write(disable_dir.join(marker), b"").unwrap();
        }

        fn audit_log(&self) -> String {
            fs::read_to_string(self.directory.join("audit.jsonl")).unwrap_or_default()
        }

        fn records(&self) -> Vec<serde_json::Value> {
            self.audit_log()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|record: &serde_json::Value| record["outcome"] != "started")
                .collect()
        }

        // The completion record written by the only request of a test.
        fn record(&self) -> serde_json::Value {
            let mut records = self.records();
            assert_eq!(records.len(), 1, "expected exactly one audit record");
            records.remove(0)
        }
    }

    fn denial(result: Result<(), ViaError>) -> (&'static str, String) {
        match result {
            Err(ViaError::Denied { reason, message }) => (reason, message),
            Err(error) => panic!("expected a denial, got {error}"),
            Ok(()) => panic!("expected a denial"),
        }
    }

    fn denial_reason<T>(result: Result<T, ViaError>) -> &'static str {
        match result {
            Err(ViaError::Denied { reason, .. }) => reason,
            Err(error) => panic!("expected a denial, got {error}"),
            Ok(_) => panic!("expected a denial"),
        }
    }

    fn http_server(responses: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_string());
                stream.write_all(response.as_bytes()).unwrap();
            }
            requests
        });

        (format!("http://{address}"), handle)
    }

    fn ok_response() -> String {
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_ssh_original_command_as_a_json_array_of_strings() {
        assert_eq!(
            parse_original_command(OsStr::new(r#"["capabilities","--json"]"#)).unwrap(),
            ["capabilities", "--json"]
        );
        assert_eq!(
            parse_original_command(OsStr::new(
                r#" [ "github", "api", "POST", "/repos/o/r/issues", "--json", "{\"title\":\"a b\"}" ] "#
            ))
            .unwrap(),
            [
                "github",
                "api",
                "POST",
                "/repos/o/r/issues",
                "--json",
                "{\"title\":\"a b\"}"
            ]
        );
    }

    #[test]
    fn rejects_ssh_original_command_that_is_not_a_json_array_of_strings() {
        for raw in [
            "",
            "capabilities --json",
            "github api /user",
            r#""capabilities""#,
            r#"{"args":["capabilities"]}"#,
            "[1, 2]",
            r#"["github", null]"#,
            r#"["github", ["api"]]"#,
            "[]",
            r#"["capabilities"] --json"#,
            r#"["capabilities"]["skill"]"#,
            r#"["capabilities""#,
            r#"['capabilities']"#,
            r#"["a\u0000b"]"#,
            "[\"a\0b\"]",
        ] {
            assert_eq!(
                denial_reason(parse_original_command(OsStr::new(raw))),
                "invalid_request",
                "raw `{raw}`"
            );
        }
    }

    #[test]
    fn limits_the_size_of_ssh_original_command() {
        let at_limit = format!("[\"{}\"]", "a".repeat(MAX_REQUEST_BYTES - 4));
        assert_eq!(at_limit.len(), MAX_REQUEST_BYTES);
        assert_eq!(
            parse_original_command(OsStr::new(&at_limit)).unwrap().len(),
            1
        );

        let too_large = format!("[\"{}\"]", "a".repeat(MAX_REQUEST_BYTES - 3));
        let (reason, message) = match parse_original_command(OsStr::new(&too_large)) {
            Err(ViaError::Denied { reason, message }) => (reason, message),
            _ => panic!("expected the oversized request to be refused"),
        };
        assert_eq!(reason, "invalid_request");
        assert!(message.contains("64 KiB"));

        let array_of = |count: usize| format!("[{}]", ["\"a\""].repeat(count).join(","));
        let at_count_limit = array_of(MAX_REQUEST_ARGS);
        assert_eq!(
            parse_original_command(OsStr::new(&at_count_limit))
                .unwrap()
                .len(),
            MAX_REQUEST_ARGS
        );
        let too_many = array_of(MAX_REQUEST_ARGS + 1);
        assert_eq!(
            denial_reason(parse_original_command(OsStr::new(&too_many))),
            "invalid_request"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_ssh_original_command_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;

        assert_eq!(
            denial_reason(parse_original_command(OsStr::from_bytes(b"[\"a\xff\"]"))),
            "invalid_request"
        );
    }

    #[test]
    fn requires_exactly_one_request_source() {
        let cli = strings(&["capabilities", "--json"]);
        let command = OsStr::new(r#"["skill","print"]"#);

        assert_eq!(
            select_request(&cli, None).unwrap(),
            ["capabilities", "--json"]
        );
        assert_eq!(
            select_request(&[], Some(command)).unwrap(),
            ["skill", "print"]
        );

        let (reason, message) = match select_request(&cli, Some(command)) {
            Err(ViaError::Denied { reason, message }) => (reason, message),
            _ => panic!("expected two request sources to be refused"),
        };
        assert_eq!(reason, "invalid_request");
        assert!(message.contains("not both"));

        let (reason, message) = match select_request(&[], None) {
            Err(ViaError::Denied { reason, message }) => (reason, message),
            _ => panic!("expected a missing request to be refused"),
        };
        assert_eq!(reason, "invalid_request");
        assert!(message.contains("no request"));

        assert_eq!(
            denial_reason(select_request(&strings(&["github", "a\0b"]), None)),
            "invalid_request"
        );
    }

    #[test]
    fn parses_the_requests_a_broker_serves() {
        assert_eq!(
            BrokerRequest::parse(strings(&["capabilities"])).unwrap(),
            BrokerRequest::Capabilities { json: false }
        );
        assert_eq!(
            BrokerRequest::parse(strings(&["capabilities", "--json"])).unwrap(),
            BrokerRequest::Capabilities { json: true }
        );
        assert_eq!(
            BrokerRequest::parse(strings(&["skill", "print"])).unwrap(),
            BrokerRequest::SkillPrint
        );
        assert_eq!(
            BrokerRequest::parse(strings(&["github", "api"])).unwrap(),
            BrokerRequest::Run {
                service: "github".to_owned(),
                capability: "api".to_owned(),
                args: Vec::new(),
            }
        );
        assert_eq!(
            BrokerRequest::parse(strings(&[
                "github",
                "api",
                "POST",
                "/user",
                "--config",
                "/tmp/other.toml"
            ]))
            .unwrap(),
            BrokerRequest::Run {
                service: "github".to_owned(),
                capability: "api".to_owned(),
                args: strings(&["POST", "/user", "--config", "/tmp/other.toml"]),
            }
        );
        assert_eq!(
            BrokerRequest::Capabilities { json: true }.kind(),
            "capabilities"
        );
        assert_eq!(BrokerRequest::SkillPrint.kind(), "skill");
    }

    #[test]
    fn refuses_requests_that_are_not_discovery_or_invocation() {
        for request in [
            &["config"][..],
            &["config", "doctor"],
            &["config", "path"],
            &["login"],
            &["login", "onepassword"],
            &["daemon", "status"],
            &["daemon", "serve"],
            &["doctor"],
            &["doctor", "github"],
            &["broker", "exec"],
            &["version"],
            &["help"],
            &["--help"],
            &["--version"],
            &["--config", "/tmp/other.toml", "capabilities"],
            &["-c", "/tmp/other.toml", "github", "api", "/user"],
            &["capabilities", "--config", "/tmp/other.toml"],
            &["capabilities", "--json", "extra"],
            &["capabilities", "json"],
            &["skill"],
            &["skill", "install"],
            &["skill", "print", "extra"],
        ] {
            assert_eq!(
                denial_reason(BrokerRequest::parse(strings(request))),
                "request_not_allowed",
                "request {request:?}"
            );
        }

        assert_eq!(
            denial_reason(BrokerRequest::parse(strings(&["github"]))),
            "invalid_request"
        );
        assert_eq!(
            denial_reason(BrokerRequest::parse(Vec::new())),
            "invalid_request"
        );
    }

    fn kill_switch_config(disable_dir: Option<&Path>) -> Config {
        let broker = match disable_dir {
            Some(path) => format!("[broker]\ndisable_dir = '{}'\n", path.display()),
            None => String::new(),
        };
        Config::from_toml_str(&format!("version = 1\n\n{broker}")).unwrap()
    }

    fn run_request_for(service: &str) -> BrokerRequest {
        BrokerRequest::Run {
            service: service.to_owned(),
            capability: "api".to_owned(),
            args: Vec::new(),
        }
    }

    #[test]
    fn kill_switch_is_off_without_a_directory_or_marker() {
        let directory = TempDir::create("broker-kill-switch-off");
        let requests = [
            BrokerRequest::Capabilities { json: true },
            BrokerRequest::SkillPrint,
            run_request_for("github"),
        ];

        for config in [
            kill_switch_config(None),
            kill_switch_config(Some(&directory.join("absent"))),
            kill_switch_config(Some(directory.path())),
        ] {
            for request in &requests {
                assert!(check_kill_switch(&config, request).is_ok());
            }
        }
    }

    #[test]
    fn kill_switch_all_marker_refuses_every_request() {
        let directory = TempDir::create("broker-kill-switch-all");
        fs::write(directory.join("all"), b"").unwrap();
        let config = kill_switch_config(Some(directory.path()));

        for request in [
            BrokerRequest::Capabilities { json: false },
            BrokerRequest::SkillPrint,
            run_request_for("github"),
            run_request_for("other"),
        ] {
            let (reason, message) = denial(check_kill_switch(&config, &request));

            assert_eq!(reason, "disabled");
            assert_eq!(message, "via broker: access is disabled");
        }
    }

    #[test]
    fn kill_switch_service_marker_refuses_only_that_service() {
        let directory = TempDir::create("broker-kill-switch-service");
        fs::write(directory.join("github"), b"").unwrap();
        let config = kill_switch_config(Some(directory.path()));

        let (reason, message) = denial(check_kill_switch(&config, &run_request_for("github")));
        assert_eq!(reason, "disabled");
        assert_eq!(message, "via broker: access is disabled");

        assert!(check_kill_switch(&config, &run_request_for("other")).is_ok());
        assert!(check_kill_switch(&config, &BrokerRequest::Capabilities { json: true }).is_ok());
        assert!(check_kill_switch(&config, &BrokerRequest::SkillPrint).is_ok());
    }

    #[test]
    fn kill_switch_validates_the_service_name_before_building_a_path() {
        let directory = TempDir::create("broker-kill-switch-names");
        let disable_dir = directory.join("disabled");
        fs::create_dir(disable_dir.as_path()).unwrap();
        // A traversal would reach this marker if the name were joined as is.
        fs::write(directory.join("outside"), b"").unwrap();

        for config in [
            kill_switch_config(Some(&disable_dir)),
            kill_switch_config(None),
        ] {
            for service in ["../outside", "a/b", "/etc", "", ".", "..", "a\\b", "a\0b"] {
                assert_eq!(
                    denial_reason(check_kill_switch(&config, &run_request_for(service))),
                    "invalid_service_name",
                    "service `{service}`"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn kill_switch_fails_closed_for_unreadable_or_unusual_markers() {
        let directory = TempDir::create("broker-kill-switch-closed");

        // A dangling symbolic link still counts as a marker.
        let links = directory.join("links");
        fs::create_dir(links.as_path()).unwrap();
        std::os::unix::fs::symlink(directory.join("absent"), links.join("all")).unwrap();
        assert_eq!(
            denial_reason(check_kill_switch(
                &kill_switch_config(Some(&links)),
                &BrokerRequest::SkillPrint
            )),
            "disabled"
        );

        // A disable_dir that is a file cannot be searched, so access is off.
        let file = directory.join("not-a-directory");
        fs::write(file.as_path(), b"").unwrap();
        assert_eq!(
            denial_reason(check_kill_switch(
                &kill_switch_config(Some(&file)),
                &run_request_for("github")
            )),
            "disabled"
        );
    }

    #[test]
    fn classifies_outcomes_for_audit_records() {
        let trace = InvocationTrace::default();
        assert_eq!(classify(&Ok(()), &trace), (AuditOutcome::Ok, None));
        assert_eq!(
            classify(
                &Err(ViaError::denied("method_not_allowed", "refused")),
                &trace
            ),
            (AuditOutcome::Denied, Some("method_not_allowed"))
        );
        assert_eq!(
            classify(&Err(ViaError::UnknownService("x".to_owned())), &trace),
            (AuditOutcome::Error, Some("unknown_service"))
        );

        let host_refused = InvocationTrace {
            denied: Some("ssh_host_not_allowed"),
            ..InvocationTrace::default()
        };
        assert_eq!(
            classify(
                &Err(ViaError::InvalidArgument("refused".to_owned())),
                &host_refused
            ),
            (AuditOutcome::Denied, Some("ssh_host_not_allowed"))
        );

        let not_found = InvocationTrace {
            mode: Some(CapabilityMode::Rest),
            status: Some(404),
            ..InvocationTrace::default()
        };
        assert_eq!(
            classify(
                &Err(ViaError::InvalidArgument("failed".to_owned())),
                &not_found
            ),
            (AuditOutcome::Error, Some("http_status"))
        );

        let ssh_exit = InvocationTrace {
            mode: Some(CapabilityMode::Ssh),
            status: Some(42),
            ..InvocationTrace::default()
        };
        assert_eq!(
            classify(
                &Err(ViaError::SshCommandFailed { status: Some(42) }),
                &ssh_exit
            ),
            (AuditOutcome::Error, Some("ssh_command_failed"))
        );
    }

    #[test]
    fn reads_the_client_address_from_ssh_connection() {
        assert_eq!(
            client_address(Some(OsStr::new(CONNECTION))).as_deref(),
            Some("198.51.100.7")
        );
        assert_eq!(
            client_address(Some(OsStr::new("2001:db8::7 51234 2001:db8::9 22"))).as_deref(),
            Some("2001:db8::7")
        );
        assert_eq!(client_address(Some(OsStr::new(""))), None);
        assert_eq!(client_address(None), None);
    }

    #[test]
    fn validates_the_caller_label() {
        assert!(validate_caller(None).is_ok());
        assert!(validate_caller(Some("sandbox-1")).is_ok());
        let too_long = "a".repeat(MAX_CALLER_BYTES + 1);
        for caller in ["", "line\nbreak", too_long.as_str()] {
            assert!(matches!(
                validate_caller(Some(caller)),
                Err(ViaError::InvalidCli(_))
            ));
        }
    }

    #[test]
    fn requires_an_absolute_config_path() {
        let harness = Harness::create("broker-config-path", UNREACHABLE);

        let mut missing = harness.invocation();
        missing.config_path = None;
        assert!(matches!(
            run_request(&missing, Some(OsStr::new(r#"["capabilities"]"#)), None),
            Err(ViaError::InvalidCli(message)) if message.contains("--config")
        ));

        let mut relative = harness.invocation();
        relative.config_path = Some(PathBuf::from("broker.toml"));
        assert!(matches!(
            run_request(&relative, Some(OsStr::new(r#"["capabilities"]"#)), None),
            Err(ViaError::InvalidCli(message)) if message.contains("absolute path")
        ));
        assert!(harness.records().is_empty());
    }

    #[test]
    fn refuses_every_request_without_an_audit_table() {
        let harness = Harness::create_in(
            TempDir::create("broker-no-audit"),
            UNREACHABLE,
            "# no audit table",
        );

        for request in [r#"["capabilities"]"#, r#"["github","api","/repos/o/r"]"#] {
            assert!(matches!(
                harness.run_raw(request),
                Err(ViaError::InvalidConfig(message)) if message.contains("[audit]")
            ));
        }
    }

    #[test]
    fn refuses_every_request_when_the_audit_sink_cannot_be_opened() {
        let directory = TempDir::create("broker-audit-unavailable");
        let audit = format!(
            "[audit]\nsink = \"file\"\npath = '{}'\n",
            directory.join("absent").join("audit.jsonl").display()
        );
        let harness = Harness::create_in(directory, UNREACHABLE, &audit);

        // A request that reached the network would fail with an HTTP error
        // instead: nothing listens at the configured address.
        for request in [r#"["capabilities"]"#, r#"["github","api","/repos/o/r"]"#] {
            assert!(matches!(
                harness.run_raw(request),
                Err(ViaError::AuditUnavailable(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reports_failure_when_the_audit_record_cannot_be_written() {
        let harness = Harness::create_in(
            TempDir::create("broker-audit-full"),
            UNREACHABLE,
            "[audit]\nsink = \"file\"\npath = \"/dev/full\"\n",
        );

        assert!(matches!(
            harness.run(&["capabilities"]),
            Err(ViaError::AuditUnavailable(message)) if message.contains("cannot be written")
        ));
    }

    #[test]
    fn audits_discovery_requests() {
        let harness = Harness::create("broker-audit-discovery", UNREACHABLE);

        harness.run(&["capabilities", "--json"]).unwrap();
        harness.run(&["skill", "print"]).unwrap();

        let records = harness.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["request"], "capabilities");
        assert_eq!(records[1]["request"], "skill");
        for record in &records {
            assert_eq!(record["outcome"], "ok");
            assert_eq!(record["caller"], "sandbox-1");
            assert_eq!(record["client"], "198.51.100.7");
            assert!(record["ts"].as_str().unwrap().ends_with('Z'));
            assert!(record["duration_ms"].is_u64());
            for field in [
                "service",
                "capability",
                "mode",
                "method",
                "host",
                "path",
                "ssh_host",
                "ssh_command",
                "reason",
                "status",
            ] {
                assert!(record[field].is_null(), "field `{field}`");
            }
        }
    }

    #[test]
    fn audits_an_allowed_rest_request_without_query_or_secrets() {
        crate::tls::install_crypto_provider();
        let (base_url, server) = http_server(vec![ok_response()]);
        let harness = Harness::create("broker-audit-rest", &base_url);

        let target = format!("/repos/o/{TOKEN}?access=query-secret");
        harness
            .run(&[
                "github",
                "api",
                target.as_str(),
                "--query",
                "page=query-value",
            ])
            .unwrap();

        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(&format!(
            "GET /repos/o/{TOKEN}?access=query-secret&page=query-value "
        )));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}")));

        let record = harness.record();
        assert_eq!(record["request"], "run");
        assert_eq!(record["service"], "github");
        assert_eq!(record["capability"], "api");
        assert_eq!(record["mode"], "rest");
        assert_eq!(record["method"], "GET");
        assert_eq!(record["host"], "127.0.0.1");
        assert_eq!(record["path"], "/repos/o/[REDACTED]");
        assert_eq!(record["outcome"], "ok");
        assert!(record["reason"].is_null());
        assert_eq!(record["status"], 200);
        let log = harness.audit_log();
        assert!(!log.contains(TOKEN));
        assert!(!log.contains("query-secret"));
        assert!(!log.contains("query-value"));
        assert!(!log.contains("access="));
    }

    #[test]
    fn audits_an_upstream_failure_with_its_status() {
        crate::tls::install_crypto_provider();
        let (base_url, server) = http_server(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        ]);
        let harness = Harness::create("broker-audit-rest-failure", &base_url);

        assert!(matches!(
            harness.run(&["github", "api", "/repos/o/missing"]),
            Err(ViaError::InvalidArgument(message)) if message.contains("404")
        ));

        assert_eq!(server.join().unwrap().len(), 1);
        let record = harness.record();
        assert_eq!(record["outcome"], "error");
        assert_eq!(record["reason"], "http_status");
        assert_eq!(record["status"], 404);
        assert_eq!(record["path"], "/repos/o/missing");
    }

    #[test]
    fn audits_requests_refused_by_rules() {
        let harness = Harness::create("broker-audit-rules", UNREACHABLE);

        for (request, reason) in [
            (
                r#"["github","api","DELETE","/repos/o/r"]"#,
                "method_not_allowed",
            ),
            (
                r#"["github","api","/user?next=/repos/o/r"]"#,
                "path_not_allowed",
            ),
            (
                r#"["github","api","/repos/o/r/secrets/NAME"]"#,
                "path_denied",
            ),
            (
                r#"["github","api","/repos/../user"]"#,
                "path_not_normalized",
            ),
            (
                r#"["github","api","/repos/%2e%2e/user"]"#,
                "path_not_normalized",
            ),
            (r#"["github","api","/repos//user"]"#, "path_not_normalized"),
            (r#"["github","api","/repos/o%2fr"]"#, "path_not_normalized"),
        ] {
            assert_eq!(denial_reason(harness.run_raw(request)), reason, "{request}");
        }

        let records = harness.records();
        assert_eq!(records.len(), 7);
        for record in &records {
            assert_eq!(record["request"], "run");
            assert_eq!(record["outcome"], "denied");
            assert_eq!(record["mode"], "rest");
            assert!(record["status"].is_null());
        }
        assert_eq!(records[0]["reason"], "method_not_allowed");
        assert_eq!(records[0]["method"], "DELETE");
        assert_eq!(records[1]["reason"], "path_not_allowed");
        assert_eq!(records[1]["path"], "/user");
        assert_eq!(records[2]["reason"], "path_denied");
        assert_eq!(records[3]["reason"], "path_not_normalized");
    }

    #[test]
    fn audits_requests_refused_by_broker_restrictions() {
        let harness = Harness::create("broker-audit-restrictions", UNREACHABLE);

        for (request, reason) in [
            (
                r#"["github","api","POST","/repos/o/r","--json","@/etc/hostname"]"#,
                "local_file_input",
            ),
            (
                r#"["github","api","POST","/repos/o/r","--data","@body.json"]"#,
                "local_file_input",
            ),
            (
                r#"["github","api","/repos/o/r","--output","/tmp/via-broker-out"]"#,
                "local_file_output",
            ),
            (r#"["github","gh","auth","token"]"#, "delegated_not_allowed"),
            (r#"["config","doctor"]"#, "request_not_allowed"),
            (r#"["login"]"#, "request_not_allowed"),
            (r#"["daemon","status"]"#, "request_not_allowed"),
            (
                r#"["../../etc","api","/repos/o/r"]"#,
                "invalid_service_name",
            ),
        ] {
            assert_eq!(denial_reason(harness.run_raw(request)), reason, "{request}");
        }
        assert_eq!(
            denial_reason(harness.run_raw("github api /repos/o/r")),
            "invalid_request"
        );

        let records = harness.records();
        assert_eq!(records.len(), 9);
        for record in &records {
            assert_eq!(record["outcome"], "denied");
            assert_eq!(record["caller"], "sandbox-1");
        }
        assert_eq!(records[0]["reason"], "local_file_input");
        assert_eq!(records[0]["method"], "POST");
        assert_eq!(records[0]["path"], "/repos/o/r");
        assert_eq!(records[2]["reason"], "local_file_output");
        assert_eq!(records[3]["reason"], "delegated_not_allowed");
        assert_eq!(records[3]["mode"], "delegated");
        assert_eq!(records[3]["capability"], "gh");
        assert_eq!(records[4]["reason"], "request_not_allowed");
        assert!(records[4]["request"].is_null());
        assert!(records[4]["service"].is_null());
        assert_eq!(records[7]["reason"], "invalid_service_name");
        assert_eq!(records[7]["service"], "../../etc");
        assert_eq!(records[8]["reason"], "invalid_request");
        assert!(records[8]["request"].is_null());
    }

    #[test]
    fn audits_requests_refused_by_the_kill_switch() {
        let harness = Harness::create("broker-audit-kill-switch", UNREACHABLE);

        harness.disable("github");
        let (reason, message) = denial(harness.run(&["github", "api", "/repos/o/r"]));
        assert_eq!(reason, "disabled");
        assert_eq!(message, "via broker: access is disabled");
        harness.run(&["capabilities"]).unwrap();

        harness.disable("all");
        let (reason, message) = denial(harness.run(&["capabilities"]));
        assert_eq!(reason, "disabled");
        assert_eq!(message, "via broker: access is disabled");

        let records = harness.records();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["outcome"], "denied");
        assert_eq!(records[0]["reason"], "disabled");
        assert_eq!(records[0]["service"], "github");
        assert_eq!(records[1]["outcome"], "ok");
        assert_eq!(records[2]["outcome"], "denied");
        assert_eq!(records[2]["reason"], "disabled");
        assert_eq!(records[2]["request"], "capabilities");
    }

    #[test]
    fn audits_failed_requests() {
        let harness = Harness::create("broker-audit-errors", UNREACHABLE);

        assert!(matches!(
            harness.run(&["missing", "api", "/repos/o/r"]),
            Err(ViaError::UnknownService(_))
        ));
        assert!(matches!(
            harness.run(&["github", "missing", "/repos/o/r"]),
            Err(ViaError::UnknownCapability { .. })
        ));
        assert!(matches!(
            harness.run(&["other", "api"]),
            Err(ViaError::MissingArgument(_))
        ));

        let records = harness.records();
        assert_eq!(records.len(), 3);
        for record in &records {
            assert_eq!(record["request"], "run");
            assert_eq!(record["outcome"], "error");
        }
        assert_eq!(records[0]["reason"], "unknown_service");
        assert_eq!(records[0]["service"], "missing");
        assert_eq!(records[1]["reason"], "unknown_capability");
        assert_eq!(records[2]["reason"], "missing_argument");
        assert_eq!(records[2]["mode"], "rest");
    }

    #[test]
    fn serves_requests_passed_after_the_separator() {
        let harness = Harness::create("broker-cli-request", UNREACHABLE);
        let mut invocation = harness.invocation();
        invocation.caller = None;
        invocation.request = strings(&["capabilities"]);

        run_request(&invocation, None, None).unwrap();
        assert_eq!(
            denial_reason(run_request(
                &invocation,
                Some(OsStr::new(r#"["capabilities"]"#)),
                None
            )),
            "invalid_request"
        );

        let records = harness.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["outcome"], "ok");
        assert!(records[0]["caller"].is_null());
        assert!(records[0]["client"].is_null());
        assert_eq!(records[1]["outcome"], "denied");
    }
}
