use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Broker {
    directory: PathBuf,
    config: PathBuf,
}

impl Broker {
    fn new(base_url: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "via-broker-security-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("broker.toml");
        let audit = directory.join("audit.jsonl");
        fs::write(
            &config,
            format!(
                r#"version = 1
[providers.files]
type = "directory"
path = '{}'
[audit]
sink = "file"
path = '{}'
[services.test]
provider = "files"
[services.test.commands.api]
mode = "rest"
base_url = "{base_url}"
asset_hosts = ["127.0.0.1"]
methods = ["POST"]
allow_paths = ["/allowed/**"]
"#,
                directory.display(),
                audit.display()
            ),
        )
        .unwrap();
        Self { directory, config }
    }

    fn spawn(&self, args: &[&str]) -> Child {
        let request: Vec<_> = ["test", "api"]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        Command::new(env!("CARGO_BIN_EXE_via"))
            .args(["broker", "exec", "--config"])
            .arg(&self.config)
            .env(
                "SSH_ORIGINAL_COMMAND",
                serde_json::to_string(&request).unwrap(),
            )
            .env("NO_PROXY", "*")
            .env("no_proxy", "*")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn records(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.directory.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("broker did not exit within ten seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn denied_targets_do_not_consume_stdin() {
    let broker = Broker::new("http://127.0.0.1:9");
    for (method, path, reason) in [
        ("DELETE", "/allowed/item", "method_not_allowed"),
        ("POST", "/forbidden", "path_not_allowed"),
    ] {
        // Keep stdin open with no bytes. Policy must reject without reading it.
        let mut child = broker.spawn(&[method, path, "--data", "@-"]);
        assert_eq!(wait(&mut child).code(), Some(2));
        let records = broker.records();
        assert_eq!(records.last().unwrap()["reason"], reason);
    }
}

#[test]
fn oversized_stdin_is_rejected_without_waiting_for_eof() {
    let broker = Broker::new("http://127.0.0.1:9");
    let mut child = broker.spawn(&["POST", "/allowed/item", "--json", "@-"]);
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&vec![b'x'; 8 * 1024 * 1024 + 1])
        .unwrap();
    assert_eq!(wait(&mut child).code(), Some(2));
    assert_eq!(broker.records().last().unwrap()["reason"], "body_too_large");
}

#[test]
fn broker_rejects_plaintext_assets_before_network_access() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let broker = Broker::new(&format!("https://{address}"));
    let target = format!("http://{address}/allowed/item");
    let mut child = broker.spawn(&["POST", &target, "--output", "-", "--data", "@-"]);
    assert_eq!(wait(&mut child).code(), Some(2));
    assert_eq!(
        broker.records().last().unwrap()["reason"],
        "asset_origin_not_allowed"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn admission_is_recorded_before_a_request_can_block_on_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let broker = Broker::new(&format!("http://{}", listener.local_addr().unwrap()));
    let (sent, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let size = stream.read(&mut request).unwrap();
        assert!(request[..size].starts_with(b"POST /allowed/item "));
        let body = vec![b'x'; 2 * 1024 * 1024];
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        sent.send(()).unwrap();
    });
    let mut child = broker.spawn(&["POST", "/allowed/item", "--output", "-"]);
    received.recv_timeout(Duration::from_secs(10)).unwrap();
    // A full pipe cannot hold the response. No reading or closing is needed
    // for the admission record to be visible.
    assert!(child.try_wait().unwrap().is_none());
    let started = broker.records();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["outcome"], "started");
    assert_eq!(started[0]["service"], "test");
    drop(child.stdout.take());
    assert_eq!(wait(&mut child).code(), Some(1));
    let records = broker.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["request_id"], records[1]["request_id"]);
    assert_eq!(records[1]["status"], 200);
    assert_eq!(records[1]["reason"], "io_error");
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn unwritable_admission_record_prevents_the_upstream_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let broker = Broker::new(&format!("http://{}", listener.local_addr().unwrap()));
    let config = fs::read_to_string(&broker.config).unwrap().replace(
        &broker.directory.join("audit.jsonl").display().to_string(),
        "/dev/full",
    );
    fs::write(&broker.config, config).unwrap();
    let mut child = broker.spawn(&["POST", "/allowed/item"]);
    assert_eq!(wait(&mut child).code(), Some(1));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
