#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct AllowedOnePasswordRef {
    pub id: String,
    pub reference: String,
}

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::io::{self, BufRead, BufReader, Write};
    #[cfg(target_os = "macos")]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use reqwest::blocking::Client;
    use serde::{Deserialize, Serialize};

    use crate::error::ViaError;
    use crate::redaction::Redactor;
    use crate::secrets::SecretValue;

    const CONNECT_WAIT: Duration = Duration::from_secs(2);
    const CONNECT_POLL: Duration = Duration::from_millis(50);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

    pub fn resolve_onepassword_secret(
        config_hash: &str,
        ref_id: &str,
        ttl_seconds: u64,
    ) -> Result<SecretValue, ViaError> {
        let span = crate::timing::span("1password daemon resolve");
        let response = match request_with_autostart(DaemonRequest::Resolve {
            config_hash: config_hash.to_owned(),
            ref_id: ref_id.to_owned(),
            ttl_seconds,
        }) {
            Ok(response) => {
                span.finish(format!(
                    "cache={}",
                    response.cache.as_deref().unwrap_or("unknown")
                ));
                response
            }
            Err(error) => {
                span.finish("failed");
                return Err(error);
            }
        };

        if response.ok {
            return response
                .value
                .ok_or_else(|| ViaError::InvalidConfig("daemon returned no secret".to_owned()));
        }

        Err(ViaError::ExternalCommandFailed {
            program: "via daemon".to_owned(),
            status: None,
            stderr: response
                .error
                .unwrap_or_else(|| "failed to resolve secret".to_owned()),
        })
    }

    pub fn register_onepassword_refs(
        config_hash: &str,
        account: Option<&str>,
        refs: Vec<super::AllowedOnePasswordRef>,
    ) -> Result<(), ViaError> {
        let response = request_with_autostart(DaemonRequest::Register {
            config_hash: config_hash.to_owned(),
            account: account.map(str::to_owned),
            refs,
        })?;
        if response.ok {
            Ok(())
        } else {
            Err(daemon_response_error(
                response,
                "failed to register 1Password references",
            ))
        }
    }

    pub fn oauth_access_token(credential: &str) -> Result<SecretValue, ViaError> {
        let span = crate::timing::span("oauth daemon access token");
        let response = match request_with_autostart(DaemonRequest::OAuthAccessToken {
            credential: credential.to_owned(),
        }) {
            Ok(response) => response,
            Err(error) => {
                span.finish("failed");
                return Err(error);
            }
        };
        span.finish(format!(
            "cache={}",
            response.cache.as_deref().unwrap_or("unknown")
        ));

        oauth_access_token_from_response(response)
    }

    fn oauth_access_token_from_response(
        response: ClientDaemonResponse,
    ) -> Result<SecretValue, ViaError> {
        if response.ok {
            return response.value.ok_or_else(|| {
                ViaError::InvalidConfig("daemon returned no OAuth access token".to_owned())
            });
        }

        Err(daemon_response_error(
            response,
            "failed to resolve OAuth access token",
        ))
    }

    pub fn serve() -> Result<(), ViaError> {
        let path = socket_path()?;
        let listener = bind_listener(&path)?;
        run_server(listener, &path)
    }

    fn bind_listener(path: &Path) -> Result<UnixListener, ViaError> {
        prepare_socket_parent(path)?;
        remove_stale_socket(path)?;

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    }

    fn remove_stale_socket(path: &Path) -> Result<(), ViaError> {
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(ViaError::InvalidConfig(
                    "via daemon is already running".to_owned(),
                ));
            }
            fs::remove_file(path)?;
        }

        Ok(())
    }

    fn run_server(listener: UnixListener, path: &Path) -> Result<(), ViaError> {
        let mut state = DaemonState::default();
        let expected_client = daemon_executable_identity()?;
        let mut last_activity = Instant::now();
        loop {
            match next_server_event(&listener, &mut last_activity)? {
                ServerEvent::Connection(stream) => {
                    let action = handle_stream(stream, &mut state, expected_client.as_ref());
                    if action == DaemonAction::Stop {
                        break;
                    }
                }
                ServerEvent::NoConnection => {}
                ServerEvent::IdleTimeout => break,
            }
        }

        let _ = fs::remove_file(path);
        Ok(())
    }

    fn next_server_event(
        listener: &UnixListener,
        last_activity: &mut Instant,
    ) -> Result<ServerEvent, ViaError> {
        match listener.accept() {
            Ok((stream, _)) => {
                *last_activity = Instant::now();
                Ok(ServerEvent::Connection(stream))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_connection(last_activity)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn wait_for_connection(last_activity: &Instant) -> Result<ServerEvent, ViaError> {
        if last_activity.elapsed() >= IDLE_TIMEOUT {
            Ok(ServerEvent::IdleTimeout)
        } else {
            thread::sleep(CONNECT_POLL);
            Ok(ServerEvent::NoConnection)
        }
    }

    pub fn status() -> Result<(), ViaError> {
        control_request(DaemonRequest::Status, print_status, "status failed")
    }

    pub fn clear() -> Result<(), ViaError> {
        control_request(
            DaemonRequest::Clear,
            |_| println!("via daemon: cache cleared"),
            "clear failed",
        )
    }

    pub fn stop() -> Result<(), ViaError> {
        control_request(
            DaemonRequest::Stop,
            |_| println!("via daemon: stopped"),
            "stop failed",
        )
    }

    fn control_request(
        daemon_request: DaemonRequest,
        print_success: impl FnOnce(&ClientDaemonResponse),
        fallback_error: &str,
    ) -> Result<(), ViaError> {
        match request(daemon_request) {
            Ok(response) if response.ok => {
                print_success(&response);
                Ok(())
            }
            Ok(response) => Err(daemon_response_error(response, fallback_error)),
            Err(error) if daemon_unavailable(&error) => {
                println!("via daemon: stopped");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn print_status(response: &ClientDaemonResponse) {
        println!("via daemon: running");
        println!("cached entries: {}", response.entries.unwrap_or(0));
    }

    fn daemon_response_error(response: ClientDaemonResponse, fallback: &str) -> ViaError {
        ViaError::ExternalCommandFailed {
            program: "via daemon".to_owned(),
            status: None,
            stderr: response.error.unwrap_or_else(|| fallback.to_owned()),
        }
    }

    fn request_with_autostart(
        daemon_request: DaemonRequest,
    ) -> Result<ClientDaemonResponse, ViaError> {
        match request(daemon_request.clone()) {
            Ok(response) => Ok(response),
            Err(error) if daemon_unavailable(&error) => {
                start_daemon()?;
                request(daemon_request)
            }
            Err(error) => Err(error),
        }
    }

    fn request(request: DaemonRequest) -> Result<ClientDaemonResponse, ViaError> {
        let path = socket_path()?;
        let mut stream = UnixStream::connect(path)?;
        let raw = SecretValue::new(serde_json::to_string(&request)?);
        stream.write_all(raw.expose().as_bytes())?;
        stream.write_all(b"\n")?;

        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        if line.trim().is_empty() {
            return Err(ViaError::InvalidConfig(
                "daemon returned an empty response".to_owned(),
            ));
        }
        let line = SecretValue::new(line);

        serde_json::from_str(line.expose()).map_err(Into::into)
    }

    fn start_daemon() -> Result<(), ViaError> {
        let exe = env::current_exe()?;
        let mut command = Command::new(exe);
        command
            .arg("daemon")
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        if crate::timing::enabled() {
            command.stderr(Stdio::inherit());
        } else {
            command.stderr(Stdio::null());
        }
        command.spawn()?;

        let started = Instant::now();
        while started.elapsed() < CONNECT_WAIT {
            if UnixStream::connect(socket_path()?).is_ok() {
                return Ok(());
            }
            thread::sleep(CONNECT_POLL);
        }

        Err(ViaError::InvalidConfig(
            "timed out waiting for via daemon to start".to_owned(),
        ))
    }

    fn handle_stream(
        mut stream: UnixStream,
        state: &mut DaemonState,
        expected_client: Option<&ExecutableIdentity>,
    ) -> DaemonAction {
        let response = match verify_peer_executable(&stream, expected_client) {
            Ok(()) => handle_verified_stream(&mut stream, state),
            Err(error) => {
                DaemonResponseInternal::error(format!("daemon client verification failed: {error}"))
            }
        };
        let action = if response.stop {
            DaemonAction::Stop
        } else {
            DaemonAction::Continue
        };

        write_daemon_response(&mut stream, response);

        action
    }

    fn handle_verified_stream(
        stream: &mut UnixStream,
        state: &mut DaemonState,
    ) -> DaemonResponseInternal {
        let mut line = String::new();
        let mut reader = BufReader::new(stream);
        match reader.read_line(&mut line) {
            Ok(_) => {
                let line = SecretValue::new(line);
                match serde_json::from_str(line.expose()) {
                    Ok(request) => state.handle(request),
                    Err(error) => {
                        DaemonResponseInternal::error(format!("invalid daemon request: {error}"))
                    }
                }
            }
            Err(error) => {
                DaemonResponseInternal::error(format!("failed to read daemon request: {error}"))
            }
        }
    }

    fn write_daemon_response(stream: &mut UnixStream, response: DaemonResponseInternal) {
        if let Ok(raw) = serde_json::to_string(&response.into_public()) {
            let raw = SecretValue::new(raw);
            let _ = stream.write_all(raw.expose().as_bytes());
            let _ = stream.write_all(b"\n");
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum DaemonRequest {
        Register {
            config_hash: String,
            account: Option<String>,
            refs: Vec<super::AllowedOnePasswordRef>,
        },
        Resolve {
            config_hash: String,
            ref_id: String,
            ttl_seconds: u64,
        },
        OAuthAccessToken {
            credential: String,
        },
        Clear,
        Status,
        Stop,
    }

    #[derive(Default)]
    struct DaemonState {
        cache: HashMap<SecretCacheKey, SecretCacheEntry>,
        oauth_cache: HashMap<String, crate::auth::oauth::CachedOAuthToken>,
        registrations: HashMap<String, RegisteredConfig>,
    }

    impl DaemonState {
        fn handle(&mut self, request: DaemonRequest) -> DaemonResponseInternal {
            self.prune_expired();

            match request {
                DaemonRequest::Register {
                    config_hash,
                    account,
                    refs,
                } => self.register(config_hash, account, refs),
                DaemonRequest::Resolve {
                    config_hash,
                    ref_id,
                    ttl_seconds,
                } => self.resolve(config_hash, ref_id, ttl_seconds),
                DaemonRequest::OAuthAccessToken { credential } => {
                    self.oauth_access_token(&credential)
                }
                DaemonRequest::Clear => {
                    self.cache.clear();
                    self.oauth_cache.clear();
                    self.registrations.clear();
                    DaemonResponseInternal::ok()
                }
                DaemonRequest::Status => {
                    let mut response = DaemonResponseInternal::ok();
                    response.entries = Some(self.cache.len() + self.oauth_cache.len());
                    response
                }
                DaemonRequest::Stop => {
                    let mut response = DaemonResponseInternal::ok();
                    response.stop = true;
                    response
                }
            }
        }

        fn register(
            &mut self,
            config_hash: String,
            account: Option<String>,
            refs: Vec<super::AllowedOnePasswordRef>,
        ) -> DaemonResponseInternal {
            if config_hash.trim().is_empty() {
                return DaemonResponseInternal::error("config hash must not be empty");
            }

            let refs = match normalize_allowed_refs(refs) {
                Ok(refs) => refs,
                Err(error) => return DaemonResponseInternal::error(error),
            };
            self.registrations
                .insert(config_hash, RegisteredConfig { account, refs });
            DaemonResponseInternal::ok()
        }

        fn resolve(
            &mut self,
            config_hash: String,
            ref_id: String,
            ttl_seconds: u64,
        ) -> DaemonResponseInternal {
            let Some(secret) = self.allowed_secret(&config_hash, &ref_id) else {
                return DaemonResponseInternal::error(
                    "secret reference is not registered for this config",
                );
            };
            let key = SecretCacheKey {
                config_hash,
                ref_id,
            };
            if let Some(entry) = self.cache.get(&key) {
                let mut response = DaemonResponseInternal::ok();
                response.value = Some(entry.value.clone());
                response.cache = Some("hit".to_owned());
                return response;
            }

            match op_read(secret.account.as_deref(), &secret.reference) {
                Ok(value) => {
                    let ttl = Duration::from_secs(ttl_seconds.max(1));
                    let response_value = value.clone();
                    self.cache.insert(
                        key,
                        SecretCacheEntry {
                            value,
                            expires_at: Instant::now() + ttl,
                        },
                    );
                    let mut response = DaemonResponseInternal::ok();
                    response.value = Some(response_value);
                    response.cache = Some("miss".to_owned());
                    response
                }
                Err(error) => DaemonResponseInternal::error(error),
            }
        }

        fn allowed_secret(&self, config_hash: &str, ref_id: &str) -> Option<AllowedSecret> {
            let registration = self.registrations.get(config_hash)?;
            let reference = registration.refs.get(ref_id)?;
            Some(AllowedSecret {
                account: registration.account.clone(),
                reference: reference.clone(),
            })
        }

        fn oauth_access_token(&mut self, credential: &str) -> DaemonResponseInternal {
            let bundle = match crate::auth::oauth::CredentialBundle::parse(credential) {
                Ok(bundle) => bundle,
                Err(error) => return DaemonResponseInternal::error(error.to_string()),
            };
            let key = crate::auth::oauth::cache_key(&bundle);
            let now = match crate::auth::oauth::unix_timestamp() {
                Ok(now) => now,
                Err(error) => return DaemonResponseInternal::error(error.to_string()),
            };

            if let Some(access_token) =
                crate::auth::oauth::cached_access_token(self.oauth_cache.get(&key), now)
            {
                let mut response = DaemonResponseInternal::ok();
                response.value = Some(SecretValue::new(access_token));
                response.cache = Some("hit".to_owned());
                return response;
            }

            let cached = self.oauth_cache.get(&key).cloned();
            let mut redactor = Redactor::new();
            redactor.add(credential);
            crate::auth::oauth::register_bundle_secrets(&bundle, &mut redactor);
            crate::auth::oauth::register_cached_secrets(cached.as_ref(), &mut redactor);

            let client = Client::new();
            match crate::auth::oauth::exchange_access_token(
                &client,
                &bundle,
                cached.as_ref(),
                &mut redactor,
            ) {
                Ok(token) => {
                    self.oauth_cache.insert(
                        key,
                        crate::auth::oauth::CachedOAuthToken {
                            access_token: token.access_token.clone(),
                            expires_at: token.expires_at,
                            refresh_token: token.refresh_token.clone(),
                        },
                    );
                    let mut response = DaemonResponseInternal::ok();
                    response.value = Some(SecretValue::new(token.access_token));
                    response.cache = Some("miss".to_owned());
                    response
                }
                Err(error) => DaemonResponseInternal::error(redactor.redact(&error.to_string())),
            }
        }

        fn prune_expired(&mut self) {
            let now = Instant::now();
            self.cache.retain(|_, entry| entry.expires_at > now);
            if let Ok(now) = crate::auth::oauth::unix_timestamp() {
                self.oauth_cache.retain(|_, entry| {
                    entry.refresh_token.is_some()
                        || crate::auth::oauth::cached_access_token(Some(entry), now).is_some()
                });
            }
        }
    }

    #[derive(Hash, Eq, PartialEq)]
    struct SecretCacheKey {
        config_hash: String,
        ref_id: String,
    }

    struct RegisteredConfig {
        account: Option<String>,
        refs: HashMap<String, String>,
    }

    struct AllowedSecret {
        account: Option<String>,
        reference: String,
    }

    struct SecretCacheEntry {
        value: SecretValue,
        expires_at: Instant,
    }

    fn normalize_allowed_refs(
        refs: Vec<super::AllowedOnePasswordRef>,
    ) -> Result<HashMap<String, String>, String> {
        let mut normalized = HashMap::new();
        for allowed_ref in refs {
            if allowed_ref.id.trim().is_empty() {
                return Err("registered secret reference id must not be empty".to_owned());
            }
            if !allowed_ref.reference.starts_with("op://") {
                return Err("registered secret reference must start with op://".to_owned());
            }
            normalized.insert(allowed_ref.id, allowed_ref.reference);
        }
        Ok(normalized)
    }

    #[derive(Serialize)]
    struct WireDaemonResponse {
        ok: bool,
        #[serde(
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_secret_value_option"
        )]
        value: Option<SecretValue>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        entries: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    }

    #[derive(Deserialize)]
    struct ClientDaemonResponse {
        ok: bool,
        value: Option<SecretValue>,
        cache: Option<String>,
        entries: Option<usize>,
        error: Option<String>,
    }

    struct DaemonResponseInternal {
        ok: bool,
        value: Option<SecretValue>,
        cache: Option<String>,
        entries: Option<usize>,
        error: Option<String>,
        stop: bool,
    }

    impl DaemonResponseInternal {
        fn ok() -> Self {
            Self {
                ok: true,
                value: None,
                cache: None,
                entries: None,
                error: None,
                stop: false,
            }
        }

        fn error(error: impl Into<String>) -> Self {
            Self {
                ok: false,
                value: None,
                cache: None,
                entries: None,
                error: Some(error.into()),
                stop: false,
            }
        }

        fn into_public(self) -> WireDaemonResponse {
            WireDaemonResponse {
                ok: self.ok,
                value: self.value,
                cache: self.cache,
                entries: self.entries,
                error: self.error,
            }
        }
    }

    fn serialize_secret_value_option<S>(
        value: &Option<SecretValue>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(value.expose()),
            None => serializer.serialize_none(),
        }
    }

    fn op_read(account: Option<&str>, reference: &str) -> Result<SecretValue, String> {
        let mut command = Command::new("op");
        command.arg("read").arg(reference);
        if let Some(account) = account {
            command.arg("--account").arg(account);
        }

        let output = command
            .output()
            .map_err(|source| format!("program `op` was not found: {source}"))?;

        if !output.status.success() {
            return Err(format!(
                "program `op` failed with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        Ok(SecretValue::from_utf8_lossy_trimmed(output.stdout))
    }

    fn socket_path() -> Result<PathBuf, ViaError> {
        if let Some(path) = env_path("VIA_DAEMON_SOCKET") {
            return Ok(path);
        }

        if let Some(runtime) = env_path("XDG_RUNTIME_DIR") {
            return Ok(runtime.join("via").join("daemon.sock"));
        }

        Ok(env::temp_dir()
            .join(format!("via-{}", user_id()))
            .join("daemon.sock"))
    }

    fn prepare_socket_parent(path: &Path) -> Result<(), ViaError> {
        let parent = path.parent().ok_or_else(|| {
            ViaError::InvalidConfig("daemon socket path has no parent".to_owned())
        })?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn env_path(name: &str) -> Option<PathBuf> {
        env::var_os(name)
            .filter(|value| !value.as_os_str().is_empty())
            .map(PathBuf::from)
    }

    fn user_id() -> String {
        env::var("UID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                env::var("USER")
                    .ok()
                    .map(|value| sanitize_path_part(&value))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "unknown".to_owned())
            })
    }

    fn sanitize_path_part(value: &str) -> String {
        value
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect()
    }

    fn daemon_unavailable(error: &ViaError) -> bool {
        matches!(error, ViaError::Io(source) if matches!(
            source.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        ))
    }

    #[derive(Clone)]
    struct ExecutableIdentity {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl ExecutableIdentity {
        fn matches(&self, other: &Self) -> bool {
            self.path == other.path || (self.device == other.device && self.inode == other.inode)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn daemon_executable_identity() -> Result<Option<ExecutableIdentity>, ViaError> {
        Ok(Some(executable_identity_from_path(&env::current_exe()?)?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn daemon_executable_identity() -> Result<Option<ExecutableIdentity>, ViaError> {
        Ok(None)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn verify_peer_executable(
        stream: &UnixStream,
        expected: Option<&ExecutableIdentity>,
    ) -> Result<(), ViaError> {
        let Some(expected) = expected else {
            return Ok(());
        };
        let peer = peer_executable_identity(stream)?;
        if expected.matches(&peer) {
            Ok(())
        } else {
            Err(ViaError::InvalidConfig(
                "daemon refused connection from executable other than via".to_owned(),
            ))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn verify_peer_executable(
        _stream: &UnixStream,
        _expected: Option<&ExecutableIdentity>,
    ) -> Result<(), ViaError> {
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn executable_identity_from_path(path: &Path) -> Result<ExecutableIdentity, ViaError> {
        let metadata = fs::metadata(path)?;
        Ok(executable_identity_from_parts(path.to_path_buf(), metadata))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn executable_identity_from_parts(path: PathBuf, metadata: fs::Metadata) -> ExecutableIdentity {
        let path = fs::canonicalize(&path).unwrap_or(path);
        ExecutableIdentity {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(target_os = "linux")]
    fn peer_executable_identity(stream: &UnixStream) -> Result<ExecutableIdentity, ViaError> {
        let pid = linux_peer_pid(stream)?;
        let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let metadata = fs::metadata(&proc_exe)?;
        let path = fs::read_link(&proc_exe).unwrap_or_else(|_| proc_exe.clone());
        Ok(executable_identity_from_parts(path, metadata))
    }

    #[cfg(target_os = "linux")]
    fn linux_peer_pid(stream: &UnixStream) -> Result<libc::pid_t, ViaError> {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `credentials` points to valid writable memory for `length` bytes,
        // and `stream.as_raw_fd()` is a live Unix socket file descriptor.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(ViaError::InvalidConfig(
                "daemon could not read peer process credentials".to_owned(),
            ));
        }

        // SAFETY: `getsockopt` succeeded and wrote a complete `ucred` value.
        Ok(unsafe { credentials.assume_init() }.pid)
    }

    #[cfg(target_os = "macos")]
    fn peer_executable_identity(stream: &UnixStream) -> Result<ExecutableIdentity, ViaError> {
        let pid = macos_peer_pid(stream)?;
        let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `buffer` is valid writable memory for `buffer.len()` bytes.
        let length =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if length <= 0 {
            return Err(io::Error::last_os_error().into());
        }
        buffer.truncate(length as usize);
        let path = PathBuf::from(std::ffi::OsString::from_vec(buffer));
        executable_identity_from_path(&path)
    }

    #[cfg(target_os = "macos")]
    fn macos_peer_pid(stream: &UnixStream) -> Result<libc::pid_t, ViaError> {
        let mut pid = std::mem::MaybeUninit::<libc::pid_t>::uninit();
        let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `pid` points to valid writable memory for `length` bytes,
        // and `stream.as_raw_fd()` is a live Unix socket file descriptor.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                pid.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if length as usize != std::mem::size_of::<libc::pid_t>() {
            return Err(ViaError::InvalidConfig(
                "daemon could not read peer process id".to_owned(),
            ));
        }

        // SAFETY: `getsockopt` succeeded and wrote a complete `pid_t` value.
        Ok(unsafe { pid.assume_init() })
    }

    #[derive(PartialEq, Eq)]
    enum DaemonAction {
        Continue,
        Stop,
    }

    enum ServerEvent {
        Connection(UnixStream),
        NoConnection,
        IdleTimeout,
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        #[test]
        fn rejects_unregistered_resolve_request() {
            let mut state = DaemonState::default();

            let response = state.handle(DaemonRequest::Resolve {
                config_hash: "config".to_owned(),
                ref_id: "secret".to_owned(),
                ttl_seconds: 300,
            });

            assert!(!response.ok);
            assert!(response
                .error
                .as_deref()
                .unwrap()
                .contains("not registered"));
        }

        #[test]
        fn rejects_registered_non_op_reference() {
            let mut state = DaemonState::default();

            let response = state.handle(DaemonRequest::Register {
                config_hash: "config".to_owned(),
                account: None,
                refs: vec![super::super::AllowedOnePasswordRef {
                    id: "secret".to_owned(),
                    reference: "plaintext".to_owned(),
                }],
            });

            assert!(!response.ok);
            assert!(response
                .error
                .as_deref()
                .unwrap()
                .contains("must start with op://"));
        }

        #[test]
        fn resolves_registered_ref_id_from_cache() {
            let mut state = DaemonState::default();
            let register = state.handle(DaemonRequest::Register {
                config_hash: "config".to_owned(),
                account: None,
                refs: vec![super::super::AllowedOnePasswordRef {
                    id: "secret".to_owned(),
                    reference: "op://Private/Example/token".to_owned(),
                }],
            });
            assert!(register.ok);
            state.cache.insert(
                SecretCacheKey {
                    config_hash: "config".to_owned(),
                    ref_id: "secret".to_owned(),
                },
                SecretCacheEntry {
                    value: SecretValue::new("cached-secret".to_owned()),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );

            let response = state.handle(DaemonRequest::Resolve {
                config_hash: "config".to_owned(),
                ref_id: "secret".to_owned(),
                ttl_seconds: 300,
            });

            assert!(response.ok);
            assert_eq!(response.cache.as_deref(), Some("hit"));
            assert_eq!(
                response.value.as_ref().map(SecretValue::expose),
                Some("cached-secret")
            );
        }

        #[test]
        fn clear_drops_cached_values_and_registered_refs() {
            let mut state = DaemonState::default();
            let register = state.handle(DaemonRequest::Register {
                config_hash: "config".to_owned(),
                account: None,
                refs: vec![super::super::AllowedOnePasswordRef {
                    id: "secret".to_owned(),
                    reference: "op://Private/Example/token".to_owned(),
                }],
            });
            assert!(register.ok);
            state.cache.insert(
                SecretCacheKey {
                    config_hash: "config".to_owned(),
                    ref_id: "secret".to_owned(),
                },
                SecretCacheEntry {
                    value: SecretValue::new("cached-secret".to_owned()),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );

            let clear = state.handle(DaemonRequest::Clear);
            assert!(clear.ok);
            let response = state.handle(DaemonRequest::Resolve {
                config_hash: "config".to_owned(),
                ref_id: "secret".to_owned(),
                ttl_seconds: 300,
            });

            assert!(!response.ok);
            assert!(state.cache.is_empty());
            assert!(state.oauth_cache.is_empty());
            assert!(state.registrations.is_empty());
        }

        #[test]
        fn oauth_access_token_is_cached_in_daemon_memory() {
            let response_body = serde_json::json!({
                "access_token": "fresh-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rotated-refresh-token",
            })
            .to_string();
            let (token_url, server) = token_server(response_body);
            let mut state = DaemonState::default();
            let credential = serde_json::json!({
                "type": "service_oauth",
                "token_url": token_url,
                "grant_type": "refresh_token",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "refresh_token": "configured-refresh-token",
            })
            .to_string();

            let response = state.handle(DaemonRequest::OAuthAccessToken {
                credential: credential.clone(),
            });
            let request = server.join().unwrap();
            let cached_response = state.handle(DaemonRequest::OAuthAccessToken { credential });

            assert!(response.ok);
            assert_eq!(response.cache.as_deref(), Some("miss"));
            assert_eq!(
                response.value.as_ref().map(SecretValue::expose),
                Some("fresh-access-token")
            );
            assert!(request.contains("grant_type=refresh_token"));
            assert!(request.contains("refresh_token=configured-refresh-token"));
            assert_eq!(state.oauth_cache.len(), 1);
            assert!(cached_response.ok);
            assert_eq!(cached_response.cache.as_deref(), Some("hit"));
            assert_eq!(
                cached_response.value.as_ref().map(SecretValue::expose),
                Some("fresh-access-token")
            );
        }

        #[test]
        fn prune_expired_keeps_rotated_oauth_refresh_tokens() {
            let mut state = DaemonState::default();
            state.oauth_cache.insert(
                "oauth".to_owned(),
                crate::auth::oauth::CachedOAuthToken {
                    access_token: "expired-access-token".to_owned(),
                    expires_at: 0,
                    refresh_token: Some("rotated-refresh-token".to_owned()),
                },
            );

            state.prune_expired();

            assert_eq!(state.oauth_cache.len(), 1);
            assert_eq!(
                state
                    .oauth_cache
                    .values()
                    .next()
                    .and_then(|entry| entry.refresh_token.as_deref()),
                Some("rotated-refresh-token")
            );
        }

        fn token_server(response_body: String) -> (String, thread::JoinHandle<String>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).unwrap();
                request
            });

            (format!("http://{address}/oauth/token"), handle)
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use crate::error::ViaError;
    use crate::secrets::SecretValue;

    pub fn resolve_onepassword_secret(
        _config_hash: &str,
        _ref_id: &str,
        _ttl_seconds: u64,
    ) -> Result<SecretValue, ViaError> {
        Err(ViaError::InvalidConfig(
            "via daemon cache is only supported on Unix-like platforms".to_owned(),
        ))
    }

    pub fn register_onepassword_refs(
        _config_hash: &str,
        _account: Option<&str>,
        _refs: Vec<super::AllowedOnePasswordRef>,
    ) -> Result<(), ViaError> {
        Err(ViaError::InvalidConfig(
            "via daemon cache is only supported on Unix-like platforms".to_owned(),
        ))
    }

    pub fn oauth_access_token(_credential: &str) -> Result<SecretValue, ViaError> {
        Err(ViaError::InvalidConfig(
            "OAuth auth requires the via daemon, which is only supported on Unix-like platforms"
                .to_owned(),
        ))
    }

    pub fn serve() -> Result<(), ViaError> {
        Err(ViaError::InvalidConfig(
            "via daemon cache is only supported on Unix-like platforms".to_owned(),
        ))
    }

    pub fn status() -> Result<(), ViaError> {
        println!("via daemon: unsupported");
        Ok(())
    }

    pub fn clear() -> Result<(), ViaError> {
        println!("via daemon: unsupported");
        Ok(())
    }

    pub fn stop() -> Result<(), ViaError> {
        println!("via daemon: unsupported");
        Ok(())
    }
}

pub use imp::{
    clear, oauth_access_token, register_onepassword_refs, resolve_onepassword_secret, serve,
    status, stop,
};
