use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::config::{valid_ssh_host_value, SshCommandConfig, SshProfileConfig};
use crate::error::ViaError;
use crate::providers::SecretProvider;

static TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const TRUSTED_OPENSSH_DIRECTORIES: [&str; 3] = ["/usr/bin", "/run/current-system/sw/bin", "/bin"];
#[cfg(not(any(unix, windows)))]
const DEFAULT_SSH_PROGRAM: &str = "/usr/bin/ssh";
#[cfg(not(any(unix, windows)))]
const DEFAULT_SSH_ADD_PROGRAM: &str = "/usr/bin/ssh-add";

pub fn execute(
    config: &SshCommandConfig,
    profile: &SshProfileConfig,
    provider: &dyn SecretProvider,
    args: Vec<String>,
) -> Result<(), ViaError> {
    let invocation = SshInvocation::parse(config, args)?;
    let agent_socket = resolve_agent_socket(profile)?;
    let (ssh_program, ssh_add_program) = resolve_ssh_programs(profile)?;
    ensure_agent_socket(&agent_socket)?;

    let resolved_key = provider.resolve(&profile.public_key)?;
    let public_key = validate_public_key(resolved_key.expose())?;
    verify_agent_identity_with_program(&ssh_add_program, &agent_socket, &public_key)?;
    let identity_file = PublicKeyFile::create(&public_key)?;

    let mut command = build_command(
        &ssh_program,
        config,
        &invocation,
        &agent_socket,
        identity_file.path(),
    )?;
    let status = command.status().map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ViaError::MissingProgram {
                program: ssh_program.display().to_string(),
                source,
            }
        } else {
            ViaError::Io(source)
        }
    })?;

    if status.success() {
        Ok(())
    } else {
        Err(ViaError::SshCommandFailed {
            status: status.code(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SshInvocation {
    host: String,
    remote_args: Vec<String>,
}

impl SshInvocation {
    fn parse(config: &SshCommandConfig, args: Vec<String>) -> Result<Self, ViaError> {
        let mut args = args.into_iter();
        let host = args
            .next()
            .ok_or_else(|| ViaError::MissingArgument("SSH host".to_owned()))?;

        if !valid_ssh_host_value(&host, false) {
            return Err(ViaError::InvalidArgument(format!(
                "invalid SSH host `{host}`; pass a hostname or IP address without a user or port"
            )));
        }
        if !config
            .hosts
            .iter()
            .any(|pattern| glob_matches(pattern, &host))
        {
            return Err(ViaError::InvalidArgument(format!(
                "SSH host `{host}` is not allowed by this capability"
            )));
        }

        Ok(Self {
            host,
            remote_args: args.collect(),
        })
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase().chars().collect::<Vec<_>>();
    let value = value.to_lowercase().chars().collect::<Vec<_>>();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;

    for pattern_character in pattern {
        let mut current = vec![false; value.len() + 1];
        if pattern_character == '*' {
            current[0] = previous[0];
        }
        for index in 1..=value.len() {
            current[index] = match pattern_character {
                '*' => previous[index] || current[index - 1],
                '?' => previous[index - 1],
                literal => previous[index - 1] && literal == value[index - 1],
            };
        }
        previous = current;
    }

    previous[value.len()]
}

pub(crate) fn resolve_agent_socket(profile: &SshProfileConfig) -> Result<PathBuf, ViaError> {
    if let Some(path) = &profile.agent_socket {
        if !path.is_absolute() {
            return Err(ViaError::InvalidConfig(
                "SSH profile agent_socket must be an absolute path".to_owned(),
            ));
        }
        #[cfg(windows)]
        if path != Path::new(r"\\.\pipe\openssh-ssh-agent") {
            return Err(ViaError::InvalidConfig(
                "SSH profile agent_socket must use the Windows OpenSSH agent pipe".to_owned(),
            ));
        }
        return Ok(path.clone());
    }

    default_agent_socket(env::var_os("HOME").as_deref())
}

pub(crate) fn resolve_ssh_programs(
    profile: &SshProfileConfig,
) -> Result<(PathBuf, PathBuf), ViaError> {
    match (
        profile.ssh_program.as_deref(),
        profile.ssh_add_program.as_deref(),
    ) {
        (Some(ssh), Some(ssh_add)) => {
            let ssh = resolve_program(ssh, "ssh_program")?;
            let ssh_add = resolve_program(ssh_add, "ssh_add_program")?;
            if ssh.parent() != ssh_add.parent() {
                return Err(ViaError::InvalidConfig(
                    "SSH profile ssh_program and ssh_add_program must use the same directory"
                        .to_owned(),
                ));
            }
            Ok((ssh, ssh_add))
        }
        (None, None) => default_ssh_programs(),
        _ => Err(ViaError::InvalidConfig(
            "SSH profile ssh_program and ssh_add_program must be configured together".to_owned(),
        )),
    }
}

fn resolve_program(program: &Path, field: &str) -> Result<PathBuf, ViaError> {
    if !program.is_absolute() {
        return Err(ViaError::InvalidConfig(format!(
            "SSH profile {field} must be an absolute path"
        )));
    }
    Ok(program.to_path_buf())
}

#[cfg(unix)]
fn default_ssh_programs() -> Result<(PathBuf, PathBuf), ViaError> {
    for directory in TRUSTED_OPENSSH_DIRECTORIES {
        let ssh = Path::new(directory).join("ssh");
        let ssh_add = Path::new(directory).join("ssh-add");
        if ssh.is_file() && ssh_add.is_file() {
            return Ok((ssh, ssh_add));
        }
    }

    let directory = Path::new(TRUSTED_OPENSSH_DIRECTORIES[0]);
    Ok((directory.join("ssh"), directory.join("ssh-add")))
}

#[cfg(windows)]
fn default_ssh_programs() -> Result<(PathBuf, PathBuf), ViaError> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: `buffer` is writable for the supplied length and remains alive
    // for the complete operating-system call.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 {
        return Err(ViaError::Io(io::Error::last_os_error()));
    }
    if length as usize >= buffer.len() {
        return Err(ViaError::InvalidConfig(
            "Windows system directory is too long to locate OpenSSH".to_owned(),
        ));
    }

    let directory = PathBuf::from(OsString::from_wide(&buffer[..length as usize])).join("OpenSSH");
    Ok((directory.join("ssh.exe"), directory.join("ssh-add.exe")))
}

#[cfg(not(any(unix, windows)))]
fn default_ssh_programs() -> Result<(PathBuf, PathBuf), ViaError> {
    Ok((
        PathBuf::from(DEFAULT_SSH_PROGRAM),
        PathBuf::from(DEFAULT_SSH_ADD_PROGRAM),
    ))
}

#[cfg(target_os = "macos")]
fn default_agent_socket(home: Option<&OsStr>) -> Result<PathBuf, ViaError> {
    let home = home.ok_or_else(missing_home_for_agent)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Group Containers")
        .join("2BUA8C4S2C.com.1password")
        .join("t")
        .join("agent.sock"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn default_agent_socket(home: Option<&OsStr>) -> Result<PathBuf, ViaError> {
    let home = home.ok_or_else(missing_home_for_agent)?;
    Ok(PathBuf::from(home).join(".1password").join("agent.sock"))
}

#[cfg(windows)]
fn default_agent_socket(_home: Option<&OsStr>) -> Result<PathBuf, ViaError> {
    Ok(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
}

#[cfg(not(any(unix, windows)))]
fn default_agent_socket(_home: Option<&OsStr>) -> Result<PathBuf, ViaError> {
    Err(ViaError::SshAgentUnavailable {
        path: PathBuf::from("<default>"),
        reason: "this platform has no configured 1Password SSH agent socket default".to_owned(),
    })
}

#[cfg(unix)]
fn missing_home_for_agent() -> ViaError {
    ViaError::SshAgentUnavailable {
        path: PathBuf::from("<default>"),
        reason: "HOME is not set; configure an absolute agent_socket".to_owned(),
    }
}

#[cfg(unix)]
fn ensure_agent_socket(path: &Path) -> Result<(), ViaError> {
    use std::os::unix::fs::FileTypeExt;

    let metadata = fs::metadata(path).map_err(|source| ViaError::SshAgentUnavailable {
        path: path.to_path_buf(),
        reason: source.to_string(),
    })?;
    if !metadata.file_type().is_socket() {
        return Err(ViaError::SshAgentUnavailable {
            path: path.to_path_buf(),
            reason: "path is not a Unix socket".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn verify_agent_identity_with_program(
    ssh_add_program: &Path,
    agent_socket: &Path,
    public_key: &str,
) -> Result<(), ViaError> {
    let public_key = validate_public_key(public_key)?;
    let expected = public_key_identity(&public_key)?;
    let output = build_ssh_add_command(ssh_add_program, agent_socket)
        .output()
        .map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                ViaError::MissingProgram {
                    program: ssh_add_program.display().to_string(),
                    source,
                }
            } else {
                ViaError::Io(source)
            }
        })?;

    if !output.status.success() {
        return Err(ViaError::ExternalCommandFailed {
            program: ssh_add_program.display().to_string(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    if agent_output_contains_identity(&output.stdout, &expected) {
        Ok(())
    } else {
        Err(ViaError::SshIdentityUnavailable)
    }
}

fn build_ssh_add_command(ssh_add_program: &Path, agent_socket: &Path) -> Command {
    let mut command = Command::new(ssh_add_program);
    command
        .arg("-L")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    pass_safe_env(&mut command);
    command.env("SSH_AUTH_SOCK", agent_socket);
    command
}

#[derive(Debug, PartialEq, Eq)]
struct PublicKeyIdentity {
    key_type: String,
    blob: Vec<u8>,
}

fn public_key_identity(value: &str) -> Result<PublicKeyIdentity, ViaError> {
    let mut fields = value.split_whitespace();
    let key_type = fields
        .next()
        .ok_or_else(|| invalid_public_key("missing key type"))?;
    let encoded = fields
        .next()
        .ok_or_else(|| invalid_public_key("missing base64 key data"))?;
    let blob = BASE64
        .decode(encoded)
        .map_err(|_| invalid_public_key("key data is not valid base64"))?;
    Ok(PublicKeyIdentity {
        key_type: key_type.to_owned(),
        blob,
    })
}

fn agent_output_contains_identity(output: &[u8], expected: &PublicKeyIdentity) -> bool {
    String::from_utf8_lossy(output).lines().any(|line| {
        validate_public_key(line)
            .and_then(|line| public_key_identity(&line))
            .is_ok_and(|identity| identity == *expected)
    })
}

#[cfg(windows)]
fn ensure_agent_socket(_path: &Path) -> Result<(), ViaError> {
    // Windows OpenSSH opens the selected named pipe itself. Filesystem metadata
    // does not provide a reliable, race-free readiness check for named pipes.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_agent_socket(path: &Path) -> Result<(), ViaError> {
    Err(ViaError::SshAgentUnavailable {
        path: path.to_path_buf(),
        reason: "SSH agent sockets are unsupported on this platform".to_owned(),
    })
}

pub(crate) fn validate_public_key(value: &str) -> Result<String, ViaError> {
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty()
        || value.len() > 128 * 1024
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
        || value.contains(['\r', '\n', '\0'])
    {
        return Err(invalid_public_key(
            "expected exactly one OpenSSH public key line",
        ));
    }

    let mut fields = value.split_whitespace();
    let key_type = fields
        .next()
        .ok_or_else(|| invalid_public_key("missing key type"))?;
    let encoded = fields
        .next()
        .ok_or_else(|| invalid_public_key("missing base64 key data"))?;

    if !supported_key_type(key_type) {
        return Err(invalid_public_key("unsupported or missing SSH key type"));
    }
    if encoded.len() > 96 * 1024 {
        return Err(invalid_public_key("base64 key data is too large"));
    }

    let blob = BASE64
        .decode(encoded)
        .map_err(|_| invalid_public_key("key data is not valid base64"))?;
    let embedded_type = ssh_wire_string(&blob)
        .ok_or_else(|| invalid_public_key("key data is not a valid SSH public-key blob"))?;
    if embedded_type != key_type.as_bytes() {
        return Err(invalid_public_key(
            "declared key type does not match the SSH key data",
        ));
    }

    // Comments commonly contain 1Password item names, usernames, or workstation
    // labels. They are not part of the key identity, so do not copy them into the
    // temporary IdentityFile.
    Ok(format!("{key_type} {encoded}"))
}

fn invalid_public_key(reason: impl Into<String>) -> ViaError {
    ViaError::InvalidSshPublicKey(reason.into())
}

fn supported_key_type(key_type: &str) -> bool {
    matches!(
        key_type,
        "ssh-ed25519"
            | "ssh-ed25519-cert-v01@openssh.com"
            | "ssh-rsa"
            | "ssh-rsa-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp256-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp521"
            | "ecdsa-sha2-nistp521-cert-v01@openssh.com"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ssh-ed25519-cert-v01@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
    )
}

fn ssh_wire_string(blob: &[u8]) -> Option<&[u8]> {
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    blob.get(4..4usize.checked_add(length)?)
}

struct PublicKeyFile {
    directory: PathBuf,
    path: PathBuf,
}

impl PublicKeyFile {
    fn create(public_key: &str) -> Result<Self, ViaError> {
        let directory = create_private_temp_directory()?;
        let path = directory.join("identity.pub");
        let temporary = Self { directory, path };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&temporary.path)?;
        file.write_all(public_key.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        drop(file);
        Ok(temporary)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PublicKeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

fn create_private_temp_directory() -> io::Result<PathBuf> {
    for _ in 0..128 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let counter = TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "via-ssh-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(source) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    {
                        let _ = fs::remove_dir(&path);
                        return Err(source);
                    }
                }
                return Ok(path);
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique private SSH temporary directory",
    ))
}

#[cfg(unix)]
fn identity_file_option(identity_file: &Path) -> Result<std::ffi::OsString, ViaError> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let mut option = b"IdentityFile=\"".to_vec();
    for &byte in identity_file.as_os_str().as_bytes() {
        match byte {
            b'\\' | b'"' => {
                option.push(b'\\');
                option.push(byte);
            }
            b'%' => option.extend_from_slice(b"%%"),
            b'$' => return Err(invalid_identity_path("path contains `$`")),
            b'\0' | b'\n' | b'\r' => {
                return Err(invalid_identity_path(
                    "path contains a NUL byte or line break",
                ));
            }
            _ => option.push(byte),
        }
    }
    option.push(b'"');
    Ok(std::ffi::OsString::from_vec(option))
}

#[cfg(not(unix))]
fn identity_file_option(identity_file: &Path) -> Result<std::ffi::OsString, ViaError> {
    let identity_file = identity_file
        .to_str()
        .ok_or_else(|| invalid_identity_path("path is not valid Unicode on this platform"))?;
    let mut option = String::from("IdentityFile=\"");
    for character in identity_file.chars() {
        match character {
            '\\' | '"' => {
                option.push('\\');
                option.push(character);
            }
            '%' => option.push_str("%%"),
            '$' => return Err(invalid_identity_path("path contains `$`")),
            '\0' | '\n' | '\r' => {
                return Err(invalid_identity_path(
                    "path contains a NUL byte or line break",
                ));
            }
            _ => option.push(character),
        }
    }
    option.push('"');
    Ok(option.into())
}

fn invalid_identity_path(reason: &str) -> ViaError {
    ViaError::InvalidSshIdentityPath(reason.to_owned())
}

fn build_command(
    ssh_program: &Path,
    config: &SshCommandConfig,
    invocation: &SshInvocation,
    agent_socket: &Path,
    identity_file: &Path,
) -> Result<Command, ViaError> {
    let identity_file_option = identity_file_option(identity_file)?;
    let mut command = Command::new(ssh_program);
    command
        .arg("-F")
        .arg("none")
        .arg("-o")
        .arg("IdentityAgent=SSH_AUTH_SOCK")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg(identity_file_option)
        .arg("-o")
        .arg("CertificateFile=none")
        .arg("-o")
        .arg("ForwardAgent=no")
        .arg("-o")
        .arg("ForwardX11=no")
        .arg("-o")
        .arg("Tunnel=no")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("EscapeChar=none")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("AddKeysToAgent=no")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-o")
        .arg("PubkeyAuthentication=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("HostbasedAuthentication=no")
        .arg("-l")
        .arg(&config.user);
    if let Some(port) = config.port {
        command.arg("-p").arg(port.to_string());
    }
    command.arg("--").arg(&invocation.host);
    command.args(&invocation.remote_args);

    command.env_clear();
    pass_safe_env(&mut command);
    command.env("SSH_AUTH_SOCK", agent_socket);
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(command)
}

pub(crate) fn pass_safe_env(command: &mut Command) {
    for key in [
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "TEMP",
        "TMP",
        "SystemRoot",
        "WINDIR",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::secrets::SecretValue;

    fn ssh_config(hosts: &[&str]) -> SshCommandConfig {
        SshCommandConfig {
            description: None,
            profile: "production".to_owned(),
            user: "volt".to_owned(),
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            port: Some(2222),
        }
    }

    fn profile(agent_socket: Option<PathBuf>) -> SshProfileConfig {
        SshProfileConfig {
            provider: "onepassword".to_owned(),
            public_key: "op://Private/SSH/public key".to_owned(),
            agent_socket,
            ssh_program: None,
            ssh_add_program: None,
        }
    }

    #[cfg(windows)]
    fn absolute_test_programs() -> (PathBuf, PathBuf) {
        (
            PathBuf::from(r"C:\OpenSSH\ssh.exe"),
            PathBuf::from(r"C:\OpenSSH\ssh-add.exe"),
        )
    }

    #[cfg(not(windows))]
    fn absolute_test_programs() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/opt/openssh/bin/ssh"),
            PathBuf::from("/opt/openssh/bin/ssh-add"),
        )
    }

    fn public_key(key_type: &str) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        blob.extend_from_slice(key_type.as_bytes());
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[7; 32]);
        format!("{key_type} {} via-test", BASE64.encode(blob))
    }

    #[cfg(unix)]
    struct FakeProvider {
        public_key: String,
    }

    #[cfg(unix)]
    impl SecretProvider for FakeProvider {
        fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
            assert_eq!(reference, "op://Private/SSH/public key");
            Ok(SecretValue::new(self.public_key.clone()))
        }
    }

    struct NeverResolveProvider;

    impl SecretProvider for NeverResolveProvider {
        fn resolve(&self, _reference: &str) -> Result<SecretValue, ViaError> {
            panic!("provider must not run before SSH host validation")
        }
    }

    #[cfg(unix)]
    struct TestDirectory {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TestDirectory {
        fn create() -> Self {
            Self {
                path: create_private_temp_directory().unwrap(),
            }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn write_executable(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path(name);
            fs::write(&path, contents).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
    }

    #[cfg(unix)]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.path) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.path);
        }
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    #[test]
    fn parses_allowed_host_and_preserves_remote_arguments() {
        let invocation = SshInvocation::parse(
            &ssh_config(&["btcd-*.internal", "2001:db8::*"]),
            vec![
                "BTCD-12.Internal".to_owned(),
                "printf".to_owned(),
                "%s\\n".to_owned(),
                "hello world".to_owned(),
            ],
        )
        .unwrap();

        assert_eq!(invocation.host, "BTCD-12.Internal");
        assert_eq!(invocation.remote_args, ["printf", "%s\\n", "hello world"]);
    }

    #[test]
    fn host_globs_are_full_string_and_support_star_and_question_mark() {
        assert!(glob_matches("node-?.example.*", "NODE-1.example.com"));
        assert!(glob_matches("2001:db8::*", "2001:DB8::42"));
        assert!(!glob_matches("node-?.example.*", "node-12.example.com"));
        assert!(!glob_matches("example.com", "prefix.example.com"));
    }

    #[test]
    fn invocation_rejects_missing_invalid_and_disallowed_hosts_before_resolution() {
        let config = ssh_config(&["*.example.com"]);
        assert!(matches!(
            SshInvocation::parse(&config, vec![]),
            Err(ViaError::MissingArgument(_))
        ));
        for host in [
            "-v",
            "user@example.com",
            "example.com:22",
            "example.com/path",
            "*.example.com",
        ] {
            assert!(matches!(
                SshInvocation::parse(&config, vec![host.to_owned()]),
                Err(ViaError::InvalidArgument(_))
            ));
        }
        assert!(matches!(
            SshInvocation::parse(&config, vec!["other.test".to_owned()]),
            Err(ViaError::InvalidArgument(message)) if message.contains("not allowed")
        ));
    }

    #[test]
    fn execute_rejects_a_disallowed_host_before_provider_or_agent_access() {
        let error = execute(
            &ssh_config(&["allowed.example.com"]),
            &profile(None),
            &NeverResolveProvider,
            vec!["denied.example.com".to_owned()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::InvalidArgument(message) if message.contains("not allowed")
        ));
    }

    #[test]
    fn validates_one_openssh_public_key_and_wire_type() {
        let key = public_key("ssh-ed25519");
        assert_eq!(
            validate_public_key(&key).unwrap(),
            key.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
        );

        for invalid in [
            "",
            "command=whoami ssh-ed25519 AAAA",
            "ssh-ed25519 not-base64",
            "ssh-dss AAAA",
            "ssh-ed25519 AAAA\nssh-ed25519 AAAA",
        ] {
            assert!(matches!(
                validate_public_key(invalid),
                Err(ViaError::InvalidSshPublicKey(_))
            ));
        }

        let mismatched = public_key("ssh-rsa").replacen("ssh-rsa", "ssh-ed25519", 1);
        assert!(matches!(
            validate_public_key(&mismatched),
            Err(ViaError::InvalidSshPublicKey(message)) if message.contains("does not match")
        ));
    }

    #[test]
    fn builds_isolated_publickey_only_ssh_command() {
        let config = ssh_config(&["*.example.com"]);
        let invocation = SshInvocation {
            host: "host.example.com".to_owned(),
            remote_args: vec!["uname".to_owned(), "-a".to_owned()],
        };
        let command = build_command(
            Path::new("/secure/bin/ssh"),
            &config,
            &invocation,
            Path::new("/tmp/agent socket"),
            Path::new("/tmp/public key.pub"),
        )
        .unwrap();
        let identity_option = identity_file_option(Path::new("/tmp/public key.pub")).unwrap();
        let args = command.get_args().map(OsString::from).collect::<Vec<_>>();

        assert_eq!(command.get_program(), "/secure/bin/ssh");
        assert_eq!(
            args,
            vec![
                "-F".into(),
                "none".into(),
                "-o".into(),
                "IdentityAgent=SSH_AUTH_SOCK".into(),
                "-o".into(),
                "IdentitiesOnly=yes".into(),
                "-o".into(),
                identity_option,
                "-o".into(),
                "CertificateFile=none".into(),
                "-o".into(),
                "ForwardAgent=no".into(),
                "-o".into(),
                "ForwardX11=no".into(),
                "-o".into(),
                "Tunnel=no".into(),
                "-o".into(),
                "ClearAllForwardings=yes".into(),
                "-o".into(),
                "EscapeChar=none".into(),
                "-o".into(),
                "PermitLocalCommand=no".into(),
                "-o".into(),
                "AddKeysToAgent=no".into(),
                "-o".into(),
                "PreferredAuthentications=publickey".into(),
                "-o".into(),
                "PubkeyAuthentication=yes".into(),
                "-o".into(),
                "PasswordAuthentication=no".into(),
                "-o".into(),
                "KbdInteractiveAuthentication=no".into(),
                "-o".into(),
                "HostbasedAuthentication=no".into(),
                "-l".into(),
                "volt".into(),
                "-p".into(),
                "2222".into(),
                "--".into(),
                "host.example.com".into(),
                "uname".into(),
                "-a".into(),
            ]
        );
        assert!(command
            .get_envs()
            .any(|(name, value)| name == "SSH_AUTH_SOCK"
                && value == Some(OsStr::new("/tmp/agent socket"))));
        assert!(!command
            .get_envs()
            .any(|(name, _)| name == "VIA_SSH_IDENTITY_FILE"));
        assert!(!command.get_envs().any(|(name, _)| name == "PATH"));
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_option_escapes_parser_tokens_and_preserves_non_utf8() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let identity_path = PathBuf::from(OsString::from_vec(
            b"/tmp/key with spaces %h \"quoted\" \\\xFF.pub".to_vec(),
        ));
        let option = identity_file_option(&identity_path).unwrap();

        assert_eq!(
            option.as_os_str().as_bytes(),
            b"IdentityFile=\"/tmp/key with spaces %%h \\\"quoted\\\" \\\\\xFF.pub\""
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_option_rejects_expansion_and_line_boundaries() {
        use std::os::unix::ffi::OsStringExt;

        for bytes in [
            b"/tmp/key-$HOME.pub".to_vec(),
            b"/tmp/key\nnext.pub".to_vec(),
            b"/tmp/key\rnext.pub".to_vec(),
            b"/tmp/key\0next.pub".to_vec(),
        ] {
            let path = PathBuf::from(OsString::from_vec(bytes));
            assert!(matches!(
                identity_file_option(&path),
                Err(ViaError::InvalidSshIdentityPath(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn build_command_rejects_an_unsafe_identity_path() {
        use std::os::unix::ffi::OsStringExt;

        let identity_path = PathBuf::from(OsString::from_vec(b"/tmp/${HOME}/key.pub".to_vec()));
        let invocation = SshInvocation {
            host: "host.example.com".to_owned(),
            remote_args: Vec::new(),
        };
        let error = build_command(
            Path::new("/secure/bin/ssh"),
            &ssh_config(&["host.example.com"]),
            &invocation,
            Path::new("/tmp/agent.sock"),
            &identity_path,
        )
        .unwrap_err();

        assert!(matches!(error, ViaError::InvalidSshIdentityPath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn installed_ssh_effective_config_has_only_the_selected_identity() {
        let (ssh_program, _) = default_ssh_programs().unwrap();
        if !ssh_program.is_file() {
            return;
        }

        let invocation = SshInvocation {
            host: "host.example.com".to_owned(),
            remote_args: Vec::new(),
        };
        let built = build_command(
            &ssh_program,
            &ssh_config(&["host.example.com"]),
            &invocation,
            Path::new("/tmp/agent socket"),
            Path::new("/tmp/key with spaces %h.pub"),
        )
        .unwrap();
        let mut query = Command::new(built.get_program());
        query.arg("-G").args(built.get_args()).env_clear();
        for (name, value) in built.get_envs() {
            if let Some(value) = value {
                query.env(name, value);
            }
        }
        let output = query
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "ssh -G failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let effective = String::from_utf8(output.stdout).unwrap();
        let identities = effective
            .lines()
            .filter_map(|line| line.strip_prefix("identityfile "))
            .collect::<Vec<_>>();
        assert_eq!(identities, ["/tmp/key with spaces %%h.pub"]);
        assert!(!effective.contains("identityfile none"));
        assert!(!effective.contains("/.ssh/id_"));
    }

    #[cfg(unix)]
    #[test]
    fn installed_ssh_loads_a_literal_identity_path_without_token_expansion() {
        use std::os::unix::ffi::OsStringExt;

        let (ssh_program, _) = default_ssh_programs().unwrap();
        if !ssh_program.is_file() {
            return;
        }

        let temporary = TestDirectory::create();
        let file_name =
            OsString::from_vec(b"identity with spaces %h \"quoted\" \\\xFF.pub".to_vec());
        let identity_path = temporary.path.join(file_name);
        fs::write(&identity_path, public_key("ssh-ed25519")).unwrap();
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600)).unwrap();
        let identity_option = identity_file_option(&identity_path).unwrap();

        let output = Command::new(ssh_program)
            .arg("-vvv")
            .arg("-F")
            .arg("none")
            .arg("-o")
            .arg(identity_option)
            .arg("-o")
            .arg("CertificateFile=none")
            .arg("-o")
            .arg("ProxyCommand=/via-test-command-that-does-not-exist")
            .arg("--")
            .arg("host.example.com")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr
                .lines()
                .filter(|line| line.contains("identity file"))
                .any(|line| line.contains(" type ") && !line.ends_with("type -1")),
            "OpenSSH did not load the literal identity path:\n{stderr}"
        );
    }

    #[test]
    fn omitted_port_uses_the_isolated_openssh_default() {
        let mut config = ssh_config(&["host.example.com"]);
        config.port = None;
        let invocation = SshInvocation {
            host: "host.example.com".to_owned(),
            remote_args: Vec::new(),
        };
        let command = build_command(
            Path::new("/secure/bin/ssh"),
            &config,
            &invocation,
            Path::new("/tmp/agent.sock"),
            Path::new("/tmp/identity.pub"),
        )
        .unwrap();
        let args = command.get_args().collect::<Vec<_>>();

        assert!(!args.iter().any(|argument| *argument == OsStr::new("-p")));
        assert_eq!(args.last(), Some(&OsStr::new("host.example.com")));
    }

    #[test]
    fn builds_isolated_agent_identity_query() {
        let command = build_ssh_add_command(
            Path::new("/secure/bin/ssh-add"),
            Path::new("/tmp/selected-agent.sock"),
        );

        assert_eq!(command.get_program(), "/secure/bin/ssh-add");
        assert_eq!(command.get_args().collect::<Vec<_>>(), [OsStr::new("-L")]);
        assert!(command.get_envs().any(|(name, value)| {
            name == "SSH_AUTH_SOCK" && value == Some(OsStr::new("/tmp/selected-agent.sock"))
        }));
        assert!(!command.get_envs().any(|(name, _)| name == "SSH_AGENT_PID"));
        assert!(!command.get_envs().any(|(name, _)| name == "PATH"));
    }

    #[cfg(unix)]
    #[test]
    fn execute_preserves_failure_and_cleans_private_identity_directory() {
        let temporary = TestDirectory::create();
        let agent_socket = temporary.path("agent.sock");
        let _listener = UnixListener::bind(&agent_socket).unwrap();
        let ssh_add_socket_record = temporary.path("ssh-add-socket");
        let ssh_socket_record = temporary.path("ssh-socket");
        let ssh_args_record = temporary.path("ssh-args");
        let canonical_key = validate_public_key(&public_key("ssh-ed25519")).unwrap();

        let ssh_add = temporary.write_executable(
            "ssh-add",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$SSH_AUTH_SOCK\" > {}\nprintf '%s\\n' {}\n",
                shell_quote(&ssh_add_socket_record.to_string_lossy()),
                shell_quote(&canonical_key),
            ),
        );
        let ssh = temporary.write_executable(
            "ssh",
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$SSH_AUTH_SOCK\" > {}\n: > {}\nfor argument in \"$@\"; do\n  printf '%s\\n' \"$argument\" >> {}\ndone\nexit 42\n",
                shell_quote(&ssh_socket_record.to_string_lossy()),
                shell_quote(&ssh_args_record.to_string_lossy()),
                shell_quote(&ssh_args_record.to_string_lossy()),
            ),
        );
        let mut profile = profile(Some(agent_socket.clone()));
        profile.ssh_program = Some(ssh.clone());
        profile.ssh_add_program = Some(ssh_add.clone());

        let error = execute(
            &ssh_config(&["node.example.com"]),
            &profile,
            &FakeProvider {
                public_key: canonical_key,
            },
            vec![
                "node.example.com".to_owned(),
                "uname".to_owned(),
                "-a".to_owned(),
            ],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::SshCommandFailed { status: Some(42) }
        ));

        assert_eq!(
            fs::read_to_string(&ssh_add_socket_record).unwrap().trim(),
            agent_socket.to_string_lossy()
        );
        assert_eq!(
            fs::read_to_string(&ssh_socket_record).unwrap().trim(),
            agent_socket.to_string_lossy()
        );
        let arguments = fs::read_to_string(&ssh_args_record)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let identity_option = arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("IdentityFile=\"")?.strip_suffix('"'))
            .unwrap();
        let identity_path = PathBuf::from(identity_option);
        assert!(!identity_path.exists());
        assert!(!identity_path.parent().unwrap().exists());
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["-o", "CertificateFile=none"]));
        assert!(arguments
            .windows(2)
            .any(|pair| pair[0] == "-o" && pair[1].starts_with("IdentityFile=\"")));
        assert!(!arguments.iter().any(|argument| argument == "-i"));
        assert_eq!(
            &arguments[arguments.len() - 3..],
            ["node.example.com", "uname", "-a"]
        );
    }

    #[test]
    fn agent_identity_match_uses_exact_blob_and_ignores_comment() {
        let expected_key = public_key("ssh-ed25519");
        let expected = public_key_identity(&expected_key).unwrap();
        let same_key = expected_key.replace("via-test", "workstation key");
        let other_key = public_key("ssh-rsa");
        let output = format!("malformed output\n{other_key}\n{same_key}\n");

        assert!(agent_output_contains_identity(output.as_bytes(), &expected));
        assert!(!agent_output_contains_identity(
            other_key.as_bytes(),
            &expected
        ));
    }

    #[test]
    fn explicit_agent_socket_must_be_absolute() {
        let error =
            resolve_agent_socket(&profile(Some(PathBuf::from("relative.sock")))).unwrap_err();
        assert!(matches!(error, ViaError::InvalidConfig(_)));
    }

    #[test]
    fn explicit_openssh_programs_are_resolved_as_an_absolute_pair() {
        let mut profile = profile(None);
        let (ssh, ssh_add) = absolute_test_programs();
        profile.ssh_program = Some(ssh.clone());
        profile.ssh_add_program = Some(ssh_add.clone());

        assert_eq!(resolve_ssh_programs(&profile).unwrap(), (ssh, ssh_add));

        profile.ssh_add_program = None;
        assert!(matches!(
            resolve_ssh_programs(&profile),
            Err(ViaError::InvalidConfig(message)) if message.contains("must be configured together")
        ));
    }

    #[test]
    fn explicit_openssh_programs_must_be_absolute_at_execution_time() {
        let mut profile = profile(None);
        let (_, ssh_add) = absolute_test_programs();
        profile.ssh_program = Some(PathBuf::from("ssh"));
        profile.ssh_add_program = Some(ssh_add);

        assert!(matches!(
            resolve_ssh_programs(&profile),
            Err(ViaError::InvalidConfig(message)) if message.contains("ssh_program must be an absolute path")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_default_openssh_programs_are_a_trusted_absolute_pair() {
        let (ssh, ssh_add) = default_ssh_programs().unwrap();

        assert!(ssh.is_absolute());
        assert!(ssh_add.is_absolute());
        assert_eq!(ssh.parent(), ssh_add.parent());
        assert_eq!(ssh.file_name(), Some(OsStr::new("ssh")));
        assert_eq!(ssh_add.file_name(), Some(OsStr::new("ssh-add")));
        assert!(TRUSTED_OPENSSH_DIRECTORIES
            .iter()
            .any(|directory| ssh.parent() == Some(Path::new(directory))));
    }

    #[cfg(windows)]
    #[test]
    fn windows_defaults_use_the_system_openssh_directory() {
        let (ssh, ssh_add) = default_ssh_programs().unwrap();

        assert!(ssh.is_absolute());
        assert_eq!(ssh.parent(), ssh_add.parent());
        assert_eq!(ssh.file_name(), Some(OsStr::new("ssh.exe")));
        assert_eq!(ssh_add.file_name(), Some(OsStr::new("ssh-add.exe")));
        assert_eq!(
            ssh.parent().unwrap().file_name(),
            Some(OsStr::new("OpenSSH"))
        );
        assert_eq!(
            default_agent_socket(None).unwrap(),
            PathBuf::from(r"\\.\pipe\openssh-ssh-agent")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_option_escapes_unicode_paths_and_rejects_invalid_unicode() {
        use std::os::windows::ffi::OsStringExt;

        let option = identity_file_option(Path::new(r#"C:\Temp Dir\key%h"quoted".pub"#)).unwrap();
        assert_eq!(
            option.to_str().unwrap(),
            r#"IdentityFile="C:\\Temp Dir\\key%%h\"quoted\".pub""#
        );
        for invalid in [
            "C:\\Temp\\key-$HOME.pub",
            "C:\\Temp\\key\nnext.pub",
            "C:\\Temp\\key\rnext.pub",
            "C:\\Temp\\key\0next.pub",
        ] {
            assert!(matches!(
                identity_file_option(Path::new(invalid)),
                Err(ViaError::InvalidSshIdentityPath(_))
            ));
        }

        let invalid_unicode =
            OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0xd800]);
        assert!(matches!(
            identity_file_option(Path::new(&invalid_unicode)),
            Err(ViaError::InvalidSshIdentityPath(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_a_custom_agent_endpoint() {
        let error =
            resolve_agent_socket(&profile(Some(PathBuf::from(r"\\.\pipe\different-agent"))))
                .unwrap_err();

        assert!(matches!(error, ViaError::InvalidConfig(_)));
    }

    #[cfg(unix)]
    #[test]
    fn default_unix_agent_socket_is_under_home() {
        let path = default_agent_socket(Some(OsStr::new("/users/example"))).unwrap();

        #[cfg(target_os = "macos")]
        assert_eq!(
            path,
            PathBuf::from(
                "/users/example/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
            )
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(path, PathBuf::from("/users/example/.1password/agent.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn agent_path_must_point_to_a_unix_socket() {
        let temporary = PublicKeyFile::create(&public_key("ssh-ed25519")).unwrap();
        let error = ensure_agent_socket(temporary.path()).unwrap_err();

        assert!(matches!(
            error,
            ViaError::SshAgentUnavailable { reason, .. } if reason.contains("not a Unix socket")
        ));
    }

    #[test]
    fn public_key_temp_file_is_cleaned_up() {
        let path;
        let directory;
        {
            let canonical = validate_public_key(&public_key("ssh-ed25519")).unwrap();
            let temporary = PublicKeyFile::create(&canonical).unwrap();
            path = temporary.path().to_path_buf();
            directory = temporary.directory.clone();
            assert!(path.exists());
            assert_eq!(path.parent(), Some(directory.as_path()));
            let contents = fs::read_to_string(&path).unwrap();
            assert_eq!(contents.lines().count(), 1);
            assert_eq!(contents.split_whitespace().count(), 2);
            assert!(!contents.contains("via-test"));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
        assert!(!path.exists());
        assert!(!directory.exists());
    }
}
