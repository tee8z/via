use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::directory_credential_name;
use crate::error::ViaError;
use crate::providers::SecretProvider;
use crate::secrets::SecretValue;

pub(crate) const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;

pub struct DirectoryProvider {
    path: Option<PathBuf>,
}

impl DirectoryProvider {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path }
    }
}

impl SecretProvider for DirectoryProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
        let directory = credentials_directory(self.path.as_deref())?;
        read_credential(&directory, reference)
    }
}

pub(crate) fn credentials_directory(configured: Option<&Path>) -> Result<PathBuf, ViaError> {
    select_credentials_directory(configured, env::var_os(CREDENTIALS_DIRECTORY_ENV))
}

fn select_credentials_directory(
    configured: Option<&Path>,
    from_environment: Option<OsString>,
) -> Result<PathBuf, ViaError> {
    let directory = match configured {
        Some(path) => path.to_path_buf(),
        None => from_environment
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                ViaError::InvalidConfig(format!(
                    "directory provider has no `path` and {CREDENTIALS_DIRECTORY_ENV} is not set"
                ))
            })?,
    };
    if !directory.is_absolute() {
        return Err(ViaError::InvalidConfig(
            "directory provider path must be an absolute path".to_owned(),
        ));
    }

    Ok(directory)
}

fn read_credential(directory: &Path, reference: &str) -> Result<SecretValue, ViaError> {
    let name = directory_credential_name(reference).ok_or_else(|| {
        ViaError::InvalidConfig(
            "directory provider references must be `cred://<name>` with a single file name"
                .to_owned(),
        )
    })?;
    let unavailable = |reason: &'static str| ViaError::SecretUnavailable {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };

    let checked = CredentialPath::prepare(directory, name).map_err(unavailable)?;
    let file = checked.open().map_err(unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable("the credential file could not be inspected"))?;
    check_credential_metadata(&metadata).map_err(unavailable)?;

    let mut bytes = Vec::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable("the credential file could not be read"))?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(unavailable("the credential file is larger than 1 MiB"));
    }
    let mut value = String::from_utf8(bytes)
        .map_err(|_| unavailable("the credential file is not valid UTF-8"))?;
    strip_one_trailing_newline(&mut value);

    Ok(SecretValue::new(value))
}

// Keep the directory handle across validation and opening. cap-std enforces
// confinement during resolution on Unix and Windows, including replacements
// of a previously checked file or directory with a symlink/reparse point.
struct CredentialPath {
    directory: cap_std::fs::Dir,
    name: OsString,
}

impl CredentialPath {
    fn prepare(directory: &Path, name: &str) -> Result<Self, &'static str> {
        let canonical = fs::canonicalize(directory)
            .map_err(|_| "the credential directory does not exist or is not accessible")?;
        let directory =
            cap_std::fs::Dir::open_ambient_dir(&canonical, cap_std::ambient_authority())
                .map_err(|_| "the credential directory could not be opened")?;
        let resolved = fs::canonicalize(canonical.join(name))
            .map_err(|_| "the credential file does not exist or is not accessible")?;
        if resolved.parent() != Some(canonical.as_path()) {
            return Err("the credential file resolves outside the credential directory");
        }
        let metadata = fs::metadata(&resolved)
            .map_err(|_| "the credential file does not exist or is not accessible")?;
        check_credential_metadata(&metadata)?;
        let name = resolved
            .file_name()
            .ok_or("the credential path has no file name")?
            .to_owned();
        Ok(Self { directory, name })
    }

    fn open(&self) -> Result<File, &'static str> {
        let mut options = cap_std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use cap_std::fs::OpenOptionsExt;
            // A replacement FIFO must not block before handle validation.
            options.custom_flags(libc::O_NONBLOCK);
        }
        self.directory
            .open_with(&self.name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|_| "the credential file could not be opened within its directory")
    }
}

fn check_credential_metadata(metadata: &fs::Metadata) -> Result<(), &'static str> {
    if !metadata.is_file() {
        return Err("the credential path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o004 != 0 {
            return Err("the credential file is readable by other users");
        }
    }

    Ok(())
}

fn strip_one_trailing_newline(value: &mut String) {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::providers::ProviderRegistry;
    #[cfg(unix)]
    use crate::test_support::set_mode;
    use crate::test_support::TempDir;

    fn unavailable_reason(result: Result<SecretValue, ViaError>) -> String {
        match result {
            Err(ViaError::SecretUnavailable { reason, .. }) => reason,
            Err(error) => panic!("expected an unavailable credential, got {error}"),
            Ok(_) => panic!("expected an unavailable credential, got a value"),
        }
    }

    #[test]
    fn reads_a_credential_file_by_name() {
        let directory = TempDir::create("directory-read");
        directory.write_private("github-token", b"secret-token");

        let secret = read_credential(directory.path(), "cred://github-token").unwrap();

        assert_eq!(secret.expose(), "secret-token");
    }

    #[test]
    fn strips_exactly_one_trailing_newline() {
        let directory = TempDir::create("directory-newline");
        for (name, contents, expected) in [
            ("unix", "secret-token\n", "secret-token"),
            ("windows", "secret-token\r\n", "secret-token"),
            ("double", "secret-token\n\n", "secret-token\n"),
            ("inner", "line-one\nline-two\n", "line-one\nline-two"),
            ("carriage-return", "secret-token\r", "secret-token\r"),
            ("empty", "", ""),
        ] {
            directory.write_private(name, contents.as_bytes());

            let secret = read_credential(directory.path(), &format!("cred://{name}")).unwrap();

            assert_eq!(secret.expose(), expected, "credential `{name}`");
        }
    }

    #[test]
    fn rejects_references_that_are_not_a_single_file_name() {
        let directory = TempDir::create("directory-names");
        directory.write_private("github-token", b"secret-token");

        for reference in [
            "cred://",
            "cred://.",
            "cred://..",
            "cred://../github-token",
            "cred://nested/github-token",
            "cred:///etc/passwd",
            "cred://github-token/",
            "cred://a\\b",
            "cred://github-token\0",
            "op://Private/GitHub/token",
            "github-token",
        ] {
            let error = match read_credential(directory.path(), reference) {
                Ok(_) => panic!("expected `{reference}` to be rejected"),
                Err(error) => error,
            };

            assert!(
                matches!(&error, ViaError::InvalidConfig(message) if message.contains("cred://<name>")),
                "unexpected error for `{reference}`: {error}"
            );
        }
    }

    #[test]
    fn reports_missing_files_and_directories_without_a_value() {
        let directory = TempDir::create("directory-missing");

        assert!(
            unavailable_reason(read_credential(directory.path(), "cred://absent"))
                .contains("credential file does not exist")
        );
        assert!(unavailable_reason(read_credential(
            &directory.join("absent-directory"),
            "cred://github-token"
        ))
        .contains("credential directory does not exist"));
    }

    #[test]
    fn rejects_paths_that_are_not_regular_files() {
        let directory = TempDir::create("directory-kind");
        fs::create_dir(directory.join("nested")).unwrap();

        assert!(
            unavailable_reason(read_credential(directory.path(), "cred://nested"))
                .contains("not a regular file")
        );
    }

    #[test]
    fn rejects_files_that_are_not_utf8_without_echoing_them() {
        let directory = TempDir::create("directory-utf8");
        directory.write_private("binary", &[0xff, 0xfe, b's', b'e', b'c', b'r', b'e', b't']);

        let error = match read_credential(directory.path(), "cred://binary") {
            Ok(_) => panic!("expected invalid UTF-8 to be rejected"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("not valid UTF-8"));
        assert!(!error.to_string().contains("secret"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_files_readable_by_other_users() {
        let directory = TempDir::create("directory-mode");
        for mode in [0o644, 0o604, 0o444] {
            let path = directory.write_private("github-token", b"secret-token");
            set_mode(&path, mode);

            assert!(
                unavailable_reason(read_credential(directory.path(), "cred://github-token"))
                    .contains("readable by other users"),
                "mode {mode:o}"
            );
        }

        for mode in [0o600, 0o400, 0o640] {
            let path = directory.write_private("group-token", b"secret-token");
            set_mode(&path, mode);

            assert!(
                read_credential(directory.path(), "cred://group-token").is_ok(),
                "mode {mode:o}"
            );
            // Restore write access so the next iteration can replace the file.
            set_mode(&path, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_links_that_leave_the_directory() {
        let directory = TempDir::create("directory-symlink");
        let outside = TempDir::create("directory-symlink-outside");
        let target = outside.write_private("outside-token", b"outside-secret");
        std::os::unix::fs::symlink(target, directory.join("escape")).unwrap();
        fs::create_dir(directory.join("nested")).unwrap();
        let nested = directory.join("nested").join("token");
        fs::write(nested.as_path(), b"nested-secret").unwrap();
        set_mode(&nested, 0o600);
        std::os::unix::fs::symlink(nested, directory.join("nested-link")).unwrap();

        for name in ["escape", "nested-link"] {
            assert!(
                unavailable_reason(read_credential(directory.path(), &format!("cred://{name}")))
                    .contains("outside the credential directory"),
                "link `{name}`"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn follows_symbolic_links_that_stay_in_the_directory() {
        let directory = TempDir::create("directory-symlink-inside");
        let target = directory.write_private("github-token", b"secret-token");
        std::os::unix::fs::symlink(target, directory.join("alias")).unwrap();

        let secret = read_credential(directory.path(), "cred://alias").unwrap();

        assert_eq!(secret.expose(), "secret-token");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_swapped_in_after_validation() {
        let directory = TempDir::create("credential-swap");
        let outside = TempDir::create("credential-swap-outside");
        let path = directory.write_private("token", b"inside");
        let target = outside.write_private("token", b"outside");
        let checked = CredentialPath::prepare(directory.path(), "token").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(checked.open().is_err());
        fs::remove_file(&path).unwrap();
        // Exercise relative traversal as well as an absolute link.
        let relative = Path::new("..")
            .join(outside.path().file_name().unwrap())
            .join("token");
        std::os::unix::fs::symlink(relative, &path).unwrap();
        assert!(checked.open().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn keeps_the_original_directory_when_its_path_is_replaced() {
        let root = TempDir::create("credential-directory-swap");
        let directory = root.join("credentials");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("token"), b"inside").unwrap();
        set_mode(&directory.join("token"), 0o600);
        let checked = CredentialPath::prepare(&directory, "token").unwrap();
        fs::rename(&directory, root.join("original")).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("token"), b"replacement").unwrap();
        let mut value = String::new();
        checked.open().unwrap().read_to_string(&mut value).unwrap();
        assert_eq!(value, "inside");
    }

    #[test]
    fn rejects_credentials_larger_than_the_limit() {
        let directory = TempDir::create("directory-size");
        let contents = "a".repeat(1024 * 1024 + 1);
        directory.write_private("large", contents.as_bytes());

        assert!(
            unavailable_reason(read_credential(directory.path(), "cred://large"))
                .contains("larger than 1 MiB")
        );
    }

    #[test]
    fn prefers_the_configured_directory_over_the_environment() {
        let configured = TempDir::create("directory-configured");
        let from_environment = TempDir::create("directory-environment");

        assert_eq!(
            select_credentials_directory(
                Some(configured.path()),
                Some(from_environment.path().as_os_str().to_owned())
            )
            .unwrap(),
            configured.path()
        );
        assert_eq!(
            select_credentials_directory(
                None,
                Some(from_environment.path().as_os_str().to_owned())
            )
            .unwrap(),
            from_environment.path()
        );
    }

    #[test]
    fn requires_a_configured_or_environment_directory() {
        for from_environment in [None, Some(OsString::new())] {
            assert!(matches!(
                select_credentials_directory(None, from_environment),
                Err(ViaError::InvalidConfig(message)) if message.contains(CREDENTIALS_DIRECTORY_ENV)
            ));
        }
        assert!(matches!(
            select_credentials_directory(None, Some(OsString::from("relative/credentials"))),
            Err(ViaError::InvalidConfig(message)) if message.contains("absolute path")
        ));
        assert!(matches!(
            select_credentials_directory(Some(Path::new("relative/credentials")), None),
            Err(ViaError::InvalidConfig(message)) if message.contains("absolute path")
        ));
    }

    #[test]
    fn registry_resolves_cred_references_from_the_configured_directory() {
        let directory = TempDir::create("directory-registry");
        directory.write_private("github-token", b"secret-token\n");
        let config = Config::from_toml_str(&format!(
            r#"
version = 1

[providers.files]
type = "directory"
path = '{}'

[services.github]
provider = "files"

[services.github.secrets]
token = "cred://github-token"
"#,
            directory.path().display()
        ))
        .unwrap();
        let providers = ProviderRegistry::from_config(&config).unwrap();

        let secret = providers
            .get("files")
            .unwrap()
            .resolve(&config.services["github"].secrets["token"])
            .unwrap();

        assert_eq!(secret.expose(), "secret-token");
    }
}
