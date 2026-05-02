use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Mutex;

use crate::config::OnePasswordCacheMode;
use crate::error::ViaError;
use crate::providers::SecretProvider;
use crate::secrets::SecretValue;

pub struct OnePasswordCliProvider {
    account: Option<String>,
    cache: OnePasswordCacheMode,
    cache_ttl_seconds: u64,
    config_hash: String,
    ref_ids: BTreeMap<String, String>,
    registered: Mutex<bool>,
}

impl OnePasswordCliProvider {
    pub fn new(
        account: Option<String>,
        cache: OnePasswordCacheMode,
        cache_ttl_seconds: u64,
        allowed_refs: Vec<String>,
    ) -> Self {
        let config_hash = cache_config_hash(account.as_deref(), &allowed_refs);
        let ref_ids = allowed_refs
            .into_iter()
            .map(|reference| {
                let id = reference_id(account.as_deref(), &reference);
                (reference, id)
            })
            .collect();

        Self {
            account,
            cache,
            cache_ttl_seconds,
            config_hash,
            ref_ids,
            registered: Mutex::new(false),
        }
    }
}

impl SecretProvider for OnePasswordCliProvider {
    fn resolve(&self, reference: &str) -> Result<SecretValue, ViaError> {
        if self.cache == OnePasswordCacheMode::Daemon {
            return self.resolve_via_daemon(reference);
        }

        resolve_direct(self.account.as_deref(), reference)
    }
}

impl OnePasswordCliProvider {
    fn resolve_via_daemon(&self, reference: &str) -> Result<SecretValue, ViaError> {
        self.ensure_daemon_registered()?;
        let ref_id = self.ref_ids.get(reference).ok_or_else(|| {
            ViaError::InvalidConfig(
                "1Password daemon refused to resolve a secret outside the provider allowlist"
                    .to_owned(),
            )
        })?;
        crate::daemon::resolve_onepassword_secret(&self.config_hash, ref_id, self.cache_ttl_seconds)
    }

    fn ensure_daemon_registered(&self) -> Result<(), ViaError> {
        let mut registered = self.registered.lock().map_err(|_| {
            ViaError::InvalidConfig("1Password daemon registration lock was poisoned".to_owned())
        })?;
        if *registered {
            return Ok(());
        }

        let refs = self
            .ref_ids
            .iter()
            .map(|(reference, id)| crate::daemon::AllowedOnePasswordRef {
                id: id.clone(),
                reference: reference.clone(),
            })
            .collect::<Vec<_>>();
        crate::daemon::register_onepassword_refs(&self.config_hash, self.account.as_deref(), refs)?;
        *registered = true;
        Ok(())
    }
}

fn resolve_direct(account: Option<&str>, reference: &str) -> Result<SecretValue, ViaError> {
    let mut command = Command::new("op");
    command.arg("read").arg(reference);
    if let Some(account) = account {
        command.arg("--account").arg(account);
    }

    let span = crate::timing::span("1password op read");
    let output = match command.output() {
        Ok(output) => {
            span.finish(format!("status={:?}", output.status.code()));
            output
        }
        Err(source) => {
            span.finish("failed_to_start");
            return Err(ViaError::MissingProgram {
                program: "op".to_owned(),
                source,
            });
        }
    };

    if !output.status.success() {
        return Err(ViaError::ExternalCommandFailed {
            program: "op".to_owned(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(SecretValue::from_utf8_lossy_trimmed(output.stdout))
}

fn cache_config_hash(account: Option<&str>, refs: &[String]) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(b"via:1password-cache:v1");
    context.update(b"\0");
    context.update(account.unwrap_or("").as_bytes());
    for reference in refs {
        context.update(b"\0");
        context.update(reference.as_bytes());
    }
    hex_encode(context.finish().as_ref())
}

fn reference_id(account: Option<&str>, reference: &str) -> String {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    context.update(b"via:1password-ref:v1");
    context.update(b"\0");
    context.update(account.unwrap_or("").as_bytes());
    context.update(b"\0");
    context.update(reference.as_bytes());
    hex_encode(context.finish().as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
