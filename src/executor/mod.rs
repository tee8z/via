use crate::config::{CapabilityMode, CommandConfig, Config};
use crate::error::ViaError;
use crate::providers::ProviderRegistry;
use crate::redaction::Redactor;

mod delegated;
mod rest;
pub(crate) mod ssh;

// How a capability is being executed. The entry point selects the context
// and passes it down explicitly; nothing in a request or in the environment
// can change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionContext {
    broker: bool,
}

impl ExecutionContext {
    // A caller that runs via in its own session.
    pub const fn direct() -> Self {
        Self { broker: false }
    }

    // An untrusted remote caller served through `via broker exec`.
    pub const fn broker() -> Self {
        Self { broker: true }
    }

    pub const fn is_broker(&self) -> bool {
        self.broker
    }
}

// What an invocation did, for the broker audit record. It never holds a
// query string, a body or a header value.
#[derive(Default)]
pub struct InvocationTrace {
    pub mode: Option<CapabilityMode>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_command: Option<String>,
    // An HTTP status or a process exit code.
    pub status: Option<i64>,
    // Set when an executor refuses a request for a policy reason that it
    // reports with a general error type.
    pub denied: Option<&'static str>,
    // Secrets resolved during the invocation, so records can be redacted.
    pub redactor: Redactor,
}

pub fn invoke(
    config: &Config,
    providers: &ProviderRegistry,
    service_name: &str,
    capability_name: &str,
    args: Vec<String>,
) -> Result<(), ViaError> {
    invoke_with_context(
        &ExecutionContext::direct(),
        config,
        providers,
        service_name,
        capability_name,
        args,
        &mut InvocationTrace::default(),
    )
}

pub fn invoke_with_context(
    context: &ExecutionContext,
    config: &Config,
    providers: &ProviderRegistry,
    service_name: &str,
    capability_name: &str,
    args: Vec<String>,
    trace: &mut InvocationTrace,
) -> Result<(), ViaError> {
    let service = config
        .services
        .get(service_name)
        .ok_or_else(|| ViaError::UnknownService(service_name.to_owned()))?;
    let command =
        service
            .commands
            .get(capability_name)
            .ok_or_else(|| ViaError::UnknownCapability {
                service: service_name.to_owned(),
                capability: capability_name.to_owned(),
            })?;
    trace.mode = Some(command.mode());
    match command {
        CommandConfig::Rest(rest) => {
            let provider = providers.get(&service.provider)?;
            rest::execute(context, service_name, service, rest, provider, args, trace)
        }
        CommandConfig::Delegated(delegated) => {
            // A delegated child receives the secret and runs with the
            // broker account's access, so a remote caller may not start one.
            if context.is_broker() {
                return Err(ViaError::denied(
                    "delegated_not_allowed",
                    "delegated capabilities are not available in broker mode",
                ));
            }
            let provider = providers.get(&service.provider)?;
            delegated::execute(service_name, service, delegated, provider, args)
        }
        CommandConfig::Ssh(ssh_config) => {
            let profile = config.ssh_profiles.get(&ssh_config.profile).ok_or_else(|| {
                ViaError::InvalidConfig(format!(
                    "command `{service_name}.{capability_name}` references unknown SSH profile `{}`",
                    ssh_config.profile
                ))
            })?;
            let provider = providers.get(&profile.provider)?;
            ssh::execute(context, ssh_config, profile, provider, args, trace)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::from_toml_str(
            r#"
version = 1

[providers.onepassword]
type = "1password"

[services.github]
provider = "onepassword"

[services.github.secrets]
token = "op://Private/GitHub/token"

[services.github.commands.api]
mode = "rest"
base_url = "https://api.github.com"

[services.github.commands.gh]
mode = "delegated"
program = "via-test-missing-delegated-program"
"#,
        )
        .unwrap()
    }

    #[test]
    fn contexts_are_explicit_about_broker_mode() {
        assert!(!ExecutionContext::direct().is_broker());
        assert!(ExecutionContext::broker().is_broker());
    }

    #[test]
    fn broker_context_refuses_delegated_capabilities() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let mut trace = InvocationTrace::default();
        let error = invoke_with_context(
            &ExecutionContext::broker(),
            &config,
            &providers,
            "github",
            "gh",
            vec!["auth".to_owned(), "token".to_owned()],
            &mut trace,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ViaError::Denied { reason, .. } if reason == "delegated_not_allowed"
        ));
        assert!(matches!(trace.mode, Some(CapabilityMode::Delegated)));
    }

    #[test]
    fn direct_context_still_runs_delegated_capabilities() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let error = invoke(&config, &providers, "github", "gh", Vec::new()).unwrap_err();

        // The refusal above is specific to broker mode: a direct caller
        // reaches the point where the configured program is started.
        assert!(matches!(error, ViaError::Io(_)));
    }

    #[test]
    fn invoke_rejects_unknown_service() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let error = invoke(&config, &providers, "missing", "api", Vec::new()).unwrap_err();

        assert!(matches!(error, ViaError::UnknownService(service) if service == "missing"));
    }

    #[test]
    fn invoke_rejects_unknown_capability() {
        let config = config();
        let providers = ProviderRegistry::from_config(&config).unwrap();
        let error = invoke(&config, &providers, "github", "missing", Vec::new()).unwrap_err();

        assert!(matches!(
            error,
            ViaError::UnknownCapability {
                service,
                capability
            } if service == "github" && capability == "missing"
        ));
    }
}
