use std::env;
use std::time::{Duration, Instant};

pub struct TimingSpan {
    enabled: bool,
    label: String,
    started_at: Instant,
}

pub fn span(label: impl Into<String>) -> TimingSpan {
    TimingSpan {
        enabled: enabled(),
        label: label.into(),
        started_at: Instant::now(),
    }
}

pub fn event(label: impl AsRef<str>, detail: impl AsRef<str>) {
    if enabled() {
        eprintln!("via timing: {} {}", label.as_ref(), detail.as_ref());
    }
}

pub fn enabled() -> bool {
    env_flag("VIA_TIMING") || env_flag("VIA_DEBUG_TIMING")
}

impl TimingSpan {
    pub fn finish(self, detail: impl AsRef<str>) -> Duration {
        let elapsed = self.started_at.elapsed();
        if self.enabled {
            eprintln!(
                "via timing: {} {} ({:.1}ms)",
                self.label,
                detail.as_ref(),
                elapsed.as_secs_f64() * 1000.0
            );
        }
        elapsed
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            let value = value.trim();
            !value.is_empty()
                && value != "0"
                && !value.eq_ignore_ascii_case("false")
                && !value.eq_ignore_ascii_case("off")
                && !value.eq_ignore_ascii_case("no")
        })
        .unwrap_or(false)
}
