#[derive(Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, secret: &str) {
        if secret.is_empty() {
            return;
        }

        self.secrets.push(secret.to_owned());
    }

    pub fn redact(&self, value: &str) -> String {
        let mut redacted = value.to_owned();
        for secret in &self.secrets {
            redacted = redacted.replace(secret, "[REDACTED]");
        }
        redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_registered_secret() {
        let mut redactor = Redactor::new();
        redactor.add("secret-token");

        assert_eq!(redactor.redact("token=secret-token"), "token=[REDACTED]");
    }

    #[test]
    fn ignores_empty_secret() {
        let mut redactor = Redactor::new();
        redactor.add("");

        assert_eq!(redactor.redact("abc"), "abc");
    }
}
