#[derive(Default)]
pub struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, secret: &str) {
        if secret.is_empty() || self.secrets.iter().any(|known| known == secret) {
            return;
        }

        // Longest first: when one secret contains another, replacing the
        // shorter one first would leave the rest of the longer one in place.
        let position = self
            .secrets
            .partition_point(|known| known.len() >= secret.len());
        self.secrets.insert(position, secret.to_owned());
    }

    pub fn redact(&self, value: &str) -> String {
        let mut redacted = value.to_owned();
        for secret in &self.secrets {
            redacted = redacted.replace(secret, REDACTED);
        }
        redacted
    }

    // Redacts raw bytes, which need not be valid UTF-8.
    pub fn redact_bytes(&self, value: &[u8]) -> Vec<u8> {
        let mut redacted = value.to_vec();
        for secret in &self.secrets {
            redacted = replace_bytes(&redacted, secret.as_bytes(), REDACTED.as_bytes());
        }
        redacted
    }
}

const REDACTED: &str = "[REDACTED]";

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }

    let mut replaced = Vec::with_capacity(haystack.len());
    let mut index = 0;
    while index < haystack.len() {
        if haystack[index..].starts_with(needle) {
            replaced.extend_from_slice(replacement);
            index += needle.len();
        } else {
            replaced.push(haystack[index]);
            index += 1;
        }
    }
    replaced
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
    fn redacts_registered_secrets_from_raw_bytes() {
        let mut redactor = Redactor::new();
        redactor.add("secret-token");
        redactor.add("other");

        let mut body = vec![0xff, 0x00];
        body.extend_from_slice(b"token=secret-token&secret-tokensecret-token\xfeother");

        let mut expected = vec![0xff, 0x00];
        expected.extend_from_slice(b"token=[REDACTED]&[REDACTED][REDACTED]\xfe[REDACTED]");
        assert_eq!(redactor.redact_bytes(&body), expected);
    }

    #[test]
    fn leaves_raw_bytes_without_secrets_unchanged() {
        let mut redactor = Redactor::new();
        redactor.add("secret-token");
        let body = [
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, b's', b'e', b'c', b'r', b'e', b't',
        ];

        assert_eq!(redactor.redact_bytes(&body), body);
        assert_eq!(Redactor::new().redact_bytes(&body), body);
        assert_eq!(redactor.redact_bytes(b""), b"");
    }

    #[test]
    fn redacts_a_secret_that_contains_another_secret_in_full() {
        for order in [
            ["secret", "secret-token-suffix"],
            ["secret-token-suffix", "secret"],
        ] {
            let mut redactor = Redactor::new();
            for secret in order {
                redactor.add(secret);
            }

            assert_eq!(
                redactor.redact("a=secret-token-suffix b=secret"),
                "a=[REDACTED] b=[REDACTED]"
            );
            assert_eq!(
                redactor.redact_bytes(b"a=secret-token-suffix\xff b=secret"),
                b"a=[REDACTED]\xff b=[REDACTED]"
            );
        }
    }

    #[test]
    fn ignores_empty_secret() {
        let mut redactor = Redactor::new();
        redactor.add("");

        assert_eq!(redactor.redact("abc"), "abc");
    }
}
