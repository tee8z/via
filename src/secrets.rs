use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};

#[derive(Clone)]
pub struct SecretValue {
    value: SecretString,
}

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self {
            value: SecretString::from(value),
        }
    }

    pub fn from_utf8_lossy_trimmed(bytes: Vec<u8>) -> Self {
        let value = match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
        };
        Self::new_trimmed(value)
    }

    pub fn expose(&self) -> &str {
        self.value.expose_secret()
    }

    fn new_trimmed(mut value: String) -> Self {
        while value.ends_with(['\r', '\n']) {
            value.pop();
        }
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_secret_value_when_explicitly_requested() {
        let secret = SecretValue::new("secret-token".to_owned());

        assert_eq!(secret.expose(), "secret-token");
    }

    #[test]
    fn builds_secret_value_from_trimmed_utf8_output() {
        let secret = SecretValue::from_utf8_lossy_trimmed(b"secret-token\r\n".to_vec());

        assert_eq!(secret.expose(), "secret-token");
    }
}
