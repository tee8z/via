use secrecy::{ExposeSecret, SecretString};

pub struct SecretValue {
    value: SecretString,
}

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self {
            value: SecretString::from(value),
        }
    }

    pub fn expose(&self) -> &str {
        self.value.expose_secret()
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
}
