use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::Value;

use crate::error::ViaError;

pub fn sign_rs256(claims: &Value, private_key_pem: &str) -> Result<String, ViaError> {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
    });
    let header = encode_json(&header)?;
    let claims = encode_json(claims)?;
    let signing_input = format!("{header}.{claims}");
    let key_pair = rsa_key_pair_from_pem(private_key_pem)?;
    let rng = SystemRandom::new();
    let mut signature = vec![0; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| ViaError::InvalidConfig("failed to sign JWT".to_owned()))?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn encode_json(value: &Value) -> Result<String, ViaError> {
    let raw = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn rsa_key_pair_from_pem(pem: &str) -> Result<RsaKeyPair, ViaError> {
    let der = decode_private_key_pem(pem)?;

    RsaKeyPair::from_der(&der)
        .or_else(|_| RsaKeyPair::from_pkcs8(&der))
        .map_err(|_| {
            ViaError::InvalidConfig(
                "GitHub App private_key must be an RSA private key in PEM format".to_owned(),
            )
        })
}

fn decode_private_key_pem(pem: &str) -> Result<Vec<u8>, ViaError> {
    let mut body = String::new();
    let mut in_key = false;

    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") && line.ends_with(" PRIVATE KEY-----") {
            in_key = true;
            continue;
        }
        if line.starts_with("-----END ") && line.ends_with(" PRIVATE KEY-----") {
            break;
        }
        if in_key {
            body.push_str(line);
        }
    }

    if body.is_empty() {
        return Err(ViaError::InvalidConfig(
            "GitHub App private_key must be PEM encoded".to_owned(),
        ));
    }

    STANDARD.decode(body).map_err(|_| {
        ViaError::InvalidConfig("GitHub App private_key PEM body is not valid base64".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RSA_PRIVATE_KEY: &str =
        include_str!("../../tests/fixtures/rsa-private-key.pkcs1.pem");

    #[test]
    fn rejects_non_pem_private_key() {
        let error = sign_rs256(&serde_json::json!({"iss": "test"}), "not a key").unwrap_err();

        assert!(
            matches!(error, ViaError::InvalidConfig(message) if message.contains("PEM encoded"))
        );
    }

    #[test]
    fn signs_rs256_jwt() {
        let jwt = sign_rs256(
            &serde_json::json!({
                "iss": "client-id",
                "iat": 1,
                "exp": 2,
            }),
            TEST_RSA_PRIVATE_KEY,
        )
        .unwrap();

        let parts = jwt.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            parts[0], "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
            "header should be stable"
        );
    }
}
