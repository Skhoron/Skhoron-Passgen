//! Хеширование паролей через Argon2id.

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{
    PasswordHash,
    PasswordHasher,
    PasswordVerifier,
    SaltString,
};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("argon2 error: {0}")]
    Argon2(#[from] password_hash::Error),

    #[error("invalid argon2 parameters: {0}")]
    InvalidParams(String),
}

#[derive(Debug, Clone, Copy)]
pub struct HashParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for HashParams {
    fn default() -> Self {
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }
}

pub struct PasswordHasherWrapper {
    argon2: Argon2<'static>,
}

impl PasswordHasherWrapper {
    pub fn new(params: HashParams) -> Result<Self, HashError> {
        let argon2_params = Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            None,
        )
        .map_err(|error| {
            HashError::InvalidParams(error.to_string())
        })?;

        Ok(Self {
            argon2: Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                argon2_params,
            ),
        })
    }

    pub fn default_params() -> Self {
        Self::new(HashParams::default())
            .expect("default Argon2 parameters are valid")
    }

    /// Хеширует пароль и возвращает PHC-строку.
    pub fn hash(&self, password: &str) -> Result<String, HashError> {
        let salt = SaltString::generate(&mut OsRng);

        let hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)?;

        Ok(hash.to_string())
    }

    /// Проверяет пароль против PHC-хеша.
    ///
    /// Неверный пароль возвращается как Ok(false).
    /// Повреждённый PHC-хеш возвращает Err.
    pub fn verify(
        &self,
        password: &str,
        stored_hash: &str,
    ) -> Result<bool, HashError> {
        let parsed = PasswordHash::new(stored_hash)?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed)
        {
            Ok(()) => Ok(true),

            Err(password_hash::Error::Password) => Ok(false),

            Err(error) => Err(HashError::Argon2(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hasher = PasswordHasherWrapper::default_params();

        let hash = hasher
            .hash("Tr0ub4dor&3xample")
            .unwrap();

        assert!(
            hasher
                .verify("Tr0ub4dor&3xample", &hash)
                .unwrap()
        );

        assert!(
            !hasher
                .verify("wrong-password", &hash)
                .unwrap()
        );
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let hasher = PasswordHasherWrapper::default_params();

        let h1 = hasher.hash("same-password").unwrap();
        let h2 = hasher.hash("same-password").unwrap();

        assert_ne!(h1, h2);

        assert!(
            hasher
                .verify("same-password", &h1)
                .unwrap()
        );

        assert!(
            hasher
                .verify("same-password", &h2)
                .unwrap()
        );
    }
}