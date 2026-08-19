//! Хеширование паролей: Argon2id (RFC 9106) через crate `argon2`.
//!
//! Сама хеш-функция — библиотечная, стандартизированная, не наша. Наша
//! часть — параметры, формат хранения, интеграция с остальным инструментом.
//! Соль генерируется автоматически внутри `argon2::PasswordHasher`
//! через OsRng (не пишем свой генератор соли отдельно — это то же самое
//! "не изобретай RNG", просто соль тоже случайные байты).

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("argon2 error: {0}")]
    Argon2(#[from] password_hash::Error),
    #[error("invalid argon2 parameters")]
    InvalidParams,
}

#[derive(Debug, Clone, Copy)]
pub struct HashParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for HashParams {
    fn default() -> Self {
        // OWASP-минимум для мобильных устройств. Для десктопа/сервера
        // разумно поднять memory_kib (например до 46*1024).
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
        let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, None)
            .map_err(|_| HashError::InvalidParams)?;
        Ok(Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params),
        })
    }

    pub fn default_params() -> Self {
        Self::new(HashParams::default()).expect("default params are always valid")
    }

    /// Хеширует пароль, соль генерируется автоматически (OsRng).
    /// Возвращает PHC-строку: `$argon2id$v=19$m=...,t=...,p=...$salt$hash`
    pub fn hash(&self, password: &str) -> Result<String, HashError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    /// Проверяет пароль против PHC-хеша. Constant-time сравнение
    /// обеспечивается самой crate `argon2`/`password-hash`.
    pub fn verify(&self, password: &str, stored_hash: &str) -> Result<bool, HashError> {
        let parsed = PasswordHash::new(stored_hash)?;
        Ok(self.argon2.verify_password(password.as_bytes(), &parsed).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hasher = PasswordHasherWrapper::default_params();
        let hash = hasher.hash("Tr0ub4dor&3xample").unwrap();
        assert!(hasher.verify("Tr0ub4dor&3xample", &hash).unwrap());
        assert!(!hasher.verify("wrong-password", &hash).unwrap());
    }

    #[test]
    fn same_password_produces_different_hashes_due_to_random_salt() {
        let hasher = PasswordHasherWrapper::default_params();
        let h1 = hasher.hash("same-password").unwrap();
        let h2 = hasher.hash("same-password").unwrap();
        assert_ne!(h1, h2, "different random salts must yield different PHC strings");
        assert!(hasher.verify("same-password", &h1).unwrap());
        assert!(hasher.verify("same-password", &h2).unwrap());
    }
}