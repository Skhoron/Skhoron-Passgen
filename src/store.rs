//! Локальное хранилище хешей паролей: простой файл вида
//! `label:phc_hash_string` построчно. Не шифрование, не крипто-примитив —
//! обычная работа с файлами, поэтому пишем сами.
//!
//! ⚠️ Файл хранит PHC-хеши (Argon2id), НЕ сами пароли — это безопасно
//! хранить открытым текстом (как /etc/shadow). Но если нужна ещё и
//! конфиденциальность самого факта "какие сервисы у пользователя есть"
//! (label'ы), стоит рассмотреть шифрование файла целиком отдельным слоем
//! (например через XChaCha20-Poly1305 с ключом из мастер-пароля) — это
//! уже отдельная задача, не реализована здесь.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed line in store file: {0:?}")]
    MalformedLine(String),
    #[error("label {0:?} not found in store")]
    LabelNotFound(String),
    #[error("label {0:?} already exists — use a different label or remove the old one first")]
    LabelAlreadyExists(String),
}

pub struct PasswordStore {
    entries: HashMap<String, String>, // label -> PHC hash string
    path: std::path::PathBuf,
}

impl PasswordStore {
    /// Загружает хранилище из файла, если он существует, иначе создаёт пустое.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let mut entries = HashMap::new();

        if path.exists() {
            let content = fs::read_to_string(&path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (label, hash) = line
                    .split_once(':')
                    .ok_or_else(|| StoreError::MalformedLine(line.to_string()))?;
                entries.insert(label.to_string(), hash.to_string());
            }
        }

        Ok(Self { entries, path })
    }

    pub fn add(&mut self, label: &str, phc_hash: &str) -> Result<(), StoreError> {
        if self.entries.contains_key(label) {
            return Err(StoreError::LabelAlreadyExists(label.to_string()));
        }
        self.entries.insert(label.to_string(), phc_hash.to_string());
        self.persist()
    }

    pub fn get(&self, label: &str) -> Result<&str, StoreError> {
        self.entries
            .get(label)
            .map(|s| s.as_str())
            .ok_or_else(|| StoreError::LabelNotFound(label.to_string()))
    }

    pub fn remove(&mut self, label: &str) -> Result<(), StoreError> {
        if self.entries.remove(label).is_none() {
            return Err(StoreError::LabelNotFound(label.to_string()));
        }
        self.persist()
    }

    pub fn list_labels(&self) -> Vec<&str> {
        let mut labels: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        labels.sort_unstable();
        labels
    }

    fn persist(&self) -> Result<(), StoreError> {
        // PHC-строки сами по себе не содержат ':' (разделены '$'), поэтому
        // простой формат "label:hash" однозначно парсится обратно.
        let mut content = String::new();
        content.push_str("# Skhoron-Passgen store — labels + Argon2id PHC hashes.\n");
        content.push_str("# НЕ содержит сами пароли, только их хеши.\n");
        let mut labels: Vec<&String> = self.entries.keys().collect();
        labels.sort_unstable();
        for label in labels {
            content.push_str(label);
            content.push(':');
            content.push_str(&self.entries[label]);
            content.push('\n');
        }
        fs::write(&self.path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn add_get_remove_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        std::fs::remove_file(path).ok(); // load_or_create должен уметь создать заново

        let mut store = PasswordStore::load_or_create(path).unwrap();
        store.add("example.com", "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA").unwrap();

        assert_eq!(
            store.get("example.com").unwrap(),
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA"
        );

        store.remove("example.com").unwrap();
        assert!(matches!(store.get("example.com"), Err(StoreError::LabelNotFound(_))));
    }

    #[test]
    fn persists_across_reload() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        {
            let mut store = PasswordStore::load_or_create(&path).unwrap();
            store.add("service-a", "hash-a-placeholder").unwrap();
        }

        let store2 = PasswordStore::load_or_create(&path).unwrap();
        assert_eq!(store2.get("service-a").unwrap(), "hash-a-placeholder");
    }

    #[test]
    fn rejects_duplicate_label() {
        let file = NamedTempFile::new().unwrap();
        let mut store = PasswordStore::load_or_create(file.path()).unwrap();
        store.add("dup", "hash1").unwrap();
        assert!(matches!(store.add("dup", "hash2"), Err(StoreError::LabelAlreadyExists(_))));
    }
}