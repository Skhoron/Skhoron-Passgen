//! Локальное хранилище Argon2id-хешей.
//!
//! Формат:
//! label:phc_hash
//!
//! Пароли здесь НЕ хранятся.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("malformed line in store file: {0:?}")]
    MalformedLine(String),

    #[error("invalid label: {0}")]
    InvalidLabel(String),

    #[error("invalid hash value")]
    InvalidHash,

    #[error("label {0:?} not found in store")]
    LabelNotFound(String),

    #[error("label {0:?} already exists — use a different label or remove the old one first")]
    LabelAlreadyExists(String),
}

pub struct PasswordStore {
    entries: HashMap<String, String>,
    path: PathBuf,
}

impl PasswordStore {
    /// Загружает существующее хранилище или создаёт пустое.
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

                validate_label(label)?;
                validate_hash(hash)?;

                if entries.insert(label.to_string(), hash.to_string()).is_some() {
                    return Err(StoreError::MalformedLine(format!(
                        "duplicate label: {label:?}"
                    )));
                }
            }
        }

        Ok(Self { entries, path })
    }

    pub fn add(&mut self, label: &str, phc_hash: &str) -> Result<(), StoreError> {
        validate_label(label)?;
        validate_hash(phc_hash)?;

        if self.entries.contains_key(label) {
            return Err(StoreError::LabelAlreadyExists(label.to_string()));
        }

        self.entries
            .insert(label.to_string(), phc_hash.to_string());

        if let Err(error) = self.persist() {
            self.entries.remove(label);
            return Err(error);
        }

        Ok(())
    }

    pub fn get(&self, label: &str) -> Result<&str, StoreError> {
        validate_label(label)?;

        self.entries
            .get(label)
            .map(String::as_str)
            .ok_or_else(|| StoreError::LabelNotFound(label.to_string()))
    }

    pub fn remove(&mut self, label: &str) -> Result<(), StoreError> {
        validate_label(label)?;

        let old_value = self
            .entries
            .remove(label)
            .ok_or_else(|| StoreError::LabelNotFound(label.to_string()))?;

        if let Err(error) = self.persist() {
            self.entries.insert(label.to_string(), old_value);
            return Err(error);
        }

        Ok(())
    }

    pub fn list_labels(&self) -> Vec<&str> {
        let mut labels: Vec<&str> =
            self.entries.keys().map(String::as_str).collect();

        labels.sort_unstable();
        labels
    }

    fn persist(&self) -> Result<(), StoreError> {
        let mut content = String::new();

        content.push_str(
            "# Skhoron-Passgen store — labels + Argon2id PHC hashes.\n",
        );
        content.push_str("# НЕ содержит сами пароли, только их хеши.\n");

        let mut labels: Vec<&String> = self.entries.keys().collect();
        labels.sort_unstable();

        for label in labels {
            content.push_str(label);
            content.push(':');
            content.push_str(&self.entries[label]);
            content.push('\n');
        }

        atomic_write(&self.path, content.as_bytes())?;

        Ok(())
    }
}

/// Проверяет label, чтобы он не мог сломать формат store-файла.
fn validate_label(label: &str) -> Result<(), StoreError> {
    if label.is_empty() {
        return Err(StoreError::InvalidLabel(
            "label cannot be empty".to_string(),
        ));
    }

    if label.starts_with('#') {
        return Err(StoreError::InvalidLabel(
            "label cannot start with '#'".to_string(),
        ));
    }

    if label.contains(':') {
        return Err(StoreError::InvalidLabel(
            "label cannot contain ':'".to_string(),
        ));
    }

    if label.contains('\n') || label.contains('\r') {
        return Err(StoreError::InvalidLabel(
            "label cannot contain newline characters".to_string(),
        ));
    }

    Ok(())
}

/// Проверяет значение хеша.
fn validate_hash(hash: &str) -> Result<(), StoreError> {
    if hash.is_empty() {
        return Err(StoreError::InvalidHash);
    }

    if hash.contains('\n') || hash.contains('\r') {
        return Err(StoreError::InvalidHash);
    }

    Ok(())
}

/// Записывает файл через временный файл и rename.
///
/// Это уменьшает риск получить частично записанный store,
/// если процесс будет остановлен во время записи.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("store");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let temp_path = parent.join(format!(
        ".{file_name}.tmp-{}-{timestamp}",
        std::process::id()
    ));

    fs::write(&temp_path, data)?;

    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),

        Err(rename_error) => {
            // На некоторых платформах rename не заменяет
            // существующий файл.
            if path.exists() {
                fs::remove_file(path)?;

                match fs::rename(&temp_path, path) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let _ = fs::remove_file(&temp_path);
                        Err(error)
                    }
                }
            } else {
                let _ = fs::remove_file(&temp_path);
                Err(rename_error)
            }
        }
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

        fs::remove_file(path).ok();

        let mut store = PasswordStore::load_or_create(path).unwrap();

        store
            .add(
                "example.com",
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA",
            )
            .unwrap();

        assert_eq!(
            store.get("example.com").unwrap(),
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaA"
        );

        store.remove("example.com").unwrap();

        assert!(matches!(
            store.get("example.com"),
            Err(StoreError::LabelNotFound(_))
        ));
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

        assert_eq!(
            store2.get("service-a").unwrap(),
            "hash-a-placeholder"
        );
    }

    #[test]
    fn rejects_duplicate_label() {
        let file = NamedTempFile::new().unwrap();

        let mut store =
            PasswordStore::load_or_create(file.path()).unwrap();

        store.add("dup", "hash1").unwrap();

        assert!(matches!(
            store.add("dup", "hash2"),
            Err(StoreError::LabelAlreadyExists(_))
        ));
    }

    #[test]
    fn rejects_invalid_labels() {
        let file = NamedTempFile::new().unwrap();

        let mut store =
            PasswordStore::load_or_create(file.path()).unwrap();

        assert!(matches!(
            store.add("", "hash"),
            Err(StoreError::InvalidLabel(_))
        ));

        assert!(matches!(
            store.add("a:b", "hash"),
            Err(StoreError::InvalidLabel(_))
        ));

        assert!(matches!(
            store.add("a\nb", "hash"),
            Err(StoreError::InvalidLabel(_))
        ));

        assert!(matches!(
            store.add("#comment", "hash"),
            Err(StoreError::InvalidLabel(_))
        ));
    }

    #[test]
    fn rejects_invalid_hash() {
        let file = NamedTempFile::new().unwrap();

        let mut store =
            PasswordStore::load_or_create(file.path()).unwrap();

        assert!(matches!(
            store.add("example", ""),
            Err(StoreError::InvalidHash)
        ));

        assert!(matches!(
            store.add("example", "hash\nbroken"),
            Err(StoreError::InvalidHash)
        ));
    }

    #[test]
    fn rejects_duplicate_labels_in_file() {
        let file = NamedTempFile::new().unwrap();

        fs::write(
            file.path(),
            "example:hash1\nexample:hash2\n",
        )
        .unwrap();

        let result = PasswordStore::load_or_create(file.path());

        assert!(matches!(
            result,
            Err(StoreError::MalformedLine(_))
        ));
    }
}