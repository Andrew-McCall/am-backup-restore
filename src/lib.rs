use crypt_guard::error::CryptError;
use crypt_guard::{DecryptBuilder, EncryptBuilder, KyberKeygenBuilder, SymmetricAlg};
use std::path::Path;
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// Magic bytes identifying an am-backup payload file: "AMBK"
const FORMAT_MAGIC: &[u8] = b"AMBK";
const VERSION: u8 = 0;

// ── Binary parsing helpers ────────────────────────────────────────────────────

fn read_u32(buf: &[u8], pos: &mut usize) -> u32 {
    let v = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    v
}

fn read_u64(buf: &[u8], pos: &mut usize) -> u64 {
    let v = u64::from_le_bytes(buf[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    v
}

fn read_slice<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> &'a [u8] {
    let s = &buf[*pos..*pos + len];
    *pos += len;
    s
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("failed to read source file: {0}")]
    ReadSource(std::io::Error),

    #[error("failed to write output file: {0}")]
    WriteOutput(#[from] std::io::Error),

    #[error("encryption failed: {0}")]
    Encrypt(#[from] CryptError),
}

#[derive(Debug, Error)]
pub enum RestoreError {
    #[error("failed to read backup file: {0}")]
    ReadBackup(#[from] std::io::Error),

    #[error("not an am-backup file (bad magic bytes)")]
    BadMagic,

    #[error("corrupt backup file (invalid UTF-8): {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("decryption failed: {0}")]
    Decrypt(#[from] CryptError),
}

// ── EncryptionConfig ──────────────────────────────────────────────────────────

/// Holds the passphrase and salt used for backup and restore operations.
///
/// Create with [`EncryptionConfig::new`] (salt auto-generated) or
/// [`EncryptionConfig::with_salt`] when a specific salt is required.
pub struct EncryptionConfig {
    pub(crate) passphrase: String,
    /// Metadata salt written into the backup header.
    /// For restore operations the salt is read from the file; this field is ignored.
    pub salt: String,
}

impl EncryptionConfig {
    /// Creates a config with an auto-generated salt derived from the current time.
    pub fn new(passphrase: impl Into<String>) -> Self {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            passphrase: passphrase.into(),
            salt: format!("{}.{:09}", d.as_secs(), d.subsec_nanos()),
        }
    }

    /// Creates a config with an explicit salt.
    pub fn with_salt(passphrase: impl Into<String>, salt: impl Into<String>) -> Self {
        Self {
            passphrase: passphrase.into(),
            salt: salt.into(),
        }
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct EncryptionResult {
    /// Paths that were successfully encrypted into the backup.
    pub success: Vec<String>,
    /// Paths that could not be read, with a reason.
    pub skipped: Vec<(String, BackupError)>,
}

#[derive(Debug, Default)]
pub struct DecryptionResult {
    /// Paths that were successfully restored.
    pub success: Vec<String>,
    /// Paths that could not be written, with a reason.
    pub skipped: Vec<(String, RestoreError)>,
}

// ── restore_payload ───────────────────────────────────────────────────────────

/// Reads an am-backup payload file, decrypts it, and restores each file to its
/// original path (creating parent directories as needed).
///
/// The Kyber secret key and salt are both read from the backup file itself;
/// only the passphrase is required.
pub async fn restore_payload(
    backup: &Path,
    config: &EncryptionConfig,
) -> Result<DecryptionResult, RestoreError> {
    let mut result = DecryptionResult::default();

    let raw = tokio::fs::read(backup).await?;
    let mut pos = 0;

    // Verify magic and version.
    if raw.get(..4) != Some(FORMAT_MAGIC) {
        return Err(RestoreError::BadMagic);
    }
    pos += 4;
    let _version = raw[pos];
    pos += 1;

    // Salt (metadata only).
    let salt_len = read_u32(&raw, &mut pos) as usize;
    read_slice(&raw, &mut pos, salt_len); // skip

    // Kyber secret key (stored in the header so only the passphrase is needed).
    let sk_len = read_u32(&raw, &mut pos) as usize;
    let secret_key = read_slice(&raw, &mut pos, sk_len).to_vec();

    // Kyber cipher (encapsulated key).
    let cipher_len = read_u32(&raw, &mut pos) as usize;
    let cipher = read_slice(&raw, &mut pos, cipher_len).to_vec();

    // XChaCha20-Poly1305 nonce.
    let nonce_len = read_u32(&raw, &mut pos) as usize;
    let nonce = std::str::from_utf8(read_slice(&raw, &mut pos, nonce_len))?.to_owned();

    // Encrypted blob is everything that remains.
    let encrypted = raw[pos..].to_vec();

    // Decrypt with Kyber1024 + XChaCha20-Poly1305.
    let plaintext = DecryptBuilder::new()
        .key(secret_key)
        .key_size(1024)
        .data(encrypted)
        .passphrase(&config.passphrase)
        .cipher(cipher)
        .nonce(nonce)
        .algorithm(SymmetricAlg::XChaCha20Poly1305)
        .run()?;

    // Parse length-prefixed entries and write files.
    let mut pos = 0;
    while pos < plaintext.len() {
        let name_len = read_u32(&plaintext, &mut pos) as usize;
        let name = std::str::from_utf8(read_slice(&plaintext, &mut pos, name_len))?.to_owned();

        let data_len = read_u64(&plaintext, &mut pos) as usize;
        let data = read_slice(&plaintext, &mut pos, data_len);

        let path = std::path::PathBuf::from(&name);
        if let Some(parent) = path.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            result.skipped.push((name, RestoreError::ReadBackup(e)));
            continue;
        }

        match tokio::fs::write(&path, data).await {
            Ok(()) => result.success.push(name),
            Err(e) => result.skipped.push((name, RestoreError::ReadBackup(e))),
        }
    }

    Ok(result)
}

// ── backup_payload ────────────────────────────────────────────────────────────

/// Backs up `targets` into a single encrypted file at `output`.
///
/// A Kyber1024 keypair is generated for each backup run. The secret key is
/// stored in the plaintext header so that `restore_payload` only needs the
/// passphrase — no separate key management required.
///
/// # File format
/// ```text
/// [AMBK 4B][version 1B]                   plaintext header
/// [salt_len: u32 LE][salt: utf-8]          metadata stored in the clear
/// [sk_len: u32 LE][sk: bytes]              Kyber secret key (enables passphrase-only restore)
/// [cipher_len: u32 LE][cipher: bytes]      Kyber-encapsulated session key
/// [nonce_len: u32 LE][nonce: utf-8]        XChaCha20-Poly1305 nonce
/// [encrypted blob]                         authenticated ciphertext
/// ```
///
/// The decrypted blob contains, for each file:
/// ```text
/// [name_len: u32 LE][name: utf-8]
/// [data_len: u64 LE][data: bytes]
/// ```
pub async fn backup_payload(
    targets: &[&Path],
    config: &EncryptionConfig,
    output: &Path,
) -> Result<EncryptionResult, BackupError> {
    let mut result = EncryptionResult::default();

    // Generate an ephemeral Kyber1024 keypair for this backup run.
    let (public_key, secret_key) = KyberKeygenBuilder::new().size(1024).generate()?;

    // Serialize all target files into a plaintext blob with length-prefixed fields.
    let mut payload: Vec<u8> = Vec::new();
    for &target in targets {
        let name = target.to_string_lossy().into_owned();
        match tokio::fs::read(target).await {
            Ok(data) => {
                let name_bytes = name.as_bytes();
                payload.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(name_bytes);
                payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
                payload.extend_from_slice(&data);
                result.success.push(name);
            }
            Err(e) => {
                result.skipped.push((name, BackupError::ReadSource(e)));
            }
        }
    }

    // Encrypt with Kyber1024 + XChaCha20-Poly1305 (authenticated).
    // crypt_guard is synchronous; for large payloads consider spawn_blocking.
    let enc = EncryptBuilder::new()
        .key(public_key)
        .key_size(1024)
        .data(payload)
        .passphrase(&config.passphrase)
        .algorithm(SymmetricAlg::XChaCha20Poly1305)
        .run()?;

    let nonce = enc.nonce.unwrap_or_default();

    // Write output file.
    let mut file = tokio::fs::File::create(output).await?;

    // Plaintext header.
    file.write_all(FORMAT_MAGIC).await?;
    file.write_all(&[VERSION]).await?;

    // Salt (length-prefixed).
    let salt_bytes = config.salt.as_bytes();
    file.write_all(&(salt_bytes.len() as u32).to_le_bytes())
        .await?;
    file.write_all(salt_bytes).await?;

    // Kyber secret key (length-prefixed) — stored so restore only needs passphrase.
    file.write_all(&(secret_key.len() as u32).to_le_bytes())
        .await?;
    file.write_all(&secret_key).await?;

    // Kyber cipher (length-prefixed) — required for decryption.
    file.write_all(&(enc.cipher.len() as u32).to_le_bytes())
        .await?;
    file.write_all(&enc.cipher).await?;

    // XChaCha20 nonce (length-prefixed) — required for decryption.
    let nonce_bytes = nonce.as_bytes();
    file.write_all(&(nonce_bytes.len() as u32).to_le_bytes())
        .await?;
    file.write_all(nonce_bytes).await?;

    // Encrypted blob.
    file.write_all(&enc.content).await?;

    Ok(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Returns a path under the system temp dir, unique per label + PID.
    fn tmp(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ambk-{label}-{}", std::process::id()))
    }

    // ── roundtrip: single text file ───────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_single_file() {
        let dir = tmp("single");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("hello.txt");
        tokio::fs::write(&src, b"hello, world!").await.unwrap();

        let backup = tmp("single.ambk");
        let enc = backup_payload(
            &[src.as_path()],
            &EncryptionConfig::with_salt("passphrase", "salt"),
            &backup,
        )
        .await
        .unwrap();

        assert!(
            enc.skipped.is_empty(),
            "unexpected skips: {:?}",
            enc.skipped
        );
        assert_eq!(enc.success.len(), 1);

        // Remove source so restore has real work to do.
        tokio::fs::remove_file(&src).await.unwrap();

        let dec = restore_payload(&backup, &EncryptionConfig::new("passphrase"))
            .await
            .unwrap();
        assert!(dec.skipped.is_empty(), "restore skips: {:?}", dec.skipped);
        assert_eq!(dec.success.len(), 1);

        assert_eq!(tokio::fs::read(&src).await.unwrap(), b"hello, world!");

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        tokio::fs::remove_file(&backup).await.unwrap();
    }

    // ── roundtrip: multiple files ─────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_multiple_files() {
        let dir = tmp("multi");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let files: Vec<(PathBuf, &[u8])> = vec![
            (dir.join("a.txt"), b"file A"),
            (dir.join("b.txt"), b"file B"),
            (dir.join("c.txt"), b"file C"),
        ];
        for (path, content) in &files {
            tokio::fs::write(path, content).await.unwrap();
        }

        let targets: Vec<&Path> = files.iter().map(|(p, _)| p.as_path()).collect();
        let backup = tmp("multi.ambk");
        let enc = backup_payload(
            &targets,
            &EncryptionConfig::with_salt("passphrase", "salt"),
            &backup,
        )
        .await
        .unwrap();

        assert!(enc.skipped.is_empty());
        assert_eq!(enc.success.len(), 3);

        for (path, _) in &files {
            tokio::fs::remove_file(path).await.unwrap();
        }

        let dec = restore_payload(&backup, &EncryptionConfig::new("passphrase"))
            .await
            .unwrap();
        assert!(dec.skipped.is_empty(), "restore skips: {:?}", dec.skipped);
        assert_eq!(dec.success.len(), 3);

        for (path, expected) in &files {
            let actual = tokio::fs::read(path).await.unwrap();
            assert_eq!(&actual, expected, "content mismatch: {}", path.display());
        }

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        tokio::fs::remove_file(&backup).await.unwrap();
    }

    // ── roundtrip: binary data (all 256 byte values) ──────────────────────────

    #[tokio::test]
    async fn roundtrip_binary_data() {
        let dir = tmp("binary");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let binary: Vec<u8> = (0u8..=255).collect();
        let src = dir.join("binary.bin");
        tokio::fs::write(&src, &binary).await.unwrap();

        let backup = tmp("binary.ambk");
        backup_payload(
            &[src.as_path()],
            &EncryptionConfig::with_salt("pass", "salt"),
            &backup,
        )
        .await
        .unwrap();

        tokio::fs::remove_file(&src).await.unwrap();
        restore_payload(&backup, &EncryptionConfig::new("pass"))
            .await
            .unwrap();

        assert_eq!(tokio::fs::read(&src).await.unwrap(), binary);

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        tokio::fs::remove_file(&backup).await.unwrap();
    }

    // ── roundtrip: empty file ─────────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_empty_file() {
        let dir = tmp("empty");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let src = dir.join("empty.txt");
        tokio::fs::write(&src, b"").await.unwrap();

        let backup = tmp("empty.ambk");
        backup_payload(
            &[src.as_path()],
            &EncryptionConfig::with_salt("pass", "salt"),
            &backup,
        )
        .await
        .unwrap();

        tokio::fs::remove_file(&src).await.unwrap();
        restore_payload(&backup, &EncryptionConfig::new("pass"))
            .await
            .unwrap();

        assert!(tokio::fs::read(&src).await.unwrap().is_empty());

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        tokio::fs::remove_file(&backup).await.unwrap();
    }

    // ── unreadable source is skipped, not fatal ───────────────────────────────

    #[tokio::test]
    async fn backup_missing_file_skipped_not_fatal() {
        let dir = tmp("missing");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let exists = dir.join("exists.txt");
        let missing = dir.join("does_not_exist.txt");
        tokio::fs::write(&exists, b"I exist").await.unwrap();

        let backup = tmp("missing.ambk");
        let result = backup_payload(
            &[exists.as_path(), missing.as_path()],
            &EncryptionConfig::with_salt("pass", "salt"),
            &backup,
        )
        .await
        .unwrap();

        assert_eq!(result.success.len(), 1);
        assert_eq!(result.skipped.len(), 1);
        assert!(
            result.skipped[0].0.contains("does_not_exist"),
            "unexpected skip entry: {}",
            result.skipped[0].0,
        );

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        let _ = tokio::fs::remove_file(&backup).await;
    }

    // ── output file has correct magic bytes, version, and plaintext salt ──────

    #[tokio::test]
    async fn output_file_has_correct_header() {
        let dir = tmp("header");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let src = dir.join("f.txt");
        tokio::fs::write(&src, b"data").await.unwrap();

        let backup = tmp("header.ambk");
        backup_payload(
            &[src.as_path()],
            &EncryptionConfig::with_salt("pass", "my-salt"),
            &backup,
        )
        .await
        .unwrap();

        let raw = tokio::fs::read(&backup).await.unwrap();
        assert_eq!(&raw[..4], b"AMBK", "magic bytes missing");
        assert_eq!(raw[4], 0, "unexpected version byte");

        // Layout after magic+version: [4B salt_len][salt...]
        let salt_len = u32::from_le_bytes(raw[5..9].try_into().unwrap()) as usize;
        let salt_bytes = &raw[9..9 + salt_len];
        assert_eq!(
            salt_bytes, b"my-salt",
            "salt not stored in plaintext header"
        );

        tokio::fs::remove_dir_all(&dir).await.unwrap();
        tokio::fs::remove_file(&backup).await.unwrap();
    }

    // ── non-backup file returns BadMagic, not a panic ─────────────────────────

    #[tokio::test]
    async fn restore_wrong_magic_returns_error() {
        let garbage = tmp("garbage.ambk");
        tokio::fs::write(&garbage, b"this is not a backup file")
            .await
            .unwrap();

        let err = restore_payload(&garbage, &EncryptionConfig::new("pass"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, RestoreError::BadMagic),
            "expected BadMagic, got: {err}",
        );

        tokio::fs::remove_file(&garbage).await.unwrap();
    }
}
