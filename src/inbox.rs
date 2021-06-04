use std::{
    fmt::Display,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use super::checksum::{self, Checksum};
use serde::{Deserialize, Serialize};

pub trait Validate {
    fn is_valid(&self) -> bool;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum InboxMessageType {
    Upload,
    Rename,
    Remove,
}

impl Display for InboxMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upload => f.write_str("upload"),
            Self::Rename => f.write_str("rename"),
            Self::Remove => f.write_str("remove"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InboxMessage {
    // Common
    pub user: String,
    pub filepath: String,
    pub operation: InboxMessageType,

    // Upload
    pub filesize: Option<u64>,
    pub file_last_modified: Option<u64>,
    pub decrypted_checksums: Option<Vec<Checksum>>,
    pub encrypted_checksums: Option<Vec<Checksum>>,
    pub inbox_encryption: Option<bool>,

    // Rename
    pub oldpath: Option<String>,
}

impl InboxMessage {
    pub fn new_upload(
        user: String,
        filepath: &Path,
        filesize: u64,
        inbox_encryption: bool,
        file_last_modified: SystemTime,
        decrypted_checksums: Option<Vec<Checksum>>,
        encrypted_checksums: Option<Vec<Checksum>>,
    ) -> Self {
        let file_last_modified = match file_last_modified.duration_since(UNIX_EPOCH) {
            Ok(mtime_since_epoch) => Some(mtime_since_epoch.as_secs()),
            Err(_) => None,
        };
        Self {
            user,
            filepath: filepath.display().to_string(),
            operation: InboxMessageType::Upload,
            filesize: Some(filesize),
            inbox_encryption: Some(inbox_encryption),
            file_last_modified,
            decrypted_checksums,
            encrypted_checksums,
            oldpath: None,
        }
    }

    pub fn new_rename(user: String, filepath: &Path, oldpath: &Path) -> Self {
        Self {
            user,
            filepath: filepath.display().to_string(),
            operation: InboxMessageType::Rename,
            filesize: None,
            inbox_encryption: None,
            file_last_modified: None,
            decrypted_checksums: None,
            encrypted_checksums: None,
            oldpath: Some(oldpath.display().to_string()),
        }
    }

    pub fn new_remove(user: String, filepath: &Path) -> Self {
        Self {
            user,
            filepath: filepath.display().to_string(),
            operation: InboxMessageType::Remove,
            filesize: None,
            inbox_encryption: None,
            file_last_modified: None,
            decrypted_checksums: None,
            encrypted_checksums: None,
            oldpath: None,
        }
    }
}

impl Validate for InboxMessage {
    fn is_valid(&self) -> bool {
        match self.operation {
            InboxMessageType::Upload => {
                !self.user.is_empty()
                    && !self.filepath.is_empty()
                    && self.filesize.is_some()
                    && self.file_last_modified.is_some()
                    && self.encrypted_checksums.is_some()
                    && checksum::validate(&self.encrypted_checksums).is_ok()
            }
            InboxMessageType::Rename => {
                !self.user.is_empty() && !self.filepath.is_empty() && self.oldpath.is_some()
            }
            InboxMessageType::Remove => !self.user.is_empty() && !self.filepath.is_empty(),
        }
    }
}
