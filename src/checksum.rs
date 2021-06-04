use crate::error::Crypt4GHFSError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionType {
    Sha256,
    Md5,
    String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Checksum {
    #[serde(rename = "type")]
    pub encryption_type: EncryptionType,
    pub value: String,
}

pub fn validate(checksums: &Option<Vec<Checksum>>) -> Result<(), Crypt4GHFSError> {
    match checksums {
        Some(checksum) => checksum.iter().try_for_each(|c| {
            let ok = match c.encryption_type {
                EncryptionType::Sha256 => {
                    c.value.len() == 64 && c.value.chars().all(|digit| digit.is_ascii_hexdigit())
                }
                EncryptionType::Md5 => {
                    c.value.len() == 32 && c.value.chars().all(|digit| digit.is_ascii_hexdigit())
                }
                EncryptionType::String => unimplemented!(),
            };

            if ok {
                Ok(())
            } else {
                Err(Crypt4GHFSError::InvalidChecksumFormat)
            }
        }),
        None => Err(Crypt4GHFSError::NoChecksum),
    }
}
