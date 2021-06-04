use crate::{checksum::Checksum, error::Result, inbox::InboxMessage};
use fuser::FileAttr;
use std::path::Path;

pub trait EgaFile {
    // Attributes
    fn fh(&self) -> Vec<u64>;
    fn path(&self) -> Box<Path>;

    // Filesystem
    fn open(&mut self, flags: i32) -> Result<i32>;
    fn read(&mut self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>>;
    fn flush(&mut self, fh: u64) -> Result<()>;
    fn write(&mut self, fh: u64, data: &[u8]) -> Result<usize>;
    fn truncate(&mut self, fh: Option<u64>, size: u64) -> Result<()>;
    fn close(&mut self, fh: u64) -> Result<()>;
    fn rename(&mut self, new_path: &Path);
    fn attrs(&self, uid: u32, gid: u32) -> Result<FileAttr>;

    // Checksums
    fn encrypted_checksum(&mut self) -> Option<Vec<Checksum>>;
    fn decrypted_checksum(&mut self) -> Option<Vec<Checksum>>;

    // Messages
    fn upload_message(&mut self, username: &str, fh: u64) -> Result<InboxMessage>;
    fn rename_message(&mut self, username: &str, old_path: &Path) -> InboxMessage;
    fn remove_message(&mut self, username: &str) -> InboxMessage;
    fn needs_upload(&self) -> bool;
}
