use crate::{
    checksum::Checksum,
    egafile::EgaFile,
    error::{Crypt4GHFSError, Result},
    utils,
};
use crate::{checksum::EncryptionType, inbox::InboxMessage};
use crypto::{digest::Digest, md5::Md5, sha2::Sha256};
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::{collections::HashMap, io::Seek};
use std::{fs::File, io::Read, path::Path};

pub struct RegularFile {
    pub opened_files: HashMap<u64, Box<File>>,
    pub path: Box<Path>,
    pub decrypted_checksum_md5: Md5,
    pub decrypted_checksum_sha: Sha256,
    pub only_read: bool,
}

impl EgaFile for RegularFile {
    fn fh(&self) -> Vec<u64> {
        self.opened_files.iter().map(|(&fh, _)| fh).collect()
    }

    fn path(&self) -> Box<Path> {
        self.path.clone()
    }

    fn open(&mut self, flags: i32) -> Result<i32> {
        let path = self.path();
        let file = utils::open(&path, flags)?;
        let fh = file.as_raw_fd();
        self.opened_files.insert(fh as u64, Box::new(file));
        Ok(fh)
    }

    fn read(&mut self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>> {
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        let mut data = Vec::new();
        f.seek(SeekFrom::Start(offset as u64))?;
        f.as_ref().take(u64::from(size)).read_to_end(&mut data)?;
        Ok(data)
    }

    fn flush(&mut self, fh: u64) -> Result<()> {
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        f.flush()?;
        Ok(())
    }

    fn write(&mut self, fh: u64, data: &[u8]) -> Result<usize> {
        self.only_read = false;
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;

        // Update checksums
        self.decrypted_checksum_md5.input(data);
        self.decrypted_checksum_sha.input(data);

        // Write data
        f.write_all(data)?;
        Ok(data.len())
    }

    fn truncate(&mut self, fh: Option<u64>, size: u64) -> Result<()> {
        log::debug!("Truncate: size = {}", size);
        self.opened_files
            .iter_mut()
            .filter(|(&ffh, _)| fh.is_none() || fh == Some(ffh))
            .try_for_each(|(_, f)| f.set_len(size))?;
        Ok(())
    }

    fn close(&mut self, fh: u64) -> Result<()> {
        let f = self
            .opened_files
            .get(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        assert_eq!(f.as_raw_fd(), fh as i32);
        self.opened_files.remove(&fh);
        self.only_read = true;
        Ok(())
    }

    fn rename(&mut self, new_path: &Path) {
        self.path = new_path.into();
    }

    fn encrypted_checksum(&mut self) -> Option<Vec<Checksum>> {
        let md5 = self.decrypted_checksum_md5.result_str();
        let sha = self.decrypted_checksum_sha.result_str();
        self.decrypted_checksum_md5.reset();
        self.decrypted_checksum_sha.reset();
        Some(vec![
            Checksum {
                encryption_type: EncryptionType::Md5,
                value: md5,
            },
            Checksum {
                encryption_type: EncryptionType::Sha256,
                value: sha,
            },
        ])
    }

    fn decrypted_checksum(&mut self) -> Option<Vec<Checksum>> {
        None
    }

    fn attrs(&self, uid: u32, gid: u32) -> Result<fuser::FileAttr> {
        let stat = utils::lstat(&self.path)?;
        Ok(utils::stat_to_fileatr(stat, uid, gid))
    }

    fn upload_message(&mut self, username: &str, fh: u64) -> Result<InboxMessage> {
        let metadata = self
            .opened_files
            .get(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?
            .metadata()?;
        let filesize = metadata.len();
        let file_last_modified = metadata.modified()?;
        Ok(InboxMessage::new_upload(
            username.into(),
            &self.path(),
            filesize,
            false,
            file_last_modified,
            self.decrypted_checksum(),
            self.encrypted_checksum(),
        ))
    }

    fn rename_message(&mut self, username: &str, old_path: &Path) -> InboxMessage {
        InboxMessage::new_rename(username.into(), &self.path(), old_path)
    }

    fn remove_message(&mut self, username: &str) -> InboxMessage {
        InboxMessage::new_remove(username.into(), &self.path())
    }

    fn needs_upload(&self) -> bool {
        !self.only_read
    }
}

impl RegularFile {
    pub fn new(file: Option<Box<File>>, path: Box<Path>) -> Self {
        // Build open files
        let mut opened_files = HashMap::new();
        if let Some(f) = file {
            opened_files.insert(f.as_raw_fd() as u64, f);
        }

        // Build RegularFile object
        Self {
            opened_files,
            path,
            decrypted_checksum_md5: Md5::new(),
            decrypted_checksum_sha: Sha256::new(),
            only_read: true,
        }
    }
}
