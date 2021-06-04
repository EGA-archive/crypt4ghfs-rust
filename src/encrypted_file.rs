use crate::error::Crypt4GHFSError;
use crate::error::Result;
use crate::{checksum::Checksum, egafile::EgaFile, utils};
use crate::{checksum::EncryptionType, inbox::InboxMessage};
use chacha20poly1305_ietf::{Key, Nonce};
use crypt4gh::{Keys, SEGMENT_SIZE};
use crypto::digest::Digest;
use crypto::{md5::Md5, sha2::Sha256};
use itertools::Itertools;
use sodiumoxide::{crypto::aead::chacha20poly1305_ietf, randombytes::randombytes};
use std::os::unix::io::AsRawFd;
use std::{collections::HashMap, io::Read};
use std::{
    collections::HashSet,
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::Path,
};

pub struct EncryptedFile {
    opened_files: HashMap<u64, Box<File>>,
    path: Box<Path>,
    session_key: [u8; 32],
    keys: Vec<Keys>,
    recipient_keys: HashSet<Keys>,
    write_buffer: Vec<u8>,
    decrypted_checksum_md5: Md5,
    decrypted_checksum_sha: Sha256,
    encrypted_checksum_md5: Md5,
    encrypted_checksum_sha: Sha256,
    only_read: bool,
}

impl EgaFile for EncryptedFile {
    fn fh(&self) -> Vec<u64> {
        self.opened_files.iter().map(|(&fh, _)| fh).collect()
    }

    fn path(&self) -> Box<std::path::Path> {
        self.path.clone()
    }

    fn open(&mut self, flags: i32) -> Result<i32> {
        let mut path_str = self.path().to_string_lossy().to_string();
		path_str.push_str(".c4gh");
		let path = Path::new(&path_str);
        let file = utils::open(path, flags)?;
        let fh = file.as_raw_fd();
        self.opened_files.insert(fh as u64, Box::new(file));
        Ok(fh)
    }

    fn read(&mut self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>> {
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        f.seek(SeekFrom::Start(0))?;
        let read_size = f.read(&mut [0_u8])?;
        if read_size == 0 {
            log::debug!("Read zero");
            return Ok(Vec::new());
        }
        f.seek(SeekFrom::Start(0))?;
        f.flush()?;
        let mut decrypted_data = Vec::new();

        crypt4gh::decrypt(
            &self.keys,
            f,
            &mut decrypted_data,
            offset as usize,
            Some(size as usize),
            &None,
        )
        .map_err(|e| Crypt4GHFSError::Crypt4GHError(e.to_string()))?;
        log::debug!(
            "Read: {} bytes (offset = {}, limit = {})",
            decrypted_data.len(),
            offset,
            size
        );
        Ok(decrypted_data)
    }

    fn flush(&mut self, fh: u64) -> Result<()> {
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        if !self.write_buffer.is_empty() {
            log::info!("Writing PARTIAL segment");
            let nonce = Nonce::from_slice(&randombytes(12))
                .expect("Unable to create nonce from randombytes");
            let key =
                Key::from_slice(&self.session_key).expect("Unable to create key from session_key");
            let encrypted_segment = crypt4gh::encrypt_segment(&self.write_buffer, nonce, &key);
            f.write_all(&encrypted_segment)?;
            self.write_buffer.clear()
        }
        f.flush()?;
        Ok(())
    }

    fn write(&mut self, fh: u64, data: &[u8]) -> Result<usize> {
        // Update decrypted checksum
        self.decrypted_checksum_md5.input(data);
        self.decrypted_checksum_sha.input(data);

        // Write header
        if self.only_read {
            // Build header
            log::debug!("Writing HEADER");
            let header_bytes =
                crypt4gh::encrypt_header(&self.recipient_keys, &Some(self.session_key))
                    .map_err(|e| Crypt4GHFSError::Crypt4GHError(e.to_string()))?;
            log::debug!("Header size = {}", header_bytes.len());

            // Update encrypted checksum
            self.encrypted_checksum_md5.input(&header_bytes);
            self.encrypted_checksum_sha.input(&header_bytes);

            // Write header
            let f = self
                .opened_files
                .get_mut(&fh)
                .ok_or(Crypt4GHFSError::FileNotOpened)?;
            f.write_all(&header_bytes)?;

            // Update status
            self.only_read = false;
        }

        log::debug!(
            "write_buffer.len() = {}, data.len() = {}",
            self.write_buffer.len(),
            data.len()
        );

        // Chain write buffer with data
        let last_segment = self.write_buffer.clone();
        let write_data = last_segment.into_iter().chain(data.to_vec().into_iter());

        let mut new_last_segment = Vec::new();
        for segment in &write_data.chunks(SEGMENT_SIZE) {
            // Collect segment
            let segment_slice = segment.collect::<Vec<_>>();
            log::debug!("segment_slice.len() = {}", segment_slice.len());

            // This is the last segment, add to the struct
            if segment_slice.len() < SEGMENT_SIZE {
                log::info!("Storing PARTIAL segment");
                new_last_segment = segment_slice;
            } else {
                log::info!("Writing FULL segment");
                // Full segment, write to the file
                let f = self
                    .opened_files
                    .get_mut(&fh)
                    .ok_or(Crypt4GHFSError::FileNotOpened)?;

                // Build encrypted segment
                let nonce = Nonce::from_slice(&randombytes(12))
                    .expect("Unable to create nonce from randombytes");
                let key = Key::from_slice(&self.session_key)
                    .expect("Unable to create key from session_key");
                let encrypted_segment = crypt4gh::encrypt_segment(&segment_slice, nonce, &key);

                // Update encrypted checksums
                self.encrypted_checksum_md5.input(&encrypted_segment);
                self.encrypted_checksum_sha.input(&encrypted_segment);

                // Write segment
                f.write_all(&encrypted_segment)?;
            }
        }

        // Replace segment buffer
        self.write_buffer = new_last_segment;

        // Return
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
        self.write_buffer.clear();
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
        let md5 = self.encrypted_checksum_md5.result_str();
        let sha = self.encrypted_checksum_sha.result_str();
        self.encrypted_checksum_md5.reset();
        self.encrypted_checksum_sha.reset();
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

    fn attrs(&self, uid: u32, gid: u32) -> Result<fuser::FileAttr> {
        let mut path_str = self.path.display().to_string();
        path_str.push_str(".c4gh");
        let stat = utils::lstat(Path::new(&path_str))?;
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

impl EncryptedFile {
    pub fn new(
        file: Option<Box<File>>,
        path: Box<Path>,
        keys: &[Keys],
        recipient_keys: &HashSet<Keys>,
    ) -> Self {
        // Build session_key
        let mut session_key = [0_u8; 32];
        sodiumoxide::randombytes::randombytes_into(&mut session_key);

        // Build open files
        let mut opened_files = HashMap::new();
        if let Some(f) = file {
            opened_files.insert(f.as_raw_fd() as u64, f);
        }

        Self {
            opened_files,
            path,
            session_key,
            keys: keys.to_vec(),
            recipient_keys: recipient_keys.clone(),
            write_buffer: Vec::new(),
            decrypted_checksum_md5: Md5::new(),
            decrypted_checksum_sha: Sha256::new(),
            encrypted_checksum_md5: Md5::new(),
            encrypted_checksum_sha: Sha256::new(),
            only_read: true,
        }
    }
}
