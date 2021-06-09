use crate::egafile::EgaFile;
use crate::error::{Crypt4GHFSError, Result};
use crate::utils;
use chacha20poly1305_ietf::{Key, Nonce};
use crypt4gh::header::DecryptedHeaderPackets;
use crypt4gh::{Keys, SEGMENT_SIZE};
use itertools::Itertools;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::randombytes::randombytes;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const CIPHER_SEGMENT_SIZE: usize = SEGMENT_SIZE + 28;

pub struct EncryptedFile {
    opened_files: HashMap<u64, Box<File>>,
    path: Box<Path>,
    session_key: [u8; 32],
    keys: Vec<Keys>,
    recipient_keys: HashSet<Keys>,
    write_buffer: Vec<u8>,
    only_read: bool,

    // Optimization
    buffer: HashMap<u64, EncryptionBuffer>,
    session_keys: Vec<Vec<u8>>,
    header_len: u64,
}

#[derive(Debug, Default)]
struct EncryptionBuffer {
    data: Vec<u8>,
    pos: usize,
    valid: bool,
}

impl EgaFile for EncryptedFile {
    fn fh(&self) -> Vec<u64> {
        self.opened_files.iter().map(|(&fh, _)| fh).collect()
    }

    fn path(&self) -> Box<std::path::Path> {
        self.path.clone()
    }

    fn open(&mut self, flags: i32) -> Result<i32> {
        // Get path
        let mut path_str = self.path().to_string_lossy().to_string();
        path_str.push_str(".c4gh");
        let path = Path::new(&path_str);

        // Open file
        let mut file = utils::open(path, flags)?;
        let fh = file.as_raw_fd();

        // Buffer
        self.buffer.insert(fh as u64, EncryptionBuffer::default());
        let (keys, header_length) = self.read_header(&mut file).unwrap();
        self.session_keys = keys;
        self.header_len = u64::from(header_length);

        // Add to opened files
        self.opened_files.insert(fh as u64, Box::new(file));

        // Return
        Ok(fh)
    }

    fn read(&mut self, fh: u64, offset: i64, size: u32) -> Result<Vec<u8>> {
        let f = self
            .opened_files
            .get_mut(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;

        let first_segment = offset as usize / SEGMENT_SIZE;
        let mut off = offset as usize % SEGMENT_SIZE;

        let length = off + size as usize;
        let mut nsegments = length / SEGMENT_SIZE;
        if length % SEGMENT_SIZE != 0 {
            nsegments += 1;
        }

        let start_pos = first_segment * SEGMENT_SIZE;

        log::debug!("first_segment: {}", first_segment);
        log::debug!("off: {}", off);
        log::debug!("length: {}", length);
        log::debug!("length % SEGMENT_SIZE != 0: {}", length % SEGMENT_SIZE != 0);
        log::debug!("nsegments: {}", nsegments);
        log::debug!("start_pos: {}", start_pos);

        let buf = self.buffer.get(&fh).expect("No buffer");

        if buf.valid && buf.pos <= start_pos && ((start_pos - buf.pos) + length) <= buf.data.len() {
            log::debug!("Already have decrypted enough data");
            off += start_pos - buf.pos;

            Ok(buf.data[off..off + size as usize].into())
        } else {
            f.seek(SeekFrom::Start(
                self.header_len + first_segment as u64 * CIPHER_SEGMENT_SIZE as u64,
            ))
            .unwrap();

            let mut output = Vec::new();

            for _ in 0..nsegments {
                let mut chunk = Vec::with_capacity(CIPHER_SEGMENT_SIZE);
                let n = f
                    .take(CIPHER_SEGMENT_SIZE as u64)
                    .read_to_end(&mut chunk)
                    .unwrap();

                if n == 0 {
                    break;
                }

                let segment = Self::decrypt_block(&chunk, &self.session_keys);
                output.extend_from_slice(&segment);

                if n < CIPHER_SEGMENT_SIZE {
                    break;
                }
            }

            log::debug!("Output: {}", output.len());

            Ok(output[off..(off + size as usize).min(output.len())].into())
        }
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
        // Write header
        if self.only_read {
            // Build header
            log::debug!("Writing HEADER");
            let header_bytes =
                crypt4gh::encrypt_header(&self.recipient_keys, &Some(self.session_key))
                    .map_err(|e| Crypt4GHFSError::Crypt4GHError(e.to_string()))?;
            log::debug!("Header size = {}", header_bytes.len());

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

    fn attrs(&self, uid: u32, gid: u32) -> Result<fuser::FileAttr> {
        let mut path_str = self.path.display().to_string();
        path_str.push_str(".c4gh");
        let stat = utils::lstat(Path::new(&path_str))?;
        Ok(utils::stat_to_fileatr(stat, uid, gid))
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
            only_read: true,
            buffer: HashMap::new(),
            session_keys: Vec::new(),
            header_len: 0,
        }
    }

    fn read_header(&self, file: &mut File) -> Result<(Vec<Vec<u8>>, u32)> {
        // Get header info
        let mut header_length = 16;
        let mut temp_buf = [0_u8; 16]; // Size of the header
        file.read_exact(&mut temp_buf)?;

        let header_info = crypt4gh::header::deconstruct_header_info(&temp_buf).unwrap();

        // Calculate header packets
        let encrypted_packets = (0..header_info.packets_count)
            .map(|_| {
                // Get length
                let mut length_buffer = [0_u8; 4];
                file.read_exact(&mut length_buffer).unwrap();
                let length = u32::from_le_bytes(length_buffer);
                header_length += length;
                let length = length - 4;
                log::debug!("Packet length: {}", length);

                // Get data
                let mut encrypted_data = vec![0_u8; length as usize];
                file.read_exact(&mut encrypted_data).unwrap();
                Ok(encrypted_data)
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let DecryptedHeaderPackets {
            data_enc_packets: session_keys,
            edit_list_packet: edit_list_content,
        } = crypt4gh::header::deconstruct_header_body(encrypted_packets, &self.keys, &None)
            .unwrap();

        assert!(edit_list_content.is_none());

        Ok((session_keys, header_length))
    }

    fn decrypt_block(ciphersegment: &[u8], session_keys: &[Vec<u8>]) -> Vec<u8> {
        let (nonce_slice, data) = ciphersegment.split_at(12);
        let nonce = chacha20poly1305_ietf::Nonce::from_slice(nonce_slice).unwrap();

        log::debug!("Nonce slice: {:02x?}", nonce_slice.iter().format(""));
        log::debug!("Data len = {}", data.len());
        for key in session_keys {
            log::debug!("Session keys: {:02x?}", key.iter().format(""));
        }

        session_keys
            .iter()
            .find_map(|key| {
                chacha20poly1305_ietf::Key::from_slice(key)
                    .and_then(|key| chacha20poly1305_ietf::open(data, None, &nonce, &key).ok())
            })
            .unwrap()
    }
}
