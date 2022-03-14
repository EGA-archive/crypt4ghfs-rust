use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::egafile::EgaFile;
use crate::error::{Crypt4GHFSError, Result};
use crate::utils;

pub struct RegularFile {
	pub opened_files: HashMap<u64, Box<File>>,
	pub path: Box<Path>,
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
		let f = self.opened_files.get_mut(&fh).ok_or(Crypt4GHFSError::FileNotOpened)?;
		let mut data = Vec::new();
		f.seek(SeekFrom::Start(offset as u64))?;
		f.as_ref().take(u64::from(size)).read_to_end(&mut data)?;
		Ok(data)
	}

	fn flush(&mut self, fh: u64) -> Result<()> {
		let f = self.opened_files.get_mut(&fh).ok_or(Crypt4GHFSError::FileNotOpened)?;
		f.flush()?;
		Ok(())
	}

	fn write(&mut self, fh: u64, data: &[u8]) -> Result<usize> {
		self.only_read = false;
		let f = self.opened_files.get_mut(&fh).ok_or(Crypt4GHFSError::FileNotOpened)?;

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
		let f = self.opened_files.get(&fh).ok_or(Crypt4GHFSError::FileNotOpened)?;
		assert_eq!(f.as_raw_fd(), fh as i32);
		self.opened_files.remove(&fh);
		self.only_read = true;
		Ok(())
	}

	fn rename(&mut self, new_path: &Path) {
		self.path = new_path.into();
	}

	fn attrs(&self, uid: u32, gid: u32) -> Result<fuser::FileAttr> {
		let stat = utils::lstat(&self.path)?;
		Ok(utils::stat_to_fileatr(stat, uid, gid))
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
			only_read: true,
		}
	}
}
