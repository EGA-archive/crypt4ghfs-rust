use crate::error::Crypt4GHFSError;
use crate::error::Result;
use crate::{egafile::EgaFile, utils};
use std::{collections::HashMap, os::unix::io::AsRawFd};
use std::{fs::File, path::Path};

pub struct Directory {
    pub opened_files: HashMap<u64, Box<File>>,
    pub path: Box<Path>,
}

impl EgaFile for Directory {
    fn fh(&self) -> Vec<u64> {
        self.opened_files.iter().map(|(&fh, _)| fh).collect()
    }

    fn path(&self) -> Box<Path> {
        self.path.clone()
    }

    fn open(&mut self, flags: i32) -> Result<i32> {
        let path = self.path();
        let directory = utils::open(&path, flags)?;
        let fh = directory.as_raw_fd();
        self.opened_files.insert(fh as u64, Box::new(directory));
        Ok(fh)
    }

    fn read(&mut self, _fh: u64, _offset: i64, _size: u32) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn flush(&mut self, _fh: u64) -> Result<()> {
        unimplemented!()
    }

    fn write(&mut self, _fh: u64, _data: &[u8]) -> Result<usize> {
        unimplemented!()
    }

    fn truncate(&mut self, _fh: Option<u64>, _size: u64) -> Result<()> {
        unimplemented!()
    }

    fn close(&mut self, fh: u64) -> Result<()> {
        let f = self
            .opened_files
            .get(&fh)
            .ok_or(Crypt4GHFSError::FileNotOpened)?;
        assert_eq!(f.as_raw_fd(), fh as i32);
        self.opened_files.remove(&fh);
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

impl Directory {
    pub fn new(file: Option<Box<File>>, path: Box<Path>) -> Self {
        // Build open files
        let mut opened_files = HashMap::new();
        if let Some(f) = file {
            opened_files.insert(f.as_raw_fd() as u64, f);
        }
        Self { opened_files, path }
    }
}
