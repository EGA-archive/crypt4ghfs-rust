use crate::{error::Result};
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
}
