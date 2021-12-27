use std::collections::HashSet;
use std::fs::{DirEntry, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crypt4gh::Keys;
use fuser::{FileAttr, FileType};
use nix::fcntl::OFlag;
use nix::sys::stat::{FileStat, Mode, SFlag};
use nix::sys::statvfs::Statvfs;

use crate::directory::Directory;
use crate::egafile::EgaFile;
use crate::encrypted_file::EncryptedFile;
use crate::error::Result;
use crate::regular_file::RegularFile;

pub fn lstat(path: &Path) -> Result<FileStat> {
    let stat = nix::sys::stat::lstat(path)?;
    Ok(stat)
}

pub fn stat_to_fileatr(stat: FileStat, uid: u32, gid: u32) -> FileAttr {
    let mut perm = Mode::from_bits_truncate(stat.st_mode);
    perm.set(Mode::S_IRWXG, false);
    perm.set(Mode::S_IRWXO, false);

    let kind = match SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT {
        SFlag::S_IFDIR => FileType::Directory,
        SFlag::S_IFREG => FileType::RegularFile,
        SFlag::S_IFLNK => FileType::Symlink,
        SFlag::S_IFBLK => FileType::BlockDevice,
        SFlag::S_IFCHR => FileType::CharDevice,
        SFlag::S_IFIFO => FileType::NamedPipe,
        SFlag::S_IFSOCK => FileType::Socket,
        _ => panic!("Unknown file type"),
    };

    FileAttr {
        ino: stat.st_ino,
        size: stat.st_size as u64,
        blocks: stat.st_blocks as u64,
        atime: SystemTime::UNIX_EPOCH
            + Duration::from_secs(stat.st_atime as u64)
            + Duration::from_nanos(stat.st_atime_nsec as u64),
        mtime: SystemTime::UNIX_EPOCH
            + Duration::from_secs(stat.st_mtime as u64)
            + Duration::from_nanos(stat.st_mtime_nsec as u64),
        ctime: SystemTime::UNIX_EPOCH
            + Duration::from_secs(stat.st_ctime as u64)
            + Duration::from_nanos(stat.st_ctime_nsec as u64),
        crtime: SystemTime::UNIX_EPOCH, // TODO: Is this one okay?
        kind,
        perm: perm.bits() as u16,
        #[cfg(target_os = "macos")]
        nlink: u32::from(stat.st_nlink),
        #[cfg(target_os = "linux")]
        nlink: stat.st_nlink as u32,
        uid,
        gid,
        rdev: stat.st_rdev as u32,
        blksize: stat.st_blksize as u32,
        flags: 0,
    }
}

pub fn get_type(entry: &DirEntry) -> fuser::FileType {
    let kind = entry.file_type().expect("Unable to get file type");
    if kind.is_file() {
        fuser::FileType::RegularFile
    }
    else if kind.is_dir() {
        fuser::FileType::Directory
    }
    else if kind.is_symlink() {
        fuser::FileType::Symlink
    }
    else {
        panic!("Unknown file type");
    }
}

pub fn open(path: &Path, flags: i32) -> io::Result<File> {
    let open_flags = OFlag::from_bits_truncate(flags);
    OpenOptions::new()
        .custom_flags(flags)
        .read(open_flags.contains(OFlag::O_RDONLY) || open_flags.contains(OFlag::O_RDWR))
        .write(open_flags.contains(OFlag::O_WRONLY) || open_flags.contains(OFlag::O_RDWR))
        .open(path)
}

pub fn create(path: &Path, flags: i32, _mode: u32) -> io::Result<File> {
    let open_flags = OFlag::from_bits_truncate(flags);
    OpenOptions::new()
        .custom_flags(flags)
        //.mode(mode)
        .read(open_flags.contains(OFlag::O_RDONLY) || open_flags.contains(OFlag::O_RDWR))
        .write(open_flags.contains(OFlag::O_WRONLY) || open_flags.contains(OFlag::O_RDWR))
        .open(path)
}

pub fn wrap_file(
    path: &Path,
    file: File,
    keys: &[Keys],
    recipient_keys: &HashSet<Keys>,
) -> Box<dyn EgaFile> {
    wrapper(path.into(), Some(Box::new(file)), keys, recipient_keys)
}

pub fn wrap_path(path: &Path, keys: &[Keys], recipient_keys: &HashSet<Keys>) -> Box<dyn EgaFile> {
    wrapper(path.into(), None, keys, recipient_keys)
}

fn wrapper(
    path: Box<Path>,
    file: Option<Box<File>>,
    keys: &[Keys],
    recipient_keys: &HashSet<Keys>,
) -> Box<dyn EgaFile> {
    match path.extension() {
        Some(ext) if ext != "c4gh" => Box::new(RegularFile::new(file, path)),
        Some(_) => {
            let mut inbox_path = path.to_path_buf();
            let mut filename = inbox_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            filename = filename.strip_suffix(".c4gh").unwrap().to_string();
            inbox_path.set_file_name(filename);
            Box::new(EncryptedFile::new(
                file,
                inbox_path.into_boxed_path(),
                keys,
                recipient_keys,
            ))
        },
        None => {
            if path.is_file() {
                Box::new(EncryptedFile::new(file, path, keys, recipient_keys))
            }
            else if path.is_dir() {
                Box::new(Directory::new(file, path))
            }
            else {
                panic!("Unknown file: {:?}", path)
            }
        },
    }
}

pub fn statfs(path: &Path) -> Result<Statvfs> {
    let statvfs = nix::sys::statvfs::statvfs(path)?;
    Ok(statvfs)
}
