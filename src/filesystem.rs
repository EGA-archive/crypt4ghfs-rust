use crate::utils;
use crate::{file_admin::FileAdmin};
use crypt4gh::Keys;
use fuser::{
	Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
	ReplyWrite, Request, TimeOrNow,
};
use nix::{
	errno::Errno,
	unistd::{Gid, Uid},
};
use std::collections::HashMap;
use std::fs::{DirEntry};
use std::{collections::HashSet, ffi::OsStr, time::Duration};
use std::{os::unix::fs::DirEntryExt, time::SystemTime};
// use std::os::linux::fs::MetadataExt;

const TTL: Duration = Duration::from_secs(300);

pub struct Crypt4ghFS {
	file_admin: FileAdmin,
	keys: Vec<Keys>,
	recipients: HashSet<Keys>,
	uid: Uid,
	gid: Gid,
	entries: HashMap<u64, Vec<Result<DirEntry, std::io::Error>>>,
	duration1: std::time::Duration,
	// TODO: implement cache directories functionality
}

impl Crypt4ghFS {
	pub fn new(
		rootdir: &str,
		seckey: Vec<u8>,
		recipients: HashSet<Keys>,
		uid: Uid,
		gid: Gid,
	) -> Self {
		Self {
			file_admin: FileAdmin::new(rootdir),
			keys: vec![Keys {
				method: 0,
				privkey: seckey,
				recipient_pubkey: vec![],
			}],
			recipients,
			uid,
			gid,
			entries: HashMap::new(),
			duration1: Duration::from_secs(0),
		}
	}
}

impl Filesystem for Crypt4ghFS {
	// FILESYSTEM

	fn destroy(&mut self, _req: &Request<'_>) {
		log::info!("1 - Elapsed: {:?}", self.duration1);
	}

	fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
		let file = self.file_admin.get_file(ino);
		match file.attrs(self.uid.as_raw(), self.gid.as_raw()) {
			Ok(attrs) => reply.attr(&TTL, &attrs),
			Err(_) => reply.error(1000),
		}
	}

	fn setattr(
		&mut self,
		req: &Request<'_>,
		ino: u64,
		mode: Option<u32>,
		uid: Option<u32>,
		gid: Option<u32>,
		size: Option<u64>,
		atime: Option<TimeOrNow>,
		mtime: Option<TimeOrNow>,
		_ctime: Option<SystemTime>,
		fh: Option<u64>,
		crtime: Option<SystemTime>,
		chgtime: Option<SystemTime>,
		bkuptime: Option<SystemTime>,
		flags: Option<u32>,
		reply: ReplyAttr,
	) {
		let mut err = None;

		if mode.is_some() {
			reply.error(Errno::EPERM as i32);
			return;
		}

		if uid.is_some() || gid.is_some() {
			reply.error(Errno::EPERM as i32);
			return;
		}

		if atime.is_some() || mtime.is_some() {
			reply.error(Errno::EOPNOTSUPP as i32);
			return;
		}

		if crtime.is_some() || chgtime.is_some() || bkuptime.is_some() || flags.is_some() {
			reply.error(Errno::EOPNOTSUPP as i32);
			return;
		}

		let file = self.file_admin.get_file_mut(ino);

		if let Some(size) = size {
			if let Err(e) = file.truncate(fh, size) {
				err = Some(e)
			}
		}

		match err {
			None => match file.attrs(req.uid(), req.gid()) {
				Ok(attrs) => reply.attr(&TTL, &attrs),
				Err(e) => reply.error(e.to_raw_os_error()),
			},
			Some(e) => reply.error(e.to_raw_os_error()),
		}
	}

	fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
		
		let parent_file = self.file_admin.get_file(parent);
		
		let name_string = name.to_string_lossy().to_string();
		let new_name = name_string.strip_suffix(".c4gh").unwrap_or(&name_string);
		let path = parent_file.path().join(new_name);
		
		match self.file_admin.get_by_path(path.as_path()) {
			Some(child_file) => {
				match child_file.attrs(req.uid(), req.gid()) {
					Ok(attr) => {
						reply.entry(&TTL, &attr, 0)
					},
					Err(e) => reply.error(e.to_raw_os_error()),
				}
			},
			None => {
				reply.error(Errno::ENOENT as i32);
			},
		}
	}

	fn statfs(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyStatfs) {
		let file = self.file_admin.get_file(ino);
		match utils::statfs(&file.path()) {
			Ok(statfs) => reply.statfs(
				u64::from(statfs.blocks()),
				u64::from(statfs.blocks_free()),
				u64::from(statfs.blocks_available()),
				u64::from(statfs.files()),
				u64::from(statfs.files_free()),
				statfs.block_size() as u32,
				statfs.name_max() as u32,
				statfs.fragment_size() as u32,
			),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}

	// FILE

	fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
		let file = self.file_admin.get_file_mut(ino);
		match file.open(flags) {
			Ok(fh) => reply.opened(fh as u64, flags as u32),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}

	fn read(
		&mut self,
		_req: &Request<'_>,
		ino: u64,
		fh: u64,
		offset: i64,
		size: u32,
		_flags: i32,
		_lock_owner: Option<u64>,
		reply: ReplyData,
	) {
		let file = self.file_admin.get_file_mut(ino);
		match file.read(fh, offset, size) {
			Ok(data) => reply.data(&data),
			Err(e) => {
				log::error!("{:?}", e);
				reply.error(e.to_raw_os_error())
			},
		}
	}

	fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
		let file = self.file_admin.get_file_mut(ino);
		match file.flush(fh) {
			Ok(_) => reply.ok(),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}

	fn create(
		&mut self,
		req: &Request<'_>,
		parent: u64,
		name: &OsStr,
		mode: u32,
		umask: u32,
		flags: i32,
		reply: ReplyCreate,
	) {
		// Get path
		let parent_file = self.file_admin.get_file(parent);
		let parent_path = parent_file.path();
		let path = parent_path.join(name).into_boxed_path();
		let mut inbox_path = path.to_path_buf();
		if path.extension().is_none() || path.extension().unwrap() != "c4gh" {
			let mut filename = inbox_path.file_name().unwrap().to_string_lossy().to_string();
			filename.push_str(".c4gh");
			inbox_path.set_file_name(filename);
		}

		// Create file
		log::debug!("Create new file with path: {:?}", inbox_path);
		let file = utils::create(&inbox_path, flags, mode & umask).unwrap();

		// Build file admin entry
		let ino = utils::lstat(&inbox_path).unwrap().st_ino;
		let egafile = utils::wrap_file(&path, file, &self.keys, &self.recipients);

		// Build reply
		let attrs = egafile.attrs(req.uid(), req.gid()).unwrap();
		let fh = *egafile.fh().last().unwrap();

		// Add and reply
		self.file_admin.add(ino, egafile);
		reply.created(&TTL, &attrs, 0, fh, flags as u32)
	}

	fn write(
		&mut self,
		_req: &Request<'_>,
		ino: u64,
		fh: u64,
		_offset: i64,
		data: &[u8],
		_write_flags: u32,
		_flags: i32,
		_lock_owner: Option<u64>,
		reply: ReplyWrite,
	) {
		let file = self.file_admin.get_file_mut(ino);
		// TODO: Warn if offset != 0 => not allowed
		match file.write(fh, data) {
			Ok(size) => reply.written(size as u32),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}

	fn release(
		&mut self,
		_req: &Request<'_>,
		ino: u64,
		fh: u64,
		_flags: i32,
		_lock_owner: Option<u64>,
		_flush: bool,
		reply: ReplyEmpty,
	) {
	    let file = self.file_admin.get_file_mut(ino);

	    file.close(fh).unwrap();

	    reply.ok()
	}

	fn rename(
		&mut self,
		_req: &Request<'_>,
		parent: u64,
		name: &OsStr,
		newparent: u64,
		newname: &OsStr,
		_flags: u32,
		reply: ReplyEmpty,
	) {
		// Build paths
		let old_parent_file = self.file_admin.get_file(parent).path();
		let new_parent_path = self.file_admin.get_file(newparent).path();
		let old_path = old_parent_file.join(name);
		let new_path = new_parent_path.join(newname);

		// Change paths
		let file = self.file_admin.get_by_path_mut(&old_path).unwrap();
		file.rename(new_path.as_path());

		// Rename
		match std::fs::rename(&old_path, new_path) {
			Ok(_) => reply.ok(),
			Err(e) => reply.error(e.raw_os_error().unwrap()),
		}
	}

	fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
		// Build paths
		let parent_file = self.file_admin.get_file(parent);
		let parent_path = parent_file.path();
		let path = parent_path.join(name);

		// Remove file
		match std::fs::remove_file(path) {
			Ok(_) => reply.ok(),
			Err(e) => reply.error(e.raw_os_error().unwrap()),
		}
	}

	// DIRECTORY

    fn readdir(&mut self, _req: &Request<'_>, ino: u64, _fh: u64, skipped: i64, mut reply: ReplyDirectory) {

        let _dir = self.file_admin.get_file(ino);
		let entries = self.entries.get_mut(&ino).unwrap();

		// TODO: Make sure that they have always the same order

        let mut last_error = None;
        for (offset, entry) in entries[skipped as usize..].iter().enumerate() {
			log::debug!("Entry {} - {:?}", offset, entry);
            match entry {
                Ok(dir_entry) => {
					// Track file
                    let egafile = utils::wrap_path(dir_entry.path().as_path(), &self.keys, &self.recipients);
                    self.file_admin.add(dir_entry.ino(), egafile);

					// Kind
                    let kind = utils::get_type(dir_entry);

					// Name
                    let name = dir_entry.file_name().clone();
					let name_str = name.to_string_lossy().to_string();
					let new_name = name_str.strip_suffix(".c4gh").unwrap_or(&name_str);

					// Add entry
                    let buffer_full = reply.add(dir_entry.ino(), (skipped + offset as i64 + 1) as i64, kind, new_name);
                    if buffer_full {
                        break;
                    }
                },
                Err(e) => {
					log::error!("Error on entry {} (ERROR = {:?})", offset, e);
                    last_error = Some(e.raw_os_error().expect("Unable to convert to error"));
                },
            }
        }

        match last_error {
            None => reply.ok(),
            Some(e) => reply.error(e),
        }
    }

    // fn readdirplus(&mut self, req: &Request<'_>, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectoryPlus) {
	// 	let _dir = self.file_admin.get_file(ino);
	// 	// TODO: Make sure that they have always the same order
	// 	let entries = self.entries.get_mut(&ino).unwrap();
	// 	let mut last_error = None;
	// 	for (offset, entry) in entries.enumerate().skip(offset as usize) {
	// 		match entry {
	// 			Ok(dir_entry) => {
	// 				let egafile = utils::wrap_path(dir_entry.path().as_path(), &self.keys, &self.recipients);
	// 				self.file_admin.add(dir_entry.ino(), egafile);
	// 				let kind = utils::get_type(&dir_entry);
	// 				let name = dir_entry.file_name().clone();
    //                 let metadata = dir_entry.metadata().unwrap();
	// 				let attrs = FileAttr {
	// 					ino: dir_entry.ino(),
	// 					size: dir_entry.metadata().unwrap().len(),
	// 					blocks: metadata.blocks(),
	// 					atime: metadata.accessed().unwrap_or(std::time::UNIX_EPOCH),
	// 					mtime: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
	// 					ctime: metadata.created().unwrap_or(std::time::UNIX_EPOCH),
	// 					crtime: std::time::UNIX_EPOCH,
	// 					kind,
	// 					perm: metadata.permissions().mode() as u16,
	// 					#[cfg(target_os = "linux")]
	// 					nlink: metadata.st_nlink() as u32,
	// 					#[cfg(target_os = "macos")]
	// 					nlink: 0,
	// 					uid: req.uid(),
	// 					gid: req.gid(),
	// 					#[cfg(target_os = "linux")]
	// 					rdev: metadata.st_rdev() as u32,
	// 					#[cfg(target_os = "macos")]
	// 					rdev: metadata.rdev() as u32,
	// 					#[cfg(target_os = "linux")]
	// 					blksize: metadata.st_blksize() as u32,
	// 					#[cfg(target_os = "macos")]
	// 					blksize: metadata.blksize() as u32,
	// 					padding: 0,
	// 					flags: 0,
	// 				};
	// 				let buffer_full = reply.add(dir_entry.ino(), (offset + 1) as i64, name, &TTL, &attrs, 0);
	// 				if buffer_full {
	// 					break;
	// 				}
	// 			},
	// 			Err(e) => {
	// 				last_error = Some(e.raw_os_error().expect("Unable to convert to error"));
	// 			},
	// 		}
	// 	}
	// 	match last_error {
	// 		None => reply.ok(),
	// 		Some(e) => reply.error(e),
	// 	}
	// }

	fn mkdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
		let parent_file = self.file_admin.get_file(parent);
		let parent_path = parent_file.path();
		let path = parent_path.join(name);
		match std::fs::create_dir(&path) {
			Ok(_) => {
				let stat = utils::lstat(&path).unwrap();
				let attrs = utils::stat_to_fileatr(stat, req.uid(), req.gid());
				reply.entry(&TTL, &attrs, 0)
			},
			Err(e) => reply.error(e.raw_os_error().expect("Unable to retrieve raw OS error")),
		}
	}

	fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
		let parent_file = self.file_admin.get_file(parent);
		let parent_path = parent_file.path();
		let path = parent_path.join(name);
		self.file_admin.remove_by_path(&path);
		match std::fs::remove_dir(path) {
			Ok(_) => reply.ok(),
			Err(e) => reply.error(e.raw_os_error().expect("Unable to retrieve raw OS error")),
		}
	}

	fn opendir(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
		let file = self.file_admin.get_file_mut(ino);
		self.entries.insert(ino, std::fs::read_dir(file.path()).expect("Unable to read directory").collect());
		match file.open(flags) {
			Ok(fh) => reply.opened(fh as u64, flags as u32),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}

	fn releasedir(&mut self, _req: &Request<'_>, ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
		let file = self.file_admin.get_file_mut(ino);
		self.entries.remove(&ino);
		match file.close(fh) {
			Ok(_) => reply.ok(),
			Err(e) => reply.error(e.to_raw_os_error()),
		}
	}
}
