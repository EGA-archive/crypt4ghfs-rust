use super::libc_extras::libc;
use super::libc_wrappers;
use crypt4gh::Keys;
use fuse_mt::{CreatedEntry, DirectoryEntry, FileAttr, FileType, FilesystemMT, Statfs};
use std::{
	collections::HashSet,
	ffi::{CStr, CString, OsStr, OsString},
	fs::{self, File, OpenOptions},
	io::{self, Read, Seek, SeekFrom, Write},
	path::{Path, PathBuf},
};
use time::Timespec;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };

pub struct Crypt4ghFS {
	rootdir: String,
	keys: Vec<Keys>,
	recipients: HashSet<Keys>,
	extensions: Option<Vec<String>>,
	cache_directories: bool,
}

impl Crypt4ghFS {
	pub fn new(
		rootdir: String,
		seckey: Vec<u8>,
		recipients: HashSet<Keys>,
		extensions: Option<Vec<String>>,
		cache_directories: bool,
	) -> Self {
		log::info!("Extension: {:?}", extensions);
		Self {
			rootdir,
			keys: vec![Keys {
				method: 0,
				privkey: seckey,
				recipient_pubkey: vec![],
			}],
			recipients,
			extensions,
			cache_directories,
		}
	}

	// UTILS

	fn mode_to_filetype(&self, mode: libc::mode_t) -> FileType {
		match mode & libc::S_IFMT {
			libc::S_IFDIR => FileType::Directory,
			libc::S_IFREG => FileType::RegularFile,
			libc::S_IFLNK => FileType::Symlink,
			libc::S_IFBLK => FileType::BlockDevice,
			libc::S_IFCHR => FileType::CharDevice,
			libc::S_IFIFO => FileType::NamedPipe,
			libc::S_IFSOCK => FileType::Socket,
			_ => {
				panic!("unknown file type");
			},
		}
	}

	fn stat_to_fuse(&self, stat: libc::stat) -> FileAttr {
		// st_mode encodes both the kind and the permissions
		let kind = self.mode_to_filetype(stat.st_mode);
		let perm = (stat.st_mode & 0o7777) as u16;

		FileAttr {
			size: stat.st_size as u64,
			blocks: stat.st_blocks as u64,
			atime: Timespec {
				sec: stat.st_atime as i64,
				nsec: stat.st_atime_nsec as i32,
			},
			mtime: Timespec {
				sec: stat.st_mtime as i64,
				nsec: stat.st_mtime_nsec as i32,
			},
			ctime: Timespec {
				sec: stat.st_ctime as i64,
				nsec: stat.st_ctime_nsec as i32,
			},
			crtime: Timespec { sec: 0, nsec: 0 },
			kind,
			perm,
			nlink: stat.st_nlink as u32,
			uid: stat.st_uid,
			gid: stat.st_gid,
			rdev: stat.st_rdev as u32,
			flags: 0,
		}
	}

	#[cfg(target_os = "macos")]
	fn statfs_to_fuse(&self, statfs: libc::statfs) -> Statfs {
		Statfs {
			blocks: statfs.f_blocks,
			bfree: statfs.f_bfree,
			bavail: statfs.f_bavail,
			files: statfs.f_files,
			ffree: statfs.f_ffree,
			bsize: statfs.f_bsize as u32,
			namelen: 0, // TODO
			frsize: 0,  // TODO
		}
	}

	#[cfg(target_os = "linux")]
	fn statfs_to_fuse(&self, statfs: libc::statfs) -> Statfs {
		Statfs {
			blocks: statfs.f_blocks as u64,
			bfree: statfs.f_bfree as u64,
			bavail: statfs.f_bavail as u64,
			files: statfs.f_files as u64,
			ffree: statfs.f_ffree as u64,
			bsize: statfs.f_bsize as u32,
			namelen: statfs.f_namelen as u32,
			frsize: statfs.f_frsize as u32,
		}
	}

	fn real_path(&self, partial: &Path) -> OsString {
		PathBuf::from(&self.rootdir)
			.join(partial.strip_prefix("/").expect("Unable to strip the prefix"))
			.into_os_string()
	}

	fn stat_real(&self, path: &Path) -> io::Result<FileAttr> {
		let real: OsString = self.real_path(path);
		log::debug!("stat_real: {:?}", real);

		match libc_wrappers::lstat(real) {
			Ok(stat) => Ok(self.stat_to_fuse(stat)),
			Err(e) => Err(io::Error::from_raw_os_error(e)),
		}
	}
}

impl FilesystemMT for Crypt4ghFS {
	fn init(&self, _req: fuse_mt::RequestInfo) -> fuse_mt::ResultEmpty {
		log::debug!("INIT");
		Ok(())
	}

	fn destroy(&self, _req: fuse_mt::RequestInfo) {
		log::debug!("DESTROY");
	}

	fn getattr(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: Option<u64>) -> fuse_mt::ResultEntry {
		log::debug!("GETATTR(path = {:?}, fh = {:?})", path, fh);

		match fh {
			Some(fh) => match libc_wrappers::fstat(fh) {
				Ok(stat) => Ok((TTL, self.stat_to_fuse(stat))),
				Err(e) => Err(e),
			},
			None => match self.stat_real(path) {
				Ok(attr) => Ok((TTL, attr)),
				Err(e) => Err(e.raw_os_error().unwrap()),
			},
		}
	}

	fn chmod(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: Option<u64>, mode: u32) -> fuse_mt::ResultEmpty {
		log::debug!("chmod: {:?} to {:#o}", path, mode);

		let result = if let Some(fh) = fh {
			unsafe { libc::fchmod(fh as libc::c_int, mode as libc::mode_t) }
		}
		else {
			let real = self.real_path(path);
			unsafe {
				let path_c = CString::new(real.to_str().unwrap()).unwrap();
				libc::chmod(path_c.as_ptr(), mode as libc::mode_t)
			}
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("chmod({:?}, {:#o}): {}", path, mode, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(())
		}
	}

	fn chown(
		&self,
		_req: fuse_mt::RequestInfo,
		path: &Path,
		fh: Option<u64>,
		uid: Option<u32>,
		gid: Option<u32>,
	) -> fuse_mt::ResultEmpty {
		let uid = uid.unwrap_or(::std::u32::MAX); // docs say "-1", but uid_t is unsigned
		let gid = gid.unwrap_or(::std::u32::MAX); // ditto for gid_t
		log::debug!("chown: {:?} to {}:{}", path, uid, gid);

		let result = if let Some(fd) = fh {
			unsafe { libc::fchown(fd as libc::c_int, uid, gid) }
		}
		else {
			let real = self.real_path(path);
			unsafe {
				let path_c = CString::new(real.to_str().unwrap()).unwrap();
				libc::chown(path_c.as_ptr(), uid, gid)
			}
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("chown({:?}, {}, {}): {}", path, uid, gid, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(())
		}
	}

	fn truncate(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: Option<u64>, size: u64) -> fuse_mt::ResultEmpty {
		log::debug!("truncate: {:?} to {:#x}", path, size);

		let result = if let Some(fd) = fh {
			unsafe { libc::ftruncate(fd as libc::c_int, size as i64) }
		}
		else {
			let real = self.real_path(path);
			unsafe {
				let path_c = CString::new(real.to_str().unwrap()).unwrap();
				libc::truncate(path_c.as_ptr(), size as i64)
			}
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("truncate({:?}, {}): {}", path, size, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(())
		}
	}

	fn utimens(
		&self,
		_req: fuse_mt::RequestInfo,
		path: &Path,
		fh: Option<u64>,
		atime: Option<Timespec>,
		mtime: Option<Timespec>,
	) -> fuse_mt::ResultEmpty {
		log::debug!("utimens: {:?}: {:?}, {:?}", path, atime, mtime);

		fn timespec_to_libc(time: Option<Timespec>) -> libc::timespec {
			if let Some(time) = time {
				libc::timespec {
					tv_sec: time.sec as libc::time_t,
					tv_nsec: libc::time_t::from(time.nsec),
				}
			}
			else {
				libc::timespec {
					tv_sec: 0,
					tv_nsec: libc::UTIME_OMIT,
				}
			}
		}

		let times = [timespec_to_libc(atime), timespec_to_libc(mtime)];

		let result = if let Some(fd) = fh {
			unsafe { libc::futimens(fd as libc::c_int, &times as *const libc::timespec) }
		}
		else {
			let real = self.real_path(path);
			let path_c = CString::new(real.to_str().unwrap()).unwrap();
			libc::utimensat(
				libc::AT_FDCWD,
				path_c.as_ptr(),
				&times as *const libc::timespec,
				libc::AT_SYMLINK_NOFOLLOW,
			)
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("utimens({:?}, {:?}, {:?}): {}", path, atime, mtime, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(())
		}
	}

	fn utimens_macos(
		&self,
		_req: fuse_mt::RequestInfo,
		_path: &Path,
		_fh: Option<u64>,
		_crtime: Option<Timespec>,
		_chgtime: Option<Timespec>,
		_bkuptime: Option<Timespec>,
		_flags: Option<u32>,
	) -> fuse_mt::ResultEmpty {
		Err(libc::ENOSYS)
	}

	fn readlink(&self, _req: fuse_mt::RequestInfo, path: &Path) -> fuse_mt::ResultData {
		log::debug!("readlink: {:?}", path);

		let real = self.real_path(path);
		match ::std::fs::read_link(real) {
			Ok(target) => Ok(target.into_os_string().to_str().unwrap().as_bytes().to_vec()),
			Err(e) => Err(e.raw_os_error().unwrap()),
		}
	}

	fn mkdir(&self, _req: fuse_mt::RequestInfo, parent_path: &Path, name: &OsStr, mode: u32) -> fuse_mt::ResultEntry {
		log::debug!("mkdir {:?}/{:?} (mode={:#o})", parent_path, name, mode);

		let real = PathBuf::from(self.real_path(parent_path)).join(name);
		let result = unsafe {
			let path_c = CString::new(real.as_os_str().to_str().unwrap().as_bytes().to_vec()).unwrap();
			libc::mkdir(path_c.as_ptr(), mode as libc::mode_t)
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("mkdir({:?}, {:#o}): {}", real, mode, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			match libc_wrappers::lstat(real.clone().into_os_string()) {
				Ok(attr) => Ok((TTL, self.stat_to_fuse(attr))),
				Err(e) => {
					log::error!("lstat after mkdir({:?}, {:#o}): {}", real, mode, e);
					Err(e) // if this happens, yikes
				},
			}
		}
	}

	fn rmdir(&self, _req: fuse_mt::RequestInfo, parent_path: &Path, name: &OsStr) -> fuse_mt::ResultEmpty {
		log::debug!("rmdir: {:?}/{:?}", parent_path, name);

		let real = PathBuf::from(self.real_path(parent_path)).join(name);
		fs::remove_dir(&real).map_err(|ioerr| {
			log::error!("rmdir({:?}): {}", real, ioerr);
			ioerr.raw_os_error().unwrap()
		})
	}

	fn rename(
		&self,
		_req: fuse_mt::RequestInfo,
		parent_path: &Path,
		name: &OsStr,
		newparent: &Path,
		newname: &OsStr,
	) -> fuse_mt::ResultEmpty {
		log::debug!("rename: {:?}/{:?} -> {:?}/{:?}", parent_path, name, newparent, newname);

		let real = PathBuf::from(self.real_path(parent_path)).join(name);
		let newreal = PathBuf::from(self.real_path(newparent)).join(newname);
		fs::rename(&real, &newreal).map_err(|ioerr| {
			log::error!("rename({:?}, {:?}): {}", real, newreal, ioerr);
			ioerr.raw_os_error().unwrap()
		})
	}

	fn open(&self, _req: fuse_mt::RequestInfo, path: &Path, flags: u32) -> fuse_mt::ResultOpen {
		log::debug!("open: {:?} flags={:#x}", path, flags);

		let real = self.real_path(path);
		match libc_wrappers::open(real, flags as libc::c_int) {
			Ok(fh) => Ok((fh, flags)),
			Err(e) => {
				log::error!("open({:?}): {}", path, io::Error::from_raw_os_error(e));
				Err(e)
			},
		}
	}

	fn read(
		&self,
		_req: fuse_mt::RequestInfo,
		path: &Path,
		_fh: u64,
		offset: u64,
		size: u32,
		callback: impl FnOnce(fuse_mt::ResultSlice<'_>) -> fuse_mt::CallbackResult,
	) -> fuse_mt::CallbackResult {
		log::debug!("read: {:?} {:#x} @ {:#x}", path, size, offset);

		let real_path = self.real_path(path);
		let file_path = Path::new(&real_path);
		let mut file = File::open(file_path).expect("Read file not found");
		let mut data = Vec::new();

		// Decrypt or not based on the file extension
		match &self.extensions {
			Some(extensions) => {
				// If some extensions are specified, decrypt only those
				match file_path.extension() {
					Some(file_extension) if extensions.contains(&file_extension.to_str().unwrap().to_string()) => {
						// If the file_encryption is one of the specified
						log::info!("Reading encrypted data");
						crypt4gh::decrypt(&self.keys, &mut file, &mut data, offset as usize, None, None)
							.expect("read {:?}, {:#x} @ {:#x}: {} FAILED");
					},
					_ => {
						// If it is not (or does not have an extension)
						log::info!("Reading raw data");
						file.seek(SeekFrom::Start(offset)).unwrap();
						file.take(size as u64)
							.read_to_end(&mut data)
							.expect("Unable to read data");
					},
				}
			},
			None => {
				// If no extensions have been specified, decrypt all files
				log::info!("Reading encrypted data");
				crypt4gh::decrypt(&self.keys, &mut file, &mut data, offset as usize, None, None)
					.expect("read {:?}, {:#x} @ {:#x}: {} FAILED");
			},
		}

		log::info!("Data read successfully");

		callback(Ok(data.as_slice()))
	}

	fn write(
		&self,
		_req: fuse_mt::RequestInfo,
		path: &Path,
		_fh: u64,
		offset: u64,
		data: Vec<u8>,
		_flags: u32,
	) -> fuse_mt::ResultWrite {
		log::debug!("write: {:?} {:#x} @ {:#x}", path, data.len(), offset);

		let real_path = self.real_path(path);
		let file_path = Path::new(&real_path);
		let mut file = OpenOptions::new().read(true).write(true).open(file_path).unwrap();

		if let Err(e) = file.seek(SeekFrom::Start(offset)) {
			log::error!("seek({:?}, {}): {}", path, offset, e);
			return Err(e.raw_os_error().unwrap());
		}

		// Encrypt or not based on the file extension
		match &self.extensions {
			Some(extensions) => {
				// If some extensions are specified, encrypt only those
				match file_path.extension() {
					Some(file_extension) if extensions.contains(&file_extension.to_str().unwrap().to_string()) => {
						// If the file_encryption is one of the specified
						log::info!("Writing data encrypted");
						crypt4gh::encrypt(&self.recipients, &mut data.as_slice(), &mut file, 0, None)
							.expect("write {:?}, {:#x} @ {:#x}: {} FAILED");
					},
					_ => {
						// If it is not (or does not have an extension)
						log::info!("Writing data without encryption");
						file.write_all(&data).expect("Unable to write data");
					},
				}
			},
			None => {
				// If no extensions have been specified, encrypt all files
				log::info!("Writing data encrypted");
				crypt4gh::encrypt(&self.recipients, &mut data.as_slice(), &mut file, 0, None)
					.expect("write {:?}, {:#x} @ {:#x}: {} FAILED");
			},
		}

		Ok(data.len() as u32)
	}

	fn flush(&self, _req: fuse_mt::RequestInfo, path: &Path, _fh: u64, _lock_owner: u64) -> fuse_mt::ResultEmpty {
		log::debug!("flush: {:?}", path);
		let mut file = File::open(self.real_path(path)).expect("Should be UnmanagedFile");

		if let Err(e) = file.flush() {
			log::error!("flush({:?}): {}", path, e);
			return Err(e.raw_os_error().unwrap());
		}

		Ok(())
	}

	fn release(
		&self,
		_req: fuse_mt::RequestInfo,
		path: &Path,
		fh: u64,
		_flags: u32,
		_lock_owner: u64,
		_flush: bool,
	) -> fuse_mt::ResultEmpty {
		log::debug!("release: {:?}", path);
		libc_wrappers::close(fh)
	}

	fn fsync(&self, _req: fuse_mt::RequestInfo, path: &Path, _fh: u64, datasync: bool) -> fuse_mt::ResultEmpty {
		log::debug!("fsync: {:?}, data={:?}", path, datasync);
		let file = File::open(self.real_path(path)).expect("Should be UnmanagedFile");

		if let Err(e) = if datasync { file.sync_data() } else { file.sync_all() } {
			log::error!("fsync({:?}, {:?}): {}", path, datasync, e);
			return Err(e.raw_os_error().unwrap());
		}

		Ok(())
	}

	fn opendir(&self, _req: fuse_mt::RequestInfo, path: &Path, flags: u32) -> fuse_mt::ResultOpen {
		let real = self.real_path(path);
		log::debug!("OPENDIR: {:?} (flags = {:#o})", real, flags);

		match libc_wrappers::opendir(real) {
			Ok(fh) => Ok((fh, 0)),
			Err(e) => Err(e),
		}
	}

	fn readdir(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: u64) -> fuse_mt::ResultReaddir {
		log::debug!("READDIR: {:?}", path);
		let mut entries: Vec<DirectoryEntry> = vec![];

		if fh == 0 {
			log::error!("readdir: missing fh");
			return Err(libc::EINVAL);
		}

		loop {
			match libc_wrappers::readdir(fh) {
				Ok(Some(entry)) => {
					let name_c = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
					let name = OsStr::new(name_c.to_str().unwrap()).to_owned();

					let filetype = match entry.d_type {
						libc::DT_DIR => FileType::Directory,
						libc::DT_REG => FileType::RegularFile,
						libc::DT_LNK => FileType::Symlink,
						libc::DT_BLK => FileType::BlockDevice,
						libc::DT_CHR => FileType::CharDevice,
						libc::DT_FIFO => FileType::NamedPipe,
						libc::DT_SOCK => {
							log::warn!("FUSE doesn't support Socket file type; translating to NamedPipe instead.");
							FileType::NamedPipe
						},
						_ => {
							let entry_path = PathBuf::from(path).join(&name);
							let real_path = self.real_path(&entry_path);
							match libc_wrappers::lstat(real_path) {
								Ok(stat64) => self.mode_to_filetype(stat64.st_mode),
								Err(errno) => {
									let ioerr = io::Error::from_raw_os_error(errno);
									panic!(
										"lstat failed after readdir_r gave no file type for {:?}: {}",
										entry_path, ioerr
									);
								},
							}
						},
					};

					entries.push(DirectoryEntry { name, kind: filetype })
				},
				Ok(None) => {
					break;
				},
				Err(e) => {
					log::error!("readdir: {:?}: {}", path, e);
					return Err(e);
				},
			}
		}

		Ok(entries)
	}

	fn releasedir(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: u64, flags: u32) -> fuse_mt::ResultEmpty {
		log::debug!("RELEASEDIR: {:?} (flags = {:#o})", path, flags);
		libc_wrappers::closedir(fh)
	}

	fn fsyncdir(&self, _req: fuse_mt::RequestInfo, path: &Path, fh: u64, datasync: bool) -> fuse_mt::ResultEmpty {
		log::debug!("fsyncdir: {:?} (datasync = {:?})", path, datasync);

		// TODO: what does datasync mean with regards to a directory handle?
		let result = unsafe { libc::fsync(fh as libc::c_int) };
		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("fsyncdir({:?}): {}", path, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(())
		}
	}

	fn statfs(&self, _req: fuse_mt::RequestInfo, path: &Path) -> fuse_mt::ResultStatfs {
		log::debug!("statfs: {:?}", path);

		let real = self.real_path(path);
		let mut buf: libc::statfs = unsafe { ::std::mem::zeroed() };
		let result = unsafe {
			let path_c = CString::new(real.to_str().unwrap()).unwrap();
			libc::statfs(path_c.as_ptr(), &mut buf)
		};

		if -1 == result {
			let e = io::Error::last_os_error();
			log::error!("statfs({:?}): {}", path, e);
			Err(e.raw_os_error().unwrap())
		}
		else {
			Ok(self.statfs_to_fuse(buf))
		}
	}

	fn access(&self, _req: fuse_mt::RequestInfo, _path: &Path, _mask: u32) -> fuse_mt::ResultEmpty {
		Err(libc::ENOSYS)
	}

	fn create(
		&self,
		_req: fuse_mt::RequestInfo,
		parent_path: &Path,
		name: &OsStr,
		mode: u32,
		flags: u32,
	) -> fuse_mt::ResultCreate {
		log::debug!(
			"create: {:?}/{:?} (mode={:#o}, flags={:#x})",
			parent_path,
			name,
			mode,
			flags
		);

		let real = PathBuf::from(self.real_path(parent_path)).join(name);
		let fd = unsafe {
			let real_c = CString::new(real.clone().into_os_string().to_str().unwrap().as_bytes().to_vec()).unwrap();
			libc::open(real_c.as_ptr(), flags as i32 | libc::O_CREAT | libc::O_EXCL, mode)
		};

		if -1 == fd {
			let ioerr = io::Error::last_os_error();
			log::error!("create({:?}): {}", real, ioerr);
			Err(ioerr.raw_os_error().unwrap())
		}
		else {
			match libc_wrappers::lstat(real.clone().into_os_string()) {
				Ok(attr) => Ok(CreatedEntry {
					ttl: TTL,
					attr: self.stat_to_fuse(attr),
					fh: fd as u64,
					flags,
				}),
				Err(e) => {
					log::error!("lstat after create({:?}): {}", real, io::Error::from_raw_os_error(e));
					Err(e)
				},
			}
		}
	}

	#[cfg(target_os = "macos")]
	fn setvolname(&self, _req: fuse_mt::RequestInfo, name: &OsStr) -> fuse_mt::ResultEmpty {
		log::info!("setvolname: {:?}", name);
		Err(libc::ENOTSUP)
	}

	#[cfg(target_os = "macos")]
	fn getxtimes(&self, _req: fuse_mt::RequestInfo, path: &Path) -> fuse_mt::ResultXTimes {
		log::debug!("getxtimes: {:?}", path);
		let xtimes = fuse_mt::XTimes {
			bkuptime: Timespec { sec: 0, nsec: 0 },
			crtime: Timespec { sec: 0, nsec: 0 },
		};
		Ok(xtimes)
	}
}
