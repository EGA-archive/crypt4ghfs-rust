use std::collections::BTreeMap;
use std::path::Path;

use crate::directory::Directory;
use crate::egafile::EgaFile;

type Inode = u64;

pub struct FileAdmin {
	pub inode2file: BTreeMap<Inode, Box<dyn EgaFile>>,
	path2inode: BTreeMap<Box<Path>, Inode>,
}

impl FileAdmin {
	pub fn new(rootdir: &str) -> Self {
		// Create file admin
		let mut file_admin = Self {
			inode2file: BTreeMap::new(),
			path2inode: BTreeMap::new(),
		};

		// Add rootdir
		file_admin.add(1, Box::new(Directory::new(None, Path::new(rootdir).into())));

		// Return
		file_admin
	}

	pub fn add(&mut self, ino: u64, file: Box<dyn EgaFile>) {
		self.path2inode.insert(file.path(), ino);
		self.inode2file.insert(ino, file);
	}

	pub fn get_by_path(&self, path: &Path) -> Option<&dyn EgaFile> {
		self.path2inode.get(path).map(|ino| self.get_file(*ino))
	}

	pub fn get_by_path_mut(&mut self, path: &Path) -> Option<&mut dyn EgaFile> {
		self.path2inode
			.get(path)
			.copied()
			.map(move |ino| self.get_file_mut(ino))
	}

	pub fn get_file(&self, ino: u64) -> &dyn EgaFile {
		self.inode2file.get(&ino).expect("Unable to get file").as_ref()
	}

	pub fn get_file_mut(&mut self, ino: u64) -> &mut dyn EgaFile {
		self.inode2file.get_mut(&ino).expect("Unable to get file").as_mut()
	}

	pub fn remove(&mut self, ino: u64) -> Option<Box<dyn EgaFile>> {
		self.inode2file.remove(&ino)
	}

	pub fn remove_by_path(&mut self, path: &Path) -> Option<Box<dyn EgaFile>> {
		// Find inode+
		let mut inode = None;
		for (ino, file) in &mut self.inode2file {
			if file.path() == path.into() {
				inode = Some(*ino);
				break;
			}
		}

		// Remove inode
		self.remove(inode?)
	}
}
