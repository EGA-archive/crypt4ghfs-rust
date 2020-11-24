use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::{env, fs::File};
use std::{ffi::OsStr, process::Child};

use run_script::ScriptError;

pub const TEMP_LOCATION: &str = "tests/tempfiles";

pub struct CommandUnderTest {
	raw: Command,
	stdin: Vec<u8>,
	run: bool,
	stdout: String,
	stderr: String,
}

impl CommandUnderTest {
	pub fn new() -> CommandUnderTest {
		// To find the directory where the built binary is, we walk up the directory tree of the test binary until the
		// parent is "target/".
		let mut binary_path = env::current_exe().expect("need current binary path to find binary to test");
		loop {
			{
				let parent = binary_path.parent();
				if parent.is_none() {
					panic!(
						"Failed to locate binary path from original path: {:?}",
						env::current_exe()
					);
				}
				let parent = parent.unwrap();
				if parent.is_dir() && parent.file_name().unwrap() == "target" {
					break;
				}
			}
			binary_path.pop();
		}

		binary_path.push(if cfg!(target_os = "windows") {
			format!("{}.exe", env!("CARGO_PKG_NAME"))
		}
		else {
			env!("CARGO_PKG_NAME").to_string()
		});

		let mut cmd = Command::new(binary_path);

		let mut work_dir = PathBuf::new();
		work_dir.push(env!("CARGO_MANIFEST_DIR"));

		cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).current_dir(work_dir);

		CommandUnderTest {
			raw: cmd,
			run: false,
			stdin: Vec::new(),
			stdout: String::new(),
			stderr: String::new(),
		}
	}

	pub fn env(&mut self, key: &str, val: &str) -> &mut Self {
		self.raw.env(key, val);
		self
	}

	pub fn same_envs(&mut self) -> &mut Self {
		self.raw.envs(env::vars());
		self
	}

	pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
		self.raw.arg(arg);
		self
	}

	pub fn args<I, S>(&mut self, args: I) -> &mut Self
	where
		I: IntoIterator<Item = S>,
		S: AsRef<OsStr>,
	{
		self.raw.args(args);
		self
	}

	pub fn pipe_in(&mut self, filename: &str) -> &mut Self {
		let file = File::open(filename).unwrap();
		self.raw.stdin(Stdio::from(file));
		self
	}

	pub fn pipe_out(&mut self, filename: &str) -> &mut Self {
		let file = File::create(filename).unwrap();
		self.raw.stdout(Stdio::from(file));
		self
	}

	pub fn run(&mut self) -> ExitStatus {
		let mut child = self.raw.spawn().expect("failed to run command");

		if self.stdin.len() > 0 {
			let stdin = child.stdin.as_mut().expect("failed to open stdin");
			stdin.write_all(&self.stdin).expect("failed to write to stdin")
		}

		let output = child
			.wait_with_output()
			.expect("failed waiting for command to complete");
		self.stdout = String::from_utf8(output.stdout).unwrap();
		self.stderr = String::from_utf8(output.stderr).unwrap();
		self.run = true;
		output.status
	}

	pub fn fails(&mut self) -> &mut Self {
		assert!(!self.run().success(), "expected command to fail");
		self
	}

	pub fn succeeds(&mut self) -> &mut Self {
		let status = self.run();
		assert!(
			status.success(),
			format!(
				"expected command to succeed, but it failed.\nexit code: {}\nstdout: {}\nstderr:{}\n",
				status.code().unwrap(),
				self.stdout,
				self.stderr,
			)
		);
		self
	}

	pub fn no_stdout(&mut self) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert!(
			self.stdout.is_empty(),
			format!("expected no stdout, got {}", self.stdout)
		);
		self
	}

	pub fn no_stderr(&mut self) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert!(
			self.stderr.is_empty(),
			format!("expected no stderr, got {}", self.stderr)
		);
		self
	}

	pub fn stdout_is(&mut self, expected: &str) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert_eq!(&self.stdout[..], expected, "stdout does not match expected");
		self
	}

	pub fn stderr_is(&mut self, expected: &str) -> &mut Self {
		assert!(self.run, "command has not yet been run, use succeeds()/fails()");
		assert_eq!(&self.stderr[..], expected, "stderr does not match expected");
		self
	}
}

pub struct Cleanup {
	old_passphrase: Option<String>,
}

impl Drop for Cleanup {
	fn drop(&mut self) {
		
		match self.old_passphrase.to_owned() {
			Some(passphrase) => std::env::set_var("C4GH_PASSPHRASE", passphrase),
			None => std::env::remove_var("C4GH_PASSPHRASE"),
		}

		eprintln!("DROP");
		remove_file(TEMP_LOCATION);
	}
}

impl Cleanup {
	pub fn new() -> Self {
		eprintln!("Created!");
		Command::new("mkdir")
			.arg(TEMP_LOCATION)
			.stderr(Stdio::null())
			.spawn()
			.unwrap()
			.wait()
			.unwrap();
		
		let old_passphrase = std::env::var("C4GH_PASSPHRASE").ok();
		std::env::set_var("C4GH_PASSPHRASE", "bob");
		
		Self {
			old_passphrase,
		}
	}
}

pub fn equal(file1: &str, file2: &str) {
	let status = Command::new("diff")
		.arg(file1)
		.arg(file2)
		.stderr(Stdio::null())
		.stdout(Stdio::null())
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.code()
		.unwrap();
	assert_eq!(status, 0)
}

pub fn new_random_file(filename: &str, size_in_mb: usize) {
	File::create(filename).unwrap();
	let status = Command::new("dd")
		.arg("if=/dev/urandom")
		.arg("bs=1048576")
		.arg(format!("count={}", size_in_mb))
		.arg(format!("of={}", filename))
		.stderr(Stdio::null())
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.code()
		.unwrap();
	assert_eq!(status, 0);
}

pub fn remove_file(file_pattern: &str) {
	let _ = Command::new("rm").arg("-rf").arg(file_pattern).spawn().unwrap().wait();
}

pub fn temp_file(filename: &str) -> String {
	let mut s = TEMP_LOCATION.to_string();
	s.push_str("/");
	s.push_str(filename);
	s
}

pub fn strip_prefix(filename: &str) -> String {
	let ref_file = PathBuf::from(temp_file(filename));
	let ref_file = ref_file.strip_prefix("tests/").unwrap();
	ref_file.to_str().unwrap().to_string()
}

pub fn add_prefix(filename: &str) -> String {
	let mut ref_file = PathBuf::new();
	ref_file.push("tests/");
	ref_file.push(filename);
	ref_file.to_str().unwrap().to_string()
}

pub fn echo(message: &str, filename: &str) {
	let file = File::create(filename).unwrap();
	let status = Command::new("echo")
		.arg("-n")
		.arg(message)
		.stderr(Stdio::null())
		.stdout(Stdio::from(file))
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.code()
		.unwrap();
	assert_eq!(status, 0);
}

pub fn count_characters(filepath: &str, assert_size: usize) {
	let (code, output, err) = run(format!("wc -c {} | awk '{{ print $1 }}'", filepath).as_str()).unwrap();
	assert!(code == 0, "Unable to count characters (ERROR = {})", err);
	assert_eq!(assert_size, output.trim().parse().unwrap(),);
}

pub fn grep(filepath: &str, substring: &str) {
	let status = Command::new("grep")
		.arg("-v")
		.arg(substring)
		.arg(filepath)
		.stderr(Stdio::null())
		.spawn()
		.unwrap()
		.wait()
		.unwrap()
		.code()
		.unwrap();
	assert_eq!(status, 1);
}

pub fn wait_with_timeout(command: &str, max_millis: usize, step_by: usize) {
	let mut finished = false;
	for _ in (0..max_millis).step_by(step_by) {
		std::thread::sleep(std::time::Duration::from_millis(step_by as u64));
		if let Ok((0, _, _)) = run(command) {
			finished = true;
			break;
		}
	}
	assert!(finished, "Timeout triggered with {}", command);
}

pub fn run(command: &str) -> Result<(i32, String, String), ScriptError> {
	run_script::run_script!(command)
}

pub fn spawn(command: &str) -> Result<Child, ScriptError> {
	run_script::spawn(command, &vec![], &run_script::ScriptOptions::new())
}
