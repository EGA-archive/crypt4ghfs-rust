mod test_common;

use crypt4ghfs::{config::*, run_with_config};
pub use test_common::*;

#[test]
fn test_mount_foreground() {
	// Init
	let init = Cleanup::new();

	// Check that path is unmounted
	run("diskutil umount tests/mountpoint").unwrap();

	// Spawn mount
	let mut child = spawn("cargo run -- -fv --conf tests/configs/fs.conf tests/mountpoint").unwrap();

	// Wait
	wait_with_timeout("mount | grep tests/mountpoint > /dev/null", 10_000, 100);

	// Unmount
	let (code, _, err) = run("diskutil umount tests/mountpoint").unwrap();
	assert!(code == 0, err);

	// Check termination
	assert!(child.wait().unwrap().success());

	// Cleanup
	drop(init);
}

#[test]
fn test_mount_background() {
	// Init
	let init = Cleanup::new();

	// Check that path is unmounted
	run("diskutil umount tests/mountpoint").unwrap();

	// Run daemon
	let mut child = spawn("cargo run -- -v --conf tests/configs/fs.conf tests/mountpoint").unwrap();

	// Wait until child is spawned
	assert!(child.wait().unwrap().success());

	// Wait
	wait_with_timeout("mount | grep tests/mountpoint > /dev/null", 10_000, 100);

	// Unmount
	let (code, _, err) = run("diskutil umount tests/mountpoint").unwrap();
	assert!(code == 0, err);

	// Cleanup
	drop(init);
}

#[test]
fn test_extension_txt() {
	// Init
	let init = Cleanup::new();

	// Check that path is unmounted
	run("diskutil umount tests/mountpoint").unwrap();

	// Custom config
	let config = Config::new_with_defaults("tests/rootdir".into(), "tests/testfiles/bob.sec".into())
		.with_log_level(LogLevel::Error)
		.with_extensions(vec!["c4gh".into()]);

	// Mount
	run_with_config(config, 1, "tests/mountpoint".into(), false).unwrap();

	// Wait until mounted
	wait_with_timeout("mount | grep tests/mountpoint > /dev/null", 10_000, 100);

	// Write "hello" to file.c4gh
	run("echo 'hello' > tests/mountpoint/file.txt").unwrap();
	count_characters("tests/mountpoint/file.txt", 6);

	// Unmount
	let (code, _, err) = run("diskutil umount tests/mountpoint").unwrap();
	assert!(code == 0, err);

	// Cleanup
	drop(init);
}

#[test]
fn test_extension_c4gh() {
	// Init
	let init = Cleanup::new();

	// Check that path is unmounted
	run("diskutil umount tests/mountpoint").unwrap();

	// Custom config
	let config = Config::new_with_defaults("tests/rootdir".into(), "tests/testfiles/bob.sec".into())
		.with_log_level(LogLevel::Error)
		.with_extensions(vec!["c4gh".into()]);

	// Mount
	run_with_config(config, 1, "tests/mountpoint".into(), false).unwrap();

	// Wait until mounted
	wait_with_timeout("mount | grep tests/mountpoint > /dev/null", 10_000, 100);

	// Write "hello" to file.c4gh
	run("echo 'hello' > tests/mountpoint/file.c4gh").unwrap();
	count_characters("tests/mountpoint/file.c4gh", 158);

	// Unmount
	let (code, _, err) = run("diskutil umount tests/mountpoint").unwrap();
	assert!(code == 0, err);

	// Cleanup
	drop(init);
}