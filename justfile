
run:
    echo "The passphrase is 'bob'"
    cargo run -- --conf tests/configs/fs.conf tests/mountpoint

keygen:
    crypt4gh keygen --pk testkey.pub --sk testkey.sec

encrypt:
    crypt4gh encrypt --sk tests/keys/testkey.sec --recipient_pk tests/keys/bob.pub < tests/decrypted/file.txt > tests/rootdir/file.txt.c4gh

decrypt:
    echo "The passphrase is 'bob'"
    crypt4gh decrypt --sk tests/keys/bob.sec < tests/rootdir/file.txt.c4gh

umount:
    umount tests/mountpoint
