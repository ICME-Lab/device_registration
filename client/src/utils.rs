use std::{io::BufRead, process::Command};

pub fn sign(digest: String) -> (String, String, String) {
    if !digest.starts_with("0x") {
        panic!("Digest must start with 0x");
    }
    if !digest.len() == 66 {
        panic!("Digest must be 32 bytes long");
    }
    let mut command = Command::new("node");
    command
        .arg("./lib/ioid-registration-js/signDigest.js")
        .arg(digest)
        .stdout(std::process::Stdio::piped());

    let child = command.spawn().expect("failed to execute child");
    let output = child.wait_with_output().expect("failed to wait on child");

    let mut output_lines = output.stdout.lines();
    output_lines.next();
    output_lines.next();

    let v = output_lines.next().unwrap().unwrap();
    let r = output_lines.next().unwrap().unwrap();
    let s = output_lines.next().unwrap().unwrap();

    (v, r, s)
}
