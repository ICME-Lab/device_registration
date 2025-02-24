use std::{env, fs::File, io::{BufRead, Read, Write}, process::Command};

use bson::{from_slice, to_vec};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Signature {
    pub v: String,
    pub r: String,
    pub s: String,
}


pub fn sign(digest: String) -> Signature {
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

    Signature { v, r, s }
}

/// Save any serializable object to a BSON file.
pub fn save_to_bson<T: Serialize>(data: &T, filename: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let mut file = File::create(format!("{}/cache/{}", manifest_dir, filename)).expect("Failed to create file");
    let serialized = to_vec(data).expect("Failed to serialize");
    file.write_all(&serialized)
        .expect("Failed to write to file");
}

/// Load any deserializable object from a BSON file.
pub fn load_from_bson<T: for<'de> Deserialize<'de>>(filename: &str) -> T {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let mut file = File::open(format!("{}/cache/{}", manifest_dir, filename)).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    from_slice(&buffer).expect("Failed to deserialize")
}
