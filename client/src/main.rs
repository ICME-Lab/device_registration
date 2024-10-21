use anyhow::Result;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use std::time::SystemTime;

use sha2::{self, Digest};
use zk_engine::precompiles::signing::{CircuitTypes, SigningCircuit};

type CompressedProof = <SigningCircuit as CircuitTypes>::CompressedProof;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: f64,
    longitude: f64,
    timestamp: u64,
}

#[derive(Serialize)]
struct SendDataBody {
    data: Position,
    snark: CompressedProof,
    did: String,
}

#[derive(Deserialize)]
struct SendDataResult {
    message: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // Simulate inputs
    let secret_key_hex = std::env::var("SECRET_KEY_HEX").expect("SECRET_KEY must be set");
    let secret_key = hex::decode(secret_key_hex).unwrap();

    let latitude = 48.8566;
    let longitude = 2.3522;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // build position object
    let position = Position {
        latitude,
        longitude,
        timestamp,
    };

    let hash = hash_position(&position);

    // create signing circuit
    let circuit_primary = SigningCircuit::new(hash.clone(), secret_key);

    println!("Producing public parameters...");
    let pp = circuit_primary.get_public_params().unwrap();

    /*
     * PROVING CODE EXECUTION
     */
    println!("Proving...");
    let proof = circuit_primary.prove(&pp).unwrap();

    /*
     * COMPRESS PROOF
     */
    let pp = circuit_primary.get_public_params().unwrap();
    println!("Compressing...");
    let compressed_proof = SigningCircuit::compress_proof(&pp, &proof).unwrap();

    /*
     * SENDING TO SERVER
     */

    println!("Sending data to server...");

    let client = reqwest::Client::new();

    let diddoc_str = fs::read_to_string("./device_register/peerDIDDoc.json").expect("file read");

    let diddoc_json: serde_json::Value = serde_json::from_str(&diddoc_str).expect("JSON parse");

    let did = diddoc_json["id"].as_str().expect("DID string").to_string();

    let body = SendDataBody {
        data: position,
        snark: compressed_proof,
        did,
    };
    let url = "http://127.0.0.1:3000/send_data";
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).expect("JSON serialization"))
        .send()
        .await?;

    let result: SendDataResult = response.json().await?;
    println!("Result: {}", result.message);
    Ok(())
}

fn hash_position(position: &Position) -> Vec<u8> {
    let payload = serde_json::to_string(&position).expect("JSON serialization");
    let result = hash_message(&payload);
    result.to_vec()
}

fn hash_message(message: &str) -> Box<[u8]> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(message.as_bytes());
    hasher.finalize().as_slice().into()
}
