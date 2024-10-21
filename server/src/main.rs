use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{self, Digest};
use std::collections::HashMap;
use std::process::Command;

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use zk_engine::precompiles::signing::{CircuitTypes, SigningCircuit};

type CompressedProof = <SigningCircuit as CircuitTypes>::CompressedProof;
type PublicParams = <SigningCircuit as CircuitTypes>::PublicParams;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: f64,
    longitude: f64,
    timestamp: u64,
}

#[derive(Deserialize)]
struct SendDataBody {
    data: Position,
    snark: CompressedProof,
    did: String,
}

#[derive(Serialize)]
struct SendDataResult {
    message: String,
}

#[derive(Deserialize)]
struct RegisterDeviceBody {
    diddoc: String,
}

#[derive(Serialize)]
struct RegisterResult {
    message: String,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/register_device", post(register_device))
        .route("/send_data", post(receive_data));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Listening on: {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> String {
    "Hello, World!".to_string()
}

async fn register_device(
    Json(register_device_body): Json<RegisterDeviceBody>,
) -> (StatusCode, Json<RegisterResult>) {
    println!("Received DIDDoc: {}", register_device_body.diddoc);

    let diddoc_json: serde_json::Value =
        serde_json::from_str(&register_device_body.diddoc).expect("Failed to parse DIDDoc");

    let did = diddoc_json["id"].as_str().expect("DID not found");

    let result = Command::new("./add_client/build/add_client")
        .arg(register_device_body.diddoc)
        .output()
        .expect("failed to execute process")
        .stdout;

    let public_key: [u8; 64] = result.try_into().unwrap();

    let mut public_key_with_prefix = [0; 65];
    public_key_with_prefix[0] = 0x04;
    public_key_with_prefix[1..].copy_from_slice(&public_key);

    update_hashmap(did, &public_key_with_prefix);

    println!("New device registered");

    let result = RegisterResult {
        message: "Device registered".to_string(),
    };
    (StatusCode::CREATED, Json(result))
}

async fn receive_data(Json(body): Json<SendDataBody>) -> Json<SendDataResult> {
    println!("Received data");
    // Make sure device is registered
    let did = &body.did;
    let pubkey_bytes = match get_public_key(did) {
        Some(public_key) => public_key,
        None => {
            return Json(SendDataResult {
                message: "Device not registered".to_string(),
            })
        }
    };

    /*
    RECOVER VERIFIER KEY
     */

    let pp = get_public_params();

    /*
     * VERIFY PROOF
     */

    println!("Verifying ...");
    let compressed_proof = body.snark;
    let res2 = SigningCircuit::verify_compressed(&pp, &compressed_proof);

    /*
     * RECOVER SIGNATURE
     */

    let signature = res2.unwrap();
    let mut signature_bytes: [u8; 64] = [0; 64];
    for (i, signature_part) in signature.into_iter().enumerate() {
        let part: [u8; 32] = signature_part.into();
        signature_bytes[i * 16..(i + 1) * 16].copy_from_slice(&part[0..16]);
    }

    /*
     * VERIFY SIGNATURE
     */

    let hash = hash_position(&body.data);
    let public_key = deser_pubkey(&pubkey_bytes);

    let is_valid = verify_signature(&public_key, &signature_bytes, &hash);

    if is_valid {
        println!("Proof and signature succesfully verified");
        Json(SendDataResult {
            message: "Data received and signature verified".to_string(),
        })
    } else {
        println!("Proof and signature verification failed");
        Json(SendDataResult {
            message: "Data received but signature verification failed".to_string(),
        })
    }
}

fn load_hashmap() -> HashMap<String, String> {
    if !std::path::Path::new("storage/device_map.json").exists() {
        return HashMap::new();
    }
    let hashmap_str = std::fs::read_to_string("storage/device_map.json").unwrap();
    serde_json::from_str(&hashmap_str).unwrap()
}

fn save_hashmap(hashmap: &HashMap<String, String>) {
    if !std::path::Path::new("storage").exists() {
        std::fs::create_dir("storage").unwrap();
    }
    let hashmap_str = serde_json::to_string(hashmap).unwrap();
    std::fs::write("storage/device_map.json", hashmap_str).unwrap();
}

fn update_hashmap(did: &str, public_key: &[u8; 65]) {
    let mut hashmap = load_hashmap();
    let public_key_base64 = base64::encode(public_key);
    hashmap.insert(did.to_string(), public_key_base64);
    save_hashmap(&hashmap);
}

fn get_public_key(did: &str) -> Option<[u8; 65]> {
    let hashmap = load_hashmap();
    let public_key_base64 = hashmap.get(did)?;
    let public_key = base64::decode(public_key_base64).unwrap();
    let mut public_key_array = [0; 65];
    public_key_array.copy_from_slice(&public_key);
    Some(public_key_array)
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

fn verify_signature(public_key: &PublicKey, sig: &[u8], hash: &[u8]) -> bool {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&hash).expect("32 bytes");
    let signature = Signature::from_compact(sig).expect("64 bytes");
    secp.verify_ecdsa(&message, &signature, &public_key).is_ok()
}

fn deser_pubkey(pubkey_bytes: &[u8; 65]) -> PublicKey {
    PublicKey::from_slice(pubkey_bytes).expect("65 bytes")
}

fn get_public_params() -> PublicParams {
    let pp_str = std::fs::read_to_string("storage/public_params.json").unwrap_or_else(|_| {
        panic!("Could not read public parameters file");
    });
    let pp: PublicParams = serde_json::from_str(&pp_str).unwrap();
    pp
}
