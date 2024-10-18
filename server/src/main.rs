use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{self, Digest};
use std::collections::HashMap;
use std::process::Command;

use ff::Field;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use zk_engine::nova::{
    provider::{ipa_pc, PallasEngine, VestaEngine},
    spartan::{ppsnark, snark},
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams,
};
use zk_engine::precompiles::signing::SigningCircuit;

type E1 = PallasEngine;
type E2 = VestaEngine;
type EE1 = ipa_pc::EvaluationEngine<E1>;
type EE2 = ipa_pc::EvaluationEngine<E2>;
type S1 = ppsnark::RelaxedR1CSSNARK<E1, EE1>;
type S2 = snark::RelaxedR1CSSNARK<E2, EE2>;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: f64,
    longitude: f64,
    timestamp: u64,
}

#[derive(Deserialize)]
struct SendDataBody {
    data: Position,
    snark: CompressedSNARK<E1, S1, S2>,
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
    println!("DIDDoc: {}", register_device_body.diddoc);

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

    // produce public parameters, used to produce vk, the verifier key (could only be done only once for a given circuit)
    println!("Producing public parameters...");
    type C1 = SigningCircuit<<E1 as Engine>::Scalar>;
    type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
    let circuit_primary = C1::new([1; 32].to_vec(), [1; 32].to_vec());
    let circuit_secondary = C2::default();
    let pp = PublicParams::<E1>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*S1::ck_floor(),
        &*S2::ck_floor(),
    )
    .unwrap();
    let (_, vk) = CompressedSNARK::<E1, S1, S2>::setup(&pp).unwrap();

    /*
     * VERIFY PROOF
     */
    let z0_primary = [<E1 as Engine>::Scalar::ZERO; 4];
    let z0_secondary = [<E2 as Engine>::Scalar::ZERO];

    println!("Verifying ...");
    let snark = body.snark;
    let res2 = snark.verify(&vk, 1, &z0_primary, &z0_secondary).unwrap();

    /*
     * RECOVERING SIGNATURE
     */

    let (signature, _) = res2;
    let mut signature_bytes: [u8; 64] = [0; 64];
    for (i, signature_part) in signature.into_iter().enumerate() {
        let part: [u8; 32] = signature_part.into();
        signature_bytes[i * 16..(i + 1) * 16].copy_from_slice(&part[0..16]);
    }

    /*
     * VERIFYING SIGNATURE
     */

    let hash = hash_position(&body.data);
    let public_key = deser_pubkey(&pubkey_bytes);

    let is_valid = verify_signature(&public_key, &signature_bytes, &hash);
    println!("Signature is valid: {:?}", is_valid);

    if is_valid {
        Json(SendDataResult {
            message: "Data received and signature verified".to_string(),
        })
    } else {
        Json(SendDataResult {
            message: "Data received but signature verification failed".to_string(),
        })
    }
}

fn load_hashmap() -> HashMap<String, String> {
    if !std::path::Path::new("did_mapping/device_map.json").exists() {
        return HashMap::new();
    }
    let hashmap_str = std::fs::read_to_string("did_mapping/device_map.json").unwrap();
    serde_json::from_str(&hashmap_str).unwrap()
}

fn save_hashmap(hashmap: &HashMap<String, String>) {
    if !std::path::Path::new("did_mapping").exists() {
        std::fs::create_dir("did_mapping").unwrap();
    }
    let hashmap_str = serde_json::to_string(hashmap).unwrap();
    std::fs::write("did_mapping/device_map.json", hashmap_str).unwrap();
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
