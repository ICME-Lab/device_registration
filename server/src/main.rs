use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{self, Digest};

use ff::Field;
use nova_snark::CompressedSNARK;
use nova_snark::{provider, spartan};
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    VerifierKey,
};
use radius_circuit::circuit::ProximityCircuit;

use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<G1> = spartan::ppsnark::RelaxedR1CSSNARK<G1, EE1<G1>>;
type S2Prime<G2> = spartan::ppsnark::RelaxedR1CSSNARK<G2, EE2<G2>>;

#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: u64,
    longitude: u64,
}

#[derive(Deserialize)]
struct SendDataBody {
    snark: CompressedSNARK<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
        S1Prime<G1>,
        S2Prime<G2>,
    >,
    signature: String,
}

#[derive(Serialize)]
struct SendDataResult {
    message: String,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
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

async fn receive_data(Json(body): Json<SendDataBody>) -> Json<SendDataResult> {
    let num_steps = 1;
    println!("Received data");

    // recover signer's public key
    let signature_str = body.signature;
    let signature_slice: [u8; 65] = hex::decode(signature_str).unwrap().try_into().unwrap();
    let recovery_id = RecoverableSignature::from_compact(
        &signature_slice[1..],
        (signature_slice[0] as i32).try_into().unwrap(),
    )
    .unwrap();

    let proof_serialized = serde_json::to_string(&body.snark).expect("JSON serialization");
    let hash = sha2::Sha256::digest(proof_serialized.as_bytes());

    let secp = Secp256k1::new();
    let _public_key = secp
        .recover_ecdsa(
            &Message::from_digest(hash.try_into().unwrap()),
            &recovery_id,
        )
        .unwrap();

    // Make sure device is registered on a project by checking ioid contract

    /*
    RECOVER VERIFIER KEY
     */

    let vk = get_vk();

    /*
     * VERIFY PROOF
     */

    println!("Verifying ...");

    let compressed_snark = body.snark;
    // verify the compressed SNARK
    let res = compressed_snark.verify(
        &vk,
        num_steps,
        vec![<G1 as Group>::Scalar::ZERO],
        vec![<G2 as Group>::Scalar::ONE],
    );

    if res.is_err() {
        return Json(SendDataResult {
            message: "Proof verification failed".to_string(),
        });
    }

    return Json(SendDataResult {
        message: "Proof verified".to_string(),
    });
}

fn get_vk() -> VerifierKey<
    G1,
    G2,
    ProximityCircuit<<G1 as Group>::Scalar>,
    TrivialTestCircuit<<G2 as Group>::Scalar>,
    S1Prime<G1>,
    S2Prime<G2>,
> {
    let pp_str = std::fs::read_to_string("storage/vk.json").unwrap_or_else(|_| {
        panic!("Could not read public parameters file");
    });
    let pp: VerifierKey<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
        S1Prime<G1>,
        S2Prime<G2>,
    > = serde_json::from_str(&pp_str).unwrap();
    pp
}
