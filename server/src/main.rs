use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use ff::Field;
use nova_snark::{
    provider, spartan,
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK, VerifierKey,
};
use radius_circuit::circuit::ProximityCircuit;

use web3::{
    api::Namespace,
    types::H160,
    types::{Recovery, RecoveryMessage, H256},
};

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
    signed_data: SignedData,
}

#[derive(Deserialize)]
struct SignedData {
    hash: [u8; 32],
    v: String,
    r: String,
    s: String,
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
    let signed_data = body.signed_data;
    let public_key = recover_address(signed_data);
    println!("Recovered device's public key: {:?}", public_key);

    // Make sure device is registered on a project by checking ioid contract
    // TODO

    /*
    RECOVER VERIFIER KEY
     */

    let vk = get_vk();

    /*
     * VERIFY PROOF
     */

    println!("Verifying proof...");

    let compressed_snark = body.snark;
    // verify the compressed SNARK
    let res = compressed_snark.verify(
        &vk,
        num_steps,
        vec![<G1 as Group>::Scalar::ZERO],
        vec![<G2 as Group>::Scalar::ONE],
    );

    if res.is_err() {
        println!("Proof verification failed");
        return Json(SendDataResult {
            message: "Proof verification failed".to_string(),
        });
    }

    println!("Proof verified");
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

fn recover_address(signed_data: SignedData) -> H160 {
    let hash = signed_data.hash;
    let message = RecoveryMessage::Hash(H256::from_slice(&hash));
    let v: u64 = u64::from_str_radix(&signed_data.v[2..], 16).unwrap();
    let r: H256 = H256::from_slice(&hex::decode(&signed_data.r[2..]).unwrap());
    let s: H256 = H256::from_slice(&hex::decode(&signed_data.s[2..]).unwrap());

    let recovery: Recovery = Recovery {
        message: message,
        v: v,
        r: r,
        s: s,
    };

    let websocket = web3::transports::Http::new("https://babel-api.testnet.iotex.io").unwrap();
    let account = web3::api::Accounts::new(websocket);
    let address = account.recover(recovery).unwrap();
    address
}
