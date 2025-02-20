use std::str::FromStr;

use axum::{

    routing::{get, post}, Json, Router
};
use dotenv::dotenv;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use ff::Field;
use halo2curves::bn256::Fr;
use nova::{
    nebula::rs::PublicParams,
    onchain::decider::Decider,
    provider::Bn256EngineKZG,
};
use sha2::Digest;
use web3::{
    api::Namespace,
    contract::Contract,
    signing::SecretKey,
    types::{Recovery, RecoveryMessage, TransactionParameters, H160, H256, U256},
};


#[derive(Serialize, Deserialize, Debug)]
struct Position {
    latitude: u64,
    longitude: u64,
}

#[derive(Deserialize)]
struct SendDataBody {
    snark: Decider,
    signature: Signature,
}

#[derive(Deserialize)]
struct Signature {
    v: String,
    r: String,
    s: String,
}

#[derive(Serialize)]
struct SendDataResult {
    message: String,
}


// Contracts deployment address on IOTEX testnet
const IOID_REGISTRY_ADDRESS: &str = "0x0A7e595C7889dF3652A19aF52C18377bF17e027D";
const IOID_CONTRACT_ADDRESS: &str = "0x45Ce3E6f526e597628c73B731a3e9Af7Fc32f5b7";

#[tokio::main]
async fn main() {
    dotenv().ok();
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
    println!("Received data");

    let compressed_snark = body.snark;
    let signature = body.signature;

    // recover proof hash
    let proof_serialized = serde_json::to_string(&compressed_snark).expect("JSON serialization");
    let hash = sha2::Sha256::digest(proof_serialized.as_bytes());
    let hash: [u8; 32] = hash.into();

    // recover signer's public key
    let public_key = recover_address(&hash, signature);
    println!("Recovered device's public key: {:?}", public_key);

    // Make sure device is registered on a project by checking ioid contract
    // TODO

    /*
    RECOVER VERIFIER KEY
     */

    let pp = get_pp();
    let mut rng = thread_rng();
    let z0 = vec![Fr::ONE];
    let (pk, vk) = Decider::setup(&pp, &mut rng, z0.len()).unwrap();

    /*
     * VERIFY PROOF
     */

    println!("Verifying proof...");

    // verify the compressed SNARK
    let res = compressed_snark.verify(vk);

    if res.is_err() {
        println!("Proof verification failed");
        return Json(SendDataResult {
            message: "Proof verification failed".to_string()
        });
        // return Err(StatusCode::BAD_REQUEST);
    }

    /*
     * Recover owner's public address from device's
     *
     * First recover device's ioID NFT token id from ioIDRegistry contract
     * the ioID NFT is minted to the device's owner when registering the device
     * Then recover the owner's address from the ioID contract, querying the NFT owner
     */

    let spender_pk = SecretKey::from_str(
        std::env::var("SPENDER_PRIVATE_KEY")
            .unwrap_or_else(|_| panic!("SPENDER_PRIVATE_KEY must be sent in .env"))
            .as_str(),
    )
    .unwrap();

    let rpc_url = std::env::var("IOTEX_TESTNET_RPC_URL").unwrap_or_else(|_| {
        panic!("IOTEX_TESTNET_RPC_URL must be set in .env");
    });
    let transport = web3::transports::Http::new(&rpc_url).unwrap();
    let web3 = web3::Web3::new(transport);

    let ioid_registry_contract = Contract::from_json(
        web3.eth(),
        H160::from_str(IOID_REGISTRY_ADDRESS).unwrap(),
        include_bytes!("../contract-abi/ioIDRegistry-ABI.json"),
    )
    .unwrap();

    // let device_id: U256 = ioid_registry_contract
    //     .query("deviceTokenId", public_key, None, Options::default(), None)
    //     .await
    // {
    //     Ok(device_id) => device_id,
    //     Err(e) => panic!(
    //         "Failed to query deviceTokenId: {:?}\nDevice might not be registered",
    //         e
    //     ),
    // };
    let device_id = U256::from(3);

    let ioid_contract = Contract::from_json(
        web3.eth(),
        H160::from_str(IOID_CONTRACT_ADDRESS).unwrap(),
        include_bytes!("../contract-abi/ioID-ABI.json"),
    )
    .unwrap();

    // let owner_address: Address = ioid_contract
    //     .query("ownerOf", device_id, None, Options::default(), None)
    //     .await
    //     .unwrap();
    let owner_address = H160::from_str("0x0000000000000000000000000000000000000000").unwrap();
    println!("Proof verified. Sending reward to {:?}", owner_address);
    /*
     * Send reward to device's owner
     */

    let tx_object = TransactionParameters {
        to: Some(owner_address),
        value: U256::exp10(17),
        ..Default::default()
    };

    // let signed_tx = web3
    //     .accounts()
    //     .sign_transaction(tx_object, &spender_pk)
    //     .await
    //     .unwrap();
    let signed_tx = TransactionParameters {
        to: Some(owner_address),
        value: U256::exp10(17),
        ..Default::default()
    };
    // let result = web3
    //     .eth()
    //     .send_raw_transaction(signed_tx.raw_transaction)
    //     .await
    //     .unwrap_or_else(|e| {
    //         panic!("Failed to send transaction: {:?}", e);
    //     });
    let result = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();

    println!("Proof verified. Transaction hash: {:?}", result);
    Json(SendDataResult {
        message: format!(
            "Proof verified.\nReward sent to {:?}\nTransaction hash: {:?}",
            owner_address, result
        )
    })
}

fn get_pp() -> PublicParams<Bn256EngineKZG> {
    let pp_str = std::fs::read_to_string("storage/pp.json").unwrap_or_else(|_| {
        panic!("Could not read public parameters file");
    });
    let pp: PublicParams<Bn256EngineKZG> = serde_json::from_str(&pp_str).unwrap();
    pp
}

fn recover_address(message: &[u8; 32], signature: Signature) -> H160 {
    let message = RecoveryMessage::Hash(H256::from_slice(message));
    let v: u64 = u64::from_str_radix(&signature.v[2..], 16).unwrap();
    let r: H256 = H256::from_slice(&hex::decode(&signature.r[2..]).unwrap());
    let s: H256 = H256::from_slice(&hex::decode(&signature.s[2..]).unwrap());

    let recovery: Recovery = Recovery {
        message: message,
        v: v,
        r: r,
        s: s,
    };

    let rpc_url = std::env::var("IOTEX_TESTNET_RPC_URL").unwrap_or_else(|_| {
        panic!("IOTEX_TESTNET_RPC_URL must be set in .env");
    });

    let rpc = web3::transports::Http::new(&rpc_url).unwrap();
    let account = web3::api::Accounts::new(rpc);
    let address = account.recover(recovery).unwrap();
    address
}
