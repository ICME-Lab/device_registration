use anyhow::Result;
use halo2curves::bn256::Bn256;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json;

use ff::Field;
use radius_circuit::circuit::ProximityCircuit;
use sha2::{self, Digest};

use nova::{
    nebula::rs::{PublicParams, RecursiveSNARK},
    onchain::decider::Decider,
    provider::{Bn256EngineKZG, GrumpkinEngine},
    traits::{snark::RelaxedR1CSSNARKTrait, Engine},
};

type E1 = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = nova::provider::hyperkzg::EvaluationEngine<Bn256, E1>;
type EE2 = nova::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = nova::spartan::snark::RelaxedR1CSSNARK<E1, EE1>; // non-preprocessing SNARK
type S2 = nova::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; // non-preprocessing SNARK

pub mod utils;
use utils::sign;

#[derive(Serialize)]
struct SendDataBody {
    snark: Decider,
    signature: Signature,
}

#[derive(Serialize)]
struct Signature {
    v: String,
    r: String,
    s: String,
}

#[derive(Deserialize)]
struct SendDataResult {
    message: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let latitude = 4990;
    let longitude = 5010;

    // create signing circuit
    // checks that the input is in a radius of 100 from the point at (5000, 5000), hardcoded in the circuit definition
    let circuit = ProximityCircuit::new(
        <<E1 as Engine>::Scalar>::from(latitude as u64),
        <<E1 as Engine>::Scalar>::from(longitude as u64),
    );

    println!("Producing public parameters...");
    // produce public parameters
    let rs_pp = PublicParams::<E1>::setup(&circuit.clone(), &*S1::ck_floor(), &*S2::ck_floor());

    let num_steps = 3;
    let z0 = [<E1 as Engine>::Scalar::ZERO];

    // produce a recursive SNARK
    let mut rs = RecursiveSNARK::<E1>::new(&rs_pp, &circuit, &z0).unwrap();
    let mut ic_i = <E1 as Engine>::Scalar::ZERO;
    for _i in 0..num_steps {
        rs.prove_step(&rs_pp, &circuit, ic_i).unwrap();

        ic_i = rs.increment_commitment(&rs_pp, &circuit);
    }

    // verify the recursive SNARK
    let res = rs.verify(&rs_pp, num_steps, &z0, ic_i);
    assert!(res.is_ok());
    println!("RecursiveSNARK::verify: {:?}", res.is_ok(),);

    let zn = res.unwrap();
    // sanity: check the claimed output with a direct computation of the same
    assert_eq!(zn, vec![<E1 as Engine>::Scalar::ONE]);
    let mut rng = thread_rng();

    // produce the prover and verifier keys for compressed snark
    let (decider_pk, _decider_vk) = Decider::setup(&rs_pp, &mut rng, z0.len()).unwrap();

    // produce a compressed SNARK
    let res = Decider::prove(&rs_pp, &decider_pk, &rs, &mut rng);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    /*
     * SENDING PROOF TO DEVICE TO BE SIGNED
     */

    // compute proof hash
    let proof_serialized = serde_json::to_string(&compressed_snark).expect("JSON serialization");
    let hash = sha2::Sha256::digest(proof_serialized.as_bytes());
    let hash: [u8; 32] = hash.into();

    // send proof_serialized to device ( DEVICE_URL ), receive signature
    println!("Sending hash to device to be signed...");
    let (v, r, s) = sign("0x".to_owned() + &hex::encode(hash));
    println!("Signature: \nv: {}, \nr: {}, \ns: {}", v, r, s);

    let signature = Signature { v, r, s };

    /*
     * SEND TO SERVER FOR VERIFICATION
     * The server will verify the proof, recover the signer's public key using the signature
     *
     * TODO: then request the ioID contract to recover the device's owner, to send him the reward
     */

    let body = SendDataBody {
        snark: compressed_snark,
        signature: signature,
    };

    println!("Sending proof and signature to server...");
    let client = reqwest::Client::new();
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
