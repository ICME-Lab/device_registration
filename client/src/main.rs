use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;

use ff::Field;
use radius_circuit::circuit::ProximityCircuit;
use sha2::{self, Digest};

use nova::{
    provider::{self, PallasEngine, VestaEngine},
    spartan,
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};

type E1 = PallasEngine;
type E2 = VestaEngine;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<E> = spartan::ppsnark::RelaxedR1CSSNARK<E, EE1<E>>;
type S2Prime<E> = spartan::ppsnark::RelaxedR1CSSNARK<E, EE2<E>>;

pub mod utils;
use utils::sign;

#[derive(Serialize)]
struct SendDataBody {
    snark: CompressedSNARK<E1, S1Prime<E1>, S2Prime<E2>>,
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
    let circuit_primary = ProximityCircuit::new(
        <<E1 as Engine>::Scalar>::from(latitude as u64),
        <<E1 as Engine>::Scalar>::from(longitude as u64),
    );
    let circuit_secondary = TrivialCircuit::default();

    println!("Producing public parameters...");
    // produce public parameters
    let pp = PublicParams::<E1>::setup(
        &circuit_primary.clone(),
        &circuit_secondary.clone(),
        &*S1Prime::ck_floor(),
        &*S2Prime::ck_floor(),
    )
    .unwrap();

    let num_steps = 1;

    // produce a recursive SNARK
    let mut recursive_snark = RecursiveSNARK::<E1>::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        &[<E1 as Engine>::Scalar::ZERO],
        &[<E2 as Engine>::Scalar::ONE],
    )
    .unwrap();

    for _i in 0..num_steps {
        let _res = recursive_snark
            .prove_step(&pp, &circuit_primary, &circuit_secondary)
            .unwrap();
    }

    // verify the recursive SNARK
    let res = recursive_snark.verify(
        &pp,
        num_steps,
        &[<E1 as Engine>::Scalar::ZERO],
        &[<E2 as Engine>::Scalar::ONE],
    );
    assert!(res.is_ok());

    // produce the prover and verifier keys for compressed snark
    let (pk, _vk) = CompressedSNARK::<E1, S1Prime<E1>, S2Prime<E2>>::setup(&pp).unwrap();

    // produce a compressed SNARK
    let res = CompressedSNARK::<E1, S1Prime<E1>, S2Prime<E2>>::prove(&pp, &pk, &recursive_snark);
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
