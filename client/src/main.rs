use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json;

use ff::Field;
use radius_circuit::circuit::ProximityCircuit;
use sha2::{self, Digest};

use nova::{
    provider, spartan,
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<G1> = spartan::ppsnark::RelaxedR1CSSNARK<G1, EE1<G1>>;
type S2Prime<G2> = spartan::ppsnark::RelaxedR1CSSNARK<G2, EE2<G2>>;

pub mod utils;
use utils::sign;

#[derive(Serialize)]
struct SendDataBody {
    snark: CompressedSNARK<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
        S1Prime<G1>,
        S2Prime<G2>,
    >,
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
        <<G1 as Group>::Scalar>::from(latitude as u64),
        <<G1 as Group>::Scalar>::from(longitude as u64),
    );
    let circuit_secondary = TrivialTestCircuit::default();

    println!("Producing public parameters...");
    // produce public parameters
    let pp = PublicParams::<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
    >::setup(circuit_primary.clone(), circuit_secondary.clone());

    let num_steps = 1;

    // produce a recursive SNARK
    let mut recursive_snark = RecursiveSNARK::<
        G1,
        G2,
        ProximityCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
    >::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        vec![<G1 as Group>::Scalar::ZERO],
        vec![<G2 as Group>::Scalar::ONE],
    );

    for _i in 0..num_steps {
        let res = recursive_snark.prove_step(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            vec![<G1 as Group>::Scalar::ZERO],
            vec![<G2 as Group>::Scalar::ONE],
        );
        assert!(res.is_ok());
    }

    // verify the recursive SNARK
    let res = recursive_snark.verify(
        &pp,
        num_steps,
        &[<G1 as Group>::Scalar::ZERO],
        &[<G2 as Group>::Scalar::ONE],
    );
    assert!(res.is_ok());

    // produce the prover and verifier keys for compressed snark
    let (pk, _vk) = CompressedSNARK::<_, _, _, _, S1Prime<G1>, S2Prime<G2>>::setup(&pp).unwrap();

    // produce a compressed SNARK
    let res =
        CompressedSNARK::<_, _, _, _, S1Prime<G1>, S2Prime<G2>>::prove(&pp, &pk, &recursive_snark);
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
