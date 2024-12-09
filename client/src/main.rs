use anyhow::Result;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json;

use ff::Field;
use nova_snark::traits::{circuit::TrivialTestCircuit, Group};
use radius_circuit::circuit::ProximityCircuit;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{self, Digest};

use nova_snark::{provider, spartan};
use nova_snark::{CompressedSNARK, PublicParams, RecursiveSNARK};

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;

type EE1<G1> = provider::ipa_pc::EvaluationEngine<G1>;
type EE2<G2> = provider::ipa_pc::EvaluationEngine<G2>;

type S1Prime<G1> = spartan::ppsnark::RelaxedR1CSSNARK<G1, EE1<G1>>;
type S2Prime<G2> = spartan::ppsnark::RelaxedR1CSSNARK<G2, EE2<G2>>;

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
    signature: String,
}

#[derive(Deserialize)]
struct SendDataResult {
    message: String,
}

const DEVICE_URL: &str = "http://127.0.0.1:8000";

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

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
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1Prime<G1>, S2Prime<G2>>::setup(&pp).unwrap();

    // produce a compressed SNARK
    let res =
        CompressedSNARK::<_, _, _, _, S1Prime<G1>, S2Prime<G2>>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    let res = compressed_snark.verify(
        &vk,
        num_steps,
        vec![<G1 as Group>::Scalar::ZERO],
        vec![<G2 as Group>::Scalar::ONE],
    );
    assert!(res.is_ok());

    /*
     * SENDING TO DEVICE TO SIGN
     */

    println!("Sending data to device...");

    let proof_serialized = serde_json::to_string(&compressed_snark).expect("JSON serialization");
    let hash = sha2::Sha256::digest(proof_serialized.as_bytes());
    let hash: [u8; 32] = hash.into();

    // send proof_serialized to device ( DEVICE_URL ), receive signature
    // currently simulating the signature
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("32 bytes, within curve order");
    let secp = Secp256k1::new();
    let message = Message::from_digest(hash);
    let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);
    let (rec_id, rec_sig) = signature.serialize_compact();
    let mut signature_slice = [0u8; 65];
    signature_slice[0] = rec_id as u8;
    signature_slice[1..].copy_from_slice(&rec_sig);
    let signature_str = hex::encode(signature_slice);

    /*
     * SEND TO SERVER FOR VERIFICATION
     * The server will verify the proof, recover the signer's public key using the signature
     * Then request the IOID contract to recover the device's owner, to send him the reward
     */

    let body = SendDataBody {
        snark: compressed_snark,
        signature: signature_str,
    };

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
