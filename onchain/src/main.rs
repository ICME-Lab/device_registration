#![allow(non_snake_case)]

use std::str::FromStr;

use anyhow::Result;
use contracts::print_reward_contract_balance;
use proof::setup_decider;
use rand::thread_rng;

use radius_circuit::circuit::ProximityCircuit;

use nova::{onchain::utils::get_formatted_calldata, provider::Bn256EngineKZG, traits::Engine};

use test::run_test_onchain_reward;
use web3::types::TransactionReceipt;
use web3::{
    contract::{Contract, Error, Options},
    transports::Http,
    types::{H256, U256},
};

use crate::{
    calldata::{generate_iotex_reward_calldata, generate_iotex_verifier_calldata},
    contracts::{get_nova_decider_contract, get_reward_distributor_contract},
    proof::{generate_decider_proof, generate_rs_proof, sign_proof_with_device, verify_proof},
    solidity::generate_solidity_verifier,
};

pub mod calldata;
pub mod constants;
pub mod contracts;
pub mod proof;
pub mod solidity;
pub mod test;
pub mod utils;

pub async fn run_onchain_verification(
    nova_decider_contract: Contract<Http>,
    verifier_calldata: (
        [U256; 3],
        [U256; 4],
        [U256; 2],
        [U256; 3],
        [U256; 2],
        [[U256; 2]; 2],
        [U256; 2],
        [U256; 4],
        [[U256; 2]; 2],
    ),
) -> Result<bool, Error> {
    nova_decider_contract
        .query(
            "verifyNovaProof",
            verifier_calldata,
            None,
            Options::default(),
            None,
        )
        .await
}

pub async fn run_onchain_reward(
    reward_distributor_contract: Contract<Http>,
    reward_calldata: (
        [U256; 3],
        [U256; 4],
        [U256; 2],
        [U256; 3],
        [U256; 2],
        [[U256; 2]; 2],
        [U256; 2],
        [U256; 4],
        [[U256; 2]; 2],
        H256,
        u8,
        H256,
        H256,
    ),
) -> Result<H256> {
    let options = Options {
        value: None,
        gas: Some(U256::from_dec_str("500000").unwrap()), 
        ..Default::default()
    };

    let secp_secret_key = web3::signing::SecretKey::from_str(
        "ee19147e85b07e448be482f7e7f946c6ac8692ba942891b9b6120d7d2aee1a98",
    )
    .expect("Invalid private key");

    let res_tx_hash: Result<TransactionReceipt, Error> = reward_distributor_contract
        .signed_call_with_confirmations(
            "verifyAndReward",
            reward_calldata,
            options,
            2,
            &secp_secret_key,
        )
        .await
        .map_err(|e| Error::from(e));

    // Wait for 5 seconds
    // tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    match res_tx_hash {
        Ok(receipt) => {
            let pretty_receipt = serde_json::to_string_pretty(&receipt)
                .unwrap_or_else(|_| "Failed to serialize receipt".to_string());
            println!("Successfully sent transaction");
            println!("Transaction Receipt: {}", pretty_receipt);
            Ok(receipt.transaction_hash)
        }
        Err(e) => {
            println!("Error sending transaction: {:?}", e);
            Err(anyhow::anyhow!("Error sending transaction: {:?}", e))
        }
    }
}


async fn generate_onchain_verifier_contract() -> Result<(Vec<u8>, [u8; 32], utils::Signature)> {
    let latitude = 4990;
    let longitude = 5010;

    let circuit = ProximityCircuit::new(
        <<Bn256EngineKZG as Engine>::Scalar>::from(latitude as u64),
        <<Bn256EngineKZG as Engine>::Scalar>::from(longitude as u64),
    );

    // ------------------------------------------------------------
    // Generate recursive zkSNARK
    // Check that the device location is within a radius of 100 
    // from the point at (5000, 5000), without revealing the location
    // ------------------------------------------------------------
    let (rs, rs_pp) = generate_rs_proof(circuit);
    // ------------------------------------------------------------
    // Compress zkSNARK
    // ------------------------------------------------------------
    let mut rng = thread_rng();
    let decider_vk = setup_decider(rs_pp.clone(), &mut rng);
    let compressed_snark = generate_decider_proof(rs, rs_pp, &mut rng);
    // ------------------------------------------------------------
    // Sign proof with device
    // ------------------------------------------------------------
    let (hash, signature) = sign_proof_with_device(&compressed_snark);
    assert!(verify_proof(&compressed_snark, &decider_vk));
    // ------------------------------------------------------------
    // Generate solidity verifier and calldata
    // ------------------------------------------------------------
    let calldata = generate_solidity_verifier(&compressed_snark, &decider_vk);
    Ok((calldata, hash, signature))
}

#[tokio::main]
async fn main() -> Result<()> {
    let (calldata, hash, signature) = generate_onchain_verifier_contract().await?;
    // ------------------------------------------------------------
    // Prepare calldata for iotex
    // ------------------------------------------------------------
    let formatted_calldata = get_formatted_calldata(calldata.clone());
    let verifier_calldata = generate_iotex_verifier_calldata(&formatted_calldata);
    let reward_calldata = generate_iotex_reward_calldata(&formatted_calldata, signature, hash);
    // ------------------------------------------------------------
    // Run onchain verifier contract (test)
    // ------------------------------------------------------------
    let nova_decider_contract = get_nova_decider_contract()?;
    let onchain_verification =
    run_onchain_verification(nova_decider_contract, verifier_calldata).await?;
    assert!(onchain_verification);
    // ------------------------------------------------------------
    // Run onchain verification and rewards contract
    // ------------------------------------------------------------
    let reward_distributor_contract = get_reward_distributor_contract()?;
    print_reward_contract_balance(&reward_distributor_contract).await;
    run_test_onchain_reward(reward_distributor_contract.clone(), reward_calldata).await;
    let onchain_reward = run_onchain_reward(reward_distributor_contract, reward_calldata).await?;
    println!("Transaction hash: {:?}", onchain_reward);
    Ok(())
}
