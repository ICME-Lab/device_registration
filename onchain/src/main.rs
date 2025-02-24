#![allow(non_snake_case)]

use std::str::FromStr;

use anyhow::Result;
use constants::RPC_URL;
use contracts::print_reward_contract_balance;
use proof::setup_decider;
use rand::thread_rng;

use radius_circuit::circuit::ProximityCircuit;
use sha2::{self, Digest};

use nova::{
    onchain::utils::get_formatted_calldata,
    provider::Bn256EngineKZG,
    traits::Engine,
};

use web3::{
    contract::Options,
    transports::Http,
    types::{H256, U256},
};
use web3::Web3;


use crate::{proof::{generate_rs_proof, generate_decider_proof, sign_proof_with_device, verify_proof}, calldata::{generate_iotex_verifier_calldata, generate_iotex_reward_calldata}, contracts::{get_reward_distributor_contract, get_nova_decider_contract}, solidity::generate_solidity_verifier};

pub mod utils;
pub mod calldata;
pub mod solidity;
pub mod proof;
pub mod contracts;
pub mod constants;


#[tokio::main]
async fn main() -> Result<()> {
    let latitude = 4990;
    let longitude = 5010;

    // create signing circuit
    // checks that the input is in a radius of 100 from the point at (5000, 5000), hardcoded in the circuit definition
    let circuit = ProximityCircuit::new(
        <<Bn256EngineKZG as Engine>::Scalar>::from(latitude as u64),
        <<Bn256EngineKZG as Engine>::Scalar>::from(longitude as u64),
    );

    let (rs, rs_pp) = generate_rs_proof(circuit);
    let mut rng = thread_rng();
    let decider_vk = setup_decider(rs_pp.clone(), &mut rng);
    let compressed_snark = generate_decider_proof(rs, rs_pp, &mut rng);
    let (hash, signature) = sign_proof_with_device(&compressed_snark);
    assert!(verify_proof(&compressed_snark, &decider_vk));
    let calldata = generate_solidity_verifier(&compressed_snark, &decider_vk);
    let formatted_calldata = get_formatted_calldata(calldata.clone());
    let verifier_calldata = generate_iotex_verifier_calldata(&formatted_calldata);
    let reward_calldata = generate_iotex_reward_calldata(&formatted_calldata, signature, hash);
    let reward_distributor_contract = get_reward_distributor_contract()?;
    let nova_decider_contract = get_nova_decider_contract()?;
    print_reward_contract_balance(&reward_distributor_contract).await;

    let options = Options {
        value: Some(U256::from_dec_str("1000000000000000000").unwrap()), // 1 IOTX in Wei
        // gas: Some(U256::from(500000)), // 500,000 gas (reasonable default)
        gas: Some(U256::from_dec_str("500000").unwrap()), // Optional, increase if needed
        // gas_price: Some(U256::from(1000000000)), // 1 Gwei
        ..Default::default()
    };

    let res_tx_hash: Result<bool, web3::contract::Error> = nova_decider_contract
        .query(
            "verifyNovaProof",
            verifier_calldata,
            None,
            Options::default(),
            None,
        )
        .await;
    match res_tx_hash {
        Ok(tx_hash) => println!("Transaction sent, hash: {:?}", tx_hash),
        Err(e) => println!("Error sending transaction: {:?}", e),
    }

    let secp_secret_key = web3::signing::SecretKey::from_str(
        "ee19147e85b07e448be482f7e7f946c6ac8692ba942891b9b6120d7d2aee1a98",
    )
    .expect("Invalid private key");

    let transport = Http::new(RPC_URL)?; // Replace with your Ethereum node URL
    let web3 = Web3::new(transport);

    let res_tx_hash: Result<H256, web3::Error> = reward_distributor_contract
        .signed_call(
            "verifyAndReward",
            reward_calldata,
            options.clone(),
            &secp_secret_key,
        )
        .await;

    // Wait for 5 seconds
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    match res_tx_hash {
        Ok(tx_hash) => {
            println!("Transaction sent, hash: {:?}", tx_hash);
            // Fetch transaction receipt
            match web3.eth().transaction_receipt(tx_hash).await? {
                Some(receipt) => {
                    println!("Transaction Receipt: {:?}", receipt);
                    if let Some(status) = receipt.status {
                        if status == 1.into() {
                            println!("✅ Transaction Successful!");
                        } else {
                            println!("❌ Transaction Failed!");
                            for log in receipt.logs {
                                println!("Log: {:?}", log);
                            }
                        }
                    }
                }
                None => println!("Transaction is still pending."),
            }
        }
        Err(e) => println!("Error sending transaction: {:?}", e),
    }
    Ok(())
}
