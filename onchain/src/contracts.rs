use web3::contract::Options;
use web3::{contract::Contract, transports::Http};
use anyhow::Result;
use std::env;
use std::{fs::File, str::FromStr};
use std::io::Read;
use serde_json::Value;
use web3::types::{H160, U256};

use crate::constants::{NOVA_DECIDER_CONTRACT_ADDRESS, REWARD_DISTRIBUTOR_CONTRACT_ADDRESS, RPC_URL};

pub fn get_nova_decider_contract() -> Result<Contract<Http>> {
    let transport = web3::transports::Http::new(RPC_URL).unwrap();
    let web3 = web3::Web3::new(transport);
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let mut abi_file =
        File::open(format!("{}/hardhat/artifacts/contracts/OnchainVerifier.sol/NovaDecider.json", manifest_dir)).unwrap();
    let mut abi_json = String::new();
    abi_file.read_to_string(&mut abi_json).unwrap();

    let abi: Value = serde_json::from_str(&abi_json)?;

    let abi_array = abi["abi"].to_string();

    std::fs::write("contract-abi/nova_decider_abi.json", abi_array.clone()).unwrap();
    let nova_decider_contract = Contract::from_json(
        web3.eth(),
        H160::from_str(NOVA_DECIDER_CONTRACT_ADDRESS).unwrap(),
        abi_array.as_bytes(),
    )
    .unwrap();

    println!(
        "Nova Decider Contract address: {:?}",
        nova_decider_contract.address()
    );

    Ok(nova_decider_contract)
}

pub fn get_reward_distributor_contract() -> Result<Contract<Http>> {
    let transport = web3::transports::Http::new(RPC_URL).unwrap();
    let web3 = web3::Web3::new(transport);
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let abi_file_path = format!("{}/hardhat/artifacts/contracts/DemoOnchainRewards.sol/IoTeXRewardDistributor.json", manifest_dir);
    println!("abi_file_path: {:?}", abi_file_path);
    let mut abi_file = File::open(abi_file_path).unwrap();
    let mut abi_json = String::new();
    abi_file.read_to_string(&mut abi_json).unwrap();

    let abi: Value = serde_json::from_str(&abi_json)?;
    let abi_array = abi["abi"].to_string();

    std::fs::write("contract-abi/nova_iotex_reward_abi.json", abi_array.clone()).unwrap();

    let reward_distributor_contract = Contract::from_json(
        web3.eth(),
        H160::from_str(REWARD_DISTRIBUTOR_CONTRACT_ADDRESS).unwrap(),
        abi_array.as_bytes(),
    )
    .unwrap();

    println!(
        "reward_distributor_contract: {:?}",
        reward_distributor_contract.address()
    );

    Ok(reward_distributor_contract)
}


pub async fn print_reward_contract_balance(reward_distributor_contract: &Contract<Http>) {
    let contract_balance: U256 = reward_distributor_contract
        .query("getContractBalance", (), None, Options::default(), None)
        .await
        .unwrap();

    println!("Contract balance: {:?}", contract_balance);

    let contract_address = reward_distributor_contract.address();

    println!("contract_address: {:?}", contract_address);
}