use std::env;

use nova::onchain::{compressed::{prepare_calldata, CompressedSNARK, CompressedVK}, eth::evm::{compile_solidity, Evm}, utils::{get_formatted_calldata, get_function_selector_for_nova_cyclefold_verifier}, verifiers::{groth16::SolidityGroth16VerifierKey, kzg::SolidityKZGVerifierKey, nebula::{get_decider_template_for_cyclefold_decider, NovaCycleFoldVerifierKey}}};


pub fn generate_solidity_verifier(
    compressed_snark: &CompressedSNARK,
    compressed_vk: &CompressedVK,
) -> Vec<u8> {
    // Now, let's generate the Solidity code that verifies this Decider final proof
    let function_selector =
        get_function_selector_for_nova_cyclefold_verifier(compressed_snark.z_0.len() * 2 + 1);

    let calldata: Vec<u8> = prepare_calldata(function_selector, &compressed_snark).unwrap();

    // prepare the setup params for the solidity verifier
    let nova_cyclefold_vk = NovaCycleFoldVerifierKey::from((
        compressed_vk.pp_hash,
        SolidityGroth16VerifierKey::from(compressed_vk.groth16_vk.clone()),
        SolidityKZGVerifierKey::from((compressed_vk.kzg_vk.clone(), Vec::new())),
        compressed_snark.z_0.len(),
    ));

    // generate the solidity code
    let decider_solidity_code = get_decider_template_for_cyclefold_decider(nova_cyclefold_vk);

    // verify the proof against the solidity code in the EVM
    let nova_cyclefold_verifier_bytecode = compile_solidity(&decider_solidity_code, "NovaDecider");
    let mut evm = Evm::default();

    let verifier_address = evm.create(nova_cyclefold_verifier_bytecode);
    // println!("verifier_address: {:?}", verifier_address);
    let (_gas, output) = evm.call(verifier_address, calldata.clone());
    // println!("Solidity::verify: {:?}, gas: {:?}", output, gas);
    assert_eq!(*output.last().unwrap(), 1);
    println!("Onchain verification successful");

    // save smart contract and the calldata
    // println!("storing OnchainVerifier.sol and the calldata into files");
    use std::fs;
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    fs::write(format!("{}/hardhat/contracts/OnchainVerifier.sol", manifest_dir), decider_solidity_code.clone())
        .expect("Unable to write to file");
    fs::write(format!("{}/hardhat/contracts/solidity-calldata.calldata", manifest_dir), calldata.clone()).expect("");
    let s = get_formatted_calldata(calldata.clone());
    fs::write(format!("{}/hardhat/contracts/solidity-calldata.inputs", manifest_dir), s.join(",\n")).expect("");

    calldata
}