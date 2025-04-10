use web3::types::{H256, U256};

use crate::utils::Signature;

pub fn generate_iotex_verifier_calldata(
    formatted_calldata: &Vec<String>,
) -> (
    [U256; 3],
    [U256; 4],
    [U256; 2],
    [U256; 3],
    [U256; 2],
    [[U256; 2]; 2],
    [U256; 2],
    [U256; 4],
    [[U256; 2]; 2],
) {
    // Convert calldata slices into fixed-size arrays
    let i_z0_zi: [U256; 3] = [
        U256::from_dec_str(&formatted_calldata[0]).unwrap(),
        U256::from_dec_str(&formatted_calldata[1]).unwrap(),
        U256::from_dec_str(&formatted_calldata[2]).unwrap(),
    ];

    let U_i_cmW_U_i_cmE: [U256; 4] = [
        U256::from_dec_str(&formatted_calldata[3]).unwrap(),
        U256::from_dec_str(&formatted_calldata[4]).unwrap(),
        U256::from_dec_str(&formatted_calldata[5]).unwrap(),
        U256::from_dec_str(&formatted_calldata[6]).unwrap(),
    ];


    let u_i_cmW: [U256; 2] = [
        U256::from_dec_str(&formatted_calldata[7]).unwrap(),
        U256::from_dec_str(&formatted_calldata[8]).unwrap(),
    ];


    let cmT_r: [U256; 3] = [
        U256::from_dec_str(&formatted_calldata[9]).unwrap(),
        U256::from_dec_str(&formatted_calldata[10]).unwrap(),
        U256::from_dec_str(&formatted_calldata[11]).unwrap(),
    ];


    let pA: [U256; 2] = [
        U256::from_dec_str(&formatted_calldata[12]).unwrap(),
        U256::from_dec_str(&formatted_calldata[13]).unwrap(),
    ];

    let pB: [[U256; 2]; 2] = [
        [
            U256::from_dec_str(&formatted_calldata[14]).unwrap(),
            U256::from_dec_str(&formatted_calldata[15]).unwrap(),
        ],
        [
            U256::from_dec_str(&formatted_calldata[16]).unwrap(),
            U256::from_dec_str(&formatted_calldata[17]).unwrap(),
        ],
    ];

    let pC: [U256; 2] = [
        U256::from_dec_str(&formatted_calldata[18]).unwrap(),
        U256::from_dec_str(&formatted_calldata[19]).unwrap(),
    ];


    let challenge_W_challenge_E_kzg_evals: [U256; 4] = [
        U256::from_dec_str(&formatted_calldata[20]).unwrap(),
        U256::from_dec_str(&formatted_calldata[21]).unwrap(),
        U256::from_dec_str(&formatted_calldata[22]).unwrap(),
        U256::from_dec_str(&formatted_calldata[23]).unwrap(),
    ];



    let kzg_proof: [[U256; 2]; 2] = [
        [
            U256::from_dec_str(&formatted_calldata[24]).unwrap(),
            U256::from_dec_str(&formatted_calldata[25]).unwrap(),
        ],
        [
            U256::from_dec_str(&formatted_calldata[26]).unwrap(),
            U256::from_dec_str(&formatted_calldata[27]).unwrap(),
        ],
    ];

    (
        i_z0_zi,
        U_i_cmW_U_i_cmE,
        u_i_cmW,
        cmT_r,
        pA,
        pB,
        pC,
        challenge_W_challenge_E_kzg_evals,
        kzg_proof,
    )
}

pub fn generate_iotex_reward_calldata(
    formatted_calldata: &Vec<String>,
    signature: Signature,
    hash: [u8; 32],
) -> (
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
) {
    let (
        i_z0_zi,
        U_i_cmW_U_i_cmE,
        u_i_cmW,
        cmT_r,
        pA,
        pB,
        pC,
        challenge_W_challenge_E_kzg_evals,
        kzg_proof,
    ) = generate_iotex_verifier_calldata(formatted_calldata);
    // Convert [u8; 32] to H256
    let hash_h256: H256 = H256::from_slice(&hash);

    // Convert `v` (String hex -> u8)
    let signature_v: u8 =
        u8::from_str_radix(signature.v.trim_start_matches("0x"), 16).expect("Invalid v format");

    // Convert `r` and `s` (String hex -> H256)
    let signature_r: H256 =
        H256::from_slice(&hex::decode(signature.r.trim_start_matches("0x")).expect("Invalid r"));

    let signature_s: H256 =
        H256::from_slice(&hex::decode(signature.s.trim_start_matches("0x")).expect("Invalid s"));

    (
        i_z0_zi,
        U_i_cmW_U_i_cmE,
        u_i_cmW,
        cmT_r,
        pA,
        pB,
        pC,
        challenge_W_challenge_E_kzg_evals,
        kzg_proof,
        hash_h256,
        signature_v,
        signature_r,
        signature_s,
    )
}