const hre = require("hardhat");

async function main() {
    const RewardDistributor = await hre.ethers.getContractFactory("IoTeXRewardDistributor");

    const contract = await RewardDistributor.deploy(
        "0xAD5f0101B94F581979AA22F123b7efd9501BfeB3", // OnchainVerifier contract
        "0x0A7e595C7889dF3652A19aF52C18377bF17e027D", // ioID Registry
        "0x45Ce3E6f526e597628c73B731a3e9Af7Fc32f5b7"  // ioID Contract
    );

    await contract.waitForDeployment();
    console.log("IoTeXRewardDistributor deployed at:", await contract.getAddress());
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
