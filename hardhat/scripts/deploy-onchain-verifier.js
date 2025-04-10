const hre = require("hardhat");

async function main() {
    const NovaDecider = await hre.ethers.getContractFactory("NovaDecider");
    const contract = await NovaDecider.deploy();
    // Wait for deployment to be mined
    const receipt = await contract.waitForDeployment();  

    console.log("Contract deployed to:", await receipt.getAddress()); 

}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});