require("@nomicfoundation/hardhat-toolbox");

require("dotenv").config();

module.exports = {
  networks: {
    iotex_testnet: {
      url: "https://babel-api.testnet.iotex.io",
      accounts: ["ee19147e85b07e448be482f7e7f946c6ac8692ba942891b9b6120d7d2aee1a98"]
    },
  },
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: true, // ✅ Enables IR compilation to reduce stack usage
    },
  },
};
