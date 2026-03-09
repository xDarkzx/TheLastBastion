/**
 * Checks wallet balance on Polygon Amoy.
 *
 * Usage: npx hardhat run scripts/check-balance.js --network amoy
 */
const hre = require("hardhat");

async function main() {
    const signers = await hre.ethers.getSigners();
    if (!signers || signers.length === 0) {
        throw new Error("No signers. Check PRIVATE_KEY in .env");
    }

    const deployer = signers[0];
    const balance = await hre.ethers.provider.getBalance(deployer.address);
    const balanceEth = hre.ethers.formatEther(balance);

    console.log("=".repeat(40));
    console.log("Wallet:", deployer.address);
    console.log("Balance:", balanceEth, "POL");
    console.log("Chain ID:", (await hre.ethers.provider.getNetwork()).chainId.toString());
    console.log("=".repeat(40));

    if (parseFloat(balanceEth) < 0.01) {
        console.log("\n⚠️  LOW BALANCE — Get testnet POL:");
        console.log("  https://faucet.polygon.technology/");
        console.log("  https://www.alchemy.com/faucets/polygon-amoy");
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
