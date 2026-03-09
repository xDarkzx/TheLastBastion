/**
 * Deploys SwarmProofRegistry to Polygon Amoy testnet.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network amoy
 *
 * After deployment, set PROOF_REGISTRY_ADDRESS in your .env files:
 *   - contracts/.env
 *   - project root .env
 */
const hre = require("hardhat");

async function main() {
    console.log("=".repeat(60));
    console.log("The Last Bastion Proof Registry — Deployment");
    console.log("=".repeat(60));

    const signers = await hre.ethers.getSigners();
    if (!signers || signers.length === 0) {
        throw new Error("No signers available. Check PRIVATE_KEY in .env");
    }

    const deployer = signers[0];
    console.log("\nDeployer:", deployer.address);

    const balance = await hre.ethers.provider.getBalance(deployer.address);
    const balanceEth = hre.ethers.formatEther(balance);
    console.log("Balance:", balanceEth, "POL");

    if (parseFloat(balanceEth) < 0.01) {
        console.log("\n⚠️  LOW BALANCE — Get testnet POL from:");
        console.log("  https://faucet.polygon.technology/ (select Amoy)");
        console.log("  https://www.alchemy.com/faucets/polygon-amoy\n");
        throw new Error("Insufficient balance for deployment");
    }

    console.log("\nDeploying SwarmProofRegistry...");
    const Factory = await hre.ethers.getContractFactory("SwarmProofRegistry");
    const contract = await Factory.deploy({
        maxPriorityFeePerGas: hre.ethers.parseUnits("30", "gwei"),
        maxFeePerGas: hre.ethers.parseUnits("50", "gwei"),
    });

    await contract.waitForDeployment();
    const address = await contract.getAddress();

    console.log("\n" + "=".repeat(60));
    console.log("✅ SwarmProofRegistry deployed!");
    console.log("=".repeat(60));
    console.log(`\nContract Address: ${address}`);
    console.log(`\nAdd to your .env files:`);
    console.log(`  PROOF_REGISTRY_ADDRESS=${address}`);
    console.log("=".repeat(60));

    // Wait for confirmations
    console.log("\nWaiting for 5 block confirmations...");
    await contract.deploymentTransaction().wait(5);

    // Verify on Polygonscan
    console.log("Verifying on Polygonscan...");
    try {
        await hre.run("verify:verify", {
            address: address,
            constructorArguments: [],
        });
        console.log("✅ Contract verified on Polygonscan!");
        console.log(
            `   View: https://amoy.polygonscan.com/address/${address}`
        );
    } catch (error) {
        console.log("⚠️  Auto-verification failed:", error.message);
        console.log("   Verify manually:");
        console.log(`   npx hardhat verify --network amoy ${address}`);
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
