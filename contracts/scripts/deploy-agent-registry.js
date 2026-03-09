/**
 * Deploys SwarmAgentRegistry to Polygon Amoy testnet.
 *
 * Usage:
 *   npx hardhat run scripts/deploy-agent-registry.js --network amoy
 *
 * After deployment, set AGENT_REGISTRY_ADDRESS in your .env files:
 *   - contracts/.env
 *   - project root .env
 *
 * This is the M2M agent marketplace contract — separate from SwarmProofRegistry
 * which handles data verification proofs.
 */
const hre = require("hardhat");

async function main() {
    console.log("=".repeat(60));
    console.log("The Last Bastion Agent Registry — Deployment");
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

    // Check if SwarmProofRegistry is already deployed
    const proofRegistryAddr = process.env.PROOF_REGISTRY_ADDRESS;
    if (proofRegistryAddr) {
        console.log("\nExisting SwarmProofRegistry:", proofRegistryAddr);
    } else {
        console.log("\n⚠️  SwarmProofRegistry not yet deployed (PROOF_REGISTRY_ADDRESS not set)");
    }

    console.log("\nDeploying SwarmAgentRegistry...");
    const Factory = await hre.ethers.getContractFactory("SwarmAgentRegistry");
    const contract = await Factory.deploy({
        maxPriorityFeePerGas: hre.ethers.parseUnits("30", "gwei"),
        maxFeePerGas: hre.ethers.parseUnits("50", "gwei"),
    });

    await contract.waitForDeployment();
    const address = await contract.getAddress();

    console.log("\n" + "=".repeat(60));
    console.log("✅ SwarmAgentRegistry deployed!");
    console.log("=".repeat(60));
    console.log(`\nContract Address: ${address}`);
    console.log(`\nAdd to your .env files:`);
    console.log(`  AGENT_REGISTRY_ADDRESS=${address}`);

    if (proofRegistryAddr) {
        console.log(`\nBoth contracts are now live:`);
        console.log(`  SwarmProofRegistry:  ${proofRegistryAddr}`);
        console.log(`  SwarmAgentRegistry:  ${address}`);
    }

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
