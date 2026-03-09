/**
 * Anchors a test proof record on-chain to verify the contract works.
 *
 * Usage:
 *   Set PROOF_REGISTRY_ADDRESS in .env first, then:
 *   npx hardhat run scripts/anchor-test.js --network amoy
 */
const hre = require("hardhat");
const crypto = require("crypto");

async function main() {
    const contractAddress = process.env.PROOF_REGISTRY_ADDRESS;

    if (!contractAddress) {
        console.error("❌ PROOF_REGISTRY_ADDRESS not set in .env");
        process.exit(1);
    }

    console.log("=".repeat(60));
    console.log("The Last Bastion — Anchor Test");
    console.log("=".repeat(60));
    console.log("Contract:", contractAddress);

    const Factory = await hre.ethers.getContractFactory("SwarmProofRegistry");
    const contract = Factory.attach(contractAddress);

    // Generate test proof data (mimics what ProofRecord.to_smart_contract_args() produces)
    const payloadHash = "0x" + crypto.createHash("sha256").update("test-payload").digest("hex");
    const evidenceHash = "0x" + crypto.createHash("sha256").update("test-evidence").digest("hex");
    const provenanceHash = "0x" + "0".repeat(64); // No attestation
    const previousHash = "0x" + "0".repeat(64);    // Genesis
    const blockHash = "0x" + crypto.createHash("sha256")
        .update(payloadHash + evidenceHash + Date.now().toString())
        .digest("hex");

    const verdict = 2; // VERIFIED
    const score = 850000; // 0.85 × 1e6
    const timestamp = Math.floor(Date.now() / 1000);

    console.log("\nAnchoring test proof:");
    console.log("  Payload hash:", payloadHash.slice(0, 18) + "...");
    console.log("  Block hash:  ", blockHash.slice(0, 18) + "...");
    console.log("  Verdict:      VERIFIED (2)");
    console.log("  Score:        0.850000");

    const tx = await contract.anchorProof(
        payloadHash,
        evidenceHash,
        provenanceHash,
        previousHash,
        blockHash,
        verdict,
        score,
        timestamp,
        {
            maxPriorityFeePerGas: hre.ethers.parseUnits("30", "gwei"),
            maxFeePerGas: hre.ethers.parseUnits("50", "gwei"),
        }
    );

    console.log("\nTransaction sent:", tx.hash);
    console.log("Waiting for confirmation...");

    const receipt = await tx.wait();
    console.log("✅ Confirmed in block:", receipt.blockNumber);
    console.log("   Gas used:", receipt.gasUsed.toString());

    // Verify the proof on-chain
    console.log("\nVerifying on-chain...");
    const [exists, retVerdict, retScore, retTimestamp, retPayloadHash] =
        await contract.verifyProof(blockHash);

    console.log("  Exists:", exists);
    console.log("  Verdict:", retVerdict, "(2 = VERIFIED)");
    console.log("  Score:", Number(retScore) / 1000000);
    console.log("  Timestamp:", new Date(Number(retTimestamp) * 1000).toISOString());

    // Get chain stats
    const chainLen = await contract.chainLength();
    const [rejected, quarantined, verified, gold] = await contract.getVerdictCounts();

    console.log("\nOn-chain stats:");
    console.log("  Total proofs:", chainLen.toString());
    console.log("  REJECTED:", rejected.toString());
    console.log("  QUARANTINE:", quarantined.toString());
    console.log("  VERIFIED:", verified.toString());
    console.log("  GOLD:", gold.toString());

    console.log("\n" + "=".repeat(60));
    console.log("✅ Anchor test PASSED — contract is working on-chain!");
    console.log("=".repeat(60));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
