// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SwarmProofRegistry
 * @author SwarmNet / Dan Hodgetts
 * @notice On-chain registry for data verification proof records.
 *
 * Every piece of data that passes through the SwarmNet verification
 * pipeline produces a ProofRecord. This contract stores those records
 * immutably so that ANYONE can verify:
 *   - Was this data verified by SwarmNet?
 *   - What was the verdict? (REJECTED / QUARANTINE / VERIFIED / GOLD)
 *   - What score did it receive?
 *   - When was it verified?
 *   - Is the hash chain intact?
 *
 * Architecture:
 *   Off-chain: VerificationPipeline → ProofLedger → batch records
 *   On-chain:  SwarmProofRegistry.anchorBatch(records)
 *   Verify:    SwarmProofRegistry.verifyProof(blockHash)
 *
 * This is NOT a token contract. It stores PROOF, not money.
 */
contract SwarmProofRegistry {

    // --- Types ---

    /// @notice Verdict codes matching the off-chain system
    enum Verdict {
        REJECTED,    // 0 — Data failed verification
        QUARANTINE,  // 1 — Data needs human review
        VERIFIED,    // 2 — Data passed verification
        GOLD         // 3 — Highest confidence
    }

    /// @notice A single proof record anchored on-chain
    struct ProofRecord {
        bytes32 payloadHash;     // SHA-256 of the original data
        bytes32 evidenceHash;    // SHA-256 of the evidence chain
        bytes32 provenanceHash;  // Attestation provenance (0x0 if none)
        bytes32 previousHash;    // Previous record in the chain
        bytes32 blockHash;       // This record's identity hash
        Verdict verdict;         // Verification outcome
        uint256 score;           // Score × 1e6 (6-decimal fixed point)
        uint256 timestamp;       // Unix timestamp of verification
        address submitter;       // Who submitted this proof
    }

    // --- State ---

    /// @notice Maps blockHash → ProofRecord for O(1) lookups
    mapping(bytes32 => ProofRecord) public proofs;

    /// @notice Ordered list of all block hashes (for chain replay)
    bytes32[] public proofChain;

    /// @notice Contract owner (SwarmNet regional core)
    address public owner;

    /// @notice Authorised submitters (SwarmNet nodes)
    mapping(address => bool) public authorisedSubmitters;

    /// @notice Total proofs anchored
    uint256 public totalProofs;

    /// @notice Counts by verdict type
    mapping(Verdict => uint256) public verdictCounts;

    // --- Events ---

    /// @notice Emitted when a proof is anchored on-chain
    event ProofAnchored(
        bytes32 indexed blockHash,
        bytes32 indexed payloadHash,
        Verdict verdict,
        uint256 score,
        uint256 timestamp,
        address submitter
    );

    /// @notice Emitted when a batch of proofs is anchored
    event BatchAnchored(
        uint256 batchSize,
        uint256 newTotal,
        address submitter
    );

    /// @notice Emitted when a submitter is authorised or revoked
    event SubmitterUpdated(address submitter, bool authorised);

    // --- Modifiers ---

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuthorised() {
        require(
            authorisedSubmitters[msg.sender] || msg.sender == owner,
            "Not authorised"
        );
        _;
    }

    // --- Constructor ---

    constructor() {
        owner = msg.sender;
        authorisedSubmitters[msg.sender] = true;
    }

    // --- Core Functions ---

    /**
     * @notice Anchor a single proof record on-chain.
     * @param payloadHash SHA-256 of the verified data
     * @param evidenceHash SHA-256 of the evidence chain
     * @param provenanceHash Attestation hash (0x0 if none)
     * @param previousHash Previous record's block hash
     * @param blockHash This record's computed block hash
     * @param verdict Verification outcome (0-3)
     * @param score Score × 1e6 (e.g., 850000 = 0.85)
     * @param timestamp Unix timestamp of verification
     */
    function anchorProof(
        bytes32 payloadHash,
        bytes32 evidenceHash,
        bytes32 provenanceHash,
        bytes32 previousHash,
        bytes32 blockHash,
        Verdict verdict,
        uint256 score,
        uint256 timestamp
    ) external onlyAuthorised {
        require(proofs[blockHash].timestamp == 0, "Proof already anchored");
        require(score <= 1000000, "Score exceeds maximum (1.0)");

        ProofRecord memory record = ProofRecord({
            payloadHash: payloadHash,
            evidenceHash: evidenceHash,
            provenanceHash: provenanceHash,
            previousHash: previousHash,
            blockHash: blockHash,
            verdict: verdict,
            score: score,
            timestamp: timestamp,
            submitter: msg.sender
        });

        proofs[blockHash] = record;
        proofChain.push(blockHash);
        totalProofs++;
        verdictCounts[verdict]++;

        emit ProofAnchored(
            blockHash,
            payloadHash,
            verdict,
            score,
            timestamp,
            msg.sender
        );
    }

    /**
     * @notice Anchor a batch of proof records in a single transaction.
     * @dev Gas-efficient: one transaction for multiple proofs.
     */
    function anchorBatch(
        bytes32[] calldata payloadHashes,
        bytes32[] calldata evidenceHashes,
        bytes32[] calldata provenanceHashes,
        bytes32[] calldata previousHashes,
        bytes32[] calldata blockHashes,
        Verdict[] calldata verdicts,
        uint256[] calldata scores,
        uint256[] calldata timestamps
    ) external onlyAuthorised {
        uint256 len = payloadHashes.length;
        require(
            len == evidenceHashes.length &&
            len == provenanceHashes.length &&
            len == previousHashes.length &&
            len == blockHashes.length &&
            len == verdicts.length &&
            len == scores.length &&
            len == timestamps.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < len; i++) {
            // Skip already-anchored proofs (idempotent)
            if (proofs[blockHashes[i]].timestamp != 0) {
                continue;
            }

            require(scores[i] <= 1000000, "Score exceeds maximum");

            ProofRecord memory record = ProofRecord({
                payloadHash: payloadHashes[i],
                evidenceHash: evidenceHashes[i],
                provenanceHash: provenanceHashes[i],
                previousHash: previousHashes[i],
                blockHash: blockHashes[i],
                verdict: verdicts[i],
                score: scores[i],
                timestamp: timestamps[i],
                submitter: msg.sender
            });

            proofs[blockHashes[i]] = record;
            proofChain.push(blockHashes[i]);
            totalProofs++;
            verdictCounts[verdicts[i]]++;

            emit ProofAnchored(
                blockHashes[i],
                payloadHashes[i],
                verdicts[i],
                scores[i],
                timestamps[i],
                msg.sender
            );
        }

        emit BatchAnchored(len, totalProofs, msg.sender);
    }

    // --- Query Functions (Public, No Gas) ---

    /**
     * @notice Verify if a proof hash exists on-chain.
     * @param blockHash The proof record's block hash
     * @return exists Whether the proof exists
     * @return verdict The verification verdict
     * @return score The verification score (× 1e6)
     * @return timestamp When it was verified
     */
    function verifyProof(bytes32 blockHash)
        external
        view
        returns (
            bool exists,
            Verdict verdict,
            uint256 score,
            uint256 timestamp,
            bytes32 payloadHash
        )
    {
        ProofRecord storage record = proofs[blockHash];
        if (record.timestamp == 0) {
            return (false, Verdict.REJECTED, 0, 0, bytes32(0));
        }
        return (
            true,
            record.verdict,
            record.score,
            record.timestamp,
            record.payloadHash
        );
    }

    /**
     * @notice Get the full proof record for a hash.
     * @param blockHash The proof record's block hash
     */
    function getProof(bytes32 blockHash)
        external
        view
        returns (ProofRecord memory)
    {
        require(proofs[blockHash].timestamp != 0, "Proof not found");
        return proofs[blockHash];
    }

    /**
     * @notice Get the current chain length.
     */
    function chainLength() external view returns (uint256) {
        return proofChain.length;
    }

    /**
     * @notice Get verdict counts for dashboard reporting.
     */
    function getVerdictCounts()
        external
        view
        returns (
            uint256 rejected,
            uint256 quarantined,
            uint256 verified,
            uint256 gold
        )
    {
        return (
            verdictCounts[Verdict.REJECTED],
            verdictCounts[Verdict.QUARANTINE],
            verdictCounts[Verdict.VERIFIED],
            verdictCounts[Verdict.GOLD]
        );
    }

    // --- Admin Functions ---

    /**
     * @notice Authorise or revoke a submitter address.
     */
    function setSubmitter(address submitter, bool authorised)
        external
        onlyOwner
    {
        authorisedSubmitters[submitter] = authorised;
        emit SubmitterUpdated(submitter, authorised);
    }

    /**
     * @notice Transfer ownership.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
