// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SwarmAgentRegistry
 * @author SwarmNet / Dan Hodgetts
 * @notice On-chain registry for M2M agent identity, reputation, services, and task receipts.
 *
 * Companion contract to SwarmProofRegistry (which handles data verification proofs).
 * This contract handles the AGENT MARKETPLACE layer:
 *
 *   - Agent Identity:   "Is this agent real and registered?"
 *   - Reputation:       "Can I trust this agent?" (score 0–100, updated by SwarmNet)
 *   - Service Registry: "What does this agent offer?"
 *   - Task Receipts:    "Proof that a task was requested, executed, and settled."
 *
 * Architecture:
 *   Off-chain: protocols/registry.py + protocols/quotation.py + protocols/auth.py
 *   On-chain:  SwarmAgentRegistry (this contract) — immutable records
 *   Lookup:    Any agent can verify identity/reputation/task history (free, no gas)
 *
 * Credits and payments are managed OFF-CHAIN by QuotationEngine.
 * This contract only records RECEIPTS — proofs that transactions happened.
 *
 * Deployed on Polygon Amoy testnet alongside SwarmProofRegistry.
 */
contract SwarmAgentRegistry {

    // =========================================================================
    // Types
    // =========================================================================

    /// @notice Agent roles matching the off-chain AgentRole enum
    enum AgentRole {
        DATA_CONSUMER,   // 0 — Buys services
        DATA_PROVIDER,   // 1 — Sells data
        VERIFIER,        // 2 — Runs verification
        BROKER,          // 3 — Intermediary
        OBSERVER         // 4 — Read-only
    }

    /// @notice Agent status on-chain
    enum AgentStatus {
        ACTIVE,          // 0 — Normal operation
        SUSPENDED,       // 1 — Temporarily restricted
        REVOKED          // 2 — Permanently banned
    }

    /// @notice Task outcome matching the off-chain verdict system
    enum TaskOutcome {
        COMPLETED,       // 0 — Task succeeded
        FAILED,          // 1 — Task failed
        DISPUTED         // 2 — Under arbitration
    }

    /// @notice On-chain agent identity record
    struct AgentRecord {
        bytes32 agentIdHash;        // keccak256 of off-chain agent ID string
        bytes32 publicKeyHash;      // keccak256 of Ed25519 public key
        AgentRole role;             // Agent's role in the ecosystem
        AgentStatus status;         // Current standing
        uint256 reputationScore;    // 0–100 (updated by operator from off-chain verdicts)
        uint256 totalTasksCompleted;
        uint256 totalTasksFailed;
        uint256 totalCreditsEarned; // × 1e6 fixed-point (e.g., 5000000 = 5.0 credits)
        uint256 totalCreditsSpent;  // × 1e6 fixed-point
        uint256 registeredAt;       // Unix timestamp
        uint256 lastActiveAt;       // Unix timestamp of last task receipt
        address registeredBy;       // Which operator registered this agent
    }

    /// @notice On-chain service listing
    struct ServiceRecord {
        bytes32 serviceIdHash;      // keccak256 of service ID (e.g., "svc-data-extraction")
        bytes32 providerIdHash;     // keccak256 of provider agent ID
        uint256 priceCredits;       // Base price × 1e6
        bytes32[] tags;             // keccak256-hashed tag names
        bool isActive;
        uint256 registeredAt;
    }

    /// @notice On-chain task receipt — proof a service was performed
    struct TaskReceipt {
        bytes32 taskIdHash;         // keccak256 of off-chain task ID
        bytes32 consumerIdHash;     // Who requested the task
        bytes32 providerIdHash;     // Who performed the task
        bytes32 serviceIdHash;      // Which service was used
        uint256 creditsCharged;     // × 1e6 fixed-point
        TaskOutcome outcome;        // Task result
        bytes32 proofHash;          // Links to SwarmProofRegistry if verification was involved
        uint256 completedAt;        // Unix timestamp
        address recordedBy;         // Which operator recorded this
    }

    // =========================================================================
    // State
    // =========================================================================

    /// @notice Maps agentIdHash → AgentRecord for O(1) lookups
    mapping(bytes32 => AgentRecord) public agents;

    /// @notice Maps serviceIdHash → ServiceRecord
    mapping(bytes32 => ServiceRecord) public services;

    /// @notice Maps taskIdHash → TaskReceipt
    mapping(bytes32 => TaskReceipt) public taskReceipts;

    /// @notice Tracks all registered agent IDs for enumeration
    bytes32[] public agentIndex;

    /// @notice Tracks all registered service IDs
    bytes32[] public serviceIndex;

    /// @notice Tracks all task receipts
    bytes32[] public receiptIndex;

    /// @notice Contract owner (SwarmNet deployer)
    address public owner;

    /// @notice Authorised operators (SwarmNet regional cores)
    mapping(address => bool) public operators;

    /// @notice Global statistics
    uint256 public totalAgents;
    uint256 public totalServices;
    uint256 public totalReceipts;
    uint256 public totalCreditsTransacted; // × 1e6

    // =========================================================================
    // Events
    // =========================================================================

    /// @notice Emitted when a new agent is registered on-chain
    event AgentRegistered(
        bytes32 indexed agentIdHash,
        AgentRole role,
        uint256 timestamp,
        address registeredBy
    );

    /// @notice Emitted when an agent's reputation is updated
    event ReputationUpdated(
        bytes32 indexed agentIdHash,
        uint256 oldScore,
        uint256 newScore,
        address updatedBy
    );

    /// @notice Emitted when an agent's status changes
    event AgentStatusChanged(
        bytes32 indexed agentIdHash,
        AgentStatus oldStatus,
        AgentStatus newStatus
    );

    /// @notice Emitted when a service is registered
    event ServiceRegistered(
        bytes32 indexed serviceIdHash,
        bytes32 indexed providerIdHash,
        uint256 priceCredits
    );

    /// @notice Emitted when a service is deactivated
    event ServiceDeactivated(
        bytes32 indexed serviceIdHash
    );

    /// @notice Emitted when a task receipt is recorded
    event TaskReceiptRecorded(
        bytes32 indexed taskIdHash,
        bytes32 indexed consumerIdHash,
        bytes32 indexed serviceIdHash,
        uint256 creditsCharged,
        TaskOutcome outcome,
        uint256 timestamp
    );

    /// @notice Emitted when an operator is added or removed
    event OperatorUpdated(address operator, bool authorised);

    // =========================================================================
    // Modifiers
    // =========================================================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyOperator() {
        require(
            operators[msg.sender] || msg.sender == owner,
            "Not authorised operator"
        );
        _;
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    constructor() {
        owner = msg.sender;
        operators[msg.sender] = true;
    }

    // =========================================================================
    // Agent Identity
    // =========================================================================

    /**
     * @notice Register an agent on-chain.
     * @param agentIdHash keccak256 of the off-chain agent ID string
     * @param publicKeyHash keccak256 of the agent's Ed25519 public key
     * @param role Agent's role in the ecosystem (0–4)
     * @dev Only operators can register agents (prevents spam).
     *      Registration is idempotent — re-registering updates the record.
     */
    function registerAgent(
        bytes32 agentIdHash,
        bytes32 publicKeyHash,
        AgentRole role
    ) external onlyOperator {
        bool isNew = agents[agentIdHash].registeredAt == 0;

        AgentRecord storage record = agents[agentIdHash];
        record.agentIdHash = agentIdHash;
        record.publicKeyHash = publicKeyHash;
        record.role = role;
        record.registeredBy = msg.sender;

        if (isNew) {
            record.status = AgentStatus.ACTIVE;
            record.reputationScore = 50; // Start at neutral reputation
            record.registeredAt = block.timestamp;
            agentIndex.push(agentIdHash);
            totalAgents++;
        }

        record.lastActiveAt = block.timestamp;

        emit AgentRegistered(agentIdHash, role, block.timestamp, msg.sender);
    }

    /**
     * @notice Update an agent's reputation score.
     * @param agentIdHash keccak256 of the agent ID
     * @param newScore New reputation score (0–100)
     * @dev Only operators can modify reputation — based on off-chain verdicts.
     *      Score reflects cumulative task performance tracked by QuotationEngine.
     */
    function updateReputation(
        bytes32 agentIdHash,
        uint256 newScore
    ) external onlyOperator {
        require(agents[agentIdHash].registeredAt != 0, "Agent not registered");
        require(newScore <= 100, "Score exceeds maximum (100)");

        uint256 oldScore = agents[agentIdHash].reputationScore;
        agents[agentIdHash].reputationScore = newScore;
        agents[agentIdHash].lastActiveAt = block.timestamp;

        emit ReputationUpdated(agentIdHash, oldScore, newScore, msg.sender);
    }

    /**
     * @notice Change an agent's status (ACTIVE, SUSPENDED, REVOKED).
     * @param agentIdHash keccak256 of the agent ID
     * @param newStatus New status code
     * @dev SUSPENDED agents cannot execute tasks. REVOKED is permanent.
     */
    function setAgentStatus(
        bytes32 agentIdHash,
        AgentStatus newStatus
    ) external onlyOperator {
        require(agents[agentIdHash].registeredAt != 0, "Agent not registered");

        AgentStatus oldStatus = agents[agentIdHash].status;
        require(oldStatus != AgentStatus.REVOKED, "Agent permanently revoked");

        agents[agentIdHash].status = newStatus;

        emit AgentStatusChanged(agentIdHash, oldStatus, newStatus);
    }

    // =========================================================================
    // Service Registry
    // =========================================================================

    /**
     * @notice Register a service offering on-chain.
     * @param serviceIdHash keccak256 of the service ID
     * @param providerIdHash keccak256 of the providing agent's ID
     * @param priceCredits Base price in credits × 1e6
     * @param tags Array of keccak256-hashed tag names
     * @dev Provider must be a registered, active agent.
     */
    function registerService(
        bytes32 serviceIdHash,
        bytes32 providerIdHash,
        uint256 priceCredits,
        bytes32[] calldata tags
    ) external onlyOperator {
        require(agents[providerIdHash].registeredAt != 0, "Provider not registered");
        require(agents[providerIdHash].status == AgentStatus.ACTIVE, "Provider not active");

        bool isNew = services[serviceIdHash].registeredAt == 0;

        ServiceRecord storage svc = services[serviceIdHash];
        svc.serviceIdHash = serviceIdHash;
        svc.providerIdHash = providerIdHash;
        svc.priceCredits = priceCredits;
        svc.tags = tags;
        svc.isActive = true;

        if (isNew) {
            svc.registeredAt = block.timestamp;
            serviceIndex.push(serviceIdHash);
            totalServices++;
        }

        emit ServiceRegistered(serviceIdHash, providerIdHash, priceCredits);
    }

    /**
     * @notice Deactivate a service listing.
     * @param serviceIdHash keccak256 of the service ID
     */
    function deactivateService(
        bytes32 serviceIdHash
    ) external onlyOperator {
        require(services[serviceIdHash].registeredAt != 0, "Service not found");
        services[serviceIdHash].isActive = false;

        emit ServiceDeactivated(serviceIdHash);
    }

    // =========================================================================
    // Task Receipts
    // =========================================================================

    /**
     * @notice Record a completed task receipt on-chain.
     * @param taskIdHash keccak256 of the off-chain task ID
     * @param consumerIdHash keccak256 of the consumer agent ID
     * @param providerIdHash keccak256 of the provider agent ID
     * @param serviceIdHash keccak256 of the service used
     * @param creditsCharged Credits spent × 1e6
     * @param outcome Task result (COMPLETED, FAILED, DISPUTED)
     * @param proofHash Optional link to SwarmProofRegistry (0x0 if none)
     * @dev Updates both consumer and provider statistics.
     *      Idempotent — will not overwrite an existing receipt.
     */
    function recordTaskReceipt(
        bytes32 taskIdHash,
        bytes32 consumerIdHash,
        bytes32 providerIdHash,
        bytes32 serviceIdHash,
        uint256 creditsCharged,
        TaskOutcome outcome,
        bytes32 proofHash
    ) external onlyOperator {
        require(taskReceipts[taskIdHash].completedAt == 0, "Receipt already recorded");
        require(agents[consumerIdHash].registeredAt != 0, "Consumer not registered");

        TaskReceipt storage receipt = taskReceipts[taskIdHash];
        receipt.taskIdHash = taskIdHash;
        receipt.consumerIdHash = consumerIdHash;
        receipt.providerIdHash = providerIdHash;
        receipt.serviceIdHash = serviceIdHash;
        receipt.creditsCharged = creditsCharged;
        receipt.outcome = outcome;
        receipt.proofHash = proofHash;
        receipt.completedAt = block.timestamp;
        receipt.recordedBy = msg.sender;

        receiptIndex.push(taskIdHash);
        totalReceipts++;
        totalCreditsTransacted += creditsCharged;

        // Update agent statistics
        if (outcome == TaskOutcome.COMPLETED) {
            agents[providerIdHash].totalTasksCompleted++;
            agents[consumerIdHash].totalCreditsSpent += creditsCharged;
            agents[providerIdHash].totalCreditsEarned += creditsCharged;
        } else if (outcome == TaskOutcome.FAILED) {
            agents[providerIdHash].totalTasksFailed++;
        }

        agents[consumerIdHash].lastActiveAt = block.timestamp;
        agents[providerIdHash].lastActiveAt = block.timestamp;

        emit TaskReceiptRecorded(
            taskIdHash,
            consumerIdHash,
            serviceIdHash,
            creditsCharged,
            outcome,
            block.timestamp
        );
    }

    // =========================================================================
    // Query Functions (Public, No Gas)
    // =========================================================================

    /**
     * @notice Look up an agent's on-chain record.
     * @param agentIdHash keccak256 of the agent ID
     * @return exists Whether the agent is registered
     * @return role Agent's role
     * @return status Agent's current standing
     * @return reputationScore Reputation 0–100
     * @return tasksCompleted Lifetime completed tasks
     * @return registeredAt Registration timestamp
     */
    function getAgent(bytes32 agentIdHash)
        external
        view
        returns (
            bool exists,
            AgentRole role,
            AgentStatus status,
            uint256 reputationScore,
            uint256 tasksCompleted,
            uint256 registeredAt
        )
    {
        AgentRecord storage record = agents[agentIdHash];
        if (record.registeredAt == 0) {
            return (false, AgentRole.OBSERVER, AgentStatus.REVOKED, 0, 0, 0);
        }
        return (
            true,
            record.role,
            record.status,
            record.reputationScore,
            record.totalTasksCompleted,
            record.registeredAt
        );
    }

    /**
     * @notice Look up a service listing.
     * @param serviceIdHash keccak256 of the service ID
     */
    function getService(bytes32 serviceIdHash)
        external
        view
        returns (
            bool exists,
            bytes32 providerIdHash,
            uint256 priceCredits,
            bool isActive,
            uint256 registeredAt
        )
    {
        ServiceRecord storage svc = services[serviceIdHash];
        if (svc.registeredAt == 0) {
            return (false, bytes32(0), 0, false, 0);
        }
        return (
            true,
            svc.providerIdHash,
            svc.priceCredits,
            svc.isActive,
            svc.registeredAt
        );
    }

    /**
     * @notice Look up a task receipt.
     * @param taskIdHash keccak256 of the task ID
     */
    function getTaskReceipt(bytes32 taskIdHash)
        external
        view
        returns (
            bool exists,
            bytes32 consumerIdHash,
            bytes32 providerIdHash,
            uint256 creditsCharged,
            TaskOutcome outcome,
            bytes32 proofHash,
            uint256 completedAt
        )
    {
        TaskReceipt storage receipt = taskReceipts[taskIdHash];
        if (receipt.completedAt == 0) {
            return (false, bytes32(0), bytes32(0), 0, TaskOutcome.FAILED, bytes32(0), 0);
        }
        return (
            true,
            receipt.consumerIdHash,
            receipt.providerIdHash,
            receipt.creditsCharged,
            receipt.outcome,
            receipt.proofHash,
            receipt.completedAt
        );
    }

    /**
     * @notice Get global registry statistics.
     */
    function getStats()
        external
        view
        returns (
            uint256 agents_,
            uint256 services_,
            uint256 receipts_,
            uint256 creditsTransacted_
        )
    {
        return (totalAgents, totalServices, totalReceipts, totalCreditsTransacted);
    }

    /**
     * @notice Get the total number of agents for enumeration.
     */
    function agentCount() external view returns (uint256) {
        return agentIndex.length;
    }

    /**
     * @notice Get the total number of services for enumeration.
     */
    function serviceCount() external view returns (uint256) {
        return serviceIndex.length;
    }

    /**
     * @notice Get the total number of receipts for enumeration.
     */
    function receiptCount() external view returns (uint256) {
        return receiptIndex.length;
    }

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /**
     * @notice Authorise or revoke an operator address.
     * @dev Operators can register agents, update reputation, and record receipts.
     */
    function setOperator(address operator, bool authorised)
        external
        onlyOwner
    {
        operators[operator] = authorised;
        emit OperatorUpdated(operator, authorised);
    }

    /**
     * @notice Transfer contract ownership.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
