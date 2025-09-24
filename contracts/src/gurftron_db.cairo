use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
use core::array::{ArrayTrait, SpanTrait};
use core::byte_array::ByteArrayTrait;
use core::option::OptionTrait;
use core::traits::{TryInto, Into};
use core::clone::Clone;
use core::pedersen::pedersen;
use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
/// @title IERC20 Interface for STRK token interactions
/// @notice Interface for ERC20 token operations required by the contract
#[starknet::interface]
trait IERC20<TContractState> {
    /// @notice Transfers tokens to a recipient
    /// @param recipient The address to receive tokens
    /// @param amount The amount of tokens to transfer
    /// @return bool Success status
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    /// @notice Transfers tokens from sender to recipient (requires approval)
    /// @param sender The address to send tokens from
    /// @param recipient The address to receive tokens
    /// @param amount The amount of tokens to transfer
    /// @return bool Success status
    fn transfer_from(ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    /// @notice Returns the token balance of an account
    /// @param account The address to query balance for
    /// @return u256 The token balance
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
}
/// @title Enhanced Database Interface with Security Features
/// @notice Core interface for database operations and user management with anti-abuse mechanisms
#[starknet::interface]
trait IDatabase<TContractState> {
    // Moderators
    fn add_moderator(ref self: TContractState, moderator: ContractAddress);
    fn remove_moderator(ref self: TContractState, moderator: ContractAddress);
    // Staking System
    fn stake_for_access(ref self: TContractState, amount: u256);
    fn withdraw_stake(ref self: TContractState);
    fn get_stake_info(self: @TContractState, user: ContractAddress) -> (u256, u64, bool);
    fn emergency_unlock_stake(ref self: TContractState, user: ContractAddress);
    // Collection Management
    fn create_collection(ref self: TContractState, name: felt252, indexed_fields: Array<felt252>);
    // Document Operations with Enhanced Security
    fn insert(ref self: TContractState, collection: felt252, compressed_data: ByteArray, fields: Array<(felt252, felt252)>) -> felt252;
    fn get(self: @TContractState, collection: felt252, id: felt252) -> (ByteArray, Array<(felt252, felt252)>);
    fn update(ref self: TContractState, collection: felt252, id: felt252, compressed_data: ByteArray, fields: Array<(felt252, felt252)>);
    fn delete(ref self: TContractState, collection: felt252, id: felt252);
    // Query Operations (Enhanced to filter approved data)
    fn find(self: @TContractState, collection: felt252, query: Array<(felt252, felt252, felt252, felt252)>, page: u32) -> Array<felt252>;
    fn find_one(self: @TContractState, collection: felt252, query: Array<(felt252, felt252, felt252, felt252)>) -> (ByteArray, Array<(felt252, felt252)>);
    fn get_all_data(self: @TContractState, collection: felt252) -> Array<felt252>;
    // Admin-only query functions (includes pending data)
    fn admin_find(self: @TContractState, collection: felt252, query: Array<(felt252, felt252, felt252, felt252)>, page: u32) -> Array<felt252>;
    fn admin_get_all_data(self: @TContractState, collection: felt252) -> Array<felt252>;
    // Validation and Voting System
    fn vote_on_document(ref self: TContractState, collection: felt252, doc_id: felt252, is_valid: bool);
    fn vote_on_whitelist(ref self: TContractState, collection: felt252, doc_id: felt252, vote_remove: bool);
    fn get_document_validation_status(self: @TContractState, collection: felt252, doc_id: felt252) -> (felt252, u32, u32, u32);
    fn report_malicious_data(ref self: TContractState, collection: felt252, doc_id: felt252, reason: felt252);
    fn get_pending_validations(self: @TContractState, page: u32) -> Array<(felt252, felt252)>; // (collection, doc_id) pairs
    // User Management (Enhanced)
    fn register_account(ref self: TContractState);
    fn ban_user(ref self: TContractState, user_address: ContractAddress);
    fn unban_user(ref self: TContractState, user_address: ContractAddress);
    fn get_user_profile(self: @TContractState, user: ContractAddress) -> (i32, u32, u32, bool, u64);
    // Statistics Methods (Enhanced)
    fn get_total_accounts_registered(self: @TContractState) -> u64;
    fn get_total_documents_inserted(self: @TContractState) -> u64;
    fn get_total_database_size_bytes(self: @TContractState) -> u256;
    fn get_security_statistics(self: @TContractState) -> (u256, u64, u64, u64);
    // Admin Functions (Enhanced)
    fn update_all_parameters(
        ref self: TContractState,
        new_points_per_insert: u32,
        new_points_per_update: u32,
        new_points_per_delete: u32,
        new_points_per_query_page: u32,
        new_points_threshold_for_claim: u32,
        new_premium_reward_multiplier: u32,
        new_badge_threshold: u32,
        new_points_to_strk_wei: u256
    );
    fn update_security_parameters(
        ref self: TContractState, 
        min_stake: u256, 
        stake_lock_period: u64, 
        cooldown_period: u64, 
        min_reputation: i32,
        max_pending_time: u64,
        approval_percentage: i32,
        slash_percentage: i32,
        transaction_fee_percent: i32
    );
    fn slash_malicious_stake(ref self: TContractState, user: ContractAddress, amount: u256, reason: felt252);
    fn force_approve_document(ref self: TContractState, collection: felt252, doc_id: felt252);
    fn force_reject_document(ref self: TContractState, collection: felt252, doc_id: felt252);
    fn delete_whitelisted_document(ref self: TContractState, collection: felt252, doc_id: felt252);
    fn cleanup_stale_pending_documents(ref self: TContractState);
}
/// @title Enhanced Event Definitions with Specific Names
/// @notice All events emitted by the contract for tracking operations and rewards
// Document Lifecycle Events
#[derive(Drop, starknet::Event)]
struct DocumentInsertedEvent {
    #[key]
    caller: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    data_hash: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentUpdatedEvent {
    #[key]
    caller: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    old_data_hash: felt252,
    new_data_hash: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentDeletedEvent {
    #[key]
    caller: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    data_hash: felt252,
    creator: ContractAddress,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentApprovedEvent {
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    #[key]
    creator: ContractAddress,
    positive_votes: u32,
    total_votes: u32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentRejectedEvent {
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    #[key]
    creator: ContractAddress,
    negative_votes: u32,
    total_votes: u32,
    timestamp: u64,
}
// Voting Events
#[derive(Drop, starknet::Event)]
struct DocumentVoteSubmitted {
    #[key]
    voter: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    #[key]
    creator: ContractAddress,
    is_valid: bool,
    positive_votes: u32,
    negative_votes: u32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct WhitelistVoteSubmitted {
    #[key]
    voter: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    #[key]
    creator: ContractAddress,
    vote_remove: bool,
    remove_votes: u32,
    keep_votes: u32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentWhitelistApproved {
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    #[key]
    creator: ContractAddress,
    data_hash: felt252,
    remove_votes: u32,
    total_votes: u32,
    timestamp: u64,
}
// Points and Rewards Events
#[derive(Drop, starknet::Event)]
struct PointsAwardedForApproval {
    #[key]
    recipient: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    points_awarded: u32,
    total_points: i32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct PointsAwardedForVoting {
    #[key]
    voter: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    points_awarded: u32,
    total_points: i32,
    vote_type: felt252, // 'approval' or 'whitelist'
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct BadgeEarnedEvent {
    #[key]
    recipient: ContractAddress,
    badge_id: u64,
    points_threshold: u32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct RewardClaimedEvent {
    #[key]
    claimant: ContractAddress,
    reward_amount: u256,
    points_used: i32,
    is_premium_bonus: bool,
    timestamp: u64,
}
// User Management Events
#[derive(Drop, starknet::Event)]
struct UserRegisteredEvent {
    #[key]
    new_user: ContractAddress,
    registration_timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct UserBannedEvent {
    #[key]
    banned_user: ContractAddress,
    #[key]
    admin: ContractAddress,
    reason: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct UserUnbannedEvent {
    #[key]
    unbanned_user: ContractAddress,
    #[key]
    admin: ContractAddress,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct PremiumStatusChangedEvent {
    #[key]
    user: ContractAddress,
    #[key]
    admin: ContractAddress,
    is_premium: bool,
    timestamp: u64,
}
// Staking Events
#[derive(Drop, starknet::Event)]
struct StakeDepositedEvent {
    #[key]
    staker: ContractAddress,
    amount: u256,
    unlock_time: u64,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct StakeWithdrawnEvent {
    #[key]
    staker: ContractAddress,
    amount: u256,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct StakeSlashedEvent {
    #[key]
    penalized_user: ContractAddress,
    #[key]
    admin: ContractAddress,
    slashed_amount: u256,
    reason: felt252,
    timestamp: u64,
}
// System Events
#[derive(Drop, starknet::Event)]
struct CollectionCreatedEvent {
    #[key]
    creator: ContractAddress,
    collection_name: felt252,
    indexed_fields_count: u32,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct FundsDepositedEvent {
    #[key]
    admin: ContractAddress,
    amount: u256,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct SystemPausedEvent {
    #[key]
    admin: ContractAddress,
    reason: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct SystemResumedEvent {
    #[key]
    admin: ContractAddress,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct ReputationChangedEvent {
    #[key]
    user: ContractAddress,
    old_reputation: i32,
    new_reputation: i32,
    reason: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct SecurityViolationEvent {
    #[key]
    violator: ContractAddress,
    violation_type: felt252, // 'cooldown', 'rate_limit', 'reputation'
    details: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct CooldownViolation {
    #[key]
    user: ContractAddress,
    action_type: felt252,
    last_action: u64,
    current_time: u64,
}
#[derive(Drop, starknet::Event)]
struct RateLimitExceeded {
    #[key]
    user: ContractAddress,
    action_type: felt252,
    current_count: u32,
    max_allowed: u32,
    hour_window: u64,
}
#[derive(Drop, starknet::Event)]
struct PointsDeducted {
    #[key]
    account: ContractAddress,
    points: u32,
    total_points: i32,
    action_type: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct MaliciousDataReported {
    #[key]
    reporter: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    doc_id: felt252,
    creator: ContractAddress,
    reason: felt252,
    report_id: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct CircuitBreakerTriggered {
    #[key]
    admin: ContractAddress,
    reason: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct PointsAwarded {
    #[key]
    account: ContractAddress,
    points: u32,
    total_points: i32,
    action_type: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct AccountRegistered {
    #[key]
    account: ContractAddress,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct PremiumStatusSet {
    #[key]
    account: ContractAddress,
    is_premium: bool,
    #[key]
    admin: ContractAddress,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct DocumentStatusChanged {
    #[key]
    collection: felt252,
    #[key]
    doc_id: felt252,
    creator: ContractAddress,
    old_status: felt252,
    new_status: felt252,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct StatisticsUpdated {
    total_accounts: u64,
    total_documents: u64,
    total_size_bytes: u256,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct ParametersUpdated {
    #[key]
    admin: ContractAddress,
    new_points_per_insert: u32,
    new_points_per_update: u32,
    new_points_per_delete: u32,
    new_points_per_query_page: u32,
    new_points_threshold_for_claim: u32,
    new_premium_reward_multiplier: u32,
    new_badge_threshold: u32,
    new_points_to_strk_wei: u256,
    timestamp: u64,
}
#[derive(Drop, starknet::Event)]
struct SecurityParametersUpdated {
    #[key]
    admin: ContractAddress,
    min_stake: u256,
    stake_lock_period: u64,
    cooldown_period: u64,
    min_reputation: i32,
    max_pending_time: u64,
    approval_percentage: i32,
    slash_percentage: i32,
    transaction_fee_percent: i32,
    timestamp: u64,
}
/// @title Enhanced Storage Structures
#[derive(Drop, Serde, starknet::Store)]
struct Document {
    compressed_data: ByteArray,
    creator: ContractAddress,
    created_at: u64,
    updated_at: u64,
    data_hash: felt252,
    validation_status: felt252, // "pending", "approved", "rejected", "deleted"
    positive_votes: u32,
    negative_votes: u32,
    total_voters: u32,
    whitelist_remove_votes: u32,
    whitelist_keep_votes: u32,
    whitelist_total_voters: u32,
    whitelist_approved_for_deletion: bool,
}
#[derive(Copy, Drop, Serde, starknet::Store)]
struct StakeInfo {
    amount: u256,
    stake_time: u64,
    unlock_time: u64,
    is_locked: bool,
}
#[derive(Copy, Drop, Serde, starknet::Store)]
struct UserProfile {
    reputation_score: i32,
    total_documents: u32,
    last_action_time: u64,
    is_premium: bool,
    warning_count: u32,
    total_votes_cast: u32,
    approved_documents: u32, // Count of approved documents
}
#[derive(Copy, Drop, Serde, starknet::Store)]
struct MaliciousReport {
    reporter: ContractAddress,
    collection: felt252,
    doc_id: felt252,
    reason: felt252,
    timestamp: u64,
    is_resolved: bool,
}
/// @title Enhanced GurftronDB Smart Contract
/// @notice Enterprise-grade decentralized database with comprehensive security and reward system
/// @dev Implements all database operations with anti-abuse mechanisms, staking, and community validation
#[starknet::contract]
mod GurftronDB {
    use super::{
        IERC20Dispatcher, IERC20DispatcherTrait, IDatabase, ContractAddress, get_caller_address,
        get_block_timestamp, get_contract_address,
        // Event structs
        DocumentInsertedEvent, DocumentUpdatedEvent, DocumentDeletedEvent, DocumentApprovedEvent, DocumentRejectedEvent,
        DocumentVoteSubmitted, WhitelistVoteSubmitted, DocumentWhitelistApproved, PointsAwardedForApproval,
        PointsAwardedForVoting, BadgeEarnedEvent, RewardClaimedEvent, UserRegisteredEvent, UserBannedEvent,
        UserUnbannedEvent, PremiumStatusChangedEvent, StakeDepositedEvent, StakeWithdrawnEvent, StakeSlashedEvent,
        CollectionCreatedEvent, FundsDepositedEvent, SystemPausedEvent, SystemResumedEvent, ReputationChangedEvent,
        SecurityViolationEvent, CooldownViolation, RateLimitExceeded, PointsDeducted, MaliciousDataReported,
        CircuitBreakerTriggered, PointsAwarded, AccountRegistered, PremiumStatusSet, DocumentStatusChanged,
        StatisticsUpdated, ParametersUpdated, SecurityParametersUpdated,
        // Storage structures
        Document, StakeInfo, UserProfile, MaliciousReport
    };
    use starknet::storage::Map;
    use core::array::{ArrayTrait, SpanTrait};
    use core::byte_array::ByteArrayTrait;
    use core::option::OptionTrait;
    use core::traits::{TryInto, Into};
    use core::pedersen::pedersen;
    use core::poseidon::PoseidonTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};
    // ============================================================================
    // ENHANCED CONSTANTS
    // ============================================================================
    /// @notice Default reward parameters - configurable by admin
    const DEFAULT_POINTS_PER_INSERT: u32 = 10;
    const DEFAULT_POINTS_PER_UPDATE: u32 = 1000;
    const DEFAULT_POINTS_PER_DELETE: u32 = 1000;
    const DEFAULT_POINTS_PER_QUERY_PAGE: u32 = 1000;
    const DEFAULT_POINTS_THRESHOLD_FOR_CLAIM: u32 = 1000;
    const DEFAULT_PREMIUM_REWARD_MULTIPLIER: u32 = 2;
    const DEFAULT_BADGE_THRESHOLD: u32 = 1000;
    const DEFAULT_POINTS_TO_STRK_WEI: u256 = 10000000000000000; // 0.01 STRK per point
    /// @notice Security and staking constants
    const MINIMUM_STAKE_AMOUNT: u256 = 10_000_000_000_000_000_000; // 10 STRK
    const STAKE_LOCK_PERIOD: u64 = 2592000; // 30 days in seconds
    const ACTION_COOLDOWN_PERIOD: u64 = 300; // 5 minutes between actions
    const MINIMUM_REPUTATION_SCORE: i32 = -100;
    const APPROVAL_PERCENTAGE: u32 = 60; // 60% positive votes needed for approval
    const VOTE_REWARD_POINTS: u32 = 2; // Points for voting
    const MAX_PENDING_TIME: u64 = 604800; // 7 days in seconds
    /// @notice Rate limiting constants
    const MAX_INSERTS_PER_HOUR: u32 = 10;
    const MAX_UPDATES_PER_HOUR: u32 = 20;
    const MAX_QUERIES_PER_HOUR: u32 = 100;
    const MAX_VOTES_PER_HOUR: u32 = 50;
    /// @notice Data validation constants
    const MAXIMUM_DATA_SIZE: u32 = 1048576; // 1MB
    const MAXIMUM_DOCUMENTS_PER_USER: u32 = 1000;
    const MAXIMUM_FIELD_LENGTH: u32 = 100;
    const MAX_QUERY_CONDITIONS: u32 = 50;
    const SLASH_PERCENTAGE: u32 = 50; // 50% of stake slashed for malicious activity
    /// @notice Query and fee constants
    const QUERY_PAGE_SIZE: u32 = 1000;
    const TRANSACTION_FEE_PERCENT: u32 = 10;
    const MAX_INDEXED_FIELDS: u32 = 10;
    // ============================================================================
    // ENHANCED STORAGE
    // ============================================================================
    #[storage]
    struct Storage {
        // Core Configuration
        admin_address: ContractAddress,
        strk_token_address: ContractAddress,
        is_circuit_breaker_active: bool,
        moderators: Map<ContractAddress, bool>,
        // Original Reward Parameters
        points_per_insert: u32,
        points_per_update: u32,
        points_per_delete: u32,
        points_per_query_page: u32,
        points_threshold_for_claim: u32,
        premium_reward_multiplier: u32,
        badge_threshold: u32,
        points_to_strk_wei: u256,
        // Security Parameters
        minimum_stake_amount: u256,
        stake_lock_period: u64,
        action_cooldown_period: u64,
        minimum_reputation_score: i32,
        max_pending_time: u64,
        approval_percentage: i32,
        slash_percentage: i32,
        transaction_fee_percent: i32,
        // Original User Management
        points: Map<ContractAddress, i32>,
        badges: Map<(ContractAddress, u64), bool>,
        is_user_premium: Map<ContractAddress, bool>,
        banned_users: Map<ContractAddress, bool>,
        accounts: Map<ContractAddress, u64>,
        // Enhanced User Management
        user_stakes: Map<ContractAddress, StakeInfo>,
        user_profiles: Map<ContractAddress, UserProfile>,
        user_last_actions: Map<(ContractAddress, felt252), u64>, // (user, action_type) -> timestamp
        user_hourly_actions: Map<(ContractAddress, felt252, u64), u32>, // (user, action_type, hour) -> count
        // Document Storage (Enhanced)
        next_id: Map<felt252, felt252>,
        documents: Map<(felt252, felt252), Document>,
        creators: Map<(felt252, felt252), ContractAddress>,
        document_voters: Map<(felt252, felt252, ContractAddress), bool>, // (collection, id, voter) -> has_voted for approval
        whitelist_voters: Map<(felt252, felt252, ContractAddress), bool>, // (collection, id, voter) -> has_voted for whitelist
        // Field Management
        field_lengths: Map<(felt252, felt252), felt252>,
        fields_data: Map<(felt252, felt252, felt252), felt252>, // (collection, id, field) -> value
        fields_list: Map<(felt252, felt252, felt252), felt252>, // (collection, id, index) -> field_name
        // Collection Management
        num_docs: Map<felt252, u32>,
        doc_ids: Map<(felt252, u32), felt252>,
        approved_docs: Map<felt252, u32>, // count of approved docs per collection
        approved_doc_ids: Map<(felt252, u32), felt252>, // approved doc IDs per collection
        // Indexing System
        num_indexed: Map<felt252, felt252>,
        indexed_fields: Map<(felt252, felt252), felt252>,
        index_num_ids: Map<(felt252, felt252, felt252), u32>, // (collection, field, value) -> count
        index_ids: Map<(felt252, felt252, felt252, u32), felt252>, // (collection, field, value, index) -> doc_id
        // Validation and Reporting System
        next_report_id: felt252,
        reports: Map<felt252, MaliciousReport>,
        pending_validations_count: u64,
        pending_validation_ids: Map<u64, (felt252, felt252)>, // index -> (collection, doc_id)
        // Original Statistics
        total_accounts_registered: u64,
        total_documents_inserted: u64,
        total_database_size_bytes: u256,
        // Security Statistics
        total_slashed_stakes: u256,
        total_malicious_reports: u64,
        total_resolved_reports: u64,
    }
    // ============================================================================
    // EVENTS
    // ============================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // Document Lifecycle Events
        DocumentInsertedEvent: DocumentInsertedEvent,
        DocumentUpdatedEvent: DocumentUpdatedEvent,
        DocumentDeletedEvent: DocumentDeletedEvent,
        DocumentApprovedEvent: DocumentApprovedEvent,
        DocumentRejectedEvent: DocumentRejectedEvent,
        DocumentStatusChanged: DocumentStatusChanged,
        // Voting Events
        DocumentVoteSubmitted: DocumentVoteSubmitted,
        WhitelistVoteSubmitted: WhitelistVoteSubmitted,
        DocumentWhitelistApproved: DocumentWhitelistApproved,
        // Points and Rewards Events
        PointsAwardedForApproval: PointsAwardedForApproval,
        PointsAwardedForVoting: PointsAwardedForVoting,
        BadgeEarnedEvent: BadgeEarnedEvent,
        RewardClaimedEvent: RewardClaimedEvent,
        PointsDeducted: PointsDeducted,
        // User Management Events
        UserRegisteredEvent: UserRegisteredEvent,
        UserBannedEvent: UserBannedEvent,
        UserUnbannedEvent: UserUnbannedEvent,
        PremiumStatusChangedEvent: PremiumStatusChangedEvent,
        // Staking Events
        StakeDepositedEvent: StakeDepositedEvent,
        StakeWithdrawnEvent: StakeWithdrawnEvent,
        StakeSlashedEvent: StakeSlashedEvent,
        // System Events
        CollectionCreatedEvent: CollectionCreatedEvent,
        FundsDepositedEvent: FundsDepositedEvent,
        SystemPausedEvent: SystemPausedEvent,
        SystemResumedEvent: SystemResumedEvent,
        ReputationChangedEvent: ReputationChangedEvent,
        SecurityViolationEvent: SecurityViolationEvent,
        CooldownViolation: CooldownViolation,
        RateLimitExceeded: RateLimitExceeded,
        MaliciousDataReported: MaliciousDataReported,
        CircuitBreakerTriggered: CircuitBreakerTriggered,
        PointsAwarded: PointsAwarded,
        AccountRegistered: AccountRegistered,
        PremiumStatusSet: PremiumStatusSet,
        StatisticsUpdated: StatisticsUpdated,
        ParametersUpdated: ParametersUpdated,
        SecurityParametersUpdated: SecurityParametersUpdated,
    }
    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================
    /// @notice Initializes the contract with admin and STRK token addresses
    /// @param admin_addr The admin address for contract management
    /// @param strk_token_addr The STRK token contract address
    #[constructor]
    fn constructor(ref self: ContractState, admin_addr: ContractAddress, strk_token_addr: ContractAddress) {
        // Validate addresses
        assert(!admin_addr.is_zero(), "Admin address cannot be zero");
        assert(!strk_token_addr.is_zero(), "STRK token address cannot be zero");
        // Set core addresses
        self.admin_address.write(admin_addr);
        self.strk_token_address.write(strk_token_addr);
        self.is_circuit_breaker_active.write(false);
        // Initialize original parameters
        self.points_per_insert.write(DEFAULT_POINTS_PER_INSERT);
        self.points_per_update.write(DEFAULT_POINTS_PER_UPDATE);
        self.points_per_delete.write(DEFAULT_POINTS_PER_DELETE);
        self.points_per_query_page.write(DEFAULT_POINTS_PER_QUERY_PAGE);
        self.points_threshold_for_claim.write(DEFAULT_POINTS_THRESHOLD_FOR_CLAIM);
        self.premium_reward_multiplier.write(DEFAULT_PREMIUM_REWARD_MULTIPLIER);
        self.badge_threshold.write(DEFAULT_BADGE_THRESHOLD);
        self.points_to_strk_wei.write(DEFAULT_POINTS_TO_STRK_WEI);
        // Initialize security parameters
        self.minimum_stake_amount.write(MINIMUM_STAKE_AMOUNT);
        self.stake_lock_period.write(STAKE_LOCK_PERIOD);
        self.action_cooldown_period.write(ACTION_COOLDOWN_PERIOD);
        self.minimum_reputation_score.write(MINIMUM_REPUTATION_SCORE);
        self.max_pending_time.write(MAX_PENDING_TIME);
        self.approval_percentage.write(APPROVAL_PERCENTAGE.try_into().unwrap());
        self.slash_percentage.write(SLASH_PERCENTAGE.try_into().unwrap());
        self.transaction_fee_percent.write(TRANSACTION_FEE_PERCENT.try_into().unwrap());
        // Initialize statistics
        self.total_accounts_registered.write(0);
        self.total_documents_inserted.write(0);
        self.total_database_size_bytes.write(0);
        self.total_slashed_stakes.write(0);
        self.total_malicious_reports.write(0);
        self.total_resolved_reports.write(0);
        self.next_report_id.write(1);
        self.pending_validations_count.write(0);
    }
    // ============================================================================
    // ENHANCED SECURITY MODIFIERS
    // ============================================================================
    #[generate_trait]
    impl ModifierImpl of ModifierTrait {
        /// @notice Ensures caller is admin or moderator
        fn only_moderator_or_admin(self: @ContractState) {
            let caller = get_caller_address();
            let admin_addr = self.admin_address.read();
            assert(caller == admin_addr || self.moderators.read(caller), "Not admin or moderator");
        }
        /// @notice Ensures caller is admin
        fn only_admin(self: @ContractState) {
            let caller = get_caller_address();
            let admin_addr = self.admin_address.read();
            assert(caller == admin_addr, "Caller is not admin");
        }
        /// @notice Ensures user is registered and not banned
        fn only_registered_non_banned(self: @ContractState) {
            let caller = get_caller_address();
            assert(self.accounts.read(caller) != 0, "Account not registered");
            assert(!self.banned_users.read(caller), "User is banned");
            assert(!self.is_circuit_breaker_active.read(), "System maintenance mode");
        }
        /// @notice Ensures user has sufficient stake
        fn only_staked_users(self: @ContractState) {
            let caller = get_caller_address();
            let stake_info = self.user_stakes.read(caller);
            let min_stake = self.minimum_stake_amount.read();
            assert(stake_info.amount >= min_stake, "Insufficient stake amount");
            assert(!stake_info.is_locked, "Stake is locked");
        }
        /// @notice Ensures user has sufficient reputation
        fn check_reputation(self: @ContractState) {
            let caller = get_caller_address();
            let profile = self.user_profiles.read(caller);
            let min_rep = self.minimum_reputation_score.read();
            assert(profile.reputation_score >= min_rep, "Reputation too low");
        }
        /// @notice Ensures user can perform read operations
        fn can_read(self: @ContractState) {
            let caller = get_caller_address();
            let is_premium = self.is_user_premium.read(caller);
            let points = self.points.read(caller);
            assert(!self.banned_users.read(caller), "User is banned");
            assert(is_premium || points >= 0, "Negative balance - upgrade to premium");
        }
        /// @notice Validates field array length
        fn validate_fields(self: @ContractState, fields: @Array<(felt252, felt252)>) {
            assert(fields.len() <= MAXIMUM_FIELD_LENGTH, "Too many fields");
        }
        /// @notice Validates query conditions length
        fn validate_query(self: @ContractState, query: @Array<(felt252, felt252, felt252, felt252)>) {
            assert(query.len() <= MAX_QUERY_CONDITIONS, "Too many query conditions");
        }
        /// @notice Enforces action cooldown
        fn enforce_cooldown(ref self: ContractState, action_type: felt252) {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let last_action = self.user_last_actions.read((caller, action_type));
            let cooldown = self.action_cooldown_period.read();
            if last_action + cooldown > current_time {
                self.emit(CooldownViolation { 
                    user: caller, 
                    action_type,
                    last_action, 
                    current_time 
                });
                assert(false, "Action on cooldown");
            }
            self.user_last_actions.write((caller, action_type), current_time);
        }
        /// @notice Enforces rate limiting
        fn enforce_rate_limit(ref self: ContractState, action_type: felt252, max_per_hour: u32) {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let current_hour = current_time / 3600;
            let current_count = self.user_hourly_actions.read((caller, action_type, current_hour));
            if current_count >= max_per_hour {
                self.emit(RateLimitExceeded { 
                    user: caller, 
                    action_type,
                    current_count, 
                    max_allowed: max_per_hour,
                    hour_window: current_hour
                });
                assert(false, "Rate limit exceeded");
            }
            self.user_hourly_actions.write((caller, action_type, current_hour), current_count + 1);
        }
        /// @notice Validates data integrity and size
        fn validate_data(self: @ContractState, data: @ByteArray) {
            assert(data.len() > 0, "Data cannot be empty");
            assert(data.len() <= MAXIMUM_DATA_SIZE, "Data size exceeds limit");
        }
    }
    // ============================================================================
    // STAKING SYSTEM
    // ============================================================================
    /// @notice Deposits STRK tokens to fund rewards (Admin only)
    /// @param amount Amount of STRK to deposit
    #[external(v0)]
    fn deposit_funds(ref self: ContractState, amount: u256) {
        self.only_admin();
        assert(amount > 0, "Amount must be greater than 0");
        let caller = get_caller_address();
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        let contract_addr = get_contract_address();
        let success = strk_token.transfer_from(caller, contract_addr, amount);
        assert(success, "Transfer failed");
        self.emit(FundsDepositedEvent { admin: caller, amount, timestamp: get_block_timestamp() });
    }
    /// @notice Sets premium status for a user (Admin only)
    /// @param user_address Address of the user
    /// @param is_premium Premium status to set
    #[external(v0)]
    fn set_user_premium_status(ref self: ContractState, user_address: ContractAddress, is_premium: bool) {
        self.only_admin();
        assert(!user_address.is_zero(), "Invalid user address");
        let caller = get_caller_address();
        self.is_user_premium.write(user_address, is_premium);
        self.emit(PremiumStatusSet { account: user_address, is_premium, admin: caller, timestamp: get_block_timestamp() });
    }
    /// @notice Emergency circuit breaker to pause system (Admin only)
    #[external(v0)]
    fn trigger_circuit_breaker(ref self: ContractState, reason: felt252) {
        self.only_admin();
        let caller = get_caller_address();
        self.is_circuit_breaker_active.write(true);
        self.emit(CircuitBreakerTriggered { admin: caller, reason, timestamp: get_block_timestamp() });
    }
    /// @notice Deactivate circuit breaker (Admin only)
    #[external(v0)]
    fn deactivate_circuit_breaker(ref self: ContractState) {
        self.only_admin();
        self.is_circuit_breaker_active.write(false);
    }
    // ============================================================================
    // DATABASE IMPLEMENTATION WITH ENHANCED SECURITY
    // ============================================================================
    #[abi(embed_v0)]
    impl DatabaseImpl of IDatabase<ContractState> {
        // Add functions to manage moderators
        /// @notice Adds a moderator (Admin only)
        /// @param moderator Address to grant moderator role
        fn add_moderator(ref self: ContractState, moderator: ContractAddress) {
            self.only_admin();
            assert(!moderator.is_zero(), "Invalid moderator address");
            self.moderators.write(moderator, true);
        }
        /// @notice Removes a moderator (Admin only)
        /// @param moderator Address to remove moderator role
        fn remove_moderator(ref self: ContractState, moderator: ContractAddress) {
            self.only_admin();
            assert(!moderator.is_zero(), "Invalid moderator address");
            self.moderators.write(moderator, false);
        }
        /// @notice Stakes STRK tokens for database access
        /// @param amount Amount of STRK to stake (minimum 10 STRK)
        fn stake_for_access(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let min_stake = self.minimum_stake_amount.read();
            assert(amount >= min_stake, "Stake amount too low");
            // Transfer STRK tokens to contract
            let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
            let contract_addr = get_contract_address();
            let success = strk_token.transfer_from(caller, contract_addr, amount);
            assert(success, "Stake transfer failed");
            let current_time = get_block_timestamp();
            let lock_period = self.stake_lock_period.read();
            // Update or create stake info
            let mut existing_stake = self.user_stakes.read(caller);
            let total_stake = existing_stake.amount + amount;
            let stake_info = StakeInfo {
                amount: total_stake,
                stake_time: current_time,
                unlock_time: current_time + lock_period,
                is_locked: false,
            };
            self.user_stakes.write(caller, stake_info);
            self.emit(StakeDepositedEvent { 
                staker: caller, 
                amount: total_stake, 
                unlock_time: current_time + lock_period,
                timestamp: current_time
            });
        }
        /// @notice Withdraws staked STRK tokens after lock period
        fn withdraw_stake(ref self: ContractState) {
            let caller = get_caller_address();
            let stake_info = self.user_stakes.read(caller);
            let current_time = get_block_timestamp();
            assert(stake_info.amount > 0, "No stake to withdraw");
            assert(current_time >= stake_info.unlock_time, "Stake still locked");
            assert(!stake_info.is_locked, "Stake locked due to disputes");
            let amount = stake_info.amount;
            // Clear stake info
            self.user_stakes.write(caller, StakeInfo {
                amount: 0,
                stake_time: 0,
                unlock_time: 0,
                is_locked: false,
            });
            // Transfer STRK back to user
            let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
            let success = strk_token.transfer(caller, amount);
            assert(success, "Withdraw transfer failed");
            self.emit(StakeWithdrawnEvent { 
                staker: caller, 
                amount, 
                timestamp: current_time 
            });
        }
        /// @notice Gets stake information for a user
        /// @param user Address to check
        /// @return (amount, unlock_time, is_locked) Stake details
        fn get_stake_info(self: @ContractState, user: ContractAddress) -> (u256, u64, bool) {
            let stake_info = self.user_stakes.read(user);
            (stake_info.amount, stake_info.unlock_time, stake_info.is_locked)
        }
        /// @notice Emergency unlock stake for a user (Admin only)
        /// @param user User to unlock stake for
        fn emergency_unlock_stake(ref self: ContractState, user: ContractAddress) {
            self.only_admin();
            let mut stake_info = self.user_stakes.read(user);
            stake_info.is_locked = false;
            self.user_stakes.write(user, stake_info);
        }
        /// @notice Creates a new collection with specified indexed fields
        /// @param name Collection name
        /// @param indexed_fields Array of field names to index for efficient querying
        fn create_collection(ref self: ContractState, name: felt252, indexed_fields: Array<felt252>) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('create_collection');
            assert(name != 0, "Collection name cannot be empty");
            assert(indexed_fields.len() <= MAX_INDEXED_FIELDS, "Too many indexed fields");
            let caller = get_caller_address();
            let len: felt252 = indexed_fields.len().try_into().unwrap();
            // Store indexed fields
            self.num_indexed.write(name, len);
            let mut i: u32 = 0;
            while i < len {
                let field = *indexed_fields.at(i.try_into().unwrap());
                assert(field != 0, "Field name cannot be empty");
                self.indexed_fields.write((name, i), field);
                i += 1;
            }
            self.emit(CollectionCreatedEvent { 
                creator: caller, 
                collection_name: name, 
                indexed_fields_count: indexed_fields.len().try_into().unwrap(),
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Inserts a document into a collection with validation
        /// @param collection Collection name
        /// @param compressed_data Document data (compressed by client)
        /// @param fields Metadata fields as key-value pairs
        /// @return felt252 Document ID
        fn insert(
            ref self: ContractState, 
            collection: felt252, 
            compressed_data: ByteArray, 
            fields: Array<(felt252, felt252)>
        ) -> felt252 {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('insert');
            self.enforce_rate_limit('insert', MAX_INSERTS_PER_HOUR);
            self.validate_fields(@fields);
            self.validate_data(@compressed_data);
            assert(collection != 0, "Collection name cannot be empty");
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            // Check user document limit (premium users have no limit)
            let profile = self.user_profiles.read(caller);
            if !self.is_user_premium.read(caller) {
                assert(profile.total_documents < MAXIMUM_DOCUMENTS_PER_USER, "Document limit reached");
            }
            // Generate document ID and update collection
            let id = self.next_id.read(collection);
            self.next_id.write(collection, id + 1);
            let index = self.num_docs.read(collection);
            self.doc_ids.write((collection, index), id);
            self.num_docs.write(collection, index + 1);
            // Compute data hash for integrity
            let data_hash = self._compute_data_hash(@compressed_data);
            // Store document with pending status and enhanced fields
            self.creators.write((collection, id), caller);
            self.documents.write((collection, id), Document {
                compressed_data: compressed_data.clone(),
                creator: caller,
                created_at: timestamp,
                updated_at: timestamp,
                data_hash: data_hash,
                validation_status: 'pending',
                positive_votes: 0,
                negative_votes: 0,
                total_voters: 0,
                whitelist_remove_votes: 0,
                whitelist_keep_votes: 0,
                whitelist_total_voters: 0,
                whitelist_approved_for_deletion: false,
            });
            // Store fields and update indices
            self._store_fields(collection, id, @fields);
            // Add to pending validations
            let pending_count = self.pending_validations_count.read();
            self.pending_validation_ids.write(pending_count, (collection, id));
            self.pending_validations_count.write(pending_count + 1);
            // Update user profile
            let mut updated_profile = profile;
            updated_profile.total_documents += 1;
            updated_profile.reputation_score += 1;
            self.user_profiles.write(caller, updated_profile);
            // Update statistics
            self._update_insert_statistics(@compressed_data);
            self.emit(DocumentInsertedEvent { 
                caller, 
                collection, 
                document_id: id, 
                data_hash,
                timestamp
            });
            id
        }
        /// @notice Retrieves a document by ID (only approved documents for regular users)
        /// @param collection Collection name
        /// @param id Document ID
        /// @return (ByteArray, Array<(felt252, felt252)>) Document data and fields
        fn get(self: @ContractState, collection: felt252, id: felt252) -> (ByteArray, Array<(felt252, felt252)>) {
            self.can_read();
            let doc = self.documents.read((collection, id));
            assert(!doc.creator.is_zero(), "Document not found");
            // Only allow approved documents for non-admin users
            let caller = get_caller_address();
            if caller != self.admin_address.read() {
                assert(doc.validation_status == "approved", "Document not approved");
            }
            let fields = self._get_document_fields(collection, id);
            (doc.compressed_data, fields)
        }
        /// @notice Updates an existing document
        /// @param collection Collection name
        /// @param id Document ID
        /// @param compressed_data New document data
        /// @param fields New metadata fields
        fn update(
            ref self: ContractState, 
            collection: felt252, 
            id: felt252, 
            compressed_data: ByteArray, 
            fields: Array<(felt252, felt252)>
        ) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('update');
            self.enforce_rate_limit('update', MAX_UPDATES_PER_HOUR);
            self.validate_fields(@fields);
            self.validate_data(@compressed_data);
            let caller = get_caller_address();
            let creator = self.creators.read((collection, id));
            assert(!creator.is_zero(), "Document not found");
            assert(caller == creator, "Only creator can update");
            // Deduct points if not premium
            self._charge_update_points(caller);
            // Calculate size difference for statistics
            let old_doc = self.documents.read((collection, id));
            let old_size = self._calculate_data_size(@old_doc.compressed_data);
            let new_size = self._calculate_data_size(@compressed_data);
            // Update document and reset validation status
            let timestamp = get_block_timestamp();
            let data_hash = self._compute_data_hash(@compressed_data);
            let mut doc = self.documents.read((collection, id));
            doc.compressed_data = compressed_data;
            doc.updated_at = timestamp;
            doc.data_hash = data_hash;
            doc.validation_status = 'pending';
            doc.positive_votes = 0;
            doc.negative_votes = 0;
            doc.total_voters = 0;
            self.documents.write((collection, id), doc);
            // Update fields and indices
            self._remove_from_all_indices(collection, id);
            self._store_fields(collection, id, @fields);
            // Add back to pending validations
            let pending_count = self.pending_validations_count.read();
            self.pending_validation_ids.write(pending_count, (collection, id));
            self.pending_validations_count.write(pending_count + 1);
            // Update database size statistics
            self._update_size_statistics(old_size, new_size);
            self.emit(DocumentUpdatedEvent { 
                caller, 
                collection, 
                document_id: id, 
                old_data_hash: old_doc.data_hash,
                new_data_hash: data_hash,
                timestamp
            });
        }
        /// @notice Deletes a document
        /// @param collection Collection name
        /// @param id Document ID
        fn delete(ref self: ContractState, collection: felt252, id: felt252) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('delete');
            let caller = get_caller_address();
            let creator = self.creators.read((collection, id));
            assert(!creator.is_zero(), "Document not found");
            assert(caller == creator, "Only creator can delete");
            // Deduct points if not premium
            self._charge_delete_points(caller);
            // Calculate size for statistics update
            let doc = self.documents.read((collection, id));
            let doc_size = self._calculate_data_size(@doc.compressed_data);
            // Remove from indices and clean up
            self._remove_from_all_indices(collection, id);
            self._cleanup_document(collection, id);
            // Update user profile
            let mut profile = self.user_profiles.read(caller);
            if profile.total_documents > 0 {
                profile.total_documents -= 1;
            }
            if doc.validation_status == 'approved' && profile.approved_documents > 0 {
                profile.approved_documents -= 1;
            }
            self.user_profiles.write(caller, profile);
            // Update statistics (reduce total size)
            self._decrease_size_statistics(doc_size);
            self.emit(DocumentDeletedEvent { 
                caller, 
                collection, 
                document_id: id,
                data_hash: doc.data_hash,
                creator: doc.creator,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Finds documents matching query conditions (approved only for regular users)
        /// @param collection Collection name
        /// @param query Query conditions array
        /// @param page Page number (1-based)
        /// @return Array<felt252> Array of matching document IDs
        fn find(
            self: @ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>, 
            page: u32
        ) -> Array<felt252> {
            self.can_read();
            self.validate_query(@query);
            assert(page > 0, "Page must be >= 1");
            let caller = get_caller_address();
            self.enforce_rate_limit('query', MAX_QUERIES_PER_HOUR);
            // Charge for pagination beyond first page
            if page > 1 && !self.is_user_premium.read(caller) {
                self._charge_query_points(caller);
            }
            // Process query and return paginated results (approved documents only)
            let candidates = self._process_approved_query(collection, @query);
            self._paginate_results(@candidates, page)
        }
        /// @notice Finds first document matching query conditions
        /// @param collection Collection name
        /// @param query Query conditions array
        /// @return (ByteArray, Array<(felt252, felt252)>) First matching document
        fn find_one(
            self: @ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>
        ) -> (ByteArray, Array<(felt252, felt252)>) {
            let ids = self.find(collection, query, 1);
            if ids.len() == 0 {
                return (Default::default(), ArrayTrait::new());
            }
            let id = *ids.at(0);
            self.get(collection, id)
        }
        /// @notice Gets all approved document IDs in a collection
        /// @param collection Collection name
        /// @return Array<felt252> All approved document IDs
        fn get_all_data(self: @ContractState, collection: felt252) -> Array<felt252> {
            self.can_read();
            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.read((collection, i));
                result.append(id);
                i += 1;
            }
            result
        }
        /// @notice Admin-only function to find all documents (including pending)
        /// @param collection Collection name
        /// @param query Query conditions array
        /// @param page Page number
        /// @return Array<felt252> All matching document IDs
        fn admin_find(
            self: @ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>, 
            page: u32
        ) -> Array<felt252> {
            self.only_admin();
            self.validate_query(@query);
            assert(page > 0, "Page must be >= 1");
            let candidates = self._process_query(collection, @query);
            self._paginate_results(@candidates, page)
        }
        /// @notice Admin-only function to get all document IDs (including pending)
        /// @param collection Collection name
        /// @return Array<felt252> All document IDs
        fn admin_get_all_data(self: @ContractState, collection: felt252) -> Array<felt252> {
            self.only_admin();
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_docs {
                let id = self.doc_ids.read((collection, i));
                result.append(id);
                i += 1;
            }
            result
        }
        /// @notice Vote on a document's validity
        /// @param collection Collection name
        /// @param doc_id Document ID
        /// @param is_valid Whether the document is valid/legitimate
        fn vote_on_document(ref self: ContractState, collection: felt252, doc_id: felt252, is_valid: bool) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_rate_limit('vote', MAX_VOTES_PER_HOUR);
            let caller = get_caller_address();
            assert(!caller.is_zero(), "Zero address cannot vote");
            let mut doc = self.documents.read((collection, doc_id));
            assert(!doc.creator.is_zero(), "Document not found");
            assert(doc.validation_status == "pending", "Document not pending validation");
            assert(doc.creator != caller, "Cannot vote on own document");
            assert(!self.document_voters.read((collection, doc_id, caller)), "Already voted on this document");
            // Record the vote
            self.document_voters.write((collection, doc_id, caller), true);
            if is_valid {
                doc.positive_votes += 1;
            } else {
                doc.negative_votes += 1;
            }
            doc.total_voters += 1;
            self.documents.write((collection, doc_id), doc);
            // Award points for voting
            let current_points = self.points.read(caller);
            let new_points = current_points + VOTE_REWARD_POINTS.try_into().unwrap();
            self.points.write(caller, new_points);
            // Update voter profile
            let mut profile = self.user_profiles.read(caller);
            profile.total_votes_cast += 1;
            self.user_profiles.write(caller, profile);
            self.emit(PointsAwardedForVoting {
                voter: caller,
                collection,
                document_id: doc_id,
                points_awarded: VOTE_REWARD_POINTS,
                total_points: new_points,
                vote_type: 'approval',
                timestamp: get_block_timestamp()
            });
            self.emit(DocumentVoteSubmitted { 
                voter: caller, 
                collection, 
                document_id: doc_id,
                creator: doc.creator,
                is_valid,
                positive_votes: doc.positive_votes,
                negative_votes: doc.negative_votes,
                timestamp: get_block_timestamp()
            });
            // Check if validation threshold reached
            self._check_validation_consensus(collection, doc_id);
        }
        /// @notice Get document validation status
        /// @param collection Collection name
        /// @param doc_id Document ID
        /// @return (status, positive_votes, negative_votes, total_votes) Validation details
        fn get_document_validation_status(
            self: @ContractState, 
            collection: felt252, 
            doc_id: felt252
        ) -> (felt252, u32, u32, u32) {
            let doc = self.documents.read((collection, doc_id));
            assert(!doc.creator.is_zero(), "Document not found");
            (doc.validation_status, doc.positive_votes, doc.negative_votes, doc.total_voters)
        }
        /// @notice Report malicious data
        /// @param collection Collection name
        /// @param doc_id Document ID
        /// @param reason Reason for reporting
        fn report_malicious_data(ref self: ContractState, collection: felt252, doc_id: felt252, reason: felt252) {
            self.only_registered_non_banned();
            self.only_staked_users();
            assert(reason != 0, "Reason cannot be empty");
            let caller = get_caller_address();
            let doc = self.documents.read((collection, doc_id));
            assert(!doc.creator.is_zero(), "Document not found");
            assert(doc.creator != caller, "Cannot report own document");
            let report_id = self.next_report_id.read();
            self.next_report_id.write(report_id + 1);
            let report = MaliciousReport {
                reporter: caller,
                collection: collection,
                doc_id: doc_id,
                reason: reason,
                timestamp: get_block_timestamp(),
                is_resolved: false,
            };
            self.reports.write(report_id, report);
            // Update statistics
            let total_reports = self.total_malicious_reports.read();
            self.total_malicious_reports.write(total_reports + 1);
            self.emit(MaliciousDataReported { 
                reporter: caller, 
                collection, 
                doc_id, 
                creator: doc.creator,
                reason, 
                report_id,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Get pending validations for voting
        /// @param page Page number
        /// @return Array<(felt252, felt252)> Array of (collection, doc_id) pairs
        fn get_pending_validations(self: @ContractState, page: u32) -> Array<(felt252, felt252)> {
            assert(page > 0, "Page must be >= 1");
            let mut result = ArrayTrait::new();
            let total_pending = self.pending_validations_count.read();
            let start_idx = (page - 1) * 10; // 10 results per page
            let end_idx = if start_idx + 10 > total_pending { total_pending } else { start_idx + 10 };
            let mut i: u64 = start_idx;
            while i < end_idx {
                let (collection, doc_id) = self.pending_validation_ids.read(i);
                let doc = self.documents.read((collection, doc_id));
                if doc.validation_status == 'pending' {
                    result.append((collection, doc_id));
                }
                i += 1;
            }
            result
        }
        /// @notice Vote to whitelist a document for deletion
        /// @param collection Collection name
        /// @param doc_id Document ID
        /// @param vote_remove Whether to vote for removal (true) or to keep (false)
        fn vote_on_whitelist(ref self: ContractState, collection: felt252, doc_id: felt252, vote_remove: bool) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_rate_limit('whitelist_vote', MAX_VOTES_PER_HOUR);
            let voter = get_caller_address();
            assert(!voter.is_zero(), "Zero address cannot vote");
            let mut doc = self.documents.read((collection, doc_id));
            assert(!doc.creator.is_zero() && doc.validation_status != "deleted", "Document not found or deleted");
            assert(doc.creator != voter, "Cannot vote on own document");
            assert(!self.whitelist_voters.read((collection, doc_id, voter)), "Already voted on whitelist");
            // Record the vote
            self.whitelist_voters.write((collection, doc_id, voter), true);
            if vote_remove {
                doc.whitelist_remove_votes += 1;
            } else {
                doc.whitelist_keep_votes += 1;
            }
            doc.whitelist_total_voters += 1;
            self.documents.write((collection, doc_id), doc);
            // Award 2 points for whitelist voting
            let current_points = self.points.read(voter);
            let new_points = current_points + VOTE_REWARD_POINTS.try_into().unwrap();
            self.points.write(voter, new_points);
            self.emit(PointsAwardedForVoting {
                voter,
                collection,
                document_id: doc_id,
                points_awarded: VOTE_REWARD_POINTS,
                total_points: new_points,
                vote_type: 'whitelist',
                timestamp: get_block_timestamp()
            });
            self.emit(WhitelistVoteSubmitted {
                voter,
                collection,
                document_id: doc_id,
                creator: doc.creator,
                vote_remove,
                remove_votes: doc.whitelist_remove_votes,
                keep_votes: doc.whitelist_keep_votes,
                timestamp: get_block_timestamp()
            });
            // Check if consensus for whitelisting is reached
            self._check_whitelist_consensus(collection, doc_id);
        }
        /// @notice Registers a user account
        fn register_account(ref self: ContractState) {
            let caller = get_caller_address();
            assert(!caller.is_zero(), "Cannot register zero address");
            assert(self.accounts.read(caller) == 0, "Account already registered");
            let timestamp = get_block_timestamp();
            self.accounts.write(caller, timestamp);
            // Initialize user profile
            let profile = UserProfile {
                reputation_score: 100, // Starting reputation
                total_documents: 0,
                last_action_time: timestamp,
                is_premium: false,
                warning_count: 0,
                total_votes_cast: 0,
                approved_documents: 0,
            };
            self.user_profiles.write(caller, profile);
            // Update statistics
            self._increment_account_statistics();
            self.emit(AccountRegistered { account: caller, timestamp });
        }
        /// @notice Bans a user from database operations (Admin only)
        /// @param user_address Address to ban
        fn ban_user(ref self: ContractState, user_address: ContractAddress) {
            self.only_admin();
            assert(!user_address.is_zero(), "Cannot ban zero address");
            let caller = get_caller_address();
            self.banned_users.write(user_address, true);
            // Update reputation severely
            let mut profile = self.user_profiles.read(user_address);
            profile.reputation_score = self.minimum_reputation_score.read() - 1;
            profile.warning_count += 1;
            self.user_profiles.write(user_address, profile);
            self.emit(UserBannedEvent { 
                banned_user: user_address, 
                admin: caller, 
                reason: 'admin_action',
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Unbans a user, restoring access (Admin only)
        /// @param user_address Address to unban
        fn unban_user(ref self: ContractState, user_address: ContractAddress) {
            self.only_admin();
            assert(!user_address.is_zero(), "Cannot unban zero address");
            let caller = get_caller_address();
            self.banned_users.write(user_address, false);
            // Reset reputation to neutral
            let mut profile = self.user_profiles.read(user_address);
            profile.reputation_score = 0;
            profile.warning_count = 0;
            self.user_profiles.write(user_address, profile);
            self.emit(UserUnbannedEvent { 
                unbanned_user: user_address, 
                admin: caller,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Gets user profile information
        /// @param user User address
        /// @return (reputation, documents, warnings, is_premium, last_action) Profile details
        fn get_user_profile(
            self: @ContractState, 
            user: ContractAddress
        ) -> (i32, u32, u32, bool, u64) {
            let profile = self.user_profiles.read(user);
            (
                profile.reputation_score,
                profile.total_documents,
                profile.warning_count,
                profile.is_premium,
                profile.last_action_time
            )
        }
        /// @notice Gets total number of registered accounts
        /// @return u64 Total accounts registered
        fn get_total_accounts_registered(self: @ContractState) -> u64 {
            self.total_accounts_registered.read()
        }
        /// @notice Gets total number of documents inserted
        /// @return u64 Total documents inserted
        fn get_total_documents_inserted(self: @ContractState) -> u64 {
            self.total_documents_inserted.read()
        }
        /// @notice Gets total database size in bytes
        /// @return u256 Total database size in bytes
        fn get_total_database_size_bytes(self: @ContractState) -> u256 {
            self.total_database_size_bytes.read()
        }
        /// @notice Gets comprehensive security statistics
        /// @return (slashed_stakes, malicious_reports, resolved_reports, pending_validations) Security stats
        fn get_security_statistics(self: @ContractState) -> (u256, u64, u64, u64) {
            (
                self.total_slashed_stakes.read(),
                self.total_malicious_reports.read(),
                self.total_resolved_reports.read(),
                self.pending_validations_count.read()
            )
        }
        /// @notice Updates all configurable parameters (Admin only)
        fn update_all_parameters(
            ref self: ContractState,
            new_points_per_insert: u32,
            new_points_per_update: u32,
            new_points_per_delete: u32,
            new_points_per_query_page: u32,
            new_points_threshold_for_claim: u32,
            new_premium_reward_multiplier: u32,
            new_badge_threshold: u32,
            new_points_to_strk_wei: u256,
        ) {
            self.only_admin();
            // Validate all parameters
            assert(new_points_per_insert > 0, "Points per insert must be > 0");
            assert(new_points_per_update > 0, "Points per update must be > 0");
            assert(new_points_per_delete > 0, "Points per delete must be > 0");
            assert(new_points_per_query_page > 0, "Points per query page must be > 0");
            assert(new_points_threshold_for_claim > 0, "Claim threshold must be > 0");
            assert(new_premium_reward_multiplier > 0, "Premium multiplier must be > 0");
            assert(new_badge_threshold > 0, "Badge threshold must be > 0");
            assert(new_points_to_strk_wei > 0, "Points to STRK ratio must be > 0");
            // Update all parameters
            self.points_per_insert.write(new_points_per_insert);
            self.points_per_update.write(new_points_per_update);
            self.points_per_delete.write(new_points_per_delete);
            self.points_per_query_page.write(new_points_per_query_page);
            self.points_threshold_for_claim.write(new_points_threshold_for_claim);
            self.premium_reward_multiplier.write(new_premium_reward_multiplier);
            self.badge_threshold.write(new_badge_threshold);
            self.points_to_strk_wei.write(new_points_to_strk_wei);
            self.emit(ParametersUpdated {
                admin: get_caller_address(),
                new_points_per_insert,
                new_points_per_update,
                new_points_per_delete,
                new_points_per_query_page,
                new_points_threshold_for_claim,
                new_premium_reward_multiplier,
                new_badge_threshold,
                new_points_to_strk_wei,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Updates security parameters (Admin only)
        fn update_security_parameters(
            ref self: ContractState, 
            min_stake: u256, 
            stake_lock_period: u64, 
            cooldown_period: u64, 
            min_reputation: i32,
            max_pending_time: u64,
            approval_percentage: i32,
            slash_percentage: i32,
            transaction_fee_percent: i32
        ) {
            self.only_admin();
            assert(min_stake > 0, "Minimum stake must be > 0");
            assert(stake_lock_period > 0, "Lock period must be > 0");
            assert(approval_percentage <= 100, "Invalid approval percentage");
            assert(slash_percentage <= 100, "Invalid slash percentage");
            assert(transaction_fee_percent <= 100, "Invalid fee percentage");
            self.minimum_stake_amount.write(min_stake);
            self.stake_lock_period.write(stake_lock_period);
            self.action_cooldown_period.write(cooldown_period);
            self.minimum_reputation_score.write(min_reputation);
            self.max_pending_time.write(max_pending_time);
            self.approval_percentage.write(approval_percentage);
            self.slash_percentage.write(slash_percentage);
            self.transaction_fee_percent.write(transaction_fee_percent);
            self.emit(SecurityParametersUpdated {
                admin: get_caller_address(),
                min_stake,
                stake_lock_period,
                cooldown_period,
                min_reputation,
                max_pending_time,
                approval_percentage,
                slash_percentage,
                transaction_fee_percent,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Slash malicious user's stake (Admin only)
        /// @param user User to slash
        /// @param amount Amount to slash
        /// @param reason Reason for slashing
        fn slash_malicious_stake(ref self: ContractState, user: ContractAddress, amount: u256, reason: felt252) {
            self.only_moderator_or_admin();
            let caller = get_caller_address();
            let mut stake_info = self.user_stakes.read(user);
            assert(stake_info.amount >= amount, "Insufficient stake to slash");
            stake_info.amount -= amount;
            stake_info.is_locked = true; // Lock remaining stake
            self.user_stakes.write(user, stake_info);
            // Update reputation severely
            let mut profile = self.user_profiles.read(user);
            profile.reputation_score -= 100;
            profile.warning_count += 1;
            self.user_profiles.write(user, profile);
            // Update slashing statistics
            let total_slashed = self.total_slashed_stakes.read();
            self.total_slashed_stakes.write(total_slashed + amount);
            self.emit(StakeSlashedEvent { 
                penalized_user: user, 
                admin: caller, 
                slashed_amount: amount, 
                reason,
                timestamp: get_block_timestamp()
            });
            self.emit(ReputationChangedEvent { 
                user, 
                old_reputation: profile.reputation_score + 100, 
                new_reputation: profile.reputation_score,
                reason: 'stake_slashed',
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Force approve a document (Admin only)
        /// @param collection Collection name
        /// @param doc_id Document ID
        fn force_approve_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_moderator_or_admin();
            self._approve_document(collection, doc_id);
        }
        /// @notice Force reject a document (Admin only)
        /// @param collection Collection name
        /// @param doc_id Document ID
        fn force_reject_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_moderator_or_admin();
            self._reject_document(collection, doc_id);
        }
        /// @notice Deletes a document that has been approved for deletion via whitelist voting
        /// @param collection Collection name
        /// @param doc_id Document ID
        fn delete_whitelisted_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_registered_non_banned();
            let caller = get_caller_address();
            let doc = self.documents.read((collection, doc_id));
            assert(!doc.creator.is_zero(), "Document not found");
            assert(doc.whitelist_approved_for_deletion, "Document not approved for deletion");
            assert(caller == doc.creator || caller == self.admin_address.read(), "Unauthorized");
            // Deduct points if not premium
            self._charge_delete_points(caller);
            // Calculate size for statistics update
            let doc_size = self._calculate_data_size(@doc.compressed_data);
            // Remove from indices and clean up
            self._remove_from_all_indices(collection, doc_id);
            self._cleanup_document(collection, doc_id);
            // Update user profile
            let mut profile = self.user_profiles.read(doc.creator);
            if profile.total_documents > 0 {
                profile.total_documents -= 1;
            }
            if profile.approved_documents > 0 {
                profile.approved_documents -= 1;
            }
            self.user_profiles.write(doc.creator, profile);
            // Update statistics
            self._decrease_size_statistics(doc_size);
            self.emit(DocumentDeletedEvent { 
                caller, 
                collection, 
                document_id: doc_id,
                data_hash: doc.data_hash,
                creator: doc.creator,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Cleans up documents pending validation beyond max_pending_time
        /// @dev Admin-only function to reject stale pending documents
        fn cleanup_stale_pending_documents(ref self: ContractState) {
            self.only_admin();
            let total_pending = self.pending_validations_count.read();
            let max_pending_time = self.max_pending_time.read();
            let current_time = get_block_timestamp();
            let mut i = 0_u64;
            while i < total_pending {
                let (collection, doc_id) = self.pending_validation_ids.read(i);
                let doc = self.documents.read((collection, doc_id));
                if doc.validation_status == 'pending' && (current_time - doc.created_at) > max_pending_time {
                    self._reject_document(collection, doc_id);
                }
                i += 1;
            }
        }
    }
    // ============================================================================
    // REWARD SYSTEM (Enhanced with Security)
    // ============================================================================
    /// @notice Claims STRK reward based on accumulated points
    #[external(v0)]
    fn claim_reward(ref self: ContractState) {
        let caller = get_caller_address();
        assert(!self.banned_users.read(caller), "User is banned");
        assert(!self.is_circuit_breaker_active.read(), "System maintenance mode");
        let profile = self.user_profiles.read(caller);
        assert(profile.reputation_score >= 0, "Reputation too low for claims");
        assert(profile.warning_count < 5, "Too many warnings");
        let stake_info = self.user_stakes.read(caller);
        let min_stake = self.minimum_stake_amount.read();
        assert(stake_info.amount >= min_stake, "Must maintain minimum stake");
        assert(!stake_info.is_locked, "Stake is locked");
        let current_points = self.points.read(caller);
        let claim_threshold = self.points_threshold_for_claim.read();
        assert(current_points >= claim_threshold.try_into().unwrap(), "Insufficient points");
        let fee_points = (current_points * TRANSACTION_FEE_PERCENT.into()) / 100_u64;
        let points_after_fee = current_points - fee_points;
        assert(points_after_fee >= claim_threshold.try_into().unwrap(), "Insufficient points after fee");
        let points_to_strk = self.points_to_strk_wei.read();
        let base_reward: u256 = points_after_fee.try_into().unwrap() * points_to_strk;
        let is_premium = self.is_user_premium.read(caller);
        let reward_amount = if is_premium {
            let multiplier = self.premium_reward_multiplier.read();
            base_reward * multiplier.into()
        } else {
            base_reward
        };
        // Update state first
        self.points.write(caller, 0);
        let mut updated_profile = profile;
        updated_profile.reputation_score += 5;
        self.user_profiles.write(caller, updated_profile);
        // Emit events
        self.emit(RewardClaimedEvent {
            claimant: caller,
            reward_amount: reward_amount,
            points_used: current_points,
            is_premium_bonus: is_premium,
            timestamp: get_block_timestamp()
        });
        self.emit(ReputationChangedEvent { 
            user: caller, 
            old_reputation: profile.reputation_score, 
            new_reputation: updated_profile.reputation_score,
            reason: 'reward_claimed',
            timestamp: get_block_timestamp()
        });
        // Transfer tokens last
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        let success = strk_token.transfer(caller, reward_amount);
        assert(success, "Transfer failed");
    }
    // ============================================================================
    // VIEW FUNCTIONS (Enhanced)
    // ============================================================================
    /// @notice Gets user's current points balance
    #[external(v0)]
    fn get_points(self: @ContractState, account: ContractAddress) -> i32 {
        self.points.read(account)
    }
    /// @notice Gets user's claimable points after fees
    #[external(v0)]
    fn get_claimable_points(self: @ContractState, account: ContractAddress) -> u32 {
        let current_points = self.points.read(account);
        let claim_threshold = self.points_threshold_for_claim.read();
        if current_points < claim_threshold.try_into().unwrap() {
            return 0;
        }
        let fee_points = (current_points * TRANSACTION_FEE_PERCENT.into()) / 100_u64;
        let points_after_fee = current_points - fee_points;
        if points_after_fee >= claim_threshold.try_into().unwrap() {
            points_after_fee.try_into().unwrap()
        } else {
            0
        }
    }
    /// @notice Checks if user has premium status
    #[external(v0)]
    fn get_is_user_premium(self: @ContractState, user_address: ContractAddress) -> bool {
        self.is_user_premium.read(user_address)
    }
    /// @notice Checks if user is banned
    #[external(v0)]
    fn is_user_banned(self: @ContractState, user_address: ContractAddress) -> bool {
        self.banned_users.read(user_address)
    }
    /// @notice Checks if user has a specific badge
    #[external(v0)]
    fn has_badge(self: @ContractState, account: ContractAddress, badge_id: u64) -> bool {
        self.badges.read((account, badge_id))
    }
    /// @notice Gets admin address
    #[external(v0)]
    fn get_admin_address(self: @ContractState) -> ContractAddress {
        self.admin_address.read()
    }
    /// @notice Gets STRK token address
    #[external(v0)]
    fn get_strk_token_address(self: @ContractState) -> ContractAddress {
        self.strk_token_address.read()
    }
    /// @notice Calculates potential reward for user
    #[external(v0)]
    fn calculate_reward(self: @ContractState, account: ContractAddress) -> u256 {
        let current_points = self.points.read(account);
        let claim_threshold = self.points_threshold_for_claim.read();
        if current_points < claim_threshold.try_into().unwrap() {
            return 0;
        }
        let fee_points = (current_points * TRANSACTION_FEE_PERCENT.into()) / 100_u64;
        let points_after_fee = current_points - fee_points;
        if points_after_fee < claim_threshold.try_into().unwrap() {
            return 0;
        }
        let points_to_strk = self.points_to_strk_wei.read();
        let base_reward: u256 = points_after_fee.try_into().unwrap() * points_to_strk;
        if self.is_user_premium.read(account) {
            let multiplier = self.premium_reward_multiplier.read();
            base_reward * multiplier.into()
        } else {
            base_reward
        }
    }
    /// @notice Gets all reward parameters
    #[external(v0)]
    fn get_reward_parameters(self: @ContractState) -> (u32, u32, u32, u32, u32, u32, u32, u256) {
        (
            self.points_per_insert.read(),
            self.points_per_update.read(),
            self.points_per_delete.read(),
            self.points_per_query_page.read(),
            self.points_threshold_for_claim.read(),
            self.premium_reward_multiplier.read(),
            self.badge_threshold.read(),
            self.points_to_strk_wei.read()
        )
    }
    /// @notice Gets collection information
    #[external(v0)]
    fn get_collection_info(self: @ContractState, collection: felt252) -> (u32, u32, Array<felt252>) {
        let num_docs = self.num_docs.read(collection);
        let num_approved = self.approved_docs.read(collection);
        let num_indexed = self.num_indexed.read(collection);
        let mut indexed_fields = ArrayTrait::new();
        let mut i: u32 = 0; 
        while i < num_indexed {
            indexed_fields.append(self.indexed_fields.read((collection, i)));
            i += 1;
        }
        (num_docs, num_approved, indexed_fields)
    }
    /// @notice Checks if user account is registered
    #[external(v0)]
    fn is_account_registered(self: @ContractState, user_address: ContractAddress) -> bool {
        self.accounts.read(user_address) != 0
    }
    /// @notice Gets comprehensive database statistics
    #[external(v0)]
    fn get_database_statistics(self: @ContractState) -> (u64, u64, u256) {
        (
            self.total_accounts_registered.read(),
            self.total_documents_inserted.read(),
            self.total_database_size_bytes.read()
        )
    }
    /// @notice Checks if user can perform specific action (public view)
    #[external(v0)]
    fn can_perform_action(self: @ContractState, user: ContractAddress, action_type: felt252) -> bool {
        let stake_info = self.user_stakes.read(user);
        let profile = self.user_profiles.read(user);
        let min_stake = self.minimum_stake_amount.read();
        let min_rep = self.minimum_reputation_score.read();
        stake_info.amount >= min_stake && 
        profile.reputation_score >= min_rep &&
        !stake_info.is_locked &&
        !self.banned_users.read(user) &&
        !self.is_circuit_breaker_active.read()
    }
    /// @notice Gets comprehensive user security profile
    #[external(v0)]
    fn get_user_security_profile(self: @ContractState, user: ContractAddress) -> (i32, u32, u32, u32, bool, u256, u64) {
        let profile = self.user_profiles.read(user);
        let stake_info = self.user_stakes.read(user);
        (
            profile.reputation_score,
            profile.total_documents,
            profile.warning_count,
            profile.total_votes_cast,
            profile.is_premium,
            stake_info.amount,
            stake_info.unlock_time
        )
    }
    /// @notice Gets system status
    #[external(v0)]
    fn get_system_status(self: @ContractState) -> bool {
        !self.is_circuit_breaker_active.read()
    }
    // ============================================================================
    // INTERNAL HELPER FUNCTIONS (Enhanced)
    // ============================================================================
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// @notice Computes hash of data for integrity verification
        fn _compute_data_hash(self: @ContractState, data: @ByteArray) -> felt252 {
            let mut hash_state = PoseidonTrait::new();
            hash_state = hash_state.update(data.len().into());
            let len = data.len();
            let mut i: u32 = 0;
            while i < len {
                if i + 4 <= len {
                    let chunk = data.at(i).unwrap().into() * 0x1000000_u32.into()
                              + data.at(i+1).unwrap().into() * 0x10000_u32.into()
                              + data.at(i+2).unwrap().into() * 0x100_u32.into()
                              + data.at(i+3).unwrap().into();
                    hash_state = hash_state.update(chunk.into());
                    i += 4;
                } else {
                    hash_state = hash_state.update(data.at(i).unwrap().into());
                    i += 1;
                }
            }
            hash_state.finalize()
        }
        /// @notice Check validation consensus based on total registered users
        fn _check_validation_consensus(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let doc = self.documents.read((collection, doc_id));
            let total_users = self.total_accounts_registered.read();
            if total_users == 0 {
                return;
            }
            // Calculate required votes (60% of total users)
            let required_votes = (total_users * (APPROVAL_PERCENTAGE as u64)) / 100_u64;
            let required_votes = required_votes.try_into().unwrap();
            if doc.positive_votes >= required_votes {
                self._approve_document(collection, doc_id);
            } else if doc.negative_votes >= required_votes {
                self._reject_document(collection, doc_id);
            }
        }
        /// @notice Approve a document
        fn _approve_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let timestamp = get_block_timestamp();
            let mut doc = self.documents.read((collection, doc_id));
            if doc.validation_status != 'pending' {
                return;
            }
            doc.validation_status = 'approved';
            self.documents.write((collection, doc_id), doc);
            let approved_count = self.approved_docs.read(collection);
            self.approved_doc_ids.write((collection, approved_count), doc_id);
            self.approved_docs.write(collection, approved_count + 1);
            self._remove_from_pending_validations(collection, doc_id);
            // Award approval points and badge
            self._award_approval_points_and_badge(doc.creator, collection, doc_id);
            let mut creator_profile = self.user_profiles.read(doc.creator);
            let old_reputation = creator_profile.reputation_score;
            creator_profile.reputation_score += 10;
            creator_profile.approved_documents += 1;
            self.user_profiles.write(doc.creator, creator_profile);
            self.emit(DocumentApprovedEvent { 
                collection, 
                document_id: doc_id, 
                creator: doc.creator,
                positive_votes: doc.positive_votes,
                total_votes: doc.total_voters,
                timestamp
            });
            self.emit(ReputationChangedEvent { 
                user: doc.creator, 
                old_reputation, 
                new_reputation: creator_profile.reputation_score,
                reason: 'document_approved',
                timestamp
            });
        }
        /// @notice Reject a document
        fn _reject_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let mut doc = self.documents.read((collection, doc_id));
            let old_status = doc.validation_status;
            doc.validation_status = 'rejected';
            self.documents.write((collection, doc_id), doc);
            // Remove from pending validations
            self._remove_from_pending_validations(collection, doc_id);
            // Penalize creator
            let mut creator_profile = self.user_profiles.read(doc.creator);
            let new_reputation = if creator_profile.reputation_score - 20 < self.minimum_reputation_score.read() {
                self.minimum_reputation_score.read()
            } else {
                creator_profile.reputation_score - 20
            };
            creator_profile.reputation_score = new_reputation;
            creator_profile.warning_count += 1;
            self.user_profiles.write(doc.creator, creator_profile);
            // Consider slashing stake if multiple rejections
            if creator_profile.warning_count >= 3 {
                let mut stake_info = self.user_stakes.read(doc.creator);
                let slash_amount = (stake_info.amount * SLASH_PERCENTAGE.into()) / 100_u256;
                let slash_amount = slash_amount.try_into().unwrap();
                stake_info.amount -= slash_amount;
                stake_info.is_locked = true;
                self.user_stakes.write(doc.creator, stake_info);
                let total_slashed = self.total_slashed_stakes.read();
                self.total_slashed_stakes.write(total_slashed + slash_amount);
                self.emit(StakeSlashedEvent { 
                    penalized_user: doc.creator, 
                    admin: get_contract_address(), 
                    slashed_amount: slash_amount, 
                    reason: 'repeated_violations',
                    timestamp: get_block_timestamp()
                });
            }
            self.emit(DocumentStatusChanged { 
                collection, 
                doc_id, 
                creator: doc.creator,
                old_status, 
                new_status: 'rejected',
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Remove document from pending validations list
        fn _remove_from_pending_validations(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let total_pending = self.pending_validations_count.read();
            let mut found_index = total_pending;
            // Find the document in pending list
            let mut i: u64 = 0;
            while i < total_pending {
                let (pending_collection, pending_doc_id) = self.pending_validation_ids.read(i);
                if pending_collection == collection && pending_doc_id == doc_id {
                    found_index = i;
                    break;
                }
                i += 1;
            }
            // If found, remove by shifting remaining elements
            if found_index < total_pending {
                let mut j = found_index;
                while j < total_pending - 1 {
                    let next_item = self.pending_validation_ids.read(j + 1);
                    self.pending_validation_ids.write(j, next_item);
                    j += 1;
                }
                self.pending_validations_count.write(total_pending - 1);
            }
        }
        /// @notice Process query for approved documents only
        fn _process_approved_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            if query.len() == 0 {
                return self._get_all_approved_document_ids(collection);
            }
            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.read((collection, i));
                if self._matches_query(collection, id, query) {
                    result.append(id);
                }
                i += 1;
            }
            result
        }
        /// @notice Get all approved document IDs
        fn _get_all_approved_document_ids(self: @ContractState, collection: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.read((collection, i));
                result.append(id);
                i += 1;
            }
            result
        }
        /// @notice Awards points and potentially a badge to a document creator upon approval.
        fn _award_approval_points_and_badge(
            ref self: ContractState, 
            creator: ContractAddress, 
            collection: felt252, 
            document_id: felt252
        ) {
            let points_to_award = self.points_per_insert.read();
            let current_points = self.points.read(creator);
            let new_points = current_points + points_to_award.try_into().unwrap();
            self.points.write(creator, new_points);
            // Emit event with correct parameters
            self.emit(PointsAwardedForApproval { 
                recipient: creator,
                collection, 
                document_id,
                points_awarded: points_to_award,
                total_points: new_points,
                timestamp: get_block_timestamp()
            });
            // Check for badge award
            let badge_threshold = self.badge_threshold.read();
            if new_points >= badge_threshold.try_into().unwrap() && 
               current_points < badge_threshold.try_into().unwrap() {
                let timestamp = get_block_timestamp();
                self.badges.write((creator, timestamp), true);
                self.emit(BadgeEarnedEvent { 
                    recipient: creator, 
                    badge_id: timestamp,
                    points_threshold: badge_threshold,
                    timestamp
                });
            }
        }
        /// @notice Charges points for document updates (premium users exempted)
        fn _charge_update_points(ref self: ContractState, account: ContractAddress) {
            if !self.is_user_premium.read(account) {
                let points_to_deduct = self.points_per_update.read();
                let current_points = self.points.read(account);
                assert(current_points >= points_to_deduct.try_into().unwrap(), "Insufficient points for update");
                let new_points = current_points - points_to_deduct.try_into().unwrap();
                self.points.write(account, new_points);
                self.emit(PointsDeducted { 
                    account, 
                    points: points_to_deduct, 
                    total_points: new_points,
                    action_type: 'update',
                    timestamp: get_block_timestamp()
                });
            }
        }
        /// @notice Charges points for document deletion (premium users exempted)
        fn _charge_delete_points(ref self: ContractState, account: ContractAddress) {
            if !self.is_user_premium.read(account) {
                let points_to_deduct = self.points_per_delete.read();
                let current_points = self.points.read(account);
                assert(current_points >= points_to_deduct.try_into().unwrap(), "Insufficient points for delete");
                let new_points = current_points - points_to_deduct.try_into().unwrap();
                self.points.write(account, new_points);
                self.emit(PointsDeducted { 
                    account, 
                    points: points_to_deduct, 
                    total_points: new_points,
                    action_type: 'delete',
                    timestamp: get_block_timestamp()
                });
            }
        }
        /// @notice Charges points for query pagination (premium users exempted)
        fn _charge_query_points(self: @ContractState, account: ContractAddress) {
            let points_to_deduct = self.points_per_query_page.read();
            let current_points = self.points.read(account);
            assert(current_points >= points_to_deduct.try_into().unwrap(), "Insufficient points for query");
            let new_points = current_points - points_to_deduct.try_into().unwrap();
            self.points.write(account, new_points);
            self.emit(PointsDeducted { 
                account, 
                points: points_to_deduct, 
                total_points: new_points,
                action_type: 'query',
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Check whitelist consensus
        fn _check_whitelist_consensus(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let mut doc = self.documents.read((collection, doc_id));
            let total_users = self.total_accounts_registered.read();
            if total_users == 0 {
                return;
            }
            // Calculate required votes (60% of total users)
            let required_votes = (total_users * (APPROVAL_PERCENTAGE as u64)) / 100_u64;
            let required_votes = required_votes.try_into().unwrap();
            if doc.whitelist_remove_votes >= required_votes {
                doc.whitelist_approved_for_deletion = true;
                self.documents.write((collection, doc_id), doc);
                self.emit(DocumentWhitelistApproved {
                    collection,
                    document_id: doc_id,
                    creator: doc.creator,
                    data_hash: doc.data_hash,
                    remove_votes: doc.whitelist_remove_votes,
                    total_votes: doc.whitelist_total_voters,
                    timestamp: get_block_timestamp()
                });
            }
        }
        // ============================================================================
        // ORIGINAL HELPER FUNCTIONS (Enhanced with Security Checks)
        // ============================================================================
        /// @notice Calculates the size of data in bytes
        fn _calculate_data_size(self: @ContractState, data: @ByteArray) -> u256 {
            data.len().into()
        }
        /// @notice Updates statistics when an account is registered
        fn _increment_account_statistics(ref self: ContractState) {
            let current_total = self.total_accounts_registered.read();
            let new_total = current_total + 1;
            self.total_accounts_registered.write(new_total);
            self.emit(StatisticsUpdated {
                total_accounts: new_total,
                total_documents: self.total_documents_inserted.read(),
                total_size_bytes: self.total_database_size_bytes.read(),
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Updates statistics when a document is inserted
        fn _update_insert_statistics(ref self: ContractState, data: @ByteArray) {
            let current_docs = self.total_documents_inserted.read();
            let new_docs_total = current_docs + 1;
            self.total_documents_inserted.write(new_docs_total);
            let data_size = self._calculate_data_size(data);
            let current_size = self.total_database_size_bytes.read();
            let new_size_total = current_size + data_size;
            self.total_database_size_bytes.write(new_size_total);
            self.emit(StatisticsUpdated {
                total_accounts: self.total_accounts_registered.read(),
                total_documents: new_docs_total,
                total_size_bytes: new_size_total,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Updates database size when document is modified
        fn _update_size_statistics(ref self: ContractState, old_size: u256, new_size: u256) {
            let current_total = self.total_database_size_bytes.read();
            let new_total = if new_size >= old_size {
                current_total + (new_size - old_size)
            } else {
                current_total - (old_size - new_size)
            };
            self.total_database_size_bytes.write(new_total);
            self.emit(StatisticsUpdated {
                total_accounts: self.total_accounts_registered.read(),
                total_documents: self.total_documents_inserted.read(),
                total_size_bytes: new_total,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Decreases database size when document is deleted
        fn _decrease_size_statistics(ref self: ContractState, size_to_remove: u256) {
            let current_total = self.total_database_size_bytes.read();
            let new_total = if current_total >= size_to_remove {
                current_total - size_to_remove
            } else {
                0
            };
            self.total_database_size_bytes.write(new_total);
            self.emit(StatisticsUpdated {
                total_accounts: self.total_accounts_registered.read(),
                total_documents: self.total_documents_inserted.read(),
                total_size_bytes: new_total,
                timestamp: get_block_timestamp()
            });
        }
        /// @notice Stores document fields and updates indices
        fn _store_fields(ref self: ContractState, collection: felt252, id: felt252, fields: @Array<(felt252, felt252)>) {
            let len: felt252 = fields.len().try_into().unwrap();
            self.field_lengths.write((collection, id), len);
            let num_indexed = self.num_indexed.read(collection); // Cache storage read
            let mut i: u32 = 0;
            while i < len {
                let (field, value) = *fields.at(i.try_into().unwrap());
                assert(field != 0, "Field name cannot be empty");
                self.fields_list.write((collection, id, i), field);
                self.fields_data.write((collection, id, field), value);
                if self._is_indexed(collection, field, num_indexed) { // Pass cached value
                    let num = self.index_num_ids.read((collection, field, value));
                    self.index_ids.write((collection, field, value, num), id);
                    self.index_num_ids.write((collection, field, value), num + 1);
                }
                i += 1;
            }
        }
        /// @notice Retrieves all fields for a document
        fn _get_document_fields(self: @ContractState, collection: felt252, id: felt252) -> Array<(felt252, felt252)> {
            let mut fields = ArrayTrait::new();
            let len = self.field_lengths.read((collection, id));
            let mut i: u32 = 0; 
            while i < len {
                let field = self.fields_list.read((collection, id, i));
                let value = self.fields_data.read((collection, id, field));
                fields.append((field, value));
                i += 1;
            }
            // Add system fields
            let doc = self.documents.read((collection, id));
            fields.append(('created_at', doc.created_at.try_into().unwrap()));
            fields.append(('updated_at', doc.updated_at.try_into().unwrap()));
            fields.append(('creator', doc.creator.try_into().unwrap()));
            fields.append(('status', doc.validation_status));
            fields
        }
        /// @notice Checks if a field is indexed for a collection
        fn _is_indexed(self: @ContractState, collection: felt252, field: felt252, num_indexed: felt252) -> bool {
            let mut i: u32 = 0;
            while i < num_indexed {
                if self.indexed_fields.read((collection, i)) == field {
                    return true;
                }
                i += 1;
            }
            false
        }
        /// @notice Removes document from all indices
        fn _remove_from_all_indices(ref self: ContractState, collection: felt252, id: felt252) {
            let len = self.field_lengths.read((collection, id));
            let mut i: u32 = 0;
            while i < len {
                let field = self.fields_list.read((collection, id, i));
                let num_indexed = self.num_indexed.read(collection);
                if self._is_indexed(collection, field, num_indexed) {
                    let value = self.fields_data.read((collection, id, field));
                    self._remove_from_index(collection, field, value, id);
                }
                self.fields_data.write((collection, id, field), 0);
                self.fields_list.write((collection, id, i), 0);
                i += 1;
            }
        }
        /// @notice Removes specific document from an index
        fn _remove_from_index(ref self: ContractState, collection: felt252, field: felt252, value: felt252, id: felt252) {
            let num = self.index_num_ids.read((collection, field, value));
            let mut index: u32 = 0;
            let mut found = false;
            // Find the document in the index
            while index < num {
                if self.index_ids.read((collection, field, value, index)) == id {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                // Shift remaining elements
                let mut k = index;
                while k < num - 1 {
                    let next_id = self.index_ids.read((collection, field, value, k + 1));
                    self.index_ids.write((collection, field, value, k), next_id);
                    k += 1;
                }
                self.index_num_ids.write((collection, field, value), num - 1);
            }
        }
        /// @notice Cleans up document storage after deletion
        fn _cleanup_document(ref self: ContractState, collection: felt252, id: felt252) {
            // Clear document data
            self.documents.write((collection, id), Document {
                compressed_data: Default::default(),
                creator: ContractAddress::ZERO,
                created_at: 0,
                updated_at: 0,
                data_hash: 0,
                validation_status: 'deleted',
                positive_votes: 0,
                negative_votes: 0,
                total_voters: 0,
                whitelist_remove_votes: 0,
                whitelist_keep_votes: 0,
                whitelist_total_voters: 0,
                whitelist_approved_for_deletion: false,
            });
            self.creators.write((collection, id), ContractAddress::ZERO);
            self.field_lengths.write((collection, id), 0);
            // Remove from document list
            let num = self.num_docs.read(collection);
            let mut index: u32 = 0;
            let mut found = false;
            while index < num {
                if self.doc_ids.read((collection, index)) == id {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                // Shift remaining document IDs
                let mut k = index;
                while k < num - 1 {
                    let next_id = self.doc_ids.read((collection, k + 1));
                    self.doc_ids.write((collection, k), next_id);
                    k += 1;
                }
                self.num_docs.write(collection, num - 1);
            }
            // Remove from approved documents if it was approved
            let num_approved = self.approved_docs.read(collection);
            let mut approved_index: u32 = 0;
            let mut found_approved = false;
            while approved_index < num_approved {
                if self.approved_doc_ids.read((collection, approved_index)) == id {
                    found_approved = true;
                    break;
                }
                approved_index += 1;
            }
            if found_approved {
                let mut k = approved_index;
                while k < num_approved - 1 {
                    let next_id = self.approved_doc_ids.read((collection, k + 1));
                    self.approved_doc_ids.write((collection, k), next_id);
                    k += 1;
                }
                self.approved_docs.write(collection, num_approved - 1);
            }
        }
        /// @notice Processes query conditions and returns matching document IDs (all documents)
        fn _process_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            if query.len() == 0 {
                return self._get_all_document_ids(collection);
            }
            // For simple equality queries on indexed fields, use index
            let num_indexed = self.num_indexed.read(collection);
            if query.len() == 1 {
                let (field, op, value, _) = *query.at(0);
                if op == 'eq' && self._is_indexed(collection, field, num_indexed) {
                    return self._get_indexed_documents(collection, field, value);
                }
            }
            // For complex queries, scan all documents
            self._scan_documents(collection, query)
        }
        /// @notice Gets all document IDs in a collection
        fn _get_all_document_ids(self: @ContractState, collection: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_docs {
                result.append(self.doc_ids.read((collection, i)));
                i += 1;
            }
            result
        }
        /// @notice Gets documents from index for equality query
        fn _get_indexed_documents(self: @ContractState, collection: felt252, field: felt252, value: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_ids = self.index_num_ids.read((collection, field, value));
            let mut i: u32 = 0;
            while i < num_ids {
                result.append(self.index_ids.read((collection, field, value, i)));
                i += 1;
            }
            result
        }
        /// @notice Scans all documents for complex query conditions
        fn _scan_documents(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.read(collection);
            let mut i: u32 = 0;
            while i < num_docs {
                let id = self.doc_ids.read((collection, i));
                if self._matches_query(collection, id, query) {
                    result.append(id);
                }
                i += 1;
            }
            result
        }
        /// @notice Checks if document matches query conditions
        fn _matches_query(self: @ContractState, collection: felt252, id: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> bool {
            let mut i: u32 = 0;
            while i < query.len() {
                let (field, op, value, logical) = *query.at(i);
                let matches = self._matches_condition(collection, id, field, op, value);
                // Simple AND logic for now (can be extended for complex logical operations)
                if !matches {
                    return false;
                }
                i += 1;
            }
            true
        }
        /// @notice Checks if document field matches a specific condition
        fn _matches_condition(self: @ContractState, collection: felt252, id: felt252, field: felt252, op: felt252, value: felt252) -> bool {
            let actual = self.fields_data.read((collection, id, field));
            match op {
                'eq' => actual == value,
                'ne' => actual != value,
                'gt' => actual > value,
                'lt' => actual < value,
                'gte' => actual >= value,
                'lte' => actual <= value,
                'exists' => {
                    // Check if field exists in document
                    let len = self.field_lengths.read((collection, id));
                    let mut found = false;
                    let mut j: u32 = 0;
                    while j < len {
                        if self.fields_list.read((collection, id, j)) == field {
                            found = true;
                            break;
                        }
                        j += 1;
                    }
                    if value == 1 { found } else { !found }
                },
                _ => false,
            }
        }
        /// @notice Paginates query results
        fn _paginate_results(self: @ContractState, candidates: @Array<felt252>, page: u32) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let start_idx = (page - 1) * QUERY_PAGE_SIZE;
            let total_len: u32 = candidates.len();
            if start_idx >= total_len {
                return result;
            }
            let end_idx = if start_idx + QUERY_PAGE_SIZE > total_len {
                total_len
            } else {
                start_idx + QUERY_PAGE_SIZE
            };
            let mut i = start_idx;
            while i < end_idx {
                result.append(*candidates.at(i));
                i += 1;
            }
            result
        }
    }
    // ============================================================================
    // ADDITIONAL SECURITY FUNCTIONS
    // ============================================================================
    /// @notice Process pending documents (Admin function - no auto-approval, just cleanup)
    #[external(v0)]
    fn cleanup_processed_pending_documents(ref self: ContractState) {
        self.only_admin();
        let total_pending = self.pending_validations_count.read();
        let mut cleaned_up = 0_u32;
        let mut i = 0_u64;
        // Only clean up documents that have already been approved or rejected
        while i < total_pending && cleaned_up < 50 {
            let (collection, doc_id) = self.pending_validation_ids.read(i);
            let doc = self.documents.read((collection, doc_id));
            if doc.validation_status != 'pending' {
                // Remove from pending list since it's already processed
                self._remove_from_pending_validations(collection, doc_id);
                cleaned_up += 1;
            }
            i += 1;
        }
    }
    /// @notice Get documents requiring validation (for validators)
    #[external(v0)]
    fn get_documents_for_validation(self: @ContractState, page: u32) -> Array<(felt252, felt252, felt252, ContractAddress)> {
        assert(page > 0, "Page must be >= 1");
        let mut result = ArrayTrait::new();
        let total_pending = self.pending_validations_count.read();
        let start_idx = (page - 1) * 10;
        let end_idx = if start_idx + 10 > total_pending { total_pending } else { start_idx + 10 };
        let mut i: u64 = start_idx;
        while i < end_idx {
            let (collection, doc_id) = self.pending_validation_ids.read(i);
            let doc = self.documents.read((collection, doc_id));
            if doc.validation_status == 'pending' {
                result.append((collection, doc_id, doc.data_hash, doc.creator));
            }
            i += 1;
        }
        result
    }
    /// @notice Emergency function to pause all operations
    #[external(v0)]
    fn emergency_pause(ref self: ContractState, reason: felt252) {
        self.only_admin();
        let caller = get_caller_address();
        self.is_circuit_breaker_active.write(true);
        self.emit(CircuitBreakerTriggered { admin: caller, reason, timestamp: get_block_timestamp() });
    }
    /// @notice Resume operations after emergency pause
    #[external(v0)]
    fn emergency_resume(ref self: ContractState) {
        self.only_admin();
        self.is_circuit_breaker_active.write(false);
    }
    /// @notice Batch approve multiple documents (Admin emergency function)
    #[external(v0)]
    fn batch_approve_documents(ref self: ContractState, documents: Array<(felt252, felt252)>) {
        self.only_moderator_or_admin();
        let mut i: u32 = 0;
        while i < documents.len() {
            let (collection, doc_id) = *documents.at(i);
            let doc = self.documents.read((collection, doc_id));
            if doc.validation_status == 'pending' {
                self._approve_document(collection, doc_id);
            }
            i += 1;
        }
    }
    /// @notice Batch reject multiple documents (Admin emergency function)
    #[external(v0)]
    fn batch_reject_documents(ref self: ContractState, documents: Array<(felt252, felt252)>) {
        self.only_moderator_or_admin();
        let mut i: u32 = 0;
        while i < documents.len() {
            let (collection, doc_id) = *documents.at(i);
            let doc = self.documents.read((collection, doc_id));
            if doc.validation_status == 'pending' {
                self._reject_document(collection, doc_id);
            }
            i += 1;
        }
    }
    /// @notice Get comprehensive system health metrics
    #[external(v0)]
    fn get_system_health(self: @ContractState) -> (u64, u64, u64, u32, bool) {
        let pending_count = self.pending_validations_count.read();
        let total_docs = self.total_documents_inserted.read();
        let pending_percentage = if total_docs > 0 { 
            ((pending_count as u64) * 100_u64) / (total_docs as u64)
        } else { 0_u32 };
        (
            self.total_accounts_registered.read(),
            self.total_documents_inserted.read(),
            pending_count,
            pending_percentage,
            self.is_circuit_breaker_active.read()
        )
    }
    /// @notice Reward active validators with bonus points
    #[external(v0)]
    fn reward_active_validators(ref self: ContractState, validators: Array<ContractAddress>, bonus_points: u32) {
        self.only_admin();
        let mut i: u32 = 0;
        while i < validators.len() {
            let validator = *validators.at(i);
            let profile = self.user_profiles.read(validator);
            // Only reward if they have cast votes recently
            if profile.total_votes_cast > 0 {
                let current_points = self.points.read(validator);
                let new_points = current_points + bonus_points.try_into().unwrap();
                self.points.write(validator, new_points);
                self.emit(PointsAwarded { 
                    account: validator, 
                    points: bonus_points, 
                    total_points: new_points,
                    action_type: 'validator_bonus',
                    timestamp: get_block_timestamp()
                });
            }
            i += 1;
        }
    }
    /// @notice Get user's voting history summary
    #[external(v0)]
    fn get_user_voting_stats(self: @ContractState, user: ContractAddress) -> (u32, i32, u32) {
        let profile = self.user_profiles.read(user);
        let stake_info = self.user_stakes.read(user);
        let vote_power = if stake_info.amount >= self.minimum_stake_amount.read() { 
            if profile.reputation_score > 100 { 2 } else { 1 }
        } else { 0 };
        (profile.total_votes_cast, profile.reputation_score, vote_power)
    }
    /// @notice Check if document can be voted on
    #[external(v0)]
    fn can_vote_on_document(self: @ContractState, user: ContractAddress, collection: felt252, doc_id: felt252) -> bool {
        let doc = self.documents.read((collection, doc_id));
        let has_already_voted = self.document_voters.read((collection, doc_id, user));
        let stake_info = self.user_stakes.read(user);
        let profile = self.user_profiles.read(user);
        !doc.creator.is_zero() &&
        doc.validation_status == 'pending' &&
        doc.creator != user &&
        !has_already_voted &&
        stake_info.amount >= self.minimum_stake_amount.read() &&
        profile.reputation_score >= self.minimum_reputation_score.read() &&
        !self.banned_users.read(user) &&
        !self.is_circuit_breaker_active.read()
    }
}