use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};

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
    fn find(ref self: TContractState, collection: felt252, query: Array<(felt252, felt252, felt252, felt252)>, page: u32) -> Array<felt252>;
    fn find_one(ref self: TContractState, collection: felt252, query: Array<(felt252, felt252, felt252, felt252)>) -> (ByteArray, Array<(felt252, felt252)>);
    fn get_all_data(ref self: TContractState, collection: felt252) -> Array<felt252>;
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

// ==============
// EVENTS
// ==============

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
#[derive(Drop, starknet::Event)]
struct PointsAwardedForApproval {
    #[key]
    recipient: ContractAddress,
    #[key]
    collection: felt252,
    #[key]
    document_id: felt252,
    points_awarded: u32,
    total_points: u32,
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
    total_points: u32,
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
    points_used: u256,
    is_premium_bonus: bool,
    timestamp: u64,
}
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
    total_points: u32,
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
    total_points: u32,
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

// ==============
// STORAGE STRUCTS
// ==============

#[derive(Clone, Drop, starknet::Store)]
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

#[derive(Drop, Copy, starknet::Store)]
struct StakeInfo {
    amount: u256,
    stake_time: u64,
    unlock_time: u64,
    is_locked: bool,
}

#[derive(Drop, Copy, starknet::Store)]
struct UserProfile {
    reputation_score: i32,
    total_documents: u32,
    last_action_time: u64,
    is_premium: bool,
    warning_count: u32,
    total_votes_cast: u32,
    approved_documents: u32, // Count of approved documents
}

#[derive(Drop, Copy, starknet::Store)]
struct MaliciousReport {
    reporter: ContractAddress,
    collection: felt252,
    doc_id: felt252,
    reason: felt252,
    timestamp: u64,
    is_resolved: bool,
}

// ==============
// CONTRACT
// ==============

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
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess};

    use core::byte_array::ByteArray;
    use core::byte_array::ByteArrayTrait;
    use core::hash::HashStateTrait;
    use core::poseidon::PoseidonTrait;
    use core::num::traits::Zero;

    trait ModifierTrait {
        fn only_moderator_or_admin(self: @ContractState);
        fn only_admin(self: @ContractState);
        fn only_registered_non_banned(self: @ContractState);
        fn only_staked_users(self: @ContractState);
        fn check_reputation(self: @ContractState);
        fn can_read(self: @ContractState);
        fn validate_fields(self: @ContractState, fields: @Array<(felt252, felt252)>);
        fn validate_query(self: @ContractState, query: @Array<(felt252, felt252, felt252, felt252)>);
        fn validate_data(self: @ContractState, data: @ByteArray);
    }

    trait StatisticsTrait {
        fn get_user_insert_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_delete_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_update_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_whitelist_vote_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_approval_vote_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_pending_insert_count(self: @ContractState, user: ContractAddress) -> u32;
        fn get_user_approved_insert_count(self: @ContractState, user: ContractAddress) -> u32;
        
        fn get_user_comprehensive_stats(self: @ContractState, user: ContractAddress) -> (u32, u32, u32, u32, u32, u32, u32);
        
    }

     trait ConsensusTrait {
        fn calculate_required_votes(self: @ContractState, total_users: u64) -> u32;
    }

    trait InternalTrait {
        // Read-only helpers
        fn _compute_data_hash(self: @ContractState, data: @ByteArray) -> felt252;
        fn _calculate_data_size(self: @ContractState, data: @ByteArray) -> u256;
        fn _get_document_fields(self: @ContractState, collection: felt252, id: felt252) -> Array<(felt252, felt252)>;
        fn _is_indexed(self: @ContractState, collection: felt252, field: felt252, num_indexed: u32) -> bool;
        fn _matches_condition(self: @ContractState, collection: felt252, id: felt252, field: felt252, op: felt252, value: felt252) -> bool;
        fn _matches_query(self: @ContractState, collection: felt252, id: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> bool;
        fn _get_all_document_ids(self: @ContractState, collection: felt252) -> Array<felt252>;
        fn _get_indexed_documents(self: @ContractState, collection: felt252, field: felt252, value: felt252) -> Array<felt252>;
        fn _scan_documents(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252>;
        fn _process_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252>;
        fn _get_all_approved_document_ids(self: @ContractState, collection: felt252) -> Array<felt252>;
        fn _process_approved_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252>;
        fn _paginate_results(self: @ContractState, candidates: @Array<felt252>, page: u32) -> Array<felt252>;
        // Mutating helpers (MUST use `ref self`)
        fn _check_validation_consensus(ref self: ContractState, collection: felt252, doc_id: felt252);
        fn _approve_document(ref self: ContractState, collection: felt252, doc_id: felt252);
        fn _reject_document(ref self: ContractState, collection: felt252, doc_id: felt252);
        fn _remove_from_pending_validations(ref self: ContractState, collection: felt252, doc_id: felt252);
        fn _award_approval_points_and_badge(ref self: ContractState, creator: ContractAddress, collection: felt252, document_id: felt252);
        fn _charge_query_points(ref self: ContractState, account: ContractAddress);
        fn _charge_update_points(ref self: ContractState, account: ContractAddress);
        fn _charge_delete_points(ref self: ContractState, account: ContractAddress);
        fn _check_whitelist_consensus(ref self: ContractState, collection: felt252, doc_id: felt252);
        fn _remove_from_all_indices(ref self: ContractState, collection: felt252, id: felt252);
        fn _remove_from_index(ref self: ContractState, collection: felt252, field: felt252, value: felt252, id: felt252);
        fn _cleanup_document(ref self: ContractState, collection: felt252, id: felt252);
        fn _increment_account_statistics(ref self: ContractState);
        fn _update_insert_statistics(ref self: ContractState, data: @ByteArray);
        fn _update_size_statistics(ref self: ContractState, old_size: u256, new_size: u256);
        fn _decrease_size_statistics(ref self: ContractState, size: u256);
        fn _store_fields(ref self: ContractState, collection: felt252, id: felt252, fields: @Array<(felt252, felt252)>);
        fn enforce_cooldown(ref self: ContractState, action_type: felt252);
        fn enforce_rate_limit(ref self: ContractState, action_type: felt252, max_per_hour: u32);

        fn _track_user_insert(ref self: ContractState, user: ContractAddress);
        fn _track_user_pending_insert(ref self: ContractState, user: ContractAddress);
        fn _track_user_approved_insert(ref self: ContractState, user: ContractAddress, was_pending: bool);
    }

    const DEFAULT_POINTS_PER_INSERT: u32 = 10;
    const DEFAULT_POINTS_PER_UPDATE: u32 = 1000;
    const DEFAULT_POINTS_PER_DELETE: u32 = 1000;
    const DEFAULT_POINTS_PER_QUERY_PAGE: u32 = 1000;
    const DEFAULT_POINTS_THRESHOLD_FOR_CLAIM: u32 = 1000;
    const DEFAULT_PREMIUM_REWARD_MULTIPLIER: u32 = 2;
    const DEFAULT_BADGE_THRESHOLD: u32 = 1000;
    const DEFAULT_POINTS_TO_STRK_WEI: u256 = 10000000000000000; // 0.01 STRK per point
    const MINIMUM_STAKE_AMOUNT: u256 = 10_000_000_000_000_000_000; // 10 STRK
    const STAKE_LOCK_PERIOD: u64 = 2592000; // 30 days in seconds
    const ACTION_COOLDOWN_PERIOD: u64 = 300; // 5 minutes between actions
    const MINIMUM_REPUTATION_SCORE: i32 = -100;
    const APPROVAL_PERCENTAGE: u32 = 60; // 60% positive votes needed for approval
    const VOTE_REWARD_POINTS: u32 = 2; // Points for voting
    const MAX_PENDING_TIME: u64 = 604800; // 7 days in seconds
    const MAX_INSERTS_PER_HOUR: u32 = 10;
    const MAX_QUERIES_PER_HOUR: u32 = 100;
    const MAX_UPDATES_PER_HOUR: u32 = 20;
    const MAX_VOTES_PER_HOUR: u32 = 50;
    const MAXIMUM_DATA_SIZE: u32 = 1048576; // 1MB
    const MAXIMUM_FIELD_LENGTH: u32 = 100;
    const MAX_QUERY_CONDITIONS: u32 = 50;
    const SLASH_PERCENTAGE: u32 = 50; // 50% of stake slashed for malicious activity
    const QUERY_PAGE_SIZE: u32 = 1000;
    const TRANSACTION_FEE_PERCENT: u32 = 10;
    const MAX_INDEXED_FIELDS: u32 = 10;

    const OP_EQ: felt252 = 'eq';
    const OP_NE: felt252 = 'ne';
    const OP_GT: felt252 = 'gt';
    const OP_LT: felt252 = 'lt';
    const OP_GTE: felt252 = 'gte';
    const OP_LTE: felt252 = 'lte';

    #[storage]
    struct Storage {
        admin_address: ContractAddress,
        strk_token_address: ContractAddress,
        is_circuit_breaker_active: bool,
        moderators: Map<ContractAddress, bool>,
        points_per_insert: u32,
        points_per_update: u32,
        points_per_delete: u32,
        points_per_query_page: u32,
        points_threshold_for_claim: u32,
        premium_reward_multiplier: u32,
        badge_threshold: u32,
        points_to_strk_wei: u256,
        minimum_stake_amount: u256,
        stake_lock_period: u64,
        action_cooldown_period: u64,
        minimum_reputation_score: i32,
        max_pending_time: u64,
        approval_percentage: i32,
        slash_percentage: i32,
        transaction_fee_percent: i32,
        points: Map<ContractAddress, u32>,
        badges: Map<(ContractAddress, u64), bool>,
        is_user_premium: Map<ContractAddress, bool>,
        banned_users: Map<ContractAddress, bool>,
        accounts: Map<ContractAddress, u64>,
        user_stakes: Map<ContractAddress, StakeInfo>,
        user_profiles: Map<ContractAddress, UserProfile>,
        user_last_actions: Map<(ContractAddress, felt252), u64>,
        user_hourly_actions: Map<(ContractAddress, felt252, u64), u32>,
        next_id: Map<felt252, felt252>,
        documents: Map<(felt252, felt252), Document>,
        creators: Map<(felt252, felt252), ContractAddress>,
        document_voters: Map<(felt252, felt252, ContractAddress), bool>,
        whitelist_voters: Map<(felt252, felt252, ContractAddress), bool>,
        field_lengths: Map<(felt252, felt252), u32>,
        fields_data: Map<(felt252, felt252, felt252), felt252>,
        fields_list: Map<(felt252, felt252, u32), felt252>,
        num_docs: Map<felt252, u32>,
        doc_ids: Map<(felt252, u32), felt252>,
        approved_docs: Map<felt252, u32>,
        approved_doc_ids: Map<(felt252, u32), felt252>,
        num_indexed: Map<felt252, u32>,
        indexed_fields: Map<(felt252, u32), felt252>,
        index_num_ids: Map<(felt252, felt252, felt252), u32>,
        index_ids: Map<(felt252, felt252, felt252, u32), felt252>,
        next_report_id: felt252,
        reports: Map<felt252, MaliciousReport>,
        pending_validations_count: u64,
        pending_validation_ids: Map<u64, (felt252, felt252)>,
        total_accounts_registered: u64,
        total_documents_inserted: u64,
        total_database_size_bytes: u256,
        total_slashed_stakes: u256,
        total_malicious_reports: u64,
        total_resolved_reports: u64,

        user_total_inserts: Map<ContractAddress, u32>,           
        user_total_deletes: Map<ContractAddress, u32>, user_total_updates: Map<ContractAddress, u32>,
        user_total_whitelist_votes: Map<ContractAddress, u32>,
        user_total_approval_votes: Map<ContractAddress, u32>,
        user_pending_inserts: Map<ContractAddress, u32>,
        user_approved_inserts: Map<ContractAddress, u32>,

    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        DocumentInsertedEvent: DocumentInsertedEvent,
        DocumentUpdatedEvent: DocumentUpdatedEvent,
        DocumentDeletedEvent: DocumentDeletedEvent,
        DocumentApprovedEvent: DocumentApprovedEvent,
        DocumentRejectedEvent: DocumentRejectedEvent,
        DocumentStatusChanged: DocumentStatusChanged,
        DocumentVoteSubmitted: DocumentVoteSubmitted,
        WhitelistVoteSubmitted: WhitelistVoteSubmitted,
        DocumentWhitelistApproved: DocumentWhitelistApproved,
        PointsAwardedForApproval: PointsAwardedForApproval,
        PointsAwardedForVoting: PointsAwardedForVoting,
        BadgeEarnedEvent: BadgeEarnedEvent,
        RewardClaimedEvent: RewardClaimedEvent,
        PointsDeducted: PointsDeducted,
        UserRegisteredEvent: UserRegisteredEvent,
        UserBannedEvent: UserBannedEvent,
        UserUnbannedEvent: UserUnbannedEvent,
        PremiumStatusChangedEvent: PremiumStatusChangedEvent,
        StakeDepositedEvent: StakeDepositedEvent,
        StakeWithdrawnEvent: StakeWithdrawnEvent,
        StakeSlashedEvent: StakeSlashedEvent,
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

    #[constructor]
    fn constructor(ref self: ContractState, admin_addr: ContractAddress, strk_token_addr: ContractAddress) {
        assert(!admin_addr.is_zero(), 'Admin address cannot be zero');
        assert(!strk_token_addr.is_zero(), 'Invalid STRK addr');
        self.admin_address.write(admin_addr);
        self.strk_token_address.write(strk_token_addr);
        self.is_circuit_breaker_active.write(false);
        self.points_per_insert.write(DEFAULT_POINTS_PER_INSERT);
        self.points_per_update.write(DEFAULT_POINTS_PER_UPDATE);
        self.points_per_delete.write(DEFAULT_POINTS_PER_DELETE);
        self.points_per_query_page.write(DEFAULT_POINTS_PER_QUERY_PAGE);
        self.points_threshold_for_claim.write(DEFAULT_POINTS_THRESHOLD_FOR_CLAIM);
        self.premium_reward_multiplier.write(DEFAULT_PREMIUM_REWARD_MULTIPLIER);
        self.badge_threshold.write(DEFAULT_BADGE_THRESHOLD);
        self.points_to_strk_wei.write(DEFAULT_POINTS_TO_STRK_WEI);
        self.minimum_stake_amount.write(MINIMUM_STAKE_AMOUNT);
        self.stake_lock_period.write(STAKE_LOCK_PERIOD);
        self.action_cooldown_period.write(ACTION_COOLDOWN_PERIOD);
        self.minimum_reputation_score.write(MINIMUM_REPUTATION_SCORE);
        self.max_pending_time.write(MAX_PENDING_TIME);
        self.approval_percentage.write(APPROVAL_PERCENTAGE.try_into().unwrap());
        self.slash_percentage.write(SLASH_PERCENTAGE.try_into().unwrap());
        self.transaction_fee_percent.write(TRANSACTION_FEE_PERCENT.try_into().unwrap());
        self.total_accounts_registered.write(0);
        self.total_documents_inserted.write(0);
        self.total_database_size_bytes.write(0);
        self.total_slashed_stakes.write(0);
        self.total_malicious_reports.write(0);
        self.total_resolved_reports.write(0);
        self.next_report_id.write(1);
        self.pending_validations_count.write(0);
    }

    impl StatisticsImpl of StatisticsTrait {
        fn get_user_insert_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_total_inserts.entry(user).read()
        }

        fn get_user_delete_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_total_deletes.entry(user).read()
        }

        fn get_user_update_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_total_updates.entry(user).read()
        }

        fn get_user_whitelist_vote_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_total_whitelist_votes.entry(user).read()
        }

        fn get_user_approval_vote_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_total_approval_votes.entry(user).read()
        }

        fn get_user_pending_insert_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_pending_inserts.entry(user).read()
        }

        fn get_user_approved_insert_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_approved_inserts.entry(user).read()
        }

        fn get_user_comprehensive_stats(self: @ContractState, user: ContractAddress) -> (u32, u32, u32, u32, u32, u32, u32) {
            (
                self.user_total_inserts.entry(user).read(),
                self.user_total_updates.entry(user).read(),
                self.user_total_deletes.entry(user).read(),
                self.user_total_approval_votes.entry(user).read(),
                self.user_total_whitelist_votes.entry(user).read(),
                self.user_pending_inserts.entry(user).read(),
                self.user_approved_inserts.entry(user).read(),
            )
        }
    }

    impl ModifierImpl of ModifierTrait {
        fn only_moderator_or_admin(self: @ContractState) {
            let caller = get_caller_address();
            let admin_addr = self.admin_address.read();
            assert(caller == admin_addr || self.moderators.entry(caller).read(), 'Not admin or moderator');
        }
        fn only_admin(self: @ContractState) {
            let caller = get_caller_address();
            let admin_addr = self.admin_address.read();
            assert(caller == admin_addr, 'Caller is not admin');
        }
        fn only_registered_non_banned(self: @ContractState) {
            let caller = get_caller_address();
            assert(self.accounts.entry(caller).read() != 0, 'Account not registered');
            assert(!self.banned_users.entry(caller).read(), 'User is banned');
            assert(!self.is_circuit_breaker_active.read(), 'System maintenance mode');
        }
        fn only_staked_users(self: @ContractState) {
            let caller = get_caller_address();
            let stake_info = self.user_stakes.entry(caller).read();
            let min_stake = self.minimum_stake_amount.read();
            assert(stake_info.amount >= min_stake, 'Insufficient stake amount');
            assert(!stake_info.is_locked, 'Stake is locked');
        }
        fn check_reputation(self: @ContractState) {
            let caller = get_caller_address();
            let profile = self.user_profiles.entry(caller).read();
            let min_rep = self.minimum_reputation_score.read();
            assert(profile.reputation_score >= min_rep, 'Reputation too low');
        }
        fn can_read(self: @ContractState) {
            let caller = get_caller_address();
            let is_premium = self.is_user_premium.entry(caller).read();
            let points = self.points.entry(caller).read();
            assert(!self.banned_users.entry(caller).read(), 'User is banned');
            assert(!self.is_circuit_breaker_active.read(), 'System maintenance mode');
            assert(is_premium || points >= 0, 'NEG_BALANCE');
        }
        fn validate_fields(self: @ContractState, fields: @Array<(felt252, felt252)>) {
            assert(fields.len() <= MAXIMUM_FIELD_LENGTH, 'Too many fields');
        }
        fn validate_query(self: @ContractState, query: @Array<(felt252, felt252, felt252, felt252)>) {
            assert(query.len() <= MAX_QUERY_CONDITIONS, 'Too many query conditions');
        }
        fn validate_data(self: @ContractState, data: @ByteArray) {
            assert(data.len() > 0, 'Data cannot be empty');
            assert(data.len() <= MAXIMUM_DATA_SIZE, 'Data size exceeds limit');
        }
    }

    #[external(v0)]
    fn deposit_funds(ref self: ContractState, amount: u256) {
        self.only_admin();
        assert(amount > 0, 'Amount must be greater than 0');
        let caller = get_caller_address();
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        let contract_addr = get_contract_address();
        let success = strk_token.transfer_from(caller, contract_addr, amount);
        assert(success, 'Transfer failed');
        self.emit(FundsDepositedEvent { admin: caller, amount, timestamp: get_block_timestamp() });
    }

    #[external(v0)]
    fn set_user_premium_status(ref self: ContractState, user_address: ContractAddress, is_premium: bool) {
        self.only_admin();
        assert(!user_address.is_zero(), 'Invalid user address');
        let caller = get_caller_address();
        self.is_user_premium.entry(user_address).write(is_premium);
        self.emit(PremiumStatusSet { account: user_address, is_premium, admin: caller, timestamp: get_block_timestamp() });
    }

    #[external(v0)]
    fn trigger_circuit_breaker(ref self: ContractState, reason: felt252) {
        self.only_admin();
        let caller = get_caller_address();
        self.is_circuit_breaker_active.write(true);
        self.emit(CircuitBreakerTriggered { admin: caller, reason, timestamp: get_block_timestamp() });
    }

    #[external(v0)]
    fn deactivate_circuit_breaker(ref self: ContractState) {
        self.only_admin();
        self.is_circuit_breaker_active.write(false);
    }

    #[abi(embed_v0)]
    impl DatabaseImpl of IDatabase<ContractState> {
        fn add_moderator(ref self: ContractState, moderator: ContractAddress) {
            self.only_admin();
            assert(!moderator.is_zero(), 'Invalid moderator address');
            self.moderators.entry(moderator).write(true);
        }

        fn remove_moderator(ref self: ContractState, moderator: ContractAddress) {
            self.only_admin();
            assert(!moderator.is_zero(), 'Invalid moderator address');
            self.moderators.entry(moderator).write(false);
        }

        fn stake_for_access(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let min_stake = self.minimum_stake_amount.read();
            assert(amount >= min_stake, 'Stake amount too low');
            let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
            let contract_addr = get_contract_address();
            let success = strk_token.transfer_from(caller, contract_addr, amount);
            assert(success, 'Stake transfer failed');
            let current_time = get_block_timestamp();
            let lock_period = self.stake_lock_period.read();
            let existing_stake = self.user_stakes.entry(caller).read();
            let total_stake = existing_stake.amount + amount;
            let stake_info = StakeInfo {
                amount: total_stake,
                stake_time: current_time,
                unlock_time: current_time + lock_period,
                is_locked: false,
            };
            self.user_stakes.entry(caller).write(stake_info);
            self.emit(StakeDepositedEvent { 
                staker: caller, 
                amount: total_stake, 
                unlock_time: current_time + lock_period,
                timestamp: current_time
            });
        }

        fn withdraw_stake(ref self: ContractState) {
            let caller = get_caller_address();
            let stake_info = self.user_stakes.entry(caller).read();
            let current_time = get_block_timestamp();
            assert(stake_info.amount > 0, 'No stake to withdraw');
            assert(current_time >= stake_info.unlock_time, 'Stake still locked');
            assert(!stake_info.is_locked, 'Stake locked due to disputes');
            let amount = stake_info.amount;
            self.user_stakes.entry(caller).write(StakeInfo {
                amount: 0,
                stake_time: 0,
                unlock_time: 0,
                is_locked: false,
            });
            let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
            let success = strk_token.transfer(caller, amount);
            assert(success, 'Withdraw transfer failed');
            self.emit(StakeWithdrawnEvent { 
                staker: caller, 
                amount, 
                timestamp: current_time 
            });
        }

        fn get_stake_info(self: @ContractState, user: ContractAddress) -> (u256, u64, bool) {
            let stake_info = self.user_stakes.entry(user).read();
            (stake_info.amount, stake_info.unlock_time, stake_info.is_locked)
        }

        fn emergency_unlock_stake(ref self: ContractState, user: ContractAddress) {
            self.only_admin();
            let mut stake_info = self.user_stakes.entry(user).read();
            let updated_stake = StakeInfo {
                amount: stake_info.amount,
                stake_time: stake_info.stake_time, 
                unlock_time: stake_info.unlock_time,
                is_locked: false,
            };
            self.user_stakes.entry(user).write(updated_stake);
        }

        fn create_collection(ref self: ContractState, name: felt252, indexed_fields: Array<felt252>) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('create_collection');
            assert(name != 0, 'Collection name cannot be empty');
            assert(indexed_fields.len() <= MAX_INDEXED_FIELDS, 'Too many indexed fields');
            let caller = get_caller_address();
            let len: u32 = indexed_fields.len();
            self.num_indexed.entry(name).write(len);
            let mut i: u32 = 0;
            while i < len {
                let field = *indexed_fields.at(i);
                assert(field != 0, 'Field name cannot be empty');
                self.indexed_fields.entry((name, i)).write(field);
                i += 1;
            }
            self.emit(CollectionCreatedEvent { 
                creator: caller, 
                collection_name: name, 
                indexed_fields_count: len,
                timestamp: get_block_timestamp()
            });
        }

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
            assert(collection != 0, 'Collection name cannot be empty');
            
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();
            let profile = self.user_profiles.entry(caller).read();
            let id = self.next_id.entry(collection).read();
            self.next_id.entry(collection).write(id + 1);
            let index = self.num_docs.entry(collection).read();
            self.doc_ids.entry((collection, index)).write(id);
            self.num_docs.entry(collection).write(index + 1);
            
            // Extract data reference before moving compressed_data
            let data_ref = @compressed_data;
            let data_hash = self._compute_data_hash(data_ref);
            
            self.creators.entry((collection, id)).write(caller);
            let doc = Document {
                compressed_data: compressed_data, // compressed_data moved here
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
            };
            self.documents.entry((collection, id)).write(doc);
            
            self._store_fields(collection, id, @fields);
            let pending_count = self.pending_validations_count.read();
            self.pending_validation_ids.entry(pending_count).write((collection, id));
            self.pending_validations_count.write(pending_count + 1);
            
            let mut updated_profile = profile;
            updated_profile.total_documents += 1;
            updated_profile.reputation_score += 1;
            self.user_profiles.entry(caller).write(updated_profile);
            
            // Use the reference we stored earlier
            self._update_insert_statistics(data_ref);
            self._track_user_insert(caller);
            
            self.emit(DocumentInsertedEvent { 
                caller, 
                collection, 
                document_id: id, 
                data_hash,
                timestamp
            });
            id
        }

        fn get(self: @ContractState, collection: felt252, id: felt252) -> (ByteArray, Array<(felt252, felt252)>) {
            self.can_read();
            let doc = self.documents.entry((collection, id)).read();
            assert(!doc.creator.is_zero(), 'Document not found');
            let caller = get_caller_address();
            if caller != self.admin_address.read() {
                assert(doc.validation_status == 'approved', 'Document not approved');
            }
            let fields = self._get_document_fields(collection, id);
            (doc.compressed_data, fields)
        }

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
            let creator = self.creators.entry((collection, id)).read();
            assert(!creator.is_zero(), 'Document not found');
            assert(caller == creator, 'Only creator can update');
            
            self._charge_update_points(caller);
            let old_doc = self.documents.entry((collection, id)).read();
            let old_size = self._calculate_data_size(@old_doc.compressed_data);
            
            // Extract data reference and hash before moving compressed_data
            let data_ref = @compressed_data;
            let new_size = self._calculate_data_size(data_ref);
            let timestamp = get_block_timestamp();
            let data_hash = self._compute_data_hash(data_ref);
            
            let updated_doc = Document {
                compressed_data: compressed_data, // moved here
                creator: old_doc.creator,
                created_at: old_doc.created_at,
                updated_at: timestamp,
                data_hash: data_hash,
                validation_status: 'pending',
                positive_votes: 0,
                negative_votes: 0,
                total_voters: 0,
                whitelist_remove_votes: old_doc.whitelist_remove_votes,
                whitelist_keep_votes: old_doc.whitelist_keep_votes,
                whitelist_total_voters: old_doc.whitelist_total_voters,
                whitelist_approved_for_deletion: old_doc.whitelist_approved_for_deletion,
            };
            self.documents.entry((collection, id)).write(updated_doc);
            
            self._remove_from_all_indices(collection, id);
            self._store_fields(collection, id, @fields);
            
            let pending_count = self.pending_validations_count.read();
            self.pending_validation_ids.entry(pending_count).write((collection, id));
            self.pending_validations_count.write(pending_count + 1);
            
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

        fn delete(ref self: ContractState, collection: felt252, id: felt252) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('delete');
            let caller = get_caller_address();
            let creator = self.creators.entry((collection, id)).read();
            assert(!creator.is_zero(), 'Document not found');
            assert(caller == creator, 'Only creator can delete');
            self._charge_delete_points(caller);
            let doc = self.documents.entry((collection, id)).read();

            let creator = doc.creator;
            let data_hash = doc.data_hash;

            let doc_size = self._calculate_data_size(@doc.compressed_data);
            self._remove_from_all_indices(collection, id);
            self._cleanup_document(collection, id);

            let mut profile = self.user_profiles.entry(caller).read();
            if profile.total_documents > 0 {
                profile.total_documents -= 1;
            }
            if doc.validation_status == 'approved' && profile.approved_documents > 0 {
                profile.approved_documents -= 1;
            }
            self.user_profiles.entry(caller).write(profile);
            self._decrease_size_statistics(doc_size);

            self.emit(DocumentDeletedEvent { 
                caller, 
                collection, 
                document_id: id,
                data_hash,
                creator,
                timestamp: get_block_timestamp()
            });
        }

        fn find(
            ref self: ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>, 
            page: u32
        ) -> Array<felt252> {
            self.can_read();
            self.validate_query(@query);
            assert(page > 0, 'Page must be >= 1');
            let caller = get_caller_address();
            self.enforce_rate_limit('find', MAX_QUERIES_PER_HOUR);

            if page > 1 && !self.is_user_premium.entry(caller).read() {
                self._charge_query_points(caller);
            }
            let candidates = self._process_approved_query(collection, @query);
            self._paginate_results(@candidates, page)
        }

        fn find_one(
            ref self: ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>
        ) -> (ByteArray, Array<(felt252, felt252)>) {
            let ids = self.find(collection, query, 1);
            if ids.len() == 0 {
                return ("", array![]);
            }
            let id = *ids.at(0);
            self.get(collection, id)
        }

        fn get_all_data(ref self: ContractState, collection: felt252) -> Array<felt252> {
            self.can_read();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_cooldown('get_all_data');
            self.enforce_rate_limit('get_all_data', MAX_QUERIES_PER_HOUR);

            let caller = get_caller_address();

            let is_premium = self.is_user_premium.entry(caller).read();
            let profile = self.user_profiles.entry(caller).read();
            let registration_time = self.accounts.entry(caller).read();
            
            if !is_premium {
                assert(profile.reputation_score >= 0, 'Upgrade to premium');
                let current_time = get_block_timestamp();
                let seven_days: u64 = 7 * 24 * 3600;
                assert(current_time - registration_time <= seven_days, 'Free access expired');
            }

            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.entry((collection, i)).read();
                result.append(id);
                i += 1;
            }
            result
        }

        fn admin_find(
            self: @ContractState, 
            collection: felt252, 
            query: Array<(felt252, felt252, felt252, felt252)>, 
            page: u32
        ) -> Array<felt252> {
            self.only_admin();
            self.validate_query(@query);
            assert(page > 0, 'Page must be >= 1');
            let candidates = self._process_query(collection, @query);
            self._paginate_results(@candidates, page)
        }

        fn admin_get_all_data(self: @ContractState, collection: felt252) -> Array<felt252> {
            self.only_admin();
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_docs {
                let id = self.doc_ids.entry((collection, i)).read();
                result.append(id);
                i += 1;
            }
            result
        }

        fn vote_on_document(ref self: ContractState, collection: felt252, doc_id: felt252, is_valid: bool) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_rate_limit('vote', MAX_VOTES_PER_HOUR);
            let caller = get_caller_address();
            assert(!caller.is_zero(), 'Zero address cannot vote');
            let mut doc = self.documents.entry((collection, doc_id)).read();

            assert(!doc.creator.is_zero(), 'Document not found');
            assert(doc.validation_status == 'pending', 'Document not pending validation');
            assert(doc.creator != caller, 'Cannot vote on own document');
            assert(!self.document_voters.entry((collection, doc_id, caller)).read(), 'Already voted on this document');

            self.document_voters.entry((collection, doc_id, caller)).write(true);
            if is_valid { doc.positive_votes += 1; } else { doc.negative_votes += 1; }
            doc.total_voters += 1;
            let positive_votes = doc.positive_votes;
            let negative_votes = doc.negative_votes;
            let creator = doc.creator;

            self.documents.entry((collection, doc_id)).write(doc);
            let current_points = self.points.entry(caller).read();
            let new_points = current_points + VOTE_REWARD_POINTS.try_into().unwrap();
            self.points.entry(caller).write(new_points);
            let mut profile = self.user_profiles.entry(caller).read();
            profile.total_votes_cast += 1;
            self.user_profiles.entry(caller).write(profile);

            let current = self.user_total_approval_votes.entry(caller).read();
            self.user_total_approval_votes.entry(caller).write(current + 1);
    
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
                creator: creator,
                is_valid,
                positive_votes: positive_votes,
                negative_votes: negative_votes,
                timestamp: get_block_timestamp()
            });
            self._check_validation_consensus(collection, doc_id);
        }

        fn vote_on_whitelist(ref self: ContractState, collection: felt252, doc_id: felt252, vote_remove: bool) {
            self.only_registered_non_banned();
            self.only_staked_users();
            self.check_reputation();
            self.enforce_rate_limit('whitelist_vote', MAX_VOTES_PER_HOUR);
            let voter = get_caller_address();
            assert(!voter.is_zero(), 'Zero address cannot vote');
            let mut doc = self.documents.entry((collection, doc_id)).read();
            assert(!doc.creator.is_zero() && doc.validation_status != 'deleted', 'Document not found or deleted');
            assert(doc.creator != voter, 'Cannot vote on own document');
            assert(!self.whitelist_voters.entry((collection, doc_id, voter)).read(), 'Already voted on whitelist');
            self.whitelist_voters.entry((collection, doc_id, voter)).write(true);
            if vote_remove { doc.whitelist_remove_votes += 1; } else { doc.whitelist_keep_votes += 1; }
            doc.whitelist_total_voters += 1;

            let creator = doc.creator;
            let whitelist_remove_votes = doc.whitelist_remove_votes;
            let whitelist_keep_votes = doc.whitelist_keep_votes;

            self.documents.entry((collection, doc_id)).write(doc);
            let current_points = self.points.entry(voter).read();
            let new_points = current_points + VOTE_REWARD_POINTS.try_into().unwrap();
            self.points.entry(voter).write(new_points);

            let current = self.user_total_whitelist_votes.entry(voter).read();
            self.user_total_whitelist_votes.entry(voter).write(current + 1);
            
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
                creator: creator,
                vote_remove,
                remove_votes: whitelist_remove_votes,
                keep_votes: whitelist_keep_votes,
                timestamp: get_block_timestamp()
            });
            self._check_whitelist_consensus(collection, doc_id);
        }

        fn get_document_validation_status(
            self: @ContractState, 
            collection: felt252, 
            doc_id: felt252
        ) -> (felt252, u32, u32, u32) {
            let doc = self.documents.entry((collection, doc_id)).read();
            assert(!doc.creator.is_zero(), 'Document not found');
            (doc.validation_status, doc.positive_votes, doc.negative_votes, doc.total_voters)
        }

        fn report_malicious_data(ref self: ContractState, collection: felt252, doc_id: felt252, reason: felt252) {
            self.only_registered_non_banned();
            self.only_staked_users();
            assert(reason != 0, 'Reason cannot be empty');
            let caller = get_caller_address();
            let doc = self.documents.entry((collection, doc_id)).read();
            assert(!doc.creator.is_zero(), 'Document not found');
            assert(doc.creator != caller, 'Cannot report own document');
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
            self.reports.entry(report_id).write(report);
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

        fn get_pending_validations(self: @ContractState, page: u32) -> Array<(felt252, felt252)> {
            self.only_moderator_or_admin();
            assert(page > 0, 'Page must be >= 1');
            let mut result = ArrayTrait::new();
            let total_pending = self.pending_validations_count.read();
            let start_idx: u64 = ((page - 1) * 10).into();
            let end_idx = if start_idx + 10 > total_pending { total_pending } else { start_idx + 10 };
            let mut i: u64 = start_idx;
            while i < end_idx {
                let (collection, doc_id) = self.pending_validation_ids.entry(i).read();
                let doc = self.documents.entry((collection, doc_id)).read();
                if doc.validation_status == 'pending' {
                    result.append((collection, doc_id));
                }
                i += 1;
            }
            result
        }

        fn register_account(ref self: ContractState) {
            let caller = get_caller_address();
            assert(!caller.is_zero(), 'Cannot register zero address');
            assert(self.accounts.entry(caller).read() == 0, 'Account already registered');
            let timestamp = get_block_timestamp();
            self.accounts.entry(caller).write(timestamp);
            let profile = UserProfile {
                reputation_score: 100,
                total_documents: 0,
                last_action_time: timestamp,
                is_premium: false,
                warning_count: 0,
                total_votes_cast: 0,
                approved_documents: 0,
            };
            self.user_profiles.entry(caller).write(profile);
            self._increment_account_statistics();
            self.emit(AccountRegistered { account: caller, timestamp });
        }

        fn ban_user(ref self: ContractState, user_address: ContractAddress) {
            self.only_admin();
            assert(!user_address.is_zero(), 'Cannot ban zero address');
            let caller = get_caller_address();
            self.banned_users.entry(user_address).write(true);
            let profile = self.user_profiles.entry(user_address).read();

            let total_documents = profile.total_documents;
            let last_action_time = profile.last_action_time;
            let is_premium = profile.is_premium;
            let total_votes_cast = profile.total_votes_cast;
            let approved_documents = profile.approved_documents;

            let updated_profile = UserProfile {
                reputation_score: self.minimum_reputation_score.read() - 1,
                total_documents,
                last_action_time,
                is_premium,
                warning_count: profile.warning_count,
                total_votes_cast,
                approved_documents,
            };
            self.user_profiles.entry(user_address).write(updated_profile);
            self.emit(UserBannedEvent { 
                banned_user: user_address, 
                admin: caller, 
                reason: 'admin_action',
                timestamp: get_block_timestamp()
            });
        }

        fn unban_user(ref self: ContractState, user_address: ContractAddress) {
            self.only_admin();
            assert(!user_address.is_zero(), 'Cannot unban zero address');
            let caller = get_caller_address();
            self.banned_users.entry(user_address).write(false);
            let profile = self.user_profiles.entry(user_address).read();

            let total_documents = profile.total_documents;
            let last_action_time = profile.last_action_time;
            let is_premium = profile.is_premium;
            let total_votes_cast = profile.total_votes_cast;
            let approved_documents = profile.approved_documents;

            let reset_profile = UserProfile {
                reputation_score: 0,
                total_documents,
                last_action_time,
                is_premium,
                warning_count: 0,
                total_votes_cast,
                approved_documents,
            };
            self.user_profiles.entry(user_address).write(reset_profile);
            self.emit(UserUnbannedEvent { 
                unbanned_user: user_address, 
                admin: caller,
                timestamp: get_block_timestamp()
            });
        }

        fn get_user_profile(
            self: @ContractState, 
            user: ContractAddress
        ) -> (i32, u32, u32, bool, u64) {
            let profile = self.user_profiles.entry(user).read();
            (
                profile.reputation_score,
                profile.total_documents,
                profile.warning_count,
                profile.is_premium,
                profile.last_action_time
            )
        }

        fn get_total_accounts_registered(self: @ContractState) -> u64 {
            self.total_accounts_registered.read()
        }

        fn get_total_documents_inserted(self: @ContractState) -> u64 {
            self.total_documents_inserted.read()
        }

        fn get_total_database_size_bytes(self: @ContractState) -> u256 {
            self.total_database_size_bytes.read()
        }

        fn get_security_statistics(self: @ContractState) -> (u256, u64, u64, u64) {
            (
                self.total_slashed_stakes.read(),
                self.total_malicious_reports.read(),
                self.total_resolved_reports.read(),
                self.pending_validations_count.read()
            )
        }

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
            assert(new_points_per_insert > 0, 'Points per insert must be > 0');
            assert(new_points_per_update > 0, 'Points per update must be > 0');
            assert(new_points_per_delete > 0, 'Points per delete must be > 0');
            assert(new_points_per_query_page > 0, 'Points/query> 0');
            assert(new_points_threshold_for_claim > 0, 'Claim threshold must be > 0');
            assert(new_premium_reward_multiplier > 0, 'Premium multiplier must be > 0');
            assert(new_badge_threshold > 0, 'Badge threshold must be > 0');
            assert(new_points_to_strk_wei > 0, 'Points/STRK > 0');
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
            assert(min_stake > 0, 'Minimum stake must be > 0');
            assert(stake_lock_period > 0, 'Lock period must be > 0');
            assert(approval_percentage <= 100, 'Invalid approval percentage');
            assert(slash_percentage <= 100, 'Invalid slash percentage');
            assert(transaction_fee_percent <= 100, 'Invalid fee percentage');
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

        fn slash_malicious_stake(ref self: ContractState, user: ContractAddress, amount: u256, reason: felt252) {
            self.only_moderator_or_admin();
            let caller = get_caller_address();
            let mut stake_info = self.user_stakes.entry(user).read();
            assert(stake_info.amount >= amount, 'Insufficient stake to slash');
            let locked_stake = StakeInfo {
                amount: stake_info.amount,
                stake_time: stake_info.stake_time,
                unlock_time: stake_info.unlock_time,
                is_locked: true,
            };
            self.user_stakes.entry(user).write(locked_stake);
            let mut profile = self.user_profiles.entry(user).read();
            profile.reputation_score -= 100;
            profile.warning_count += 1;

            let old_reputation = profile.reputation_score + 100;
            let reputation_score = profile.reputation_score;

            self.user_profiles.entry(user).write(profile);

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
                old_reputation: old_reputation, 
                new_reputation: reputation_score,
                reason: 'stake_slashed',
                timestamp: get_block_timestamp()
            });
        }

        fn force_approve_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_moderator_or_admin();
            self._approve_document(collection, doc_id);
        }

        fn force_reject_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_moderator_or_admin();
            self._reject_document(collection, doc_id);
        }

        fn delete_whitelisted_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self.only_registered_non_banned();
            let caller = get_caller_address();
            let doc = self.documents.entry((collection, doc_id)).read();
            assert(!doc.creator.is_zero(), 'Document not found');
            assert(doc.whitelist_approved_for_deletion, 'NOT_APPROVED');
            assert(caller == doc.creator || caller == self.admin_address.read(), 'Unauthorized');

            let creator = doc.creator;
            let data_hash = doc.data_hash;

            self._charge_delete_points(caller);
            let doc_size = self._calculate_data_size(@doc.compressed_data);
            self._remove_from_all_indices(collection, doc_id);
            self._cleanup_document(collection, doc_id);

            let mut profile = self.user_profiles.entry(creator).read();
            if profile.total_documents > 0 {
                profile.total_documents -= 1;
            }
            if profile.approved_documents > 0 {
                profile.approved_documents -= 1;
            }
            self.user_profiles.entry(creator).write(profile);
            self._decrease_size_statistics(doc_size);

            self.emit(DocumentDeletedEvent { 
                caller, 
                collection, 
                document_id: doc_id,
                data_hash,
                creator,
                timestamp: get_block_timestamp()
            });
        }

        fn cleanup_stale_pending_documents(ref self: ContractState) {
            self.only_admin();
            let total_pending = self.pending_validations_count.read();
            let max_pending_time = self.max_pending_time.read();
            let current_time = get_block_timestamp();
            let mut i = 0_u64;
            while i < total_pending {
                let (collection, doc_id) = self.pending_validation_ids.entry(i).read();
                let doc = self.documents.entry((collection, doc_id)).read();
                if doc.validation_status == 'pending' && (current_time - doc.created_at) > max_pending_time {
                    self._reject_document(collection, doc_id);
                }
                i += 1;
            }
        }
    }

    #[external(v0)]
    #[external(v0)]
    fn claim_reward(ref self: ContractState) {
        let caller = get_caller_address();
        assert(!self.banned_users.entry(caller).read(), 'User is banned');
        assert(!self.is_circuit_breaker_active.read(), 'System maintenance mode');
        let profile = self.user_profiles.entry(caller).read();

        let old_reputation = profile.reputation_score;
        let warning_count = profile.warning_count;

        assert(old_reputation >= 0, 'Reputation too low for claims');
        assert(warning_count < 5, 'Too many warnings');
        
        let stake_info = self.user_stakes.entry(caller).read();
        let min_stake = self.minimum_stake_amount.read();
        assert(stake_info.amount >= min_stake, 'Must maintain minimum stake');
        assert(!stake_info.is_locked, 'Stake is locked');
        
        let current_points: u32 = self.points.entry(caller).read();
        let claim_threshold: u32 = self.points_threshold_for_claim.read();
        assert(current_points >= claim_threshold, 'Insufficient points');
        
        // Fee in u32
        let fee_points: u32 = (current_points * TRANSACTION_FEE_PERCENT) / 100;
        let points_after_fee = current_points - fee_points;
        assert(points_after_fee >= claim_threshold, 'Insufficient points after fee');
        
        let points_to_strk = self.points_to_strk_wei.read();
        // Convert to u256 ONLY for reward calculation
        let base_reward: u256 = points_after_fee.into() * points_to_strk;
        
        let is_premium = self.is_user_premium.entry(caller).read();
        let reward_amount = if is_premium {
            let multiplier = self.premium_reward_multiplier.read();
            base_reward * multiplier.into()
        } else {
            base_reward
        };
        
        self.points.entry(caller).write(0);
        let mut updated_profile = profile;
        updated_profile.reputation_score += 5;
        let reputation_score = updated_profile.reputation_score;
        self.user_profiles.entry(caller).write(updated_profile);
        
        self.emit(RewardClaimedEvent {
            claimant: caller,
            reward_amount,
            points_used: current_points.into(), // Event expects u256 → convert
            is_premium_bonus: is_premium,
            timestamp: get_block_timestamp()
        });
        self.emit(ReputationChangedEvent { 
            user: caller, 
            old_reputation, 
            new_reputation: reputation_score,
            reason: 'reward_claimed',
            timestamp: get_block_timestamp()
        });
        
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        let success = strk_token.transfer(caller, reward_amount);
        assert(success, 'Transfer failed');
    }

    #[external(v0)]
    fn get_points(self: @ContractState, account: ContractAddress) -> u32 {
        self.points.entry(account).read()
    }

    #[external(v0)]
    fn get_claimable_points(self: @ContractState, account: ContractAddress) -> u32 {
        let current_points: u32 = self.points.entry(account).read();
        let claim_threshold: u32 = self.points_threshold_for_claim.read();
        if current_points < claim_threshold {
            return 0_u32;
        }
        let fee_points: u32 = (current_points * TRANSACTION_FEE_PERCENT) / 100;
        let points_after_fee = current_points - fee_points;
        if points_after_fee >= claim_threshold {
            points_after_fee
        } else {
            0_u32
        }
    }

    #[external(v0)]
    fn get_is_user_premium(self: @ContractState, user_address: ContractAddress) -> bool {
        self.is_user_premium.entry(user_address).read()
    }

    #[external(v0)]
    fn is_user_banned(self: @ContractState, user_address: ContractAddress) -> bool {
        self.banned_users.entry(user_address).read()
    }

    #[external(v0)]
    fn has_badge(self: @ContractState, account: ContractAddress, badge_id: u64) -> bool {
        self.badges.entry((account, badge_id)).read()
    }

    #[external(v0)]
    fn get_admin_address(self: @ContractState) -> ContractAddress {
        self.admin_address.read()
    }

    #[external(v0)]
    fn get_strk_token_address(self: @ContractState) -> ContractAddress {
        self.strk_token_address.read()
    }

    #[external(v0)]
    fn get_contract_token_balance(self: @ContractState) -> u256 {
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        let contract_addr = get_contract_address();
        strk_token.balance_of(contract_addr)
    }

    #[external(v0)]
    fn get_user_token_balance(self: @ContractState, user: ContractAddress) -> u256 {
        let strk_token = IERC20Dispatcher { contract_address: self.strk_token_address.read() };
        strk_token.balance_of(user)
    }

    #[external(v0)]
    fn calculate_reward(self: @ContractState, account: ContractAddress) -> u256 {
        let current_points: u32 = self.points.entry(account).read();
        let claim_threshold: u32 = self.points_threshold_for_claim.read();
        if current_points < claim_threshold {
            return 0_u256;
        }
        let fee_points: u32 = (current_points * TRANSACTION_FEE_PERCENT) / 100;
        let points_after_fee = current_points - fee_points;
        if points_after_fee < claim_threshold {
            return 0_u256;
        }
        let points_to_strk = self.points_to_strk_wei.read();
        let base_reward: u256 = points_after_fee.into() * points_to_strk;
        if self.is_user_premium.entry(account).read() {
            let multiplier = self.premium_reward_multiplier.read();
            base_reward * multiplier.into()
        } else {
            base_reward
        }
    }

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

    #[external(v0)]
    fn get_collection_info(self: @ContractState, collection: felt252) -> (u32, u32, Array<felt252>) {
        let num_docs = self.num_docs.entry(collection).read();
        let num_approved = self.approved_docs.entry(collection).read();
        let num_indexed = self.num_indexed.entry(collection).read();
        let mut indexed_fields = ArrayTrait::new();
        let mut i: u32 = 0; 
        while i < num_indexed {
            indexed_fields.append(self.indexed_fields.entry((collection, i)).read());
            i += 1;
        }
        (num_docs, num_approved, indexed_fields)
    }

    #[external(v0)]
    fn is_account_registered(self: @ContractState, user_address: ContractAddress) -> bool {
        self.accounts.entry(user_address).read() != 0
    }

    #[external(v0)]
    fn get_database_statistics(self: @ContractState) -> (u64, u64, u256) {
        (
            self.total_accounts_registered.read(),
            self.total_documents_inserted.read(),
            self.total_database_size_bytes.read()
        )
    }

    #[external(v0)]
    fn can_perform_action(self: @ContractState, user: ContractAddress, _action_type: felt252) -> bool {
        let stake_info = self.user_stakes.entry(user).read();
        let profile = self.user_profiles.entry(user).read();
        let min_stake = self.minimum_stake_amount.read();
        let min_rep = self.minimum_reputation_score.read();
        stake_info.amount >= min_stake && 
        profile.reputation_score >= min_rep &&
        !stake_info.is_locked &&
        !self.banned_users.entry(user).read() &&
        !self.is_circuit_breaker_active.read()
    }

    #[external(v0)]
    fn get_user_security_profile(self: @ContractState, user: ContractAddress) -> (i32, u32, u32, u32, bool, u256, u64) {
        let profile = self.user_profiles.entry(user).read();
        let stake_info = self.user_stakes.entry(user).read();
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

    #[external(v0)]
    fn get_system_status(self: @ContractState) -> bool {
        !self.is_circuit_breaker_active.read()
    }

    impl InternalImpl of InternalTrait {
        fn _compute_data_hash(self: @ContractState, data: @ByteArray) -> felt252 {
            let mut state = PoseidonTrait::new();
            let data_len: u32 = data.len();
            
            state = state.update(data_len.into());

            let mut i: u32 = 0;
            while i < data_len {
                let byte_option = data.at(i);
                let byte_val: u8 = byte_option.unwrap();
                state = state.update(byte_val.into());
                i += 1;
            }

            state.finalize()
        }

        fn enforce_cooldown(ref self: ContractState, action_type: felt252) {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let last_action = self.user_last_actions.entry((caller, action_type)).read();
            let cooldown = self.action_cooldown_period.read();
            if last_action + cooldown > current_time {
                self.emit(CooldownViolation { 
                    user: caller, 
                    action_type,
                    last_action, 
                    current_time 
                });
                assert(false, 'Action on cooldown');
            }
            self.user_last_actions.entry((caller, action_type)).write(current_time);
        }

        fn enforce_rate_limit(ref self: ContractState, action_type: felt252, max_per_hour: u32) {
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let current_hour = current_time / 3600;
            let current_count = self.user_hourly_actions.entry((caller, action_type, current_hour)).read();
            if current_count >= max_per_hour {
                self.emit(RateLimitExceeded { 
                    user: caller, 
                    action_type,
                    current_count, 
                    max_allowed: max_per_hour,
                    hour_window: current_hour
                });
                assert(false, 'Rate limit exceeded');
            }
            self.user_hourly_actions.entry((caller, action_type, current_hour)).write(current_count + 1);
        }

        fn _check_validation_consensus(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let doc = self.documents.entry((collection, doc_id)).read();
            let total_users = self.total_accounts_registered.read();
            if total_users <= 1 {
                return;
            }
            let eligible_voters: u32 = (total_users - 1).try_into().unwrap();
            let required_votes: u32 = ((eligible_voters * 60) + 99) / 100;
            
            if doc.positive_votes >= required_votes {
                self._approve_document(collection, doc_id);
            } else if doc.negative_votes >= required_votes {
                self._reject_document(collection, doc_id);
            }
        }

        fn _approve_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let timestamp = get_block_timestamp();
            let mut doc = self.documents.entry((collection, doc_id)).read();
            if doc.validation_status != 'pending' {
                return;
            }
            let creator = doc.creator;
            let positive_votes = doc.positive_votes;
            let total_voters = doc.total_voters;

            let updated_doc = Document {
                validation_status: 'approved',
                ..doc
            };
            self.documents.entry((collection, doc_id)).write(updated_doc);

            let approved_count = self.approved_docs.entry(collection).read();
            self.approved_doc_ids.entry((collection, approved_count)).write(doc_id);
            self.approved_docs.entry(collection).write(approved_count + 1);
            self._remove_from_pending_validations(collection, doc_id);
            self._award_approval_points_and_badge(creator, collection, doc_id);

            let mut creator_profile = self.user_profiles.entry(creator).read();
            let old_reputation = creator_profile.reputation_score;
            creator_profile.reputation_score += 10;
            let new_reputation = creator_profile.reputation_score;
            creator_profile.approved_documents += 1;
            self.user_profiles.entry(creator).write(creator_profile);

            self._track_user_approved_insert(creator, true);

            self.emit(DocumentApprovedEvent { 
                collection, 
                document_id: doc_id, 
                creator,
                positive_votes,
                total_votes: total_voters,
                timestamp
            });
            self.emit(ReputationChangedEvent { 
                user: creator, 
                old_reputation, 
                new_reputation: new_reputation,
                reason: 'document_approved',
                timestamp
            });
        }

        fn _reject_document(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let mut doc = self.documents.entry((collection, doc_id)).read().clone();

            let old_status = doc.validation_status;
            let creator = doc.creator;

            doc.validation_status = 'rejected';
            self.documents.entry((collection, doc_id)).write(doc);

            self._remove_from_pending_validations(collection, doc_id);
            let mut creator_profile = self.user_profiles.entry(creator).read();
            let new_reputation = if creator_profile.reputation_score - 20 < self.minimum_reputation_score.read() {
                self.minimum_reputation_score.read()
            } else {
                creator_profile.reputation_score - 20
            };
            creator_profile.reputation_score = new_reputation;
            creator_profile.warning_count += 1;
            let real_warning = creator_profile.warning_count;
            self.user_profiles.entry(creator).write(creator_profile);

            if real_warning >= 3 {
                let mut stake_info = self.user_stakes.entry(creator).read();
                let slash_amount = (stake_info.amount * SLASH_PERCENTAGE.into()) / 100;
                stake_info.amount -= slash_amount;
                stake_info.is_locked = true;
                self.user_stakes.entry(creator).write(stake_info);

                let total_slashed = self.total_slashed_stakes.read();
                self.total_slashed_stakes.write(total_slashed + slash_amount);
                self.emit(StakeSlashedEvent { 
                    penalized_user: creator, 
                    admin: get_contract_address(), 
                    slashed_amount: slash_amount, 
                    reason: 'repeated_violations',
                    timestamp: get_block_timestamp()
                });
            }

            self.emit(DocumentStatusChanged { 
                collection, 
                doc_id, 
                creator,
                old_status, 
                new_status: 'rejected',
                timestamp: get_block_timestamp()
            });
        }

        fn _remove_from_pending_validations(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let total_pending = self.pending_validations_count.read();
            let mut found_index = total_pending;
            let mut i: u64 = 0;
            while i < total_pending {
                let (pending_collection, pending_doc_id) = self.pending_validation_ids.entry(i).read();
                if pending_collection == collection && pending_doc_id == doc_id {
                    found_index = i;
                    break;
                }
                i += 1;
            }
            if found_index < total_pending {
                let mut j = found_index;
                while j < total_pending - 1 {
                    let next_item = self.pending_validation_ids.entry(j + 1).read();
                    self.pending_validation_ids.entry(j).write(next_item);
                    j += 1;
                }
                self.pending_validations_count.write(total_pending - 1);
            }
        }

        fn _process_approved_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            if query.len() == 0 {
                return self._get_all_approved_document_ids(collection);
            }
            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.entry((collection, i)).read();
                if self._matches_query(collection, id, query) {
                    result.append(id);
                }
                i += 1;
            }
            result
        }

        fn _get_all_approved_document_ids(self: @ContractState, collection: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_approved = self.approved_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_approved {
                let id = self.approved_doc_ids.entry((collection, i)).read();
                result.append(id);
                i += 1;
            }
            result
        }

        fn _award_approval_points_and_badge(
            ref self: ContractState, 
            creator: ContractAddress, 
            collection: felt252, 
            document_id: felt252
        ) {
            let points_to_award = self.points_per_insert.read();
            let current_points = self.points.entry(creator).read();
            let new_points = current_points + points_to_award.try_into().unwrap();
            self.points.entry(creator).write(new_points);
            self.emit(PointsAwardedForApproval { 
                recipient: creator,
                collection, 
                document_id,
                points_awarded: points_to_award,
                total_points: new_points,
                timestamp: get_block_timestamp()
            });
            let badge_threshold = self.badge_threshold.read();
            if new_points >= badge_threshold.try_into().unwrap() && 
               current_points < badge_threshold.try_into().unwrap() {
                let timestamp = get_block_timestamp();
                self.badges.entry((creator, timestamp)).write(true);
                self.emit(BadgeEarnedEvent { 
                    recipient: creator, 
                    badge_id: timestamp,
                    points_threshold: badge_threshold,
                    timestamp
                });
            }
        }

        fn _charge_update_points(ref self: ContractState, account: ContractAddress) {
            if !self.is_user_premium.entry(account).read() {
                let points_to_deduct = self.points_per_update.read();
                let current_points = self.points.entry(account).read();
                assert(current_points >= points_to_deduct.try_into().unwrap(), 'Insufficient points for update');
                let new_points = current_points - points_to_deduct.try_into().unwrap();
                self.points.entry(account).write(new_points);
                self.emit(PointsDeducted { 
                    account, 
                    points: points_to_deduct, 
                    total_points: new_points,
                    action_type: 'update',
                    timestamp: get_block_timestamp()
                });
            }
        }

        fn _charge_delete_points(ref self: ContractState, account: ContractAddress) {
            if !self.is_user_premium.entry(account).read() {
                let points_to_deduct = self.points_per_delete.read();
                let current_points = self.points.entry(account).read();
                assert(current_points >= points_to_deduct.try_into().unwrap(), 'Insufficient points for delete');
                let new_points = current_points - points_to_deduct.try_into().unwrap();
                self.points.entry(account).write(new_points);
                self.emit(PointsDeducted { 
                    account, 
                    points: points_to_deduct, 
                    total_points: new_points,
                    action_type: 'delete',
                    timestamp: get_block_timestamp()
                });
            }
        }

        fn _charge_query_points(ref self: ContractState, account: ContractAddress) {
            if !self.is_user_premium.entry(account).read() {
                let points_to_deduct = self.points_per_query_page.read();
                let current_points = self.points.entry(account).read();
                assert(current_points >= points_to_deduct.try_into().unwrap(), 'Insufficient points for query');
                let new_points = current_points - points_to_deduct.try_into().unwrap();
                self.points.entry(account).write(new_points);
                self.emit(PointsDeducted { 
                    account, 
                    points: points_to_deduct, 
                    total_points: new_points,
                    action_type: 'query',
                    timestamp: get_block_timestamp()
                });
            }
        }

        fn _check_whitelist_consensus(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let doc = self.documents.entry((collection, doc_id)).read();

            let creator = doc.creator;
            let data_hash = doc.data_hash;
            let whitelist_remove_votes = doc.whitelist_remove_votes;
            let whitelist_total_voters = doc.whitelist_total_voters; 

            let total_users = self.total_accounts_registered.read();
            if total_users <= 1 {
                return;
            }
            
            let eligible_voters: u32 = (total_users - 1).try_into().unwrap();
            let required_votes: u32 = ((eligible_voters * 60) + 99) / 100;
            
            if whitelist_remove_votes >= required_votes {
                let updated_doc = Document {
                    whitelist_approved_for_deletion: true,
                    ..doc
                };
                
                self.documents.entry((collection, doc_id)).write(updated_doc);

                self.emit(DocumentWhitelistApproved {
                    collection,
                    document_id: doc_id,
                    creator: creator,
                    data_hash: data_hash,
                    remove_votes: whitelist_remove_votes,
                    total_votes: whitelist_total_voters,
                    timestamp: get_block_timestamp()
                });
            }
        }

        fn _calculate_data_size(self: @ContractState, data: @ByteArray) -> u256 {
            data.len().into()
        }

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

        fn _decrease_size_statistics(ref self: ContractState, size: u256) {
            let current_total = self.total_database_size_bytes.read();
            let new_total = if current_total >= size {
                current_total - size
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

        fn _store_fields(ref self: ContractState, collection: felt252, id: felt252, fields: @Array<(felt252, felt252)>) {
            let len: u32 = fields.len();
            self.field_lengths.entry((collection, id)).write(len);
            let num_indexed = self.num_indexed.entry(collection).read();
            let mut i: u32 = 0;
            while i < len {
                let (field, value) = *fields.at(i);
                assert(field != 0, 'Field name cannot be empty');
                self.fields_list.entry((collection, id, i)).write(field);
                self.fields_data.entry((collection, id, field)).write(value);
                if self._is_indexed(collection, field, num_indexed) {
                    let num = self.index_num_ids.entry((collection, field, value)).read();
                    self.index_ids.entry((collection, field, value, num)).write(id);
                    self.index_num_ids.entry((collection, field, value)).write(num + 1);
                }
                i += 1;
            }
        }

        fn _get_document_fields(self: @ContractState, collection: felt252, id: felt252) -> Array<(felt252, felt252)> {
            let mut fields = ArrayTrait::new();
            let len = self.field_lengths.entry((collection, id)).read();
            let mut i: u32 = 0; 
            while i < len {
                let field = self.fields_list.entry((collection, id, i)).read();
                let value = self.fields_data.entry((collection, id, field)).read();
                fields.append((field, value));
                i += 1;
            }
            let doc = self.documents.entry((collection, id)).read();
            fields.append(('created_at', doc.created_at.try_into().unwrap()));
            fields.append(('updated_at', doc.updated_at.try_into().unwrap()));
            fields.append(('creator', doc.creator.try_into().unwrap()));
            fields.append(('status', doc.validation_status));
            fields
        }

        fn _is_indexed(self: @ContractState, collection: felt252, field: felt252, num_indexed: u32) -> bool {
            let mut i: u32 = 0;
            while i < num_indexed {
                if self.indexed_fields.entry((collection, i)).read() == field {
                    return true;
                }
                i += 1;
            }
            false
        }

        fn _remove_from_all_indices(ref self: ContractState, collection: felt252, id: felt252) {
            let len = self.field_lengths.entry((collection, id)).read();
            let mut i: u32 = 0;
            while i < len {
                let field = self.fields_list.entry((collection, id, i)).read();
                let num_indexed = self.num_indexed.entry(collection).read();
                if self._is_indexed(collection, field, num_indexed) {
                    let value = self.fields_data.entry((collection, id, field)).read();
                    self._remove_from_index(collection, field, value, id);
                }
                self.fields_data.entry((collection, id, field)).write(0);
                self.fields_list.entry((collection, id, i)).write(0);
                i += 1;
            }
        }

        fn _remove_from_index(ref self: ContractState, collection: felt252, field: felt252, value: felt252, id: felt252) {
            let num = self.index_num_ids.entry((collection, field, value)).read();
            let mut index: u32 = 0;
            let mut found = false;
            while index < num {
                if self.index_ids.entry((collection, field, value, index)).read() == id {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                let mut k = index;
                while k < num - 1 {
                    let next_id = self.index_ids.entry((collection, field, value, k + 1)).read();
                    self.index_ids.entry((collection, field, value, k)).write(next_id);
                    k += 1;
                }
                self.index_num_ids.entry((collection, field, value)).write(num - 1);
            }
        }

        fn _cleanup_document(ref self: ContractState, collection: felt252, id: felt252) {
            let ba: ByteArray = "unknown";
            let empty_byte = ba.rev();

            let unknown_contract_address: ContractAddress = 0x0.try_into().unwrap();

            let empty_doc = Document {
                compressed_data: empty_byte,
                creator: unknown_contract_address,
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
            };
            
            self.documents.entry((collection, id)).write(empty_doc);
            
            // Reset creator address
            let zero_addr = unknown_contract_address;
            self.creators.entry((collection, id)).write(zero_addr);
            
            // Reset field length
            let zero_len = ba.len();
            self.field_lengths.entry((collection, id)).write(zero_len);

            let num = self.num_docs.entry(collection).read();
            let mut index: u32 = 0;
            let mut found = false;
            while index < num {
                if self.doc_ids.entry((collection, index)).read() == id {
                    found = true;
                    break;
                }
                index += 1;
            }
            if found {
                let mut k = index;
                while k < num - 1 {
                    let next_id = self.doc_ids.entry((collection, k + 1)).read();
                    self.doc_ids.entry((collection, k)).write(next_id);
                    k += 1;
                }
                self.num_docs.entry(collection).write(num - 1);
            }
            let num_approved = self.approved_docs.entry(collection).read();
            let mut approved_index: u32 = 0;
            let mut found_approved = false;
            while approved_index < num_approved {
                if self.approved_doc_ids.entry((collection, approved_index)).read() == id {
                    found_approved = true;
                    break;
                }
                approved_index += 1;
            }
            if found_approved {
                let mut k = approved_index;
                while k < num_approved - 1 {
                    let next_id = self.approved_doc_ids.entry((collection, k + 1)).read();
                    self.approved_doc_ids.entry((collection, k)).write(next_id);
                    k += 1;
                }
                self.approved_docs.entry(collection).write(num_approved - 1);
            }
        }

        fn _process_query(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            if query.len() == 0 {
                return self._get_all_document_ids(collection);
            }
            let num_indexed = self.num_indexed.entry(collection).read();
            if query.len() == 1 {
                let (field, op, value, _) = *query.at(0);
                if op == 'eq' && self._is_indexed(collection, field, num_indexed) {
                    return self._get_indexed_documents(collection, field, value);
                }
            }
            self._scan_documents(collection, query)
        }

        fn _get_all_document_ids(self: @ContractState, collection: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_docs {
                result.append(self.doc_ids.entry((collection, i)).read());
                i += 1;
            }
            result
        }

        fn _get_indexed_documents(self: @ContractState, collection: felt252, field: felt252, value: felt252) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_ids = self.index_num_ids.entry((collection, field, value)).read();
            let mut i: u32 = 0;
            while i < num_ids {
                result.append(self.index_ids.entry((collection, field, value, i)).read());
                i += 1;
            }
            result
        }

        fn _scan_documents(self: @ContractState, collection: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let num_docs = self.num_docs.entry(collection).read();
            let mut i: u32 = 0;
            while i < num_docs {
                let id = self.doc_ids.entry((collection, i)).read();
                if self._matches_query(collection, id, query) {
                    result.append(id);
                }
                i += 1;
            }
            result
        }

        fn _matches_query(self: @ContractState, collection: felt252, id: felt252, query: @Array<(felt252, felt252, felt252, felt252)>) -> bool {
            let mut i: u32 = 0;
            while i < query.len() {
                let (field, op, value, _logical) = *query.at(i);
                let matches = self._matches_condition(collection, id, field, op, value);
                if !matches {
                    return false;
                }
                i += 1;
            }
            true
        }

        fn _matches_condition(
            self: @ContractState,
            collection: felt252,
            id: felt252,
            field: felt252,
            op: felt252,
            value: felt252,
        ) -> bool {
            let actual = self.fields_data.entry((collection, id, field)).read();

            if op == OP_EQ {
                actual == value
            } else if op == OP_NE {
                actual != value
            } else if op == OP_GT {
                let a: u256 = actual.try_into().unwrap_or(0_u256);
                let b: u256 = value.try_into().unwrap_or(0_u256);
                a > b
            } else if op == OP_LT {
                let a: u256 = actual.try_into().unwrap_or(0_u256);
                let b: u256 = value.try_into().unwrap_or(0_u256);
                a < b
            } else if op == OP_GTE {
                let a: u256 = actual.try_into().unwrap_or(0_u256);
                let b: u256 = value.try_into().unwrap_or(0_u256);
                a >= b
            } else if op == OP_LTE {
                let a: u256 = actual.try_into().unwrap_or(0_u256);
                let b: u256 = value.try_into().unwrap_or(0_u256);
                a <= b
            } else {
                false
            }
        }

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

        fn _track_user_insert(ref self: ContractState, user: ContractAddress) {
            let current = self.user_total_inserts.entry(user).read();
            self.user_total_inserts.entry(user).write(current + 1);
            
            let pending_count = self.user_pending_inserts.entry(user).read();
            self.user_pending_inserts.entry(user).write(pending_count + 1);
        }

        fn _track_user_pending_insert(ref self: ContractState, user: ContractAddress) {
            let pending = self.user_pending_inserts.entry(user).read();
            self.user_pending_inserts.entry(user).write(pending + 1);
        }

        fn _track_user_approved_insert(ref self: ContractState, user: ContractAddress, was_pending: bool) {
            let approved = self.user_approved_inserts.entry(user).read();
            self.user_approved_inserts.entry(user).write(approved + 1);
            
            if was_pending {
                let pending = self.user_pending_inserts.entry(user).read();
                if pending > 0 {
                    self.user_pending_inserts.entry(user).write(pending - 1);
                }
            }
        }
    }

    impl ConsensusImpl of ConsensusTrait {
    fn calculate_required_votes(self: @ContractState, total_users: u64) -> u32 {
            if total_users <= 1 {
               return 0_u32;
            }
            
            let eligible_voters: u32 = (total_users - 1).try_into().unwrap();
            let required_votes: u32 = ((eligible_voters * 60) + 99) / 100;
            
            required_votes
        }
    }

    #[external(v0)]
    fn cleanup_processed_pending_documents(ref self: ContractState) {
        self.only_admin();
        let total_pending = self.pending_validations_count.read();
        let mut cleaned_up = 0_u32;
        let mut i = 0_u64;
        while i < total_pending && cleaned_up < 50 {
            let (collection, doc_id) = self.pending_validation_ids.entry(i).read();
            let doc = self.documents.entry((collection, doc_id)).read();
            if doc.validation_status != 'pending' {
                self._remove_from_pending_validations(collection, doc_id);
                cleaned_up += 1;
            }
            i += 1;
        }
    }

    #[external(v0)]
    fn get_documents_for_validation(self: @ContractState, page: u32) -> Array<(felt252, felt252, felt252, ContractAddress)> {
        self.only_moderator_or_admin();
        assert(page > 0, 'Page must be >= 1');
        let mut result = ArrayTrait::new();
        let total_pending = self.pending_validations_count.read();
        let start_idx: u64 = ((page - 1) * 10).into();
        let end_idx = if start_idx + 10 > total_pending { total_pending } else { start_idx + 10 };
        let mut i: u64 = start_idx;
        while i < end_idx {
            let (collection, doc_id) = self.pending_validation_ids.entry(i).read();
            let doc = self.documents.entry((collection, doc_id)).read();
            if doc.validation_status == 'pending' {
                result.append((collection, doc_id, doc.data_hash, doc.creator));
            }
            i += 1;
        }
        result
    }

    #[external(v0)]
    fn emergency_pause(ref self: ContractState, reason: felt252) {
        self.only_admin();
        let caller = get_caller_address();
        self.is_circuit_breaker_active.write(true);
        self.emit(CircuitBreakerTriggered { admin: caller, reason, timestamp: get_block_timestamp() });
    }

    #[external(v0)]
    fn emergency_resume(ref self: ContractState) {
        self.only_admin();
        self.is_circuit_breaker_active.write(false);
    }

    #[external(v0)]
    fn batch_approve_documents(ref self: ContractState, documents: Array<(felt252, felt252)>) {
        self.only_moderator_or_admin();
        let mut i: u32 = 0;
        while i < documents.len() {
            let (collection, doc_id) = *documents.at(i);
            let doc = self.documents.entry((collection, doc_id)).read();
            if doc.validation_status == 'pending' {
                self._approve_document(collection, doc_id);
            }
            i += 1;
        }
    }

    #[external(v0)]
    fn batch_reject_documents(ref self: ContractState, documents: Array<(felt252, felt252)>) {
        self.only_moderator_or_admin();
        let mut i: u32 = 0;
        while i < documents.len() {
            let (collection, doc_id) = *documents.at(i);
            let doc = self.documents.entry((collection, doc_id)).read();
            if doc.validation_status == 'pending' {
                self._reject_document(collection, doc_id);
            }
            i += 1;
        }
    }

    #[external(v0)]
    fn get_user_voting_stats(self: @ContractState, user: ContractAddress) -> (u32, i32, u32) {
        let profile = self.user_profiles.entry(user).read();
        let stake_info = self.user_stakes.entry(user).read();
        
        let total_votes_cast = profile.total_votes_cast;
        let reputation_score = profile.reputation_score;
        let stake_info_amount = stake_info.amount;
        
        let vote_power = if stake_info_amount >= self.minimum_stake_amount.read() { 2 } else { 1 };
        
        (total_votes_cast, reputation_score, vote_power)
    }

    #[external(v0)]
    fn can_vote_on_document(self: @ContractState, user: ContractAddress, collection: felt252, doc_id: felt252) -> bool {
        let doc = self.documents.entry((collection, doc_id)).read();
        let has_already_voted = self.document_voters.entry((collection, doc_id, user)).read();
        let stake_info = self.user_stakes.entry(user).read();
        let profile = self.user_profiles.entry(user).read();

        !doc.creator.is_zero() && doc.validation_status == 'pending' && doc.creator != user && !has_already_voted && stake_info.amount >= self.minimum_stake_amount.read() && profile.reputation_score >= self.minimum_reputation_score.read() && !self.banned_users.entry(user).read() && !self.is_circuit_breaker_active.read()
    }

    #[external(v0)]
    fn get_user_statistics(self: @ContractState, user: ContractAddress) -> (u32, u32, u32, u32, u32, u32, u32) {
        self.get_user_comprehensive_stats(user)
    }
}