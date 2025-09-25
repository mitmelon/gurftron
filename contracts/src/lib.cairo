#[starknet::contract]
mod GurftronDB {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::byte_array::ByteArray;
    use core::hash::pedersen;
    use core::zeroable::Zeroable;

    // IERC20 interface for STRK token
    #[starknet::interface]
    trait IERC20<TContractState> {
        fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
        fn transfer_from(ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    }

    // Database interface
    #[starknet::interface]
    trait IDatabase<TContractState> {
        fn stake_for_access(ref self: TContractState, amount: u256);
        fn withdraw_stake(ref self: TContractState);
        fn create_collection(ref self: TContractState, name: felt252, indexed_fields: Array<felt252>);
        fn insert(ref self: TContractState, collection: felt252, data: ByteArray, fields: Array<(felt252, felt252)>) -> felt252;
        fn update(ref self: TContractState, collection: felt252, id: felt252, data: ByteArray, fields: Array<(felt252, felt252)>);
        fn delete(ref self: TContractState, collection: felt252, id: felt252);
        fn find(self: @TContractState, collection: felt252, query: Array<(felt252, felt252, felt252)>, is_admin: bool) -> Array<felt252>;
        fn vote_on_document(ref self: TContractState, collection: felt252, doc_id: felt252, is_valid: bool);
        fn vote_on_whitelist(ref self: TContractState, collection: felt252, doc_id: felt252);
        fn register_account(ref self: TContractState);
        fn ban_user(ref self: TContractState, user: ContractAddress);
        fn unban_user(ref self: TContractState, user: ContractAddress);
        fn claim_reward(ref self: TContractState);
        fn get_user_info(self: @TContractState, user: ContractAddress) -> (u256, bool, u32, bool, bool);
        fn get_stats(self: @TContractState) -> (u64, u64, u256);
        fn update_reward_parameters(ref self: TContractState, points_per_insert: u32, points_per_update: u32, points_per_delete: u32, points_per_vote: u32, points_to_strk: u256, premium_reward_multiplier: u256);
    }

    // Storage structures
    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct Document {
        data: ByteArray,
        creator: ContractAddress,
        created_at: u64,
        validation_status: felt252, // pending, approved, rejected
        whitelist_approved_for_deletion: bool,
        positive_votes: u32,
        negative_votes: u32,
        whitelist_positive_votes: u32,
        data_hash: felt252,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct StakeInfo {
        amount: u256,
        stake_time: u64,
        is_locked: bool,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct User {
        stake: StakeInfo,
        points: u32,
        total_documents: u32,
        is_premium: bool,
        is_banned: bool,
        has_good_reputation: bool,
        last_action_time: u64,
        hourly_actions: u32,
    }

    // Storage
    #[storage]
    struct Storage {
        admin: ContractAddress,
        strk_token: ContractAddress,
        paused: bool,
        users: Map<ContractAddress, User>,
        documents: Map<(felt252, felt252), Document>,
        next_id: Map<felt252, felt252>,
        num_docs: Map<felt252, u32>,
        doc_ids: Map<(felt252, u32), felt252>,
        approved_docs: Map<felt252, u32>,
        approved_doc_ids: Map<(felt252, u32), felt252>,
        document_voters: Map<(felt252, felt252, ContractAddress), bool>,
        whitelist_voters: Map<(felt252, felt252, ContractAddress), bool>,
        fields_data: Map<(felt252, felt252, felt252), felt252>,
        fields_list: Map<(felt252, felt252, u32), felt252>,
        field_lengths: Map<(felt252, felt252), u32>,
        indexed_fields: Map<(felt252, u32), felt252>,
        num_indexed: Map<felt252, u32>,
        index_num_ids: Map<(felt252, felt252, felt252), u32>,
        index_ids: Map<(felt252, felt252, felt252, u32), felt252>,
        pending_validation_ids: Map<u64, (felt252, felt252)>,
        pending_validation_count: u64,
        total_accounts: u64,
        total_documents: u64,
        total_size: u256,
        points_per_insert: u32,
        points_per_update: u32,
        points_per_delete: u32,
        points_per_vote: u32,
        points_to_strk: u256,
        premium_reward_multiplier: u256,
        min_stake: u256,
        approval_percentage: u32,
        action_cooldown_period: u64,
        hourly_action_limit: u32,
    }

    // Events
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        DocumentEvent: DocumentEvent,
        VoteSubmitted: VoteSubmitted,
        WhitelistVoteSubmitted: WhitelistVoteSubmitted,
        PointsAwarded: PointsAwarded,
        RewardClaimed: RewardClaimed,
        UserRegistered: UserRegistered,
        UserBanned: UserBanned,
        UserUnbanned: UserUnbanned,
        CollectionCreated: CollectionCreated,
        StakeDeposited: StakeDeposited,
        StakeWithdrawn: StakeWithdrawn,
        ParametersUpdated: ParametersUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct DocumentEvent {
        caller: ContractAddress,
        collection: felt252,
        doc_id: felt252,
        status: felt252, // inserted, updated, deleted, approved, rejected
        data_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct VoteSubmitted {
        voter: ContractAddress,
        collection: felt252,
        doc_id: felt252,
        is_valid: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WhitelistVoteSubmitted {
        voter: ContractAddress,
        collection: felt252,
        doc_id: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PointsAwarded {
        user: ContractAddress,
        points: u32,
        reason: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardClaimed {
        user: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserRegistered {
        user: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserBanned {
        user: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UserUnbanned {
        user: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CollectionCreated {
        name: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeDeposited {
        staker: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeWithdrawn {
        staker: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ParametersUpdated {
        timestamp: u64,
    }

    // Constants
    const MAXIMUM_DATA_SIZE: u32 = 1048576; // 1MB
    const MAXIMUM_INDEXED_FIELDS: u32 = 10;
    const MAX_QUERY_CONDITIONS: u32 = 10;
    const QUERY_PAGE_SIZE: u32 = 100;

    // Constructor
    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress, strk_token: ContractAddress) {
        assert(!admin.is_zero(), 'Admin address cannot be zero');
        assert(!strk_token.is_zero(), 'STRK token address cannot be zero');
        self.admin.write(admin);
        self.strk_token.write(strk_token);
        self.points_per_insert.write(10);
        self.points_per_update.write(5);
        self.points_per_delete.write(5);
        self.points_per_vote.write(2);
        self.points_to_strk.write(1_000_000_000_000_000_000); // 1 STRK per point
        self.premium_reward_multiplier.write(2);
        self.min_stake.write(10_000_000_000_000_000_000); // 10 STRK
        self.approval_percentage.write(60);
        self.action_cooldown_period.write(300); // 5 minutes
        self.hourly_action_limit.write(50);
    }

    // Internal functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_admin(self: @ContractState) {
            let caller = get_caller_address();
            assert(caller == self.admin.read(), 'Not admin');
        }

        fn _only_not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'Contract is paused');
        }

        fn _only_registered(self: @ContractState, caller: ContractAddress) {
            let user = self.users.entry(caller).read();
            assert(user.last_action_time != 0, 'Account not registered');
            assert(!user.is_banned, 'User is banned');
        }

        fn _enforce_security(self: @ContractState, caller: ContractAddress, action_type: felt252) {
            let mut user = self.users.entry(caller).read();
            assert(user.stake.amount >= self.min_stake.read(), 'Insufficient stake');
            assert(user.has_good_reputation, 'Bad reputation');
            let current_time = get_block_timestamp();
            assert(current_time >= user.last_action_time + self.action_cooldown_period.read(), 'Cooldown violation');
            let current_hour = current_time / 3600;
            let actions = user.hourly_actions;
            assert(actions < self.hourly_action_limit.read(), 'Hourly action limit exceeded');
            user.last_action_time = current_time;
            user.hourly_actions = actions + 1;
            self.users.entry(caller).write(user);
        }

        fn _compute_data_hash(self: @ContractState, data: @ByteArray) -> felt252 {
            let mut hasher = 0;
            let len = data.len();
            hasher = pedersen(hasher, len.into());
            let mut i = 0;
            while i < len {
                hasher = pedersen(hasher, (*data.at(i)).into());
                i += 1;
            };
            hasher
        }

        fn _check_validation_consensus(ref self: ContractState, collection: felt252, doc_id: felt252) {
            let doc = self.documents.entry((collection, doc_id)).read();
            let total_votes = doc.positive_votes + doc.negative_votes;
            let total_accounts = self.total_accounts.read();
            let required_votes = (total_accounts * self.approval_percentage.read().into()) / 100;
            if total_votes >= required_votes {
                if doc.positive_votes > doc.negative_votes {
                    let mut doc = doc;
                    doc.validation_status = 'approved';
                    self.documents.entry((collection, doc_id)).write(doc);
                    let approved_count = self.approved_docs.entry(collection).read();
                    self.approved_doc_ids.entry((collection, approved_count)).write(doc_id);
                    self.approved_docs.entry(collection).write(approved_count + 1);
                    let creator = doc.creator;
                    let mut creator_user = self.users.entry(creator).read();
                    creator_user.points += self.points_per_insert.read();
                    self.users.entry(creator).write(creator_user);
                    self.emit(DocumentEvent {
                        caller: creator,
                        collection,
                        doc_id,
                        status: 'approved',
                        data_hash: doc.data_hash,
                        timestamp: get_block_timestamp(),
                    });
                } else {
                    let mut doc = doc;
                    doc.validation_status = 'rejected';
                    self.documents.entry((collection, doc_id)).write(doc);
                    let creator = doc.creator;
                    let mut creator_user = self.users.entry(creator).read();
                    creator_user.has_good_reputation = false;
                    self.users.entry(creator).write(creator_user);
                    self.emit(DocumentEvent {
                        caller: creator,
                        collection,
                        doc_id,
                        status: 'rejected',
                        data_hash: doc.data_hash,
                        timestamp: get_block_timestamp(),
                    });
                }
            }
        }

        fn _process_fields(ref self: ContractState, collection: felt252, id: felt252, fields: @Array<(felt252, felt252)>) {
            let len = fields.len();
            self.field_lengths.entry((collection, id)).write(len);
            let num_indexed = self.num_indexed.entry(collection).read();
            let mut i = 0;
            while i < len {
                let (field, value) = *fields.at(i);
                self.fields_list.entry((collection, id, i)).write(field);
                self.fields_data.entry((collection, id, field)).write(value);
                let mut j = 0;
                let mut is_indexed = false;
                while j < num_indexed {
                    if self.indexed_fields.entry((collection, j)).read() == field {
                        is_indexed = true;
                        break;
                    }
                    j += 1;
                };
                if is_indexed {
                    let num = self.index_num_ids.entry((collection, field, value)).read();
                    self.index_ids.entry((collection, field, value, num)).write(id);
                    self.index_num_ids.entry((collection, field, value)).write(num + 1);
                }
                i += 1;
            };
        }

        fn _matches_condition(self: @ContractState, collection: felt252, id: felt252, field: felt252, operator: felt252, value: felt252) -> bool {
            let actual = self.fields_data.entry((collection, id, field)).read();
            if operator == 'eq' {
                actual == value
            } else if operator == 'gt' {
                actual > value
            } else if operator == 'lt' {
                actual < value
            } else {
                false
            }
        }

        fn _decrease_size_statistics(ref self: ContractState, size_to_remove: u256) {
            self.total_size.write(self.total_size.read() - size_to_remove);
        }
    }

    // External functions
    #[abi(embed_v0)]
    impl DatabaseImpl of IDatabase<ContractState> {
        fn stake_for_access(ref self: ContractState, amount: u256) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            assert(amount >= self.min_stake.read(), 'Stake too low');
            let strk = IERC20Dispatcher { contract_address: self.strk_token.read() };
            strk.transfer_from(caller, get_contract_address(), amount);
            let mut user = self.users.entry(caller).read();
            user.stake.amount += amount;
            user.stake.stake_time = get_block_timestamp();
            self.users.entry(caller).write(user);
            self.emit(StakeDeposited { staker: caller, amount, timestamp: get_block_timestamp() });
        }

        fn withdraw_stake(ref self: ContractState) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            let mut user = self.users.entry(caller).read();
            assert(!user.stake.is_locked, 'Stake is locked');
            assert(get_block_timestamp() >= user.stake.stake_time + 86400, 'Stake locked for 24 hours');
            let amount = user.stake.amount;
            assert(amount > 0, 'No stake to withdraw');
            user.stake.amount = 0;
            self.users.entry(caller).write(user);
            let strk = IERC20Dispatcher { contract_address: self.strk_token.read() };
            strk.transfer(caller, amount);
            self.emit(StakeWithdrawn { staker: caller, amount, timestamp: get_block_timestamp() });
        }

        fn create_collection(ref self: ContractState, name: felt252, indexed_fields: Array<felt252>) {
            self._only_admin();
            self._only_not_paused();
            let len = indexed_fields.len();
            assert(len <= MAXIMUM_INDEXED_FIELDS, 'Too many indexed fields');
            self.num_indexed.entry(name).write(len);
            let mut i = 0;
            while i < len {
                self.indexed_fields.entry((name, i)).write(*indexed_fields.at(i));
                i += 1;
            };
            self.emit(CollectionCreated { name, timestamp: get_block_timestamp() });
        }

        fn insert(ref self: ContractState, collection: felt252, data: ByteArray, fields: Array<(felt252, felt252)>) -> felt252 {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            self._enforce_security(caller, 'insert');
            assert(data.len() <= MAXIMUM_DATA_SIZE, 'Data too large');
            let id = self.next_id.entry(collection).read();
            self.next_id.entry(collection).write(id + 1);
            let index = self.num_docs.entry(collection).read();
            self.doc_ids.entry((collection, index)).write(id);
            self.num_docs.entry(collection).write(index + 1);
            let data_hash = self._compute_data_hash(@data);
            let doc = Document {
                data,
                creator: caller,
                created_at: get_block_timestamp(),
                validation_status: 'pending',
                whitelist_approved_for_deletion: false,
                positive_votes: 0,
                negative_votes: 0,
                whitelist_positive_votes: 0,
                data_hash,
            };
            self.documents.entry((collection, id)).write(doc);
            self.pending_validation_ids.entry(self.pending_validation_count.read()).write((collection, id));
            self.pending_validation_count.write(self.pending_validation_count.read() + 1);
            self._process_fields(collection, id, @fields);
            let mut user = self.users.entry(caller).read();
            user.points += self.points_per_insert.read();
            user.total_documents += 1;
            self.users.entry(caller).write(user);
            self.total_documents.write(self.total_documents.read() + 1);
            self.total_size.write(self.total_size.read() + data.len().into());
            self.emit(DocumentEvent {
                caller,
                collection,
                doc_id: id,
                status: 'inserted',
                data_hash,
                timestamp: get_block_timestamp(),
            });
            id
        }

        fn update(ref self: ContractState, collection: felt252, id: felt252, data: ByteArray, fields: Array<(felt252, felt252)>) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            self._enforce_security(caller, 'update');
            let old_doc = self.documents.entry((collection, id)).read();
            assert(old_doc.creator == caller || caller == self.admin.read(), 'Not authorized');
            assert(data.len() <= MAXIMUM_DATA_SIZE, 'Data too large');
            let data_hash = self._compute_data_hash(@data);
            let mut doc = Document {
                data,
                creator: old_doc.creator,
                created_at: old_doc.created_at,
                validation_status: 'pending',
                whitelist_approved_for_deletion: false,
                positive_votes: 0,
                negative_votes: 0,
                whitelist_positive_votes: 0,
                data_hash,
            };
            self.documents.entry((collection, id)).write(doc);
            self._process_fields(collection, id, @fields);
            self.pending_validation_ids.entry(self.pending_validation_count.read()).write((collection, id));
            self.pending_validation_count.write(self.pending_validation_count.read() + 1);
            let mut user = self.users.entry(caller).read();
            user.points += self.points_per_update.read();
            self.users.entry(caller).write(user);
            self._decrease_size_statistics(old_doc.data.len().into());
            self.total_size.write(self.total_size.read() + data.len().into());
            self.emit(DocumentEvent {
                caller,
                collection,
                doc_id: id,
                status: 'updated',
                data_hash,
                timestamp: get_block_timestamp(),
            });
        }

        fn delete(ref self: ContractState, collection: felt252, id: felt252) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            self._enforce_security(caller, 'delete');
            let doc = self.documents.entry((collection, id)).read();
            assert(doc.creator == caller || caller == self.admin.read() || doc.whitelist_approved_for_deletion, 'Not authorized');
            let num_docs = self.num_docs.entry(collection).read();
            let mut i = 0;
            while i < num_docs {
                if self.doc_ids.entry((collection, i)).read() == id {
                    let last_id = self.doc_ids.entry((collection, num_docs - 1)).read();
                    self.doc_ids.entry((collection, i)).write(last_id);
                    self.num_docs.entry(collection).write(num_docs - 1);
                    break;
                }
                i += 1;
            };
            let num_approved = self.approved_docs.entry(collection).read();
            let mut j = 0;
            while j < num_approved {
                if self.approved_doc_ids.entry((collection, j)).read() == id {
                    let last_id = self.approved_doc_ids.entry((collection, num_approved - 1)).read();
                    self.approved_doc_ids.entry((collection, j)).write(last_id);
                    self.approved_docs.entry(collection).write(num_approved - 1);
                    break;
                }
                j += 1;
            };
            self.documents.entry((collection, id)).write(Document {
                data: ByteArray::default(),
                creator: Zeroable::zero(),
                created_at: 0,
                validation_status: 'rejected',
                whitelist_approved_for_deletion: false,
                positive_votes: 0,
                negative_votes: 0,
                whitelist_positive_votes: 0,
                data_hash: 0,
            });
            self._decrease_size_statistics(doc.data.len().into());
            self.total_documents.write(self.total_documents.read() - 1);
            let mut user = self.users.entry(caller).read();
            user.points += self.points_per_delete.read();
            self.users.entry(caller).write(user);
            self.emit(DocumentEvent {
                caller,
                collection,
                doc_id: id,
                status: 'deleted',
                data_hash: doc.data_hash,
                timestamp: get_block_timestamp(),
            });
        }

        fn find(self: @ContractState, collection: felt252, query: Array<(felt252, felt252, felt252)>, is_admin: bool) -> Array<felt252> {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            if is_admin {
                self._only_admin();
            }
            let mut result = array![];
            let num_docs = self.num_docs.entry(collection).read();
            let mut i = 0;
            while i < num_docs {
                let id = self.doc_ids.entry((collection, i)).read();
                let doc = self.documents.entry((collection, id)).read();
                if !is_admin && doc.validation_status != 'approved' {
                    i += 1;
                    continue;
                }
                let mut matches = true;
                let mut j = 0;
                while j < query.len() {
                    let (field, operator, value) = *query.at(j);
                    if !self._matches_condition(collection, id, field, operator, value) {
                        matches = false;
                        break;
                    }
                    j += 1;
                };
                if matches {
                    result.append(id);
                }
                i += 1;
            };
            result
        }

        fn vote_on_document(ref self: ContractState, collection: felt252, doc_id: felt252, is_valid: bool) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            self._enforce_security(caller, 'vote');
            let mut doc = self.documents.entry((collection, doc_id)).read();
            assert(doc.validation_status == 'pending', 'Document not pending');
            assert(!self.document_voters.entry((collection, doc_id, caller)).read(), 'Already voted');
            self.document_voters.entry((collection, doc_id, caller)).write(true);
            if is_valid {
                doc.positive_votes += 1;
            } else {
                doc.negative_votes += 1;
            }
            self.documents.entry((collection, doc_id)).write(doc);
            let mut user = self.users.entry(caller).read();
            user.points += self.points_per_vote.read();
            self.users.entry(caller).write(user);
            self.emit(VoteSubmitted {
                voter: caller,
                collection,
                doc_id,
                is_valid,
                timestamp: get_block_timestamp(),
            });
            self._check_validation_consensus(collection, doc_id);
        }

        fn vote_on_whitelist(ref self: ContractState, collection: felt252, doc_id: felt252) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            self._enforce_security(caller, 'whitelist_vote');
            let mut doc = self.documents.entry((collection, doc_id)).read();
            assert(doc.validation_status == 'approved', 'Document not approved');
            assert(!self.whitelist_voters.entry((collection, doc_id, caller)).read(), 'Already voted');
            self.whitelist_voters.entry((collection, doc_id, caller)).write(true);
            doc.whitelist_positive_votes += 1;
            self.documents.entry((collection, doc_id)).write(doc);
            let mut user = self.users.entry(caller).read();
            user.points += self.points_per_vote.read();
            self.users.entry(caller).write(user);
            self.emit(WhitelistVoteSubmitted {
                voter: caller,
                collection,
                doc_id,
                timestamp: get_block_timestamp(),
            });
            if doc.whitelist_positive_votes >= (self.total_accounts.read() * self.approval_percentage.read().into()) / 100 {
                doc.whitelist_approved_for_deletion = true;
                self.documents.entry((collection, doc_id)).write(doc);
            }
        }

        fn register_account(ref self: ContractState) {
            self._only_not_paused();
            let caller = get_caller_address();
            let user = self.users.entry(caller).read();
            assert(user.last_action_time == 0, 'Account already registered');
            self.users.entry(caller).write(User {
                stake: StakeInfo { amount: 0, stake_time: 0, is_locked: false },
                points: 0,
                total_documents: 0,
                is_premium: false,
                is_banned: false,
                has_good_reputation: true,
                last_action_time: get_block_timestamp(),
                hourly_actions: 0,
            });
            self.total_accounts.write(self.total_accounts.read() + 1);
            self.emit(UserRegistered { user: caller, timestamp: get_block_timestamp() });
        }

        fn ban_user(ref self: ContractState, user: ContractAddress) {
            self._only_admin();
            self._only_not_paused();
            let mut user_data = self.users.entry(user).read();
            assert(user_data.last_action_time != 0, 'User not registered');
            user_data.is_banned = true;
            user_data.has_good_reputation = false;
            self.users.entry(user).write(user_data);
            self.emit(UserBanned { user, timestamp: get_block_timestamp() });
        }

        fn unban_user(ref self: ContractState, user: ContractAddress) {
            self._only_admin();
            self._only_not_paused();
            let mut user_data = self.users.entry(user).read();
            assert(user_data.last_action_time != 0, 'User not registered');
            user_data.is_banned = false;
            user_data.has_good_reputation = true;
            self.users.entry(user).write(user_data);
            self.emit(UserUnbanned { user, timestamp: get_block_timestamp() });
        }

        fn claim_reward(ref self: ContractState) {
            self._only_not_paused();
            let caller = get_caller_address();
            self._only_registered(caller);
            let mut user = self.users.entry(caller).read();
            let points = user.points;
            assert(points > 0, 'No points to claim');
            let multiplier = if user.is_premium { self.premium_reward_multiplier.read() } else { 1 };
            let amount = points.into() * self.points_to_strk.read() * multiplier;
            user.points = 0;
            self.users.entry(caller).write(user);
            let strk = IERC20Dispatcher { contract_address: self.strk_token.read() };
            strk.transfer(caller, amount);
            self.emit(RewardClaimed { user: caller, amount, timestamp: get_block_timestamp() });
        }

        fn get_user_info(self: @ContractState, user: ContractAddress) -> (u256, bool, u32, bool, bool) {
            let user_data = self.users.entry(user).read();
            (user_data.stake.amount, user_data.is_premium, user_data.points, user_data.is_banned, user_data.has_good_reputation)
        }

        fn get_stats(self: @ContractState) -> (u64, u64, u256) {
            (self.total_accounts.read(), self.total_documents.read(), self.total_size.read())
        }

        fn update_reward_parameters(
            ref self: ContractState,
            points_per_insert: u32,
            points_per_update: u32,
            points_per_delete: u32,
            points_per_vote: u32,
            points_to_strk: u256,
            premium_reward_multiplier: u256
        ) {
            self._only_admin();
            self._only_not_paused();
            self.points_per_insert.write(points_per_insert);
            self.points_per_update.write(points_per_update);
            self.points_per_delete.write(points_per_delete);
            self.points_per_vote.write(points_per_vote);
            self.points_to_strk.write(points_to_strk);
            self.premium_reward_multiplier.write(premium_reward_multiplier);
            self.emit(ParametersUpdated { timestamp: get_block_timestamp() });
        }
    }
}