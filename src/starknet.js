import {
  connect,
  disconnect as gsDisconnect
} from "@starknet-io/get-starknet";
import { Contract, RpcProvider, constants, shortString, WalletAccount } from 'starknet';
import { LZString } from 'lz-string';

const CONFIG = {
  NETWORK: {
    STARKNET: {
      TESTNET: {
        PROVIDER_URL: 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_8/O2Um2MxXEjalg3IN4TeL3',
        CONTRACT_ADDRESS: '0x018cafa4fe61687014475b200f4641ddf8e01d42f3fd663a51f3d5ee19df964b'
      },
      MAINNET: {
        PROVIDER_URL: 'https://starknet-mainnet.g.alchemy.com/starknet/version/rpc/v0_9/YOUR_KEY',
        CONTRACT_ADDRESS: '0x018cafa4fe61687014475b200f4641ddf8e01d42f3fd663a51f3d5ee19df964b'
      }
    }
  },
  STORAGE: {
    MAX_COMPRESSED_SIZE: 30 * 1024 // 30KB
  }
};

class CryptoUtils {
  static async generateHash(data) {
    try {
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(JSON.stringify(data)));
      return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
    } catch (error) {
      console.error('Hash generation failed:', error);
      throw new Error('Failed to generate hash');
    }
  }
}

/**
 * StarknetManager - Handles contract interaction with auto wallet connection & persistence
 * Supports both ArgentX and Braavos wallets
 */
class StarknetManager {
  constructor(networkType = 'mainnet') {
    if (typeof window === 'undefined') {
      throw new Error('StarknetManager must be used in a browser environment');
    }

    this.networkType = networkType;
    this.config = CONFIG.NETWORK.STARKNET[networkType.toUpperCase()];
    this.provider = new RpcProvider({ nodeUrl: this.config.PROVIDER_URL });
    this.account = null;
    this.contract = null;
    this._abi = null;
    this._restoring = false;
    this.walletAddress = null;
    this.walletType = null;
    this.isConnected = false;
  }

  async _getAbi() {
    if (!this._abi) {
      const classResponse = await this.provider.getClassAt(this.config.CONTRACT_ADDRESS);
      if (!classResponse?.abi) {
        throw new Error('Failed to fetch contract ABI');
      }
      this._abi = classResponse.abi;
    }
    return this._abi;
  }

  async _getContract() {
    if (!this.contract) {
      const abi = await this._getAbi();
      this.contract = new Contract(abi, this.config.CONTRACT_ADDRESS, this.provider);
    }
    if (this.account) {
      this.contract.connect(this.account);
    }
    return this.contract;
  }

  _saveConnectionState(address, chainId, walletType = null) {
    try {
      localStorage.setItem('starknet_connection', JSON.stringify({
        address,
        chainId,
        network: this.networkType,
        timestamp: Date.now(),
        walletType: walletType || this.walletType || 'unknown'
      }));
      console.log('Connection state saved');
    } catch (e) {
      console.warn('Failed to save connection state', e);
    }
  }

  _clearConnectionState() {
    try {
      localStorage.removeItem('starknet_connection');
      console.log('Connection state cleared');
    } catch (e) {
      console.warn('Failed to clear connection state', e);
    }
  }

  _onWalletDisconnected() {
    this.account = null;
    this.walletType = null;
    this.walletAddress = null;
    this.isConnected = false;
    this._clearConnectionState();
  }

  /**
   * Restore previous wallet connection
   */
  async _restoreConnection() {
    if (this._restoring) return null;
    this._restoring = true;

    try {
      const stored = localStorage.getItem('starknet_connection');
      if (!stored) {
        console.log('No stored connection found');
        return null;
      }

      const { address, chainId, network, timestamp, walletType } = JSON.parse(stored);

      if (Date.now() - timestamp > 7 * 24 * 60 * 60 * 1000 || network !== this.networkType) {
        console.log('Stored connection expired or wrong network');
        this._clearConnectionState();
        return null;
      }

      console.log(`Attempting to restore ${walletType || 'unknown'} connection...`);

      // Try silent connection first (neverAsk mode)
      const connection = await connect({
        modalMode: 'alwaysAsk'
      });

      if (!connection) {
        console.log('Silent connection returned null');
        this._clearConnectionState();
        return null;
      }

      // Handle enable based on wallet type
      try {
        if (typeof connection.enable === 'function') {
          await connection.enable();
        }
      } catch (enableErr) {
        if (enableErr.message?.includes('Not implemented')) {
          console.warn(`${connection.id} wallet does not support enable()`);
        } else {
          console.error('Enable failed:', enableErr.message);
          this._clearConnectionState();
          return null;
        }
      }

      if (!connection.isConnected || !connection.selectedAddress) {
        console.log('Connection not valid after enable');
        this._clearConnectionState();
        return null;
      }

      const account = await this._setupWalletAccount(connection, walletType);
      return account;
    } catch (error) {
      console.warn('Failed to restore wallet connection:', error.message);
      this._clearConnectionState();
      return null;
    } finally {
      this._restoring = false;
    }
  }

  /**
   * Create a simple account wrapper from connection object (for Braavos compatibility)
   */
  _createAccountFromConnection(connection) {
    return {
      address: connection.selectedAddress,
      signer: connection,
      execute: async (calls) => {
        // Format calls properly
        const payload = Array.isArray(calls) ? calls : [calls];
        
        // Use wallet's request method if available
        if (typeof connection.request === 'function') {
          return await connection.request({
            type: 'wallet_executeTransaction',
            payload
          });
        }

        // Fallback to direct wallet invocation
        if (typeof connection.invokeFunction === 'function') {
          return await connection.invokeFunction(...payload);
        }

        throw new Error('Connection does not support execute');
      },
      signMessage: async (message) => {
        if (typeof connection.request === 'function') {
          return await connection.request({
            type: 'wallet_signMessage',
            payload: message
          });
        }
        throw new Error('Connection does not support signMessage');
      }
    };
  }

  /**
   * Setup WalletAccount with fallback for Braavos
   */
  async _setupWalletAccount(connection, walletTypeOverride = null) {
    try {
      this.walletType = walletTypeOverride || connection.id || 'unknown';

      let account = null;

      // Try to use WalletAccount (works better with ArgentX)
      try {
        account = await WalletAccount.connect(
          { nodeUrl: this.config.PROVIDER_URL },
          connection
        );

        if (!account || !account.address) {
          throw new Error('WalletAccount created but has no address');
        }

        console.log(`Created WalletAccount successfully for ${this.walletType}`);
      } catch (walletAccountErr) {
        // If WalletAccount fails (common with Braavos), use connection directly
        if (walletAccountErr.message?.includes('Not implemented')) {
          console.warn(
            `${this.walletType} WalletAccount not supported, using connection directly`
          );
          account = this._createAccountFromConnection(connection);
        } else {
          throw walletAccountErr;
        }
      }

      if (!account) {
        throw new Error('Failed to create account');
      }

      this.account = account;
      this.walletAddress = connection.selectedAddress;
      this.isConnected = true;

      // Save connection state
      const chainId = connection.chainId || null;
      this._saveConnectionState(
        connection.selectedAddress,
        chainId,
        this.walletType
      );

      console.log(
        `Wallet setup complete. Type: ${this.walletType}, Address: ${this.walletAddress}`
      );

      return this.account;
    } catch (error) {
      console.error('Failed to setup WalletAccount:', error.message);
      this.account = null;
      this.walletAddress = null;
      this.walletType = null;
      this.isConnected = false;
      throw error;
    }
  }

  /**
   * Attempt connection with specific wallet
   */
  async _attemptWalletConnection(walletId, options = {}) {
    try {
      const connection = await connect({
        modalMode: 'alwaysAsk',
        ...options
      });

      if (!connection) {
        console.log(`${walletId} returned null connection`);
        return null;
      }

      if (connection.id !== walletId) {
        console.log(`Expected ${walletId} but got ${connection.id}`);
        return null;
      }

      // Try to enable the connection
      try {
        if (typeof connection.enable === 'function') {
          await connection.enable();
        }
      } catch (enableErr) {
        if (enableErr.message?.includes('Not implemented')) {
          console.warn(`${walletId} does not support enable(). Continuing...`);
        } else {
          throw enableErr;
        }
      }

      // Validate connection state
      if (!connection.isConnected) {
        console.warn(`${walletId} connection is not connected after enable`);
        return null;
      }

      if (!connection.selectedAddress) {
        console.warn(`${walletId} has no selected address`);
        return null;
      }

      console.log(`Successfully connected to ${walletId}: ${connection.selectedAddress}`);

      return await this._setupWalletAccount(connection, walletId);
    } catch (error) {
      console.warn(`Failed to connect with ${walletId}:`, error.message);
      return null;
    }
  }

  /**
   * Main method to ensure write access - supports both ArgentX and Braavos
   */
  async _ensureWriteAccess(options = {}) {
    try {
      // If already connected, return existing account
      if (this.account && this.isConnected && this.walletAddress) {
        console.log(`Using existing ${this.walletType} connection:`, this.walletAddress);
        return this.account;
      }

      // Try to restore previous connection
      const restored = await this._restoreConnection();
      if (restored) {
        console.log(`Connection restored successfully from ${this.walletType}`);
        return restored;
      }

      // Check if any wallet is installed
      if (!window.starknet) {
        throw new Error('No Starknet wallet found. Please install Argent X or Braavos.');
      }

      console.log(`Available wallet: ${window.starknet.id}`);

      // Try preferred wallet first (if specified in options)
      if (options.preferredWallet) {
        console.log(`Attempting preferred wallet: ${options.preferredWallet}`);
        const connection = await this._attemptWalletConnection(
          options.preferredWallet,
          options
        );
        if (connection) return connection;
      }

      // Try ArgentX first (most stable)
      if (window.starknet?.id === 'argentX') {
        console.log('Attempting ArgentX connection...');
        const connection = await this._attemptWalletConnection('argentX', options);
        if (connection) return connection;
      }

      // Try Braavos second
      if (window.starknet?.id === 'braavos') {
        console.log('Attempting Braavos connection...');
        const connection = await this._attemptWalletConnection('braavos', options);
        if (connection) return connection;
      }

      // If specific wallet preference failed, try with modal
      console.log('Opening wallet selection modal...');
      const connection = await connect({
        modalMode: 'alwaysAsk',
        ...options
      });

      if (!connection) {
        throw new Error('Wallet connection cancelled by user');
      }

      return await this._setupWalletAccount(connection);
    } catch (error) {
      console.error('Wallet connection error:', error.message);
      this.account = null;
      this.walletAddress = null;
      this.walletType = null;
      this.isConnected = false;
      throw error;
    }
  }

  /**
   * Execute transaction with wallet-specific handling
   */
  async _executeTransaction(calls) {
    if (!this.account) {
      throw new Error('No account connected');
    }

    try {
      // Ensure calls is an array
      const payload = Array.isArray(calls) ? calls : [calls];

      // For WalletAccount (ArgentX)
      if (this.account.execute && typeof this.account.execute === 'function') {
        return await this.account.execute(payload);
      }

      throw new Error('Account does not support transaction execution');
    } catch (error) {
      console.error(`Transaction execution failed for ${this.walletType}:`, error.message);
      throw error;
    }
  }

  async connectWallet(options = {}) {
    return await this._ensureWriteAccess(options);
  }

  isWalletReady() {
    return !!(this.account && this.isConnected && this.walletAddress);
  }

  async initialize() {
    await this._restoreConnection();
    return this.isConnected;
  }

  async disconnectWallet() {
    try {
      await gsDisconnect({ clearLastWallet: true });
    } catch (e) {
      console.warn('Disconnect warning:', e);
    }
    this._onWalletDisconnected();
    console.log('Wallet disconnected');
  }

  getAccount() { return this.account; }
  getWalletAddress() { return this.walletAddress; }
  isWalletConnected() { return this.isConnected; }
  getWalletType() { return this.walletType; }

  async _waitForTransaction(txHash) {
    const receipt = await this.provider.waitForTransaction(txHash);
    if (receipt.execution_status === 'REVERTED') {
      throw new Error(receipt.revert_reason || 'Transaction reverted');
    }
    return receipt;
  }

  async isSystemActive() {
    const contract = await this._getContract();
    return await contract.get_system_status();
  }

  async getStatistics() {
    const contract = await this._getContract();
    const [accounts, docs, size] = await contract.get_database_statistics();
    return {
      totalAccountsRegistered: accounts.toString(),
      totalDocumentsInserted: docs.toString(),
      totalDatabaseSizeBytes: size.toString(),
      totalDatabaseSizeMB: (Number(size) / (1024 * 1024)).toFixed(2),
      totalDatabaseSizeGB: (Number(size) / (1024 * 1024 * 1024)).toFixed(4)
    };
  }

  async getUserStatistics(wallet) {
    const contract = await this._getContract();
    const address = wallet || this.account?.address || this.walletAddress;
    if (!address) {
      throw new Error('No wallet address provided or connected');
    }

    const raw = await contract.get_user_statistics(address);
    let res = raw;
    if (!res) res = [];
    else if (Array.isArray(res)) {
      // already fine
    } else if (res.result && Array.isArray(res.result)) {
      res = res.result;
    } else if (typeof res === 'object') {
      // try to build an array from numeric keys
      const numericKeys = Object.keys(res).filter(k => String(Number(k)) === k).sort((a, b) => Number(a) - Number(b));
      if (numericKeys.length > 0) {
        res = numericKeys.map(k => res[k]);
      } else {
        res = [res];
      }
    } else {
      res = [res];
    }

    const [Tthreat = 0n, Tupdates = 0n, Tdelete = 0n, Tvotes = 0n, Twhitelist = 0n, Tpending = 0n, Tapproved = 0n] = res;

    return {
      totalThreatBlocked: Number(Tapproved || 0),
      activeThreat: Number(Tthreat || 0),
      whitelist: Number(Twhitelist || 0)
    };
  }

  async getThreatById(collection, id) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const [compressed, fields] = await contract.get(
      shortString.encodeShortString(collection),
      id
    );
    if (!compressed) return null;
    const status = await contract.get_document_validation_status(
      shortString.encodeShortString(collection),
      id
    );
    if (status !== shortString.encodeShortString('approved')) {
      throw new Error('Document not approved');
    }
    const data = JSON.parse(LZString.decompressFromUTF16(compressed));
    return {
      id: id.toString(),
      data,
      fields: fields.map(([k, v]) => [shortString.decodeShortString(k), shortString.decodeShortString(v)])
    };
  }

  async getThreatByUrl(collection, url) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const query = [[
      shortString.encodeShortString('url'),
      shortString.encodeShortString('eq'),
      shortString.encodeShortString(url),
      shortString.encodeShortString('and')
    ]];
    const [compressed, fields] = await contract.find_one(
      shortString.encodeShortString(collection),
      query
    );
    if (!compressed) return null;
    const data = JSON.parse(LZString.decompressFromUTF16(compressed));
    return {
      data,
      fields: fields.map(([k, v]) => [shortString.decodeShortString(k), shortString.decodeShortString(v)])
    };
  }

  async getWhitelistData(url) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const query = [[
      shortString.encodeShortString('url'),
      shortString.encodeShortString('eq'),
      shortString.encodeShortString(url),
      shortString.encodeShortString('and')
    ]];
    const [compressed, fields] = await contract.find_one(shortString.encodeShortString('whitelist'), query);
    if (!compressed) return null;
    const data = JSON.parse(LZString.decompressFromUTF16(compressed));
    const status = await contract.get_document_validation_status(shortString.encodeShortString('whitelist'), data.id);
    if (status !== shortString.encodeShortString('approved')) {
      throw new Error('Whitelist entry not approved');
    }
    return data;
  }

  async getRewardParameters() {
    const contract = await this._getContract();
    const [insert, update, del, query, claim, mult, badge, rate] = await contract.get_reward_parameters();
    return {
      pointsPerInsert: Number(insert),
      pointsPerUpdate: Number(update),
      pointsPerDelete: Number(del),
      pointsPerQueryPage: Number(query),
      pointsThresholdForClaim: Number(claim),
      premiumRewardMultiplier: Number(mult),
      badgeThreshold: Number(badge),
      pointsToStrkWei: rate.toString()
    };
  }

  async getAllData(collection) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const ids = await contract.get_all_data(shortString.encodeShortString(collection));
    return ids.map(id => id.toString());
  }

  async is_account_registered(address) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    return await contract.is_account_registered(address);
  }

  async submitWhitelistRequest(collection, url, reason) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const canInsert = await this._canPerformAction('insert');
    if (!canInsert) throw new Error('Cannot insert');

    const compressed = LZString.compressToUTF16(JSON.stringify({ url, reason }));
    if (compressed.length * 2 > CONFIG.STORAGE.MAX_COMPRESSED_SIZE) {
      throw new Error(`Whitelist data too large`);
    }
    const fields = [
      [shortString.encodeShortString('url'), shortString.encodeShortString(url)],
      [shortString.encodeShortString('status'), shortString.encodeShortString('pending')]
    ];
    const contract = await this._getContract();
    const call = contract.populate('insert', [
      shortString.encodeShortString(collection),
      compressed,
      fields
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async _canPerformAction(actionType) {
    await this._ensureWriteAccess();
    const contract = await this._getContract();
    const encoded = shortString.encodeShortString(actionType);
    const result = await contract.can_perform_action(this.account.address, encoded);
    return !!result;
  }

  async getPoints(wallet) {
    const contract = await this._getContract();
     const address = wallet || this.account?.address || this.walletAddress;
    if (!address) {
      throw new Error('No wallet address provided or connected');
    }

    const points = await contract.get_points(address);
    return Number(points);
  }

  async isPremiumUser() {
    await this._ensureWriteAccess();
    const contract = await this._getContract();
    return await contract.get_is_user_premium(this.account.address);
  }

  async claimRewards() {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const call = contract.populate('claim_reward', []);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async voteOnDocument(collection, documentId, isValid) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const canVote = await contract.can_vote_on_document(
      this.account.address,
      shortString.encodeShortString(collection),
      documentId
    );
    if (!canVote) throw new Error('Cannot vote on this document');
    const call = contract.populate('vote_on_document', [
      shortString.encodeShortString(collection),
      documentId,
      isValid ? 1n : 0n
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async reportMaliciousData(collection, documentId, reason) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const canReport = await this._canPerformAction('report_malicious');
    if (!canReport) throw new Error('Cannot report');

    const contract = await this._getContract();
    const call = contract.populate('report_malicious_data', [
      shortString.encodeShortString(collection),
      documentId,
      shortString.encodeShortString(reason)
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async stakeForAccess(amount) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const bn = BigInt(amount);
    const u256 = { low: bn & 0xFFFFFFFFFFFFFFFFn, high: bn >> 128n };
    const contract = await this._getContract();
    const call = contract.populate('stake_for_access', [u256]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async getStakeInfo(address) {
    const contract = await this._getContract();
    const raw = await contract.get_stake_info(address);
    let res = raw;
    if (!res) res = [];
    else if (Array.isArray(res)) {
      // ok
    } else if (res.result && Array.isArray(res.result)) {
      res = res.result;
    } else if (typeof res === 'object') {
      const numericKeys = Object.keys(res).filter(k => String(Number(k)) === k).sort((a, b) => Number(a) - Number(b));
      if (numericKeys.length > 0) {
        res = numericKeys.map(k => res[k]);
      } else {
        res = [res];
      }
    } else {
      res = [res];
    }

    const [amount = 0n, unlockTime = 0n, isLocked = 0n] = res;
    return {
      amount: amount ? amount.toString() : '0',
      unlockTime: Number(unlockTime || 0),
      isLocked: !!isLocked
    };
  }

  async withdrawStake() {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const call = contract.populate('withdraw_stake', []);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async getUserSecurityProfile() {
    await this._ensureWriteAccess();
    const contract = await this._getContract();
    const [rep, docs, warns, votes, premium, stake, unlock] = await contract.get_user_security_profile(this.account.address);
    return {
      reputationScore: Number(rep),
      totalDocuments: Number(docs),
      warningCount: Number(warns),
      votesCast: Number(votes),
      isPremium: !!premium,
      stakeAmount: stake.toString(),
      unlockTime: Number(unlock)
    };
  }

  async queryThreats(collection, conditions, page = 1) {
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const contract = await this._getContract();
    const query = conditions.map(({ field, operator, value, logical }) => [
      shortString.encodeShortString(field),
      shortString.encodeShortString(operator),
      shortString.encodeShortString(value),
      shortString.encodeShortString(logical || 'and')
    ]);
    const ids = await contract.find(shortString.encodeShortString(collection), query, page);
    const results = await Promise.allSettled(ids.map(async (id) => {
      try {
        const [compressed, fields] = await contract.get(shortString.encodeShortString(collection), id);
        const status = await contract.get_document_validation_status(shortString.encodeShortString(collection), id);
        if (status !== shortString.encodeShortString('approved')) return null;
        const data = JSON.parse(LZString.decompressFromUTF16(compressed));
        return {
          id: id.toString(),
          data,
          fields: fields.map(([k, v]) => [shortString.decodeShortString(k), shortString.decodeShortString(v)])
        };
      } catch (e) {
        return null;
      }
    }));
    return results
      .filter(r => r.status === 'fulfilled' && r.value)
      .map(r => r.value);
  }

  async createCollection(name, indexedFields) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const canCreate = await this._canPerformAction('create_collection');
    if (!canCreate) throw new Error('Cannot create collection');

    const contract = await this._getContract();
    const call = contract.populate('create_collection', [
      shortString.encodeShortString(name),
      indexedFields.map(f => shortString.encodeShortString(f))
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async updateDocument(collection, id, data, fields) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const canUpdate = await this._canPerformAction('update');
    if (!canUpdate) throw new Error('Cannot update');

    const compressed = LZString.compressToUTF16(JSON.stringify(data));
    if (compressed.length * 2 > CONFIG.STORAGE.MAX_COMPRESSED_SIZE) {
      throw new Error('Data too large');
    }
    const encodedFields = fields.map(([k, v]) => [shortString.encodeShortString(k), shortString.encodeShortString(v)]);
    const contract = await this._getContract();
    const call = contract.populate('update', [
      shortString.encodeShortString(collection),
      id,
      compressed,
      encodedFields
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }

  async deleteDocument(collection, id) {
    await this._ensureWriteAccess();
    if (!(await this.isSystemActive())) throw new Error('System is paused');
    const canDelete = await this._canPerformAction('delete');
    if (!canDelete) throw new Error('Cannot delete');

    const contract = await this._getContract();
    const call = contract.populate('delete', [
      shortString.encodeShortString(collection),
      id
    ]);
    const res = await this._executeTransaction(call);
    await this._waitForTransaction(res.transaction_hash);
    return { success: true, transactionHash: res.transaction_hash };
  }
}

export {
  CONFIG,
  CryptoUtils,
  StarknetManager
};