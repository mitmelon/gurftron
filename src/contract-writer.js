import { DexieStorageAdapter } from './dexieStorage.js';
class SmartContractWriter {
  constructor(trackingKey, storeName = 'users') {
    this.trackingKey = trackingKey;
    this.storeName = storeName;
  }

  async execute(method, args = [], storageData = {}, storageKey, walletAddress, onSuccess, onError) {
    try {
      const config = await new Promise((resolve) => {
        chrome.storage.sync.get(['serverUrl', 'serverKey'], (result) => {
          resolve(result);
        });
      });

      const serverUrl = config.serverUrl || 'http://localhost:3000';
      const apiKey = config.serverKey || 'your_super_secure_api_key_here_make_it_long';

      if (!apiKey) {
        const error = new Error('API key not configured. Please set your API key in settings.');
        if (onError) onError(error);
        throw error;
      }

      // Convert args array to object format expected by server
      const contractArguments = Array.isArray(args) ? this._convertArgsToObject(method, args) : args;

      // Post data to server
      const response = await fetch(`${serverUrl}/write`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          methodName: method,
          arguments: contractArguments,
          walletAddress: walletAddress
        })
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.message || result.error || 'Failed to write to smart contract');
      }

      // Store data in IndexedDB after successful transaction
      if (storageData && storageKey) {
        const storage = new DexieStorageAdapter();
        await storage.initialize();
        await storage.save(this.storeName, storageKey, { 
          ...storageData,
          transactionHash: result.transactionHash,
          requestId: result.requestId,
          timestamp: new Date().toISOString()
        });
      }

      // Call success callback if provided
      if (onSuccess) {
        onSuccess(result);
      }

      return result;

    } catch (error) {
      console.error('SmartContractWriter error:', error);
      if (onError) onError(error);
      throw error;
    }
  }

  _convertArgsToObject(method, args) {
    if (!Array.isArray(args) || args.length === 0) {
      return {};
    }

    if (args.length === 1 && typeof args[0] === 'object' && !Array.isArray(args[0])) {
      return args[0];
    }

    const argsObject = {};
    args.forEach((arg, index) => {
      argsObject[`arg${index}`] = arg;
    });
    
    return argsObject;
  }
}

export { SmartContractWriter };
