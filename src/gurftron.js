import { StarknetManager, CryptoUtils, CONFIG } from './starknet.js';

(function () {
  // Create instances
  let starknetManager = null;

  // Monitoring state management
  const monitoringState = {
    isActive: false,
    periodicInterval: null,
    clickListener: null,
    submitListener: null,
    changeListener: null,
    unloadListener: null
  };

  // ===============================================
  // INTELLIGENT DATA COLLECTION & AGGREGATION
  // ===============================================
  
  const intelligenceCollector = {
    data: {
      web3Events: [],
      behavioralEvents: [],
      pageInfo: null,
      lastCollection: Date.now()
    },
    
    config: {
      maxWeb3Events: 10,        // Keep last 10 Web3 events
      maxBehavioralEvents: 20,  // Keep last 20 behavioral events
      collectionInterval: 30000, // Send data every 30 seconds
      web3EventTypes: new Set(['eth_sendTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData', 'starknet_signMessage'])
    },

    // Collect page information once
    collectPageInfo() {
      if (this.data.pageInfo && (Date.now() - this.data.pageInfo.timestamp) < 60000) {
        return; // Already collected within last minute
      }

      this.data.pageInfo = {
        url: window.location.href,
        title: document.title,
        domain: window.location.hostname,
        hasWeb3: !!(window.ethereum || window.starknet),
        timestamp: Date.now()
      };
    },

    // Record Web3 event (smart aggregation)
    recordWeb3Event(provider, method, args) {
      // Don't record if monitoring is inactive
      if (!monitoringState.isActive) return;

      // Only track critical methods
      if (!this.config.web3EventTypes.has(method)) {
        return;
      }

      const event = {
        provider,
        method,
        args: JSON.stringify(args).slice(0, 500), // Limit size
        timestamp: Date.now()
      };

      this.data.web3Events.push(event);
      
      // Keep only last N events
      if (this.data.web3Events.length > this.config.maxWeb3Events) {
        this.data.web3Events.shift();
      }

      // If critical method, send immediately
      if (method.includes('sign') || method.includes('Transaction')) {
        this.sendIntelligence(true); // Force immediate send
      }
    },

    // Record behavioral event (aggregated)
    recordBehavioralEvent(eventType, target) {
      // Don't record if monitoring is inactive
      if (!monitoringState.isActive) return;

      const event = {
        type: eventType,
        target: target?.tagName || 'unknown',
        timestamp: Date.now()
      };

      // Aggregate similar events (e.g., multiple clicks)
      const recent = this.data.behavioralEvents.find(e => 
        e.type === eventType && 
        e.target === event.target && 
        (Date.now() - e.timestamp) < 5000
      );

      if (recent) {
        recent.count = (recent.count || 1) + 1;
        recent.lastTimestamp = Date.now();
      } else {
        event.count = 1;
        this.data.behavioralEvents.push(event);
      }

      // Keep only last N events
      if (this.data.behavioralEvents.length > this.config.maxBehavioralEvents) {
        this.data.behavioralEvents.shift();
      }
    },

    // Send aggregated intelligence to content script
    sendIntelligence(force = false) {
      // Don't send if monitoring is inactive
      if (!monitoringState.isActive) return;

      const now = Date.now();
      const timeSinceLastCollection = now - this.data.lastCollection;

      // Only send if forced or interval elapsed
      if (!force && timeSinceLastCollection < this.config.collectionInterval) {
        return;
      }

      // Only send if we have meaningful data
      if (this.data.web3Events.length === 0 && this.data.behavioralEvents.length === 0) {
        return;
      }

      this.collectPageInfo();

      const intelligence = {
        pageInfo: this.data.pageInfo,
        web3Events: [...this.data.web3Events],
        behavioralEvents: [...this.data.behavioralEvents],
        summary: {
          web3Count: this.data.web3Events.length,
          behavioralCount: this.data.behavioralEvents.length,
          collectionDuration: timeSinceLastCollection
        },
        timestamp: now
      };

      // Send to content script
      const injectedToken = document.querySelector(`[id^="gurftron-extension-injected-"], script[data-gurftron]`)?.getAttribute('data-gurftron') || null;
      window.postMessage({
        type: 'gurftron:intelligence',
        intelligence,
        pageToken: injectedToken
      }, '*');

      // Clear sent data
      this.data.web3Events = [];
      this.data.behavioralEvents = [];
      this.data.lastCollection = now;
    }
  };

  // ===============================================
  // MONITORING CONTROL FUNCTIONS
  // ===============================================

  function startMonitoring() {
    if (monitoringState.isActive) {
      console.log('[Gurftron] Monitoring already active');
      return;
    }

    console.log('[Gurftron] Starting monitoring...');
    monitoringState.isActive = true;

    // Setup behavioral listeners
    monitoringState.clickListener = (e) => {
      intelligenceCollector.recordBehavioralEvent('click', e.target);
    };
    document.addEventListener('click', monitoringState.clickListener, true);

    monitoringState.submitListener = (e) => {
      intelligenceCollector.recordBehavioralEvent('submit', e.target);
      intelligenceCollector.sendIntelligence(true);
    };
    document.addEventListener('submit', monitoringState.submitListener, true);

    monitoringState.changeListener = (e) => {
      if (e.target.type === 'password') {
        intelligenceCollector.recordBehavioralEvent('password_change', e.target);
        intelligenceCollector.sendIntelligence(true);
      }
    };
    document.addEventListener('change', monitoringState.changeListener, true);

    // Setup periodic collection
    monitoringState.periodicInterval = setInterval(() => {
      intelligenceCollector.sendIntelligence();
    }, 30000);

    // Setup unload listener
    monitoringState.unloadListener = () => {
      intelligenceCollector.sendIntelligence(true);
    };
    window.addEventListener('beforeunload', monitoringState.unloadListener);

    console.log('[Gurftron] Monitoring started successfully');
  }

  function stopMonitoring() {
    if (!monitoringState.isActive) {
      console.log('[Gurftron] Monitoring already inactive');
      return;
    }

    console.log('[Gurftron] Stopping monitoring...');
    monitoringState.isActive = false;

    // Remove behavioral listeners
    if (monitoringState.clickListener) {
      document.removeEventListener('click', monitoringState.clickListener, true);
      monitoringState.clickListener = null;
    }

    if (monitoringState.submitListener) {
      document.removeEventListener('submit', monitoringState.submitListener, true);
      monitoringState.submitListener = null;
    }

    if (monitoringState.changeListener) {
      document.removeEventListener('change', monitoringState.changeListener, true);
      monitoringState.changeListener = null;
    }

    // Clear periodic interval
    if (monitoringState.periodicInterval) {
      clearInterval(monitoringState.periodicInterval);
      monitoringState.periodicInterval = null;
    }

    // Remove unload listener
    if (monitoringState.unloadListener) {
      window.removeEventListener('beforeunload', monitoringState.unloadListener);
      monitoringState.unloadListener = null;
    }

    // Clear any buffered data
    intelligenceCollector.data.web3Events = [];
    intelligenceCollector.data.behavioralEvents = [];

    console.log('[Gurftron] Monitoring stopped successfully');
  }

  // ===============================================
  // INTERCEPT WEB3 PROVIDERS
  // ===============================================
  
  if (window.ethereum) {
    const originalEthRequest = window.ethereum.request;
    window.ethereum.request = async function(...args) {
      const method = args[0]?.method;
      if (method) {
        intelligenceCollector.recordWeb3Event('ethereum', method, args[0]);
      }
      return originalEthRequest.apply(window.ethereum, args);
    };
  }

  if (window.starknet) {
    const originalStarknetRequest = window.starknet.request;
    window.starknet.request = async function(...args) {
      const method = args[0]?.method;
      if (method) {
        intelligenceCollector.recordWeb3Event('starknet', method, args[0]);
      }
      return originalStarknetRequest.apply(window.starknet, args);
    };
  }

  // ===============================================
  // EXISTING STARKNET MESSAGE HANDLING
  // ===============================================

  // Handle incoming messages from content script
  window.addEventListener('message', async function (event) {
    if (event.source !== window) return;
    if (!event.data || !event.data.type) return;

    // Handle monitoring control messages
    if (event.data.type === 'gurftron:control') {
      const { action } = event.data;
      if (action === 'start') {
        startMonitoring();
      } else if (action === 'stop') {
        stopMonitoring();
      }
      return;
    }

    // Handle starknet messages
    if (!event.data.type.startsWith('starknet:')) return;

    const incomingToken = event.data?.pageToken || null;
    const injectedEl = document.querySelector(`[id^="gurftron-extension-injected-"], script[data-gurftron]`);
    const injectedToken = injectedEl?.getAttribute('data-gurftron') || null;
    if (!incomingToken || !injectedToken || incomingToken !== injectedToken) {
      return;
    }

    const { type, payload } = event.data;
    let response = { success: false, error: null, data: null };

    if (!starknetManager) {
      starknetManager = new StarknetManager('testnet');
    }
    (async () => {
      try {
        await starknetManager.initialize();
      } catch (error) {
        console.warn('Failed to initialize StarknetManager:', error);
      }
    })();

    try { window.__gurftron_starknet_manager = starknetManager; } catch (e) { /* ignore */ }
    
    try {
      switch (type) {
        case 'starknet:connect':
          // If we already have an in-memory account, reuse it and avoid prompting the wallet again
          if (starknetManager && starknetManager.account) {
            response = { success: true, data: starknetManager.getWalletAddress() };
            break;
          }

          const connectedAccount = await starknetManager._ensureWriteAccess({ modalMode: 'alwaysAsk' });
          response = { success: !!connectedAccount, data: starknetManager.getWalletAddress()};
          break;

        case 'starknet:disconnect':
          if (starknetManager) {
            await starknetManager.disconnectWallet();
            starknetManager = null;
          }
          response = { success: true };
          break;

        case 'starknet:isConnected':
          const isConnected = starknetManager ? starknetManager.isWalletConnected() : false;
          response = { success: true, data: isConnected };
          break;

        case 'starknet:registerAccount':
          if (!starknetManager) throw new Error('Starknet not initialized');
          const registerResult = await starknetManager.registerAccount();
          response = { success: true, data: registerResult };
          break;

        case 'starknet:getWalletStatus':
          // Wallet status check for install page verification
          try {
            let connected = false;
            let wallet = 'none';
            let network = null;

            if (starknetManager && starknetManager.account) {
              connected = true;
              wallet = starknetManager.account.address || 'none';
              network = starknetManager.config?.NETWORK || null;
            }

            response = { success: true, data: { connected, wallet, network } };
          } catch (err) {
            response = { success: false, error: err.message, data: { connected: false, wallet: 'none', network: null } };
          }
          break;

        case 'starknet:verifyWallet':
          // Verify if currently connected wallet is still active
          try {
            let verified = false;
            let connected = false;
            let wallet = 'none';

            if (starknetManager && starknetManager.account) {
              try {
                const currentAddr = starknetManager.account.address;
                if (currentAddr) {
                  connected = true;
                  wallet = currentAddr;
                  verified = true;
                }
              } catch (e) {
                console.warn('Wallet verification check failed:', e);
              }
            }

            response = { success: true, data: { connected, wallet, verified } };
          } catch (err) {
            response = { success: false, error: err.message, data: { connected: false, wallet: 'none', verified: false } };
          }
          break;

        case 'starknet:threatAction':
          try {
            if (!starknetManager.isWalletReady()) {
              console.log('Wallet not ready, connecting...');
              await starknetManager.connectWallet();
              console.log('Wallet connected:', starknetManager.getWalletAddress());
            }

            // Ensure threat id exists
            const threat = payload;
            const collection = 'threats';
            const threatId = threat.id || (threat.fullContentHash || Math.random().toString(36).slice(2));
            const url = threat.url || window.location.href;
            const contentHash = threat.fullContentHash || '';
            const threatResults = { threatType: threat.type || 'unknown', severity: threat.severity || 'unknown', confidence: threat.confidence || 1 };
            const summary = threat.evidenceSummary || threat.detectedContent || '';

            const res = await starknetManager.submitThreatReport(collection, threatId, url, contentHash, threatResults, summary);
            const txHash = (res && (res.transactionHash || res.transaction_hash)) || res || null;

            const traceId = data.traceId || (data.payload && data.payload.traceId) || null;
            window.postMessage({ type: 'starknet:threatAction', action: 'block', tx: txHash, threat, traceId: traceId || null, pageToken: injectedToken }, '*');
          } catch (err) {
            const traceIdErr = data.traceId || (data.payload && data.payload.traceId) || null;
            window.postMessage({ type: 'starknet:threatAction', action: 'block', tx: null, error: err && err.message, threat: payload, traceId: traceIdErr || null, pageToken: injectedToken }, '*');
          }
          break;

        case 'starknet:executeMethod':
          // Execute any StarknetManager method dynamically
          try {
            console.log('window.starknet:', window.starknet);
            const { method, args } = event.data;
            
            if (!method) throw new Error('No method specified');

            if (!starknetManager.isWalletReady()) {
              console.log('Wallet not ready, connecting...');
              await starknetManager.connectWallet();
              console.log('Wallet connected:', starknetManager.getWalletAddress());
            }
            const result = await starknetManager[method](...(args || []));
            console.log('Method executed successfully:', method, result);
            
            const response = { 
              success: true, 
              data: result,
              method: method,
              walletAddress: starknetManager.getWalletAddress()
            };
    
          } catch (err) {
            console.error('Error executing method:', err);
            const response = { 
              success: false, 
              error: err.message,
              method: event.data.method
            };
          }
          break;


        default:
          console.warn('Unknown starknet message type:', type);
          return; // Don't respond to unknown types
      }

    } catch (error) {
      console.error('Error handling starknet message:', error);
      response = { success: false, error: error.message };
    }
    console.log(response)

    window.postMessage({
      type: type + ':response',
      response: response,
      pageToken: injectedToken || (document.querySelector(`[id^="gurftron-extension-injected-"], script[data-gurftron]`)?.getAttribute('data-gurftron')) || null
    }, '*');
  });

  window.postMessage({
    type: 'starknet:injected:ready',
    payload: { status: 'ready' },
    pageToken: (document.querySelector(`[id^="gurftron-extension-injected-"], script[data-gurftron]`)?.getAttribute('data-gurftron')) || null
  }, '*');

})();