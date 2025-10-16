async function computeSha256(content) {
  if (!window.crypto || !window.crypto.subtle) return null;
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function sendMessageSafe(message, callback) {
  try {
    if (!chrome || !chrome.runtime || typeof chrome.runtime.sendMessage !== 'function') {
      if (typeof callback === 'function') callback(null);
      return;
    }
    chrome.runtime.sendMessage(message, (resp) => {
      try {
        if (chrome.runtime && chrome.runtime.lastError) {
          if (typeof callback === 'function') callback(null);
          return;
        }
      } catch (e) {}
      if (typeof callback === 'function') callback(resp);
    });
  } catch (e) {
    try { if (typeof callback === 'function') callback(null); } catch (_) {}
  }
}

class GurftronThreatDetector {
  constructor(options = {}) {
    this.config = {
      cacheDuration: options.cacheDuration || 60 * 60 * 1000,
      startDelayMs: options.startDelayMs || 2000,
      abuseIPKey: options.abuseIPKey || null,
      safeBrowsingKey: options.safeBrowsingKey || null,
      braveSearchKey: options.braveSearchKey || null,
      logLevel: options.logLevel || 'info',
      retryAttempts: options.retryAttempts || 3,
      threatThreshold: options.threatThreshold || 0.5,
      abuseSubmissionOptIn: options.abuseSubmissionOptIn || false,
      mutationRateThreshold: options.mutationRateThreshold || 100,
      domainInfoCacheTTL: 7 * 24 * 60 * 60 * 1000,
      domainLLMCooldownMs: options.domainLLMCooldownMs || 2 * 60 * 1000,
      debounceMs: options.debounceMs || 500,
      maxScansPerBatch: options.maxScansPerBatch || 20,
      scanCacheTTL: options.scanCacheTTL || 3600000
    };
    this.gurftronId = options.gurftronId;
    this.threatsCache = new Map();
    this.domainCache = new Map();
    this.pageScans = new Map();
    this.scannedElements = new WeakMap();
    this.monitors = new Set();
    this.isMonitoring = false;
    this.currentUrl = window.location.href;
    this.historyStack = [window.location.href];
    this.metrics = { scans: 0, threatsDetected: 0, llmCalls: 0 };
    this.threatsLog = [];
    this.signalStore = new Map();
    this.domainLLMResourceMap = new Map();
    this.signalTTL = options.signalTTL || 60 * 1000;
    this.minSignals = options.minSignals || 1;
    this.mutationCount = 0;
    this.lastMutationTime = Date.now();
    this.initConfig();
    this.log('info', 'Gurftron Threat Detector v1.0.0 initialized with advanced threat detection');
  }

  async initConfig() {
    return new Promise(resolve => {
      chrome.storage.sync.get(Object.keys(this.config), (result) => {
        Object.assign(this.config, result);
        this.log('debug', 'Configuration loaded');
        resolve();
      });
    });
  }

  /**
   * Clear all caches - useful for re-scanning a page
   * Call from console: window.gurftronDetector.clearAllCaches()
   */
  clearAllCaches() {
    this.threatsCache.clear();
    this.domainCache.clear();
    this.pageScans.clear();
    this.scannedElements = new WeakMap();
    this.signalStore.clear();
    
    this.log('info', '🧹 All caches cleared! Ready for fresh scan.');
    console.log('✅ Gurftron caches cleared. You can now run: window.gurftronDetector.fullScan()');
  }

  setupInjectorGuard() {
    this.setupIntelligenceListener();
    
    this.ensureInjectorInterval = setInterval(async () => {
      try {
        const injected = document.querySelector(`[id^="starknet-extension-injected-"], script[data-gurftron]`);
        if (!injected) {
          try {
            await this.reinjectScript();
            this.log('warn', 'Re-injected script element');
          } catch (e) {
            this.log('error', 'Re-inject failed:', e.message);
          }
          const threatJson = await this.createThreatJson(this.currentUrl, 'Injected script was removed by page; re-injected by extension', 'tamper', 'high', null, null, 'Injected script removed');
          await this.handleThreatFound(threatJson);
        }
      } catch (e) {
        this.log('error', 'ensureInjectorInterval error:', e.message);
      }
    }, 5000);

    try {
      this.injectorRemovalObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
          if (m.type === 'childList' && m.removedNodes && m.removedNodes.length) {
            for (const rn of m.removedNodes) {
              try {
                if (rn && rn.nodeType === 1) {
                  const isOur = (rn.id && rn.id.startsWith('starknet-extension-injected-')) || (rn.getAttribute && rn.getAttribute('data-gurftron') === this.gurftronId);
                  if (isOur) {
                    (async () => {
                      try {
                        const evidence = `Injected script element removed from DOM`;
                        const threatJson = await this.createThreatJson(this.currentUrl, evidence, 'tamper_injection_removal', 'high', null, null, 'Injected script removed by page mutation');
                        await this.handleThreatFound(threatJson);
                        await this.reinjectScript();
                      } catch (e) {
                        this.log('error', 'injector removal handler failed:', e.message);
                      }
                    })();
                  }
                }
              } catch (e) {}
            }
          }
        }
      });
      this.injectorRemovalObserver.observe(document.documentElement || document, { childList: true, subtree: true });
      this.monitors.add(this.injectorRemovalObserver);
    } catch (obsErr) {
      this.log('warn', 'Failed to attach injector removal observer:', obsErr && obsErr.message);
    }
  }

  async reinjectScript() {
    try {
      const script = document.createElement('script');
      try { script.src = chrome.runtime.getURL('gurftron.js'); } catch (e) { script.src = 'gurftron.js'; }
      const injectedId = `gurftron-extension-injected-${window.gurftronPageId || 'unknown'}`;
      script.id = injectedId;
      const sigResp = await new Promise((resolve) => {
        try {
          sendMessageSafe({ type: 'GURFTRON_GET_INJECT_SIGNATURE', injectedId, secureId: window.gurftronPageId }, (resp) => {
            resolve(resp || {});
          });
        } catch (e) { resolve({}); }
      });
      if (sigResp && sigResp.signature) {
        script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
        script.setAttribute('data-gurftron-sig', sigResp.signature);
        script.setAttribute('data-gurftron-ts', sigResp.ts);
      } else {
        script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
      }
      (document.head || document.documentElement).appendChild(script);
      return true;
    } catch (e) {
      this.log('error', 'reinjectScript failed:', e && e.message);
      return false;
    }
  }

  async updateConfig(updates) {
    Object.assign(this.config, updates);
    return new Promise(resolve => {
      chrome.storage.sync.set(updates, () => {
        this.log('info', 'Configuration updated');
        resolve();
      });
    });
  }

  log(level, ...args) {
    const levels = { debug: 0, info: 1, warn: 2, error: 3 };
    const timestamp = new Date().toISOString();
    const message = `[Gurftron ${timestamp} ${level.toUpperCase()}] ${args.join(' ')}`;
    try {
      if (console && typeof console[level] === 'function') console[level](message);
      else console.log(message);
    } catch (e) {
      try { console.log(message); } catch (_) {}
    }
    if (levels[level] >= 2) {
      try {
        if (chrome && chrome.runtime && typeof chrome.runtime.sendMessage === 'function') {
          chrome.runtime.sendMessage({
            action: 'log_error_to_db',
            error: { message, stack: (new Error()).stack },
            source: 'content.js',
            level
          }, (resp) => {
            try {
              if (chrome.runtime.lastError) return;
            } catch (le) {}
          });
        }
      } catch (e) {}
    }
  }

  updateMetrics() {
    try {
      sendMessageSafe({ action: 'update_metrics', metrics: this.metrics }, (response) => {
        if (response && response.success) {
          this.log('debug', 'Metrics updated in IndexedDB');
        } else {
          this.log('warn', 'Failed to update metrics:', response?.error);
        }
      });
    } catch (e) {
      this.log('error', 'Failed to send metrics update:', e.message);
    }
  }

  async retryOp(fn, maxRetries = this.config.retryAttempts) {
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        this.log('warn', `Retry attempt ${attempt}/${maxRetries} failed:`, error.message);
        if (attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * attempt));
        }
      }
    }
    throw lastError;
  }

  isResourceCached(key) {
    const cached = this.pageScans.get(key);
    if (!cached) return false;
    return (Date.now() - cached) < this.config.scanCacheTTL;
  }

  markResourceScanned(key) {
    this.pageScans.set(key, Date.now());
  }

  async checkThreatInDB(url) {
    return new Promise((resolve) => {
      sendMessageSafe({ type: 'GURFTRON_GET_THREAT', url }, (response) => {
        try {
          if (response && Array.isArray(response.threats) && response.threats.length > 0) {
            const first = response.threats[0];
            const threatObj = first?.data || first;
            resolve(threatObj || null);
            return;
          }
        } catch (e) {}
        resolve(response?.threat || null);
      });
    });
  }

  async storeThreatInDB(threat) {
    return new Promise((resolve) => {
      try {
        if (!threat || !threat._tx) {
          resolve(false);
          return;
        }
        sendMessageSafe({ type: 'GURFTRON_STORE_THREAT', threat }, (response) => {
          resolve(response?.success || false);
        });
      } catch (e) {
        resolve(false);
      }
    });
  }

  extractDomain(url) {
    try {
      return new URL(url).hostname.replace(/^www\./, '');
    } catch {
      return url.replace(/^https?:\/\/(www\.)?/, '').split('/')[0];
    }
  }

  async getDomainInfo(domain) {
    if (this.domainCache.has(domain)) {
      const cached = this.domainCache.get(domain);
      if (Date.now() - cached.timestamp < this.config.domainInfoCacheTTL) {
        return cached.data;
      }
    }
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'get_domain_info', domain }, (response) => {
        if (response && !response.error) {
          this.domainCache.set(domain, { data: response, timestamp: Date.now() });
          resolve(response);
        } else {
          resolve(null);
        }
      });
    });
  }

  async deepSearchForImpersonation(originalUrl, pageTitle, pageContent, originalDomain) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'brave_deep_search',
        originalUrl,
        pageTitle,
        pageContent: pageContent?.substring(0, 1000) || '',
        originalDomain
      }, (response) => {
        resolve(response?.evidence || []);
      });
    });
  }

  // Check cooldown for a specific resource under a domain (resourceKey should be element src or url)
  shouldAllowHeavyLLMForResource(domain, resourceKey) {
    try {
      if (!domain) return true;
      let domainMap = this.domainLLMResourceMap.get(domain);
      if (!domainMap) return true;
      const last = domainMap.get(resourceKey) || 0;
      const now = Date.now();
      return (now - last) >= (this.config.domainLLMCooldownMs || (2 * 60 * 1000));
    } catch (e) {
      return true;
    }
  }

  recordResourceLLM(domain, resourceKey) {
    try {
      if (!domain) return;
      let domainMap = this.domainLLMResourceMap.get(domain);
      if (!domainMap) {
        domainMap = new Map();
        this.domainLLMResourceMap.set(domain, domainMap);
      }
      domainMap.set(resourceKey, Date.now());
    } catch (e) {}
  }

  async analyzeWithLLM(evidenceText, category, options = {}) {
    this.metrics.llmCalls++;
    this.updateMetrics();
    
    // Log LLM call for debugging
    this.log('info', `🤖 LLM Analysis Started: ${category}`);
    
    // Default options and safe prompt size guard
    options = Object.assign({ passFullQuoted: true, maxPromptChars: 8000 }, options || {});
    let payloadText = evidenceText || '';
    if (options.passFullQuoted && typeof payloadText === 'string') {
      const safe = payloadText.replace(/\"\"\"/g, '\\\"\\\"\\\"');
      payloadText = `"""${safe}"""`;
    }

    if (typeof payloadText === 'string' && payloadText.length > options.maxPromptChars) {
      const originalLength = payloadText.length;
      // Keep head and tail with an ellipsis marker
      const keep = Math.floor(options.maxPromptChars / 2) - 64;
      const head = payloadText.slice(0, keep);
      const tail = payloadText.slice(-keep);
      payloadText = `${head}\n\n...[TRUNCATED ${originalLength - (keep * 2)} chars]...\n\n${tail}`;
      this.log('warn', `LLM prompt truncated from ${originalLength} to ${payloadText.length} chars for category=${category}`);
    }
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        action: 'llm_analyze',
        text: payloadText,
        type: category,
      }, (response) => {
        // Check for Chrome runtime errors
        if (chrome.runtime.lastError) {
          console.error('🤖 Chrome runtime error:', chrome.runtime.lastError);
          resolve({
            threat: false,
            confidence: 0,
            details: chrome.runtime.lastError.message
          });
          return;
        }
        
        // Log LLM response
        console.log('🤖 LLM response:', response);
        this.log('info', `🤖 LLM Response: ${category} - Threat: ${response?.threat}, Confidence: ${response?.confidence}`);
        
        // Check if there's an error in the response
        if (response?.error) {
          console.error('🤖 LLM API error:', response.error);
          resolve({
            threat: false,
            confidence: 0,
            details: response.error
          });
          return;
        }
        
        // Return the actual response
        resolve({
          threat: response?.threat || false,
          confidence: response?.confidence || 0,
          details: response?.details || ''
        });
      });
    });
  }

  sanitizeEvidence(text) {
    if (!text || typeof text !== 'string') return '';
    return text.replace(/\"\"\"/g, '\\\"\\\"\\\"');
  }

  async offloadApiCall(api, params) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'api_call', api, params }, (response) => {
        resolve(response || {});
      });
    });
  }

  async offloadScan(type, data) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'scan', type, data }, (response) => {
        resolve(response || {});
      });
    });
  }

  async collectPageData(eventOrMutation) {
    const cacheKey = `page_collection_${this.currentUrl}`;
    if (this.isResourceCached(cacheKey)) return null;
    this.markResourceScanned(cacheKey);

    const pageData = {
      url: this.currentUrl,
      title: document.title,
      textContent: document.body?.innerText?.slice(0, 5000) || '',
      forms: Array.from(document.forms).map(form => ({
        action: form.action,
        method: form.method,
        elements: Array.from(form.elements).map(el => ({
          tag: el.tagName,
          type: el.type,
          name: el.name,
          value: el.value?.slice(0, 200),
          hidden: el.type === 'hidden' || el.style.display === 'none'
        }))
      })),
      scripts: Array.from(document.scripts).map(script => ({
        src: script.src,
        innerHTML: script.innerHTML.slice(0, 2000),
        hasEval: /eval|Function|setTimeout|setInterval/i.test(script.innerHTML)
      })),
      links: Array.from(document.links).map(link => link.href).slice(0, 200),
      iframes: Array.from(document.querySelectorAll('iframe')).map(iframe => ({
        src: iframe.src,
        sandbox: iframe.sandbox.value,
        hidden: iframe.style.display === 'none'
      })),
      canvasElements: Array.from(document.querySelectorAll('canvas')).length,
      behavioral: eventOrMutation?.type === 'click' ? { clickTarget: eventOrMutation.target?.tagName } : null,
      web3Event: eventOrMutation?.web3Event || null,
      cookies: document.cookie.split(';').map(c => ({ name: c.split('=')[0].trim() })),
      timestamp: Date.now()
    };

    // Build appropriate prompt based on context
    let promptContext = 'general page behavior';
    if (eventOrMutation?.web3Event) {
      promptContext = `Web3 ${eventOrMutation.web3Event.provider} wallet interaction (${eventOrMutation.web3Event.method})`;
    } else if (eventOrMutation?.type === 'submit') {
      promptContext = 'form submission behavior';
    } else if (eventOrMutation?.type === 'password_change') {
      promptContext = 'password field interaction (credential harvesting check)';
    }

    const prompt = `Analyze ${promptContext} for malicious patterns, phishing attempts, crypto wallet draining, or suspicious behavior. Page data: ${JSON.stringify(pageData).slice(0, 1000)}. Return threat assessment with high confidence (>0.75) only for ACTUAL threats, not legitimate websites.`;
    
    // Wait for LLM analysis response
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'analyzeThreat',
        data: pageData,
        prompt
      }, async (response) => {
        try {
          // Only trigger threat handling if LLM confirms with high confidence
          if (response && response.threat && response.confidence >= 0.75) {
            this.log('warn', `LLM detected threat via ${promptContext}: confidence=${response.confidence}`);
            
            // Determine threat type based on context
            let threatType = 'behavioral_threat';
            let severity = response.confidence > 0.85 ? 'high' : 'medium';
            
            if (eventOrMutation?.web3Event) {
              threatType = 'web3_behavioral_threat';
              severity = 'high'; // Web3 threats are critical
            } else if (eventOrMutation?.type === 'password_change') {
              threatType = 'credential_harvesting';
              severity = 'high';
            } else if (eventOrMutation?.type === 'submit') {
              threatType = 'form_threat';
            }
            
            const threatJson = await this.createThreatJson(
              this.currentUrl,
              JSON.stringify(pageData).slice(0, 500),
              threatType,
              severity,
              null,
              null,
              response.details || `LLM-detected threat during ${promptContext}`
            );
            
            await this.handleThreatFound(threatJson);
          } else if (response && response.threat && response.confidence < 0.75) {
            // Low confidence - just log, don't alarm user
            this.log('info', `Low-confidence threat signal (${response.confidence}) - not triggering alert`);
          }
          
          resolve(response);
        } catch (e) {
          this.log('error', 'Failed to handle collectPageData threat:', e.message);
          resolve(null);
        }
      });
    });
  }

  setupIntelligenceListener() {
    // Store the listener function so it can be removed later
    this.intelligenceListener = async (event) => {
      // Security check
      if (event.source !== window) return;
      if (!event.data || event.data.type !== 'gurftron:intelligence') return;

      const intelligence = event.data.intelligence;
      if (!intelligence) return;

      this.log('debug', 'Received intelligence from injected script', {
        web3Count: intelligence.summary.web3Count,
        behavioralCount: intelligence.summary.behavioralCount,
        duration: intelligence.summary.collectionDuration
      });

      // Forward to background for LLM analysis
      try {
        const response = await new Promise((resolve) => {
          sendMessageSafe({
            action: 'analyzeThreat',
            data: {
              url: intelligence.pageInfo.url,
              domain: intelligence.pageInfo.domain,
              title: intelligence.pageInfo.title,
              hasWeb3: intelligence.pageInfo.hasWeb3,
              web3Events: intelligence.web3Events,
              behavioralEvents: intelligence.behavioralEvents,
              timestamp: intelligence.timestamp
            }
          }, resolve);
        });

        // Handle LLM response
        if (response && response.result) {
          const { threat, confidence, details } = response.result;

          this.log('info', 'LLM analysis complete', { threat, confidence, details });

          // Only trigger alerts for high-confidence threats (≥0.75)
          if (threat && confidence >= 0.75) {
            const threatJson = await this.createThreatJson(
              intelligence.pageInfo.url,
              `Web3: ${intelligence.summary.web3Count} events, Behavioral: ${intelligence.summary.behavioralCount} events`,
              'suspicious_activity',
              confidence >= 0.9 ? 'critical' : 'high',
              null,
              null,
              details
            );
            await this.handleThreatFound(threatJson);
          }
        }
      } catch (error) {
        this.log('error', 'Failed to analyze intelligence', error);
      }
    };

    window.addEventListener('message', this.intelligenceListener);

    // Signal gurftron.js to start monitoring
    window.postMessage({ 
      type: 'gurftron:control', 
      action: 'start',
      pageToken: this.gurftronId 
    }, '*');

    this.log('info', 'Intelligence listener setup complete');
  }

  startMonitoring() {
    if (this.isMonitoring) return;

    this.setupInjectorGuard();

    const observer = new MutationObserver((mutations) => {
      if (!this._pendingMutations) this._pendingMutations = [];
      this._pendingMutations.push(...mutations);
      if (this._debounceTimer) clearTimeout(this._debounceTimer);
      this._debounceTimer = setTimeout(async () => {
        const batch = (this._pendingMutations || []).splice(0, this._pendingMutations.length);
        try {
          let scansThisBatch = 0;
          let changesDetected = false;
          const totalMutations = batch.length;
          this.mutationCount += totalMutations;
          const currentTime = Date.now();
          const timeDelta = currentTime - this.lastMutationTime;
          
          if (timeDelta >= 1000) {
            const rate = this.mutationCount / (timeDelta / 1000);
            if (rate > this.config.mutationRateThreshold) {
              const evidence = `Observed mutation rate: ${rate}/s; threshold: ${this.config.mutationRateThreshold}`;
              try {
                const llmResult = await this.analyzeWithLLM(this.sanitizeEvidence(evidence, 500), 'dom_behavior_threats');
                if (llmResult.threat) {
                  const threatJson = await this.createThreatJson(this.currentUrl, evidence, 'abnormal_dom_behavior', 'high', null, null, llmResult.details);
                  this.recordThreat(threatJson);
                }
              } catch (error) {
                this.log('error', 'Mutation scan error:', error.message);
              }
            }
            this.mutationCount = 0;
            this.lastMutationTime = currentTime;
          }

          for (const mutation of batch) {
            if (mutation.type === 'childList') {
              for (const node of mutation.addedNodes) {
                try {
                  if (scansThisBatch >= this.config.maxScansPerBatch) break;
                  if (node.nodeType !== 1) continue;
                  if (node.getAttribute && node.getAttribute('data-gurftron') === this.gurftronId) continue;
                  try { if (this.shouldSkipScan(node)) continue; } catch (e) {}
                  changesDetected = true;
                  let content = '';
                  switch (node.tagName) {
                    case 'SCRIPT':
                      content = node.textContent || (node.src ? await this.fetchContent(node.src) : '');
                      this.log('info', `Scanning SCRIPT:`, node.src || '[inline]');
                      const scriptResult = await this.scanScript(this.sanitizeEvidence(content, 3000), node);
                      this.markScanned(node, node.src || this.currentUrl, !!scriptResult);
                      this.log('info', `SCRIPT scan result:`, scriptResult ? JSON.stringify(scriptResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    case 'LINK':
                      if (node.rel === 'stylesheet' && node.href) {
                        content = await this.fetchContent(node.href);
                        this.log('info', `Scanning LINK stylesheet:`, node.href);
                        const cssResult = await this.scanCss(this.sanitizeEvidence(content, 2000), node);
                        this.markScanned(node, node.href || this.currentUrl, !!cssResult);
                        this.log('info', `LINK scan result:`, cssResult ? JSON.stringify(cssResult) : 'No threat detected');
                        scansThisBatch++;
                      }
                      break;
                    case 'FORM':
                      this.log('info', `Scanning FORM`);
                      const formResult = await this.scanForm(node);
                      this.markScanned(node, node.action || this.currentUrl, !!formResult);
                      this.log('info', `FORM scan result:`, formResult ? JSON.stringify(formResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    case 'IFRAME':
                      this.log('info', `Scanning IFRAME:`, node.src);
                      const iframeResult = await this.scanUrl(node.src);
                      this.markScanned(node, node.src || this.currentUrl, !!iframeResult);
                      this.log('info', `IFRAME scan result:`, iframeResult ? JSON.stringify(iframeResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    case 'IMG':
                      this.log('info', `Scanning IMG:`, node.src);
                      const imgResult = await this.scanImage(node.src, node);
                      this.markScanned(node, node.src || this.currentUrl, !!imgResult);
                      this.log('info', `IMG scan result:`, imgResult ? JSON.stringify(imgResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    case 'A':
                      this.log('info', `Scanning A:`, node.href);
                      const aResult = await this.scanLink(this.sanitizeEvidence(node.href, 2000), node);
                      this.markScanned(node, node.href || this.currentUrl, !!aResult);
                      this.log('info', `A scan result:`, aResult ? JSON.stringify(aResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    case 'OBJECT':
                    case 'EMBED':
                      this.log('info', `Scanning OBJECT/EMBED:`, node.data || node.src);
                      const objResult = await this.scanFileResource(node.data || node.src, node);
                      this.log('info', `OBJECT/EMBED scan result:`, objResult ? JSON.stringify(objResult) : 'No threat detected');
                      scansThisBatch++;
                      break;
                    default:
                      const elements = node.querySelectorAll(`script:not([data-gurftron="${this.gurftronId}"]), form, iframe, link[rel="stylesheet"], img, a, object, embed`);
                      for (const el of elements) {
                        try {
                          if (scansThisBatch >= this.config.maxScansPerBatch) break;
                          if (this.shouldSkipScan && this.shouldSkipScan(el)) continue;
                          if (el.tagName === 'SCRIPT') {
                            content = el.textContent || (el.src ? await this.fetchContent(el.src) : '');
                            this.log('info', `Scanning SCRIPT:`, el.src || '[inline]');
                            const elScriptResult = await this.scanScript(this.sanitizeEvidence(content, 3000), el);
                            this.markScanned(el, el.src || this.currentUrl, !!elScriptResult);
                            this.log('info', `SCRIPT scan result:`, elScriptResult ? JSON.stringify(elScriptResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'LINK' && el.rel === 'stylesheet' && el.href) {
                            content = await this.fetchContent(el.href);
                            this.log('info', `Scanning LINK stylesheet:`, el.href);
                            const elCssResult = await this.scanCss(this.sanitizeEvidence(content, 2000), el);
                            this.markScanned(el, el.href || this.currentUrl, !!elCssResult);
                            this.log('info', `LINK scan result:`, elCssResult ? JSON.stringify(elCssResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'FORM') {
                            this.log('info', `Scanning FORM`);
                            const elFormResult = await this.scanForm(el);
                            this.markScanned(el, el.action || this.currentUrl, !!elFormResult);
                            this.log('info', `FORM scan result:`, elFormResult ? JSON.stringify(elFormResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'IFRAME') {
                            this.log('info', `Scanning IFRAME:`, el.src);
                            const elIframeResult = await this.scanUrl(el.src);
                            this.markScanned(el, el.src || this.currentUrl, !!elIframeResult);
                            this.log('info', `IFRAME scan result:`, elIframeResult ? JSON.stringify(elIframeResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'IMG') {
                            this.log('info', `Scanning IMG:`, el.src);
                            const elImgResult = await this.scanImage(el.src, el);
                            this.markScanned(el, el.src || this.currentUrl, !!elImgResult);
                            this.log('info', `IMG scan result:`, elImgResult ? JSON.stringify(elImgResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'A') {
                            this.log('info', `Scanning A:`, el.href);
                            const elAResult = await this.scanLink(this.sanitizeEvidence(el.href, 2000), el);
                            this.markScanned(el, el.href || this.currentUrl, !!elAResult);
                            this.log('info', `A scan result:`, elAResult ? JSON.stringify(elAResult) : 'No threat detected');
                            scansThisBatch++;
                          } else if (el.tagName === 'OBJECT' || el.tagName === 'EMBED') {
                            this.log('info', `Scanning OBJECT/EMBED:`, el.data || el.src);
                            const elObjResult = await this.scanFileResource(el.data || el.src, el);
                            this.markScanned(el, el.data || el.src || this.currentUrl, !!elObjResult);
                            this.log('info', `OBJECT/EMBED scan result:`, elObjResult ? JSON.stringify(elObjResult) : 'No threat detected');
                            scansThisBatch++;
                          }
                        } catch (elScanError) {
                          this.log('error', `Element scan error:`, elScanError.message);
                        }
                      }
                  }
                } catch (scanError) {
                  this.log('error', `Node scan error:`, scanError.message);
                }
              }
            } else if (mutation.type === 'attributes') {
              const target = mutation.target;
              try {
                if (mutation.attributeName === 'src' && (target.tagName === 'SCRIPT' || target.tagName === 'IFRAME' || target.tagName === 'IMG')) {
                  if (target.tagName === 'IMG') {
                    this.log('info', `Scanning IMG (attribute change):`, target.src);
                    const attrImgResult = await this.scanImage(target.src);
                    this.log('info', `IMG scan result:`, attrImgResult ? JSON.stringify(attrImgResult) : 'No threat detected');
                  } else {
                    this.log('info', `Scanning SCRIPT/IFRAME (attribute change):`, target.src);
                    const attrScriptIframeResult = await this.scanUrl(target.src);
                    this.log('info', `SCRIPT/IFRAME scan result:`, attrScriptIframeResult ? JSON.stringify(attrScriptIframeResult) : 'No threat detected');
                  }
                } else if (mutation.attributeName === 'href' && (target.tagName === 'LINK' || target.tagName === 'A')) {
                  if (target.tagName === 'LINK' && target.rel === 'stylesheet') {
                    this.log('info', `Scanning LINK stylesheet (attribute change):`, target.href);
                    const attrLinkResult = await this.fetchContent(target.href);
                    const attrCssResult = await this.scanCss(this.sanitizeEvidence(attrLinkResult, 2000), target);
                    this.log('info', `LINK scan result:`, attrCssResult ? JSON.stringify(attrCssResult) : 'No threat detected');
                  } else if (target.tagName === 'A') {
                    this.log('info', `Scanning A (attribute change):`, target.href);
                    const attrAResult = await this.scanLink(this.sanitizeEvidence(target.href, 2000), target);
                    this.log('info', `A scan result:`, attrAResult ? JSON.stringify(attrAResult) : 'No threat detected');
                  }
                } else if (mutation.attributeName === 'action' && target.tagName === 'FORM') {
                  this.log('info', `Scanning FORM (attribute change)`);
                  const attrFormResult = await this.scanForm(target);
                  this.log('info', `FORM scan result:`, attrFormResult ? JSON.stringify(attrFormResult) : 'No threat detected');
                } else if (mutation.attributeName === 'data' && target.tagName === 'OBJECT') {
                  this.log('info', `Scanning OBJECT (attribute change):`, target.data);
                  const attrObjResult = await this.scanFileResource(target.data, target);
                  this.log('info', `OBJECT scan result:`, attrObjResult ? JSON.stringify(attrObjResult) : 'No threat detected');
                }
              } catch (attrScanError) {
                this.log('error', `Attribute scan error:`, attrScanError.message);
              }
            }
          }

          if (changesDetected) {
            this.metrics.scans++;
            this.updateMetrics();
          }
        } catch (e) {
          this.log('error', 'Mutation batch processing failed:', e.message);
        }
      }, this.config.debounceMs || 500);
    });

    const targetNode = document.documentElement || document;
    observer.observe(targetNode, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'action', 'data']
    });
    this.monitors.add(observer);
    this.isMonitoring = true;
    this.log('info', 'Mutation observer attached and monitoring started');

    try {
      if (!window._gurftron_reportedScripts) window._gurftron_reportedScripts = new Map();
      const scriptObserver = new MutationObserver((mutations) => {
        for (const m of mutations) {
          try {
            if (m.type === 'childList') {
              for (const n of m.addedNodes) {
                if (n && n.nodeType === 1 && n.tagName === 'SCRIPT') {
                  try {
                    const src = n.src || null;
                    let key;
                    if (src) {
                      key = src;
                    } else if (n.textContent && n.textContent.length) {
                      key = 'inline:' + n.textContent.slice(0, 200).replace(/\s+/g, ' ');
                    } else {
                      key = 'inline:unknown:' + Date.now();
                    }
                    const last = window._gurftron_reportedScripts.get(key);
                    const now = Date.now();
                    if (last && (now - last) < 30000) continue;
                    window._gurftron_reportedScripts.set(key, now);
                    const sig = n.getAttribute && n.getAttribute('data-gurftron-sig');
                    const sTs = n.getAttribute && n.getAttribute('data-gurftron-ts');
                    try { sendMessageSafe({ action: 'network_script_loaded', url: src || null, inline: !!(!src && n.textContent), snippet: (n.textContent || '').slice(0, 1000), signature: sig || null, sigTs: sTs || null }); } catch (e) {}
                  } catch (sk) {
                    this.log('debug', 'scriptObserver report failed:', sk.message);
                  }
                }
              }
            } else if (m.type === 'attributes' && m.target && m.target.tagName === 'SCRIPT' && m.attributeName === 'src') {
              const t = m.target;
              const src = t.src || null;
              const key = src || null;
              if (!key) continue;
              const last = window._gurftron_reportedScripts.get(key);
              const now = Date.now();
              if (last && (now - last) < 30000) continue;
              window._gurftron_reportedScripts.set(key, now);
              try { sendMessageSafe({ action: 'network_script_loaded', url: src, tabless: true, signature: t.getAttribute && t.getAttribute('data-gurftron-sig') || null, sigTs: t.getAttribute && t.getAttribute('data-gurftron-ts') || null }); } catch (e) {}
            }
          } catch (e) {}
        }
      });
      scriptObserver.observe(document.documentElement || document, { childList: true, subtree: true, attributes: true, attributeFilter: ['src'] });
      this.monitors.add(scriptObserver);
      this.log('info', 'Content-side script reporter active');
    } catch (e) {
      this.log('warn', 'Content-side script reporter unavailable:', e && e.message);
    }

    (async () => {
      try {
        this.log('info', 'Initial quick-scan starting to enumerate existing elements');
        const elements = document.querySelectorAll(`script:not([data-gurftron="${this.gurftronId}"]), form, iframe, link[rel="stylesheet"], img, a, object, embed`);
        for (const el of elements) {
          try {
            if (el.tagName === 'SCRIPT') {
              this.log('info', 'Initial scan detected SCRIPT - scanning', el.src || '[inline]');
              const content = el.textContent || (el.src ? await this.fetchContent(el.src) : '');
              await this.scanScript(content, el);
            } else if (el.tagName === 'LINK' && el.rel === 'stylesheet') {
              this.log('info', 'Initial scan detected LINK stylesheet - scanning', el.href);
              const content = el.href ? await this.fetchContent(el.href) : '';
              await this.scanCss(content, el);
            } else if (el.tagName === 'FORM') {
              this.log('info', 'Initial scan detected FORM - scanning form element');
              await this.scanForm(el);
            } else if (el.tagName === 'IFRAME') {
              this.log('info', 'Initial scan detected IFRAME - scanning', el.src);
              await this.scanUrl(el.src);
            } else if (el.tagName === 'IMG') {
              this.log('info', 'Initial scan detected IMG - scanning', el.src);
              await this.scanImage(el.src, el);
            } else if (el.tagName === 'A') {
              this.log('info', 'Initial scan detected LINK element - scanning', el.href);
              await this.scanLink(el.href, el);
            } else if (el.tagName === 'OBJECT' || el.tagName === 'EMBED') {
              this.log('info', 'Initial scan detected OBJECT/EMBED - scanning', el.data || el.src);
              await this.scanFileResource(el.data || el.src, el);
            }
          } catch (scanErr) {
            this.log('error', 'Initial scan element error:', scanErr.message);
          }
        }
        this.log('info', 'Initial quick-scan complete');
      } catch (e) {
        this.log('error', 'Initial quick-scan failed:', e.message);
      }
    })();

    const originalPushState = history.pushState;
    history.pushState = (...args) => {
      this.historyStack.push(window.location.href);
      if (this.historyStack.length > 5) {
        this.detectHijackingRedirections();
      }
      return originalPushState.apply(history, args);
    };

    const originalReplaceState = history.replaceState;
    history.replaceState = (...args) => {
      const res = originalReplaceState.apply(history, args);
      try { this.handleUrlChange(window.location.href); } catch (e) {}
      return res;
    };

    window.addEventListener('popstate', (e) => { try { this.handleUrlChange(window.location.href); } catch (err) {} });
    this.log('info', 'Comprehensive monitoring enabled');

    document.addEventListener('click', this.collectPageData.bind(this), true);
    if (window.ethereum) {
      const original = window.ethereum.request;
      window.ethereum.request = (...args) => {
        this.collectPageData({ web3Event: { method: args[0]?.method, args: JSON.stringify(args) } });
        return original.apply(window.ethereum, args);
      };
    }
    if (window.starknet) {
      const original = window.starknet.request;
      window.starknet.request = (...args) => {
        this.collectPageData({ web3Event: { method: args[0]?.method, args: JSON.stringify(args) } });
        return original.apply(window.starknet, args);
      };
    }
    window.addEventListener('load', this.collectPageData.bind(this));
    setInterval(this.collectPageData.bind(this), 5000);
  }

  stopMonitoring() {
    this.monitors.forEach(obs => obs.disconnect());
    this.monitors.clear();
    this.isMonitoring = false;
    
    // Clear the injector guard interval
    try {
      if (this.ensureInjectorInterval) {
        clearInterval(this.ensureInjectorInterval);
        this.ensureInjectorInterval = null;
      }
    } catch (e) {
      this.log('error', 'Failed to clear injector interval:', e.message);
    }

    // Remove intelligence listener
    try {
      if (this.intelligenceListener) {
        window.removeEventListener('message', this.intelligenceListener);
        this.intelligenceListener = null;
      }
    } catch (e) {
      this.log('error', 'Failed to remove intelligence listener:', e.message);
    }

    // Signal gurftron.js to stop monitoring
    try {
      window.postMessage({ 
        type: 'gurftron:control', 
        action: 'stop',
        pageToken: this.gurftronId 
      }, '*');
    } catch (e) {
      this.log('error', 'Failed to signal gurftron.js to stop:', e.message);
    }

    this.log('info', 'Monitoring disabled');
  }

  markScanned(element, key, hadThreat = false) {
    try {
      const now = Date.now();
      const ttl = this.config.cacheDuration || 60 * 60 * 1000;
      this.scannedElements.set(element, { ts: now, key, hadThreat, ttl });
    } catch (e) {
      this.log('error', 'markScanned failed:', e.message);
    }
  }

  shouldSkipScan(element) {
    try {
      if (!element) return false;
      const info = this.scannedElements.get(element);
      if (!info) return false;
      const now = Date.now();
      if (info.hadThreat) return false;
      if ((now - info.ts) < (info.ttl || (this.config.cacheDuration || 60 * 60 * 1000))) return true;
      return false;
    } catch (e) {
      this.log('error', 'shouldSkipScan failed:', e.message);
      return false;
    }
  }

  async fetchContent(url) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return await response.text();
      } else {
        this.log('warn', 'Content fetch failed with status', response.status, 'for', url);
      }
    } catch (error) {
      this.log('error', 'Content fetch error:', url, error.message);
    }
    return '';
  }

  async handleUrlChange(newUrl) {
    try {
      if (!newUrl) newUrl = window.location.href;
      if (newUrl === this.currentUrl) return;
      this.log('info', 'Detected URL change', this.currentUrl, '->', newUrl);
      this.currentUrl = newUrl;
      this.historyStack.push(newUrl);
      try { this.scannedElements = new WeakMap(); } catch (e) { this.scannedElements = new WeakMap(); }
      try {
        await this.fullScan();
      } catch (e) {
        this.log('error', 'fullScan after URL change failed:', e && e.message);
      }
    } catch (e) {
      this.log('error', 'handleUrlChange failed:', e && e.message);
    }
  }

  async detectPhishing(url, pageContent = null, pageTitle = null) {
    try {
      this.log('info', '🔍 Starting phishing detection for:', url);
      
      const startTime = Date.now();
      let evidence = [];
      let confidence = 0;
      let isPhishing = false;
      let severity = 'safe';
      let shouldBlock = false;

      const domain = this.extractDomain(url);
      this.log('info', `🌐 Extracted domain: ${domain}`);
      
      const domainInfo = await this.getDomainInfo(domain);
      this.log('info', `📊 Domain info retrieved:`, domainInfo ? 'Yes' : 'No');

      const safeBrowsingResult = await this.checkGoogleSafeBrowsing(url);
      this.log('info', `🛡️ Google Safe Browsing result: ${safeBrowsingResult.isThreat ? 'THREAT' : 'Safe'}`);
      
      if (safeBrowsingResult.isThreat) {
        evidence.push({
          reason: safeBrowsingResult.details,
          source: 'google_safe_browsing',
          score: 1.0
        });
        return {
          url,
          domain,
          isPhishing: true,
          confidence: 1.0,
          severity: 'critical',
          shouldBlock: true,
          domainInfo,
          evidence,
          analysisTimeMs: Date.now() - startTime,
          method: 'intelligent_phishing_detection'
        };
      }

      evidence.push({
        reason: safeBrowsingResult.details,
        source: 'google_safe_browsing',
        score: 0
      });

      let domainRiskAnalysis = null;
      if (domainInfo) {
        const domainRiskPrompt = `Analyze this domain registration and hosting data for phishing risk. Return ONLY a valid JSON object with: {"isSuspicious": boolean, "confidence": number (0.0 to 1.0), "reasons": string[], "redFlags": string[]}. Domain: ${domain}. Data: ${JSON.stringify(domainInfo, null, 2)}`;
        const llmResult = await this.analyzeWithLLM(domainRiskPrompt, 'domain_analysis', { passFullQuoted: true });
        try {
          domainRiskAnalysis = JSON.parse(llmResult.details);
          if (domainRiskAnalysis.isSuspicious) {
            confidence = Math.max(confidence, domainRiskAnalysis.confidence);
            evidence.push(...domainRiskAnalysis.reasons.map(reason => ({
              reason,
              source: 'domain_llm_analysis',
              score: domainRiskAnalysis.confidence
            })));
          }
        } catch (e) {
          this.log('warn', 'Failed to parse domain LLM analysis:', e);
        }
      }

      let searchEvidence = [];
      if (pageTitle && pageContent) {
        this.log('info', '🔍 Calling Brave Search for impersonation detection...');
        searchEvidence = await this.deepSearchForImpersonation(url, pageTitle, pageContent, domain);
        this.log('info', `Brave Search returned ${searchEvidence.length} evidence items`);
        
        if (searchEvidence.length > 0) {
          const maxSearchScore = Math.max(...searchEvidence.map(e => e.score));
          confidence = Math.max(confidence, maxSearchScore);
          evidence.push(...searchEvidence);
          if (maxSearchScore >= 0.7) isPhishing = true;
          
          this.log('warn', `Brave Search found suspicious results! Max score: ${maxSearchScore.toFixed(2)}`);
        } else {
          this.log('info', 'Brave Search found no suspicious results');
        }
      } else {
        this.log('warn', 'Skipping Brave Search - missing pageTitle or pageContent');
      }

      const llmReasoningPrompt = `You are a senior cybersecurity analyst. Your task: determine if this URL is a phishing site. Return ONLY a valid JSON object with: {"isPhishing": boolean, "confidence": number (0.0 to 1.0), "summary": string, "keyEvidence": string[], "recommendedAction": "block" | "warn" | "allow"}. CONTEXT: URL: ${url}, Domain: ${domain}, Page Title: ${pageTitle || 'N/A'}, Page Snippet: ${pageContent?.substring(0, 300) || 'N/A'}, Domain Info: ${JSON.stringify(domainInfo || {}, null, 2)}, Search Evidence: ${JSON.stringify(searchEvidence, null, 2)}, Domain Risk Analysis: ${JSON.stringify(domainRiskAnalysis || {}, null, 2)}`;

      // Respect per-resource cooldown for heavy LLM reasoning
      const reasonDomain = this.extractDomain(url);
      const reasonResource = url;
      let llmReasoningResult;
      if (!this.shouldAllowHeavyLLMForResource(reasonDomain, reasonResource)) {
        this.log('info', `Skipping heavy phishing LLM reasoning due to resource cooldown for: ${reasonResource} on ${reasonDomain}`);
        // Perform a lighter LLM check with a shorter context
        const litePrompt = `Quickly check for obvious phishing keywords or urgent lures in the page snippet: ${pageContent?.substring(0, 800) || 'N/A'}`;
        llmReasoningResult = await this.analyzeWithLLM(litePrompt, 'phishing_reasoning_lite');
      } else {
        this.recordResourceLLM(reasonDomain, reasonResource);
        llmReasoningResult = await this.analyzeWithLLM(llmReasoningPrompt, 'phishing_reasoning', { passFullQuoted: true });
      }
      let llmVerdict = null;

      try {
        llmVerdict = JSON.parse(llmReasoningResult.details);
        if (llmVerdict.isPhishing) {
          isPhishing = true;
          confidence = Math.max(confidence, llmVerdict.confidence);
          evidence.push(...(llmVerdict.keyEvidence || []).map(reason => ({
            reason: `LLM: ${reason}`,
            source: 'llm_reasoning',
            score: llmVerdict.confidence
          })));
        }
        if (llmVerdict.recommendedAction === 'block' && llmVerdict.confidence >= 0.8) {
          shouldBlock = true;
        }
      } catch (e) {
        this.log('error', 'Failed to parse LLM reasoning result:', e);
        evidence.push({
          reason: 'LLM analysis failed to parse',
          source: 'llm_reasoning',
          score: 0.0
        });
      }

      severity = this.calculateSeverity({ confidence });
      shouldBlock = shouldBlock || (isPhishing && confidence >= 0.7);

      const finalResult = {
        url,
        domain,
        isPhishing,
        confidence,
        severity,
        shouldBlock,
        domainInfo,
        evidence,
        analysisTimeMs: Date.now() - startTime,
        method: 'intelligent_phishing_detection'
      };

      // Log final phishing detection result
      this.log('warn', `🚨 Phishing Detection Complete: isPhishing=${isPhishing}, confidence=${confidence.toFixed(2)}, shouldBlock=${shouldBlock}, evidence=${evidence.length} items`);
      
      if (isPhishing) {
        this.log('error', `⚠️ PHISHING DETECTED! Domain: ${domain}, Confidence: ${confidence.toFixed(2)}, Severity: ${severity}`);
        
        const canonicalUrl = new URL(url, window.location.origin).href;
        const threatRecord = {
          id: await computeSha256(canonicalUrl),
          url: canonicalUrl,
          contentHash: pageContent ? await computeSha256(pageContent) : null,
          contentSummary: pageContent?.substring(0, 200) || 'No content',
          threatResults: { ...finalResult, timestamp: Date.now() }
        };
        this.recordThreat(threatRecord);
      } else {
        this.log('info', `No phishing detected for: ${domain}`);
      }

      return finalResult;
    } catch (error) {
      this.log('error', 'Intelligent phishing detection failed:', error);
      return {
        url,
        isPhishing: false,
        confidence: 0,
        severity: 'safe',
        shouldBlock: false,
        domainInfo: null,
        evidence: [{ reason: 'Detection system failed internally.', source: 'system_error', score: 0 }],
        analysisTimeMs: 0,
        method: 'intelligent_phishing_detection'
      };
    }
  }

  async checkGoogleSafeBrowsing(url) {
    const response = await this.offloadApiCall('safebrowsing', { url, key: this.config.safeBrowsingKey });
    if (response?.matches && response.matches.length > 0) {
      return {
        isThreat: true,
        details: `Flagged by Google Safe Browsing as ${response.matches[0].threatType}.`
      };
    }
    return { isThreat: false, details: 'URL is not listed in Google Safe Browsing.' };
  }

  async scanUrl(url, options = {}) {
    if (!url || typeof url !== 'string') return null;
    const normalized = new URL(url, window.location.origin).href;
    const cacheKey = `url_${normalized}`;
    const cached = this.threatsCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.config.cacheDuration) {
      return cached.threat ? cached.threatJson : null;
    }

    const evidences = [];
    const apiResults = await Promise.allSettled([
      this.checkPhishTank(normalized),
      this.checkOpenPhish(normalized),
      this.checkGoogleSafeBrowsing(normalized),
      this.checkUrlhaus(normalized),
      this.checkHybridAnalysis(normalized),
      this.checkUrlscan(normalized),
      this.extractIpAndCheckAbuse(normalized)
    ]);
    evidences.push(`API check results: ${JSON.stringify(apiResults.filter(r => r.value).map(r => r.reason))}`);
    const headerEvidence = await this.checkResourceHeaders(normalized, 'url');
    if (headerEvidence) evidences.push(`Header analysis: ${JSON.stringify(headerEvidence)}`);

    const evidenceText = evidences.join('\n');
    const llmResult = await this.analyzeWithLLM(evidenceText, 'url_threats');
    const isThreat = llmResult.threat;

    const entry = { threat: isThreat, timestamp: Date.now() };
    this.threatsCache.set(cacheKey, entry);
    this.metrics.scans++;
    this.updateMetrics();

    if (isThreat) {
      const threatJson = await this.createThreatJson(normalized, evidenceText, 'url_threat', llmResult.confidence > 0.7 ? 'high' : 'medium', null, null, llmResult.details);
      entry.threatJson = threatJson;
      this.registerSignal('url_threat', normalized, llmResult.confidence || 1.0, llmResult.details);
      return threatJson;
    }
    return null;
  }

  async getCachedData(type) {
    const cacheKey = `feed_${type}`;
    let entry = this.threatsCache.get(cacheKey);
    if (!entry || (Date.now() - entry.timestamp) > this.config.cacheDuration) {
      try {
        const data = await this.retryOp(() => this.offloadApiCall(type, {}));
        entry = { data, timestamp: Date.now() };
        this.threatsCache.set(cacheKey, entry);
      } catch (error) {
        this.log('error', `Feed load failed for ${type}:`, error.message);
        return null;
      }
    }
    return entry.data;
  }

  async checkPhishTank(url) {
    const data = await this.getCachedData('phishtank');
    return data?.urlSet?.has(url) ? 'PhishTank positive' : '';
  }

  async checkOpenPhish(url) {
    const data = await this.getCachedData('openphish');
    return data?.urls?.includes(url) ? 'OpenPhish positive' : '';
  }

  async checkUrlhaus(url) {
    const data = await this.getCachedData('urlhaus');
    return data?.urls?.includes(url) ? 'URLhaus positive' : '';
  }

  async checkMalwareBazaar(hash) {
    const response = await this.retryOp(() => this.offloadApiCall('malwarebazaar', { hash }));
    return response?.query_status === 'ok' && response?.data?.length > 0 ? `MalwareBazaar hit: ${response.data.length}` : '';
  }

  async checkHybridAnalysis(url) {
    const response = await this.retryOp(() => this.offloadApiCall('hybridanalysis', { url }));
    return response?.result?.length > 0 ? `HybridAnalysis results: ${response.result.length}` : '';
  }

  async checkUrlscan(url) {
    const response = await this.retryOp(() => this.offloadApiCall('urlscan', { url }));
    return response?.results?.length > 0 ? `Urlscan results: ${response.results.length}` : '';
  }

  async extractIpAndCheckAbuse(url) {
    const ipMatch = url.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (!ipMatch || !this.config.abuseIPKey) return '';
    const ip = ipMatch[0];
    const response = await this.retryOp(() => this.offloadApiCall('abuseipdb', { ip, key: this.config.abuseIPKey }));
    const isAbuse = response?.data?.abuseConfidenceScore > 50;
    if (isAbuse && this.config.abuseSubmissionOptIn) {
      await this.offloadApiCall('abuseipdb_submit', { ip, categories: 'phishing' });
    }
    return isAbuse ? `AbuseIPDB score: ${response.data.abuseConfidenceScore}` : '';
  }

  async scanForm(form) {
    const formText = form.innerHTML + form.textContent;
    const evidences = [];
    const inputs = form.querySelectorAll('input[type="hidden"], input[style*="display:none"], input[style*="visibility:hidden"]');
    evidences.push(`Hidden inputs count: ${inputs.length}; Names: ${Array.from(inputs).map(i => i.name).join(', ')}`);
    const overlays = form.querySelectorAll('[style*="position:fixed"], [style*="z-index:9999"], iframe');
    evidences.push(`Overlays count: ${overlays.length}; X-Frame-Options present: ${!!document.querySelector('meta[http-equiv="X-Frame-Options"]')}`);
    const evidenceText = evidences.join('\n') + `\nForm content: ${formText}`;
    const prompt = `Detect phishing forms, credential harvesting, hidden fields, and overlay attacks: ${evidenceText}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'form_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      const score = llmResult.confidence || 0.6;
      this.registerSignal('form_threat', form.action || this.currentUrl, score, llmResult.details);
    }
    return null;
  }

  async scanScript(content, element = null) {
    if (!content) return null;

    const evidences = [];
    const length = content.length;
    const entropy = this.calculateEntropy(content);
    const hasDynamic = /eval|Function\(|setTimeout|setInterval|new Function/i.test(content);
    const networkCalls = (content.match(/fetch\(|XMLHttpRequest|axios|open\(|send\(/i) || []).length;
    const storageAccess = (content.match(/localStorage|sessionStorage|document.cookie/i) || []).length;

    evidences.push(`Script content length: ${length}; Entropy: ${entropy.toFixed(2)}`);
    evidences.push(`Contains eval/dynamic code: ${hasDynamic ? 'Yes' : 'No'}`);
    evidences.push(`Event listeners: ${content.match(/addEventListener/g)?.length || 0}`);
    evidences.push(`Network calls: ${networkCalls}`);
    evidences.push(`Storage access: ${storageAccess}`);

    // Heuristic: if a script is very large but has no dynamic or network indicators and low entropy,
    // skip LLM analysis to avoid false positives and heavy prompts.
    const VERY_LARGE = 200000; // chars
    const LARGE = 20000; // chars
    if (length > VERY_LARGE && !hasDynamic && networkCalls === 0 && entropy < 4.0) {
      this.log('info', `Skipping LLM for very large benign-appearing script (len=${length}, entropy=${entropy.toFixed(2)})`);
      // still register a light signal so it can be cached/seen later
      this.registerSignal('script_skipped_large', element?.src || this.currentUrl, 0.0, 'Skipped large benign script');
      return null;
    }

    // Build a compact sample for LLM when content is large. Keep head, middle, tail excerpts.
    let sample = content;
    if (length > LARGE) {
      // Try to extract only suspicious parts (preferable to naive head/middle/tail sampling)
      try {
        const extracted = await this.extractSuspiciousScriptParts(content, 6000);
        if (extracted && extracted.length > 128) {
          sample = extracted;
          this.log('info', `Using extracted suspicious parts for LLM (original len=${length}, sample len=${sample.length})`);
        } else {
          const part = Math.floor(LARGE / 3);
          const head = content.slice(0, part);
          const middle = content.slice(Math.floor((length - part) / 2), Math.floor((length + part) / 2));
          const tail = content.slice(-part);
          sample = `${head}\n\n/*...SNIPPET MIDDLE...*/\n\n${middle}\n\n/*...SNIPPET END...*/\n\n${tail}`;
          this.log('info', `Using sampled script excerpts for LLM (original len=${length}, sample len=${sample.length})`);
        }
      } catch (e) {
        const part = Math.floor(LARGE / 3);
        const head = content.slice(0, part);
        const middle = content.slice(Math.floor((length - part) / 2), Math.floor((length + part) / 2));
        const tail = content.slice(-part);
        sample = `${head}\n\n/*...SNIPPET MIDDLE...*/\n\n${middle}\n\n/*...SNIPPET END...*/\n\n${tail}`;
        this.log('warn', 'extractSuspiciousScriptParts failed, falling back to sampled excerpts:', e && e.message);
      }
    }

    const evidenceText = evidences.join('\n') + `\nScript sample length: ${sample.length}`;
    const prompt = `Analyze script for malicious activity, obfuscation, eval usage, data exfiltration, wallet draining. Provide concise JSON: {threat: boolean, confidence: number, details: string}. Script evidence: ${evidenceText}\nSample:\n${sample}`;

    // Check per-resource cooldown to avoid repeated heavy LLM analyses for same resource
    const domain = this.extractDomain(this.currentUrl);
    const resourceKey = element?.src || this.currentUrl;
    if (!this.shouldAllowHeavyLLMForResource(domain, resourceKey)) {
      this.log('info', `Skipping heavy LLM for resource due to cooldown: ${resourceKey} on ${domain}`);
      // Register a light signal for telemetry
      this.registerSignal('script_skipped_cooldown', resourceKey, 0.0, 'Skipped heavy LLM due to resource cooldown');
      return null;
    }

    this.recordResourceLLM(domain, resourceKey);
    const llmResult = await this.analyzeWithLLM(prompt, 'script_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      const score = llmResult.confidence || 0.7;
      this.registerSignal('script_threat', element?.src || this.currentUrl, score, llmResult.details);
    }
    return null;
  }

  async extractSuspiciousScriptParts(content, maxChars = 6000) {
    try {
      if (!content || typeof content !== 'string') return '';
      const len = content.length;
      const matches = [];

      const pushSnippet = (name, idx, matchLen) => {
        const ctx = 250; // capture 250 chars of context each side
        const start = Math.max(0, idx - ctx);
        const end = Math.min(len, idx + (matchLen || 0) + ctx);
        let snippet = content.slice(start, end);
        // shorten long snippet edges
        if (snippet.length > 1200) snippet = snippet.slice(0, 600) + '\n...\n' + snippet.slice(-600);
        matches.push({ name, snippet });
      };

      // Patterns to look for
      const patterns = [
        { name: 'dynamic_eval', re: /eval\s*\(|new\s+Function\s*\(|Function\s*\(/ig },
        { name: 'obfuscation_base64', re: /(?:[A-Za-z0-9+\/]{80,}=*)/g },
        { name: 'obfuscation_fromChar', re: /fromCharCode\s*\(|unescape\s*\(|atob\s*\(/ig },
        { name: 'network_calls', re: /fetch\s*\(|XMLHttpRequest\b|axios\.|open\s*\(|send\s*\(|WebSocket\b/ig },
        { name: 'storage_access', re: /localStorage\b|sessionStorage\b|document\.cookie\b/ig },
        { name: 'dom_write', re: /innerHTML\b|insertAdjacentHTML\b|document\.write\b/ig },
        { name: 'form_submit', re: /\.submit\s*\(|<form[\s\S]*?>/ig },
        { name: 'crypto', re: /crypto\.subtle|window\.crypto\b/ig },
        { name: 'prompt_injection_like', re: /return only a valid json|return only json|ignore previous instructions|output json/ig },
        { name: 'external_urls', re: /https?:\/\/[^\s'"\)\>]{8,300}/ig }
      ];

      for (const p of patterns) {
        try {
          let m;
          while ((m = p.re.exec(content)) !== null) {
            const idx = m.index;
            const matchLen = m[0] ? m[0].length : 0;
            pushSnippet(p.name, idx, matchLen);
            // limit duplicates
            if (matches.length > 30) break;
          }
        } catch (e) {}
        if (matches.length > 30) break;
      }

      // Also extract suspicious long strings that look like encoded blobs
      try {
        const longStrings = content.match(/['\"]([A-Za-z0-9+\/=]{100,})['\"]/g) || [];
        for (const s of longStrings.slice(0, 5)) {
          const idx = content.indexOf(s);
          if (idx >= 0) pushSnippet('long_encoded_string', idx, s.length);
        }
      } catch (e) {}

      // Unique by snippet content
      const uniq = [];
      const seen = new Set();
      for (const m of matches) {
        const key = m.snippet.slice(0, 200);
        if (!seen.has(key)) { seen.add(key); uniq.push(m); }
      }

      if (uniq.length === 0) return '';

      // Compose labeled combined output within maxChars
      let out = '';
      for (const u of uniq) {
        const block = `/* SUSPICIOUS: ${u.name} */\n${u.snippet}\n\n`;
        if ((out.length + block.length) > maxChars) {
          // try to trim the block to fit
          const remain = Math.max(0, maxChars - out.length - 64);
          if (remain <= 0) break;
          out += block.slice(0, remain) + '\n...\n';
          break;
        }
        out += block;
      }

      // If still empty or too small, return '' to allow fallback sampling
      return out.trim().slice(0, maxChars);
    } catch (e) {
      this.log('error', 'extractSuspiciousScriptParts failed:', e && e.message);
      return '';
    }
  }

  calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  calculateSeverity(prediction) {
    const score = prediction.confidence || prediction.score || 0;
    if (score > 0.9) return 'critical';
    if (score > 0.7) return 'high';
    if (score > 0.5) return 'medium';
    return 'low';
  }

  async scanCss(content, element = null) {
    if (!content) return null;
    const evidences = [];
    evidences.push(`CSS rules count: ${content.match(/{/g)?.length || 0}`);
    evidences.push(`Position/visibility manipulations: ${content.match(/position|display|visibility|opacity|z-index/g)?.length || 0}`);
    const evidenceText = evidences.join('\n') + `\nFull content: ${content}`;
    const prompt = `Check for CSS-based attacks, keylogging styles, overlay manipulations, clickjacking: ${evidenceText}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'css_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      this.registerSignal('css_threat', element?.href || this.currentUrl, llmResult.confidence || 0.5, llmResult.details);
    }
    return null;
  }

  async scanDomText() {
    const text = document.body?.textContent || '';
    const evidences = [];
    evidences.push(`Text length: ${text.length}`);

    // First: use Brave deep search to find similar pages that might be impersonators
    const domain = this.extractDomain(this.currentUrl);
    let searchResults = [];

    // If this specific resource (page) is under cooldown, skip heavy Brave deep search and comparison
    const resourceKey = this.currentUrl;
    if (!this.shouldAllowHeavyLLMForResource(domain, resourceKey)) {
      this.log('info', `Skipping Brave deep search for resource due to cooldown: ${resourceKey} on ${domain}`);
      // fall back to original DOM analysis
      const evidenceText = evidences.join('\n') + `\nFull text snapshot: ${text.slice(0, 4000)}`;
      const prompt = `Analyze DOM text for phishing keywords, urgency tactics, credential requests: ${evidenceText}`;
      const domResult = await this.analyzeWithLLM(prompt, 'dom_threats');
      const domThreat = domResult.threat;
      if (domThreat) {
        this.registerSignal('dom_threat', this.currentUrl, domResult.confidence || 0.4, domResult.details);
      }
      return null;
    }
    try {
      this.log('info', 'Running Brave deep search for impersonation candidates');
      searchResults = await this.deepSearchForImpersonation(this.currentUrl, document.title, text, domain) || [];
      this.log('info', `Brave deep search returned ${searchResults.length} candidates`);
    } catch (e) {
      this.log('warn', 'Brave deep search failed:', e && e.message);
      searchResults = [];
    }

    // Limit the number of candidates to check to avoid excessive LLM calls
    const MAX_CANDIDATES = 5;
    for (const cand of (searchResults.slice(0, MAX_CANDIDATES))) {
      try {
        const candUrl = (cand && (cand.url || cand.link || cand.target || cand.href)) || String(cand || '');
        if (!candUrl) continue;

        // Avoid comparing with the same URL or same domain (self-links) to reduce false positives
        const candDomain = this.extractDomain(candUrl);
        if (!candUrl || candUrl === this.currentUrl || candDomain === domain) {
          this.log('debug', 'Skipping candidate (same domain or same URL):', candUrl);
          continue;
        }

        this.log('info', 'Fetching candidate snippet for comparison:', candUrl);

        // Try background-offloaded snippet first (background can bypass CORS), fall back to fetch
        let candSnippet = '';
        try {
          candSnippet = await this.offloadScan('link_snippet', { url: candUrl }) || '';
        } catch (e) {
          this.log('debug', 'offloadScan link_snippet failed, falling back to fetchContent:', e && e.message);
          candSnippet = '';
        }
        if (!candSnippet) {
          try { candSnippet = await this.fetchContent(candUrl); } catch (e) { candSnippet = ''; }
        }

        // Prepare compact samples for comparison to keep prompts small
        const sampleOriginal = text.slice(0, 2000);
        const sampleCandidate = (typeof candSnippet === 'string' ? candSnippet : JSON.stringify(candSnippet || '')).slice(0, 4000);

        const comparePrompt = `You are a senior cybersecurity analyst. Compare the ORIGINAL page and the CANDIDATE page and determine if the CANDIDATE is impersonating the ORIGINAL. Return ONLY a JSON object with exactly: {"isImpersonation": boolean, "confidence": number (0.0-1.0), "reasons": string[] }.\n\nORIGINAL_URL: ${this.currentUrl}\nORIGINAL_TITLE: ${document.title || 'N/A'}\nORIGINAL_SNIPPET: ${sampleOriginal}\n\nCANDIDATE_URL: ${candUrl}\nCANDIDATE_SNIPPET: ${sampleCandidate}`;

        const llmResult = await this.analyzeWithLLM(comparePrompt, 'impersonation_check', { passFullQuoted: true, maxPromptChars: 8000 });

        // Parse structured JSON result if possible
        let parsed = null;
        try { parsed = JSON.parse(llmResult.details); } catch (e) {
          // Fallback: try to extract first JSON-like object from details
          const m = (llmResult.details || '').match(/\{[\s\S]*\}/);
          if (m) {
            try { parsed = JSON.parse(m[0]); } catch (e2) { parsed = null; }
          }
        }

        const isImpersonation = parsed?.isImpersonation || false;
        const conf = parsed?.confidence || llmResult.confidence || 0;

        if (isImpersonation && conf >= 0.75) {
          this.log('warn', `Impersonation detected: ${candUrl} (confidence=${conf})`);
          this.registerSignal('impersonation', candUrl, conf, (parsed && parsed.reasons) ? parsed.reasons.join('; ') : llmResult.details);

          const threatJson = await this.createThreatJson(candUrl, sampleCandidate.slice(0, 500), 'impersonation', conf >= 0.9 ? 'critical' : 'high', null, null, (parsed && parsed.reasons) ? parsed.reasons.join('; ') : llmResult.details);
          this.recordThreat(threatJson);
          return threatJson;
        } else {
          this.log('info', `Candidate not impersonation or low confidence (${conf.toFixed ? conf.toFixed(2) : conf}): ${candUrl}`);
        }
      } catch (e) {
        this.log('error', 'Impersonation candidate check failed:', e && e.message);
      }
    }

    // If no impersonation candidates were found/flagged, fall back to the original DOM analysis
    const evidenceText = evidences.join('\n') + `\nFull text snapshot: ${text.slice(0, 4000)}`;
    const prompt = `Analyze DOM text for phishing keywords, urgency tactics, credential requests: ${evidenceText}`;
    const domResult = await this.analyzeWithLLM(prompt, 'dom_threats');
    const domThreat = domResult.threat;
    if (domThreat) {
      this.registerSignal('dom_threat', this.currentUrl, domResult.confidence || 0.4, domResult.details);
    }
    return null;
  }

  async detectCryptojacking() {
    const usage = await this.offloadScan('cpu_monitor', { duration: 5000 });
    const evidences = `CPU usage: ${usage}%; Threshold: 80; Context: Background monitoring over 5s`;
    const prompt = `Detect cryptojacking based on high CPU usage and resource consumption: ${evidences}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'cryptojacking_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      this.registerSignal('cryptojacking', this.currentUrl, llmResult.confidence || 1.0, llmResult.details);
    }
    return null;
  }

  async detectTrackers() {
    this.log('info', 'Analyzing cookies and fingerprinting for trackers');
    const cookies = document.cookie ? document.cookie.split(';') : [];
    const thirdParty = cookies.filter(c => {
      const domain = c.split('=')[0].trim();
      return !domain.includes(window.location.hostname) && /tracker|analytics/i.test(domain) && c.includes('id=');
    });
    if (thirdParty.length > 0) this.log('info', 'Detected trackers in cookies:', thirdParty.map(c => c.split('=')[0].trim()));
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('GurftronTest', 2, 2);
    const data = canvas.toDataURL();
    const evidences = `Third-party cookies: ${thirdParty.length}; Fingerprint data sample: ${data.slice(0, 1000)}`;
    this.log('info', 'Performing tracker heuristic scans (fingerprint/cookie analysis)');
    const prompt = `Detect third-party trackers, fingerprinting, analytics cookies, and surveillance patterns: ${evidences}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'tracker_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      this.log('info', 'Detected TRACKER threat - registering signal for trackers');
      this.registerSignal('trackers', this.currentUrl, llmResult.confidence || 0.5, llmResult.details);
    }
    return null;
  }

  async detectHijackingRedirections() {
    if (this.historyStack.length > 3 && new Set(this.historyStack).size > 2) {
      const evidences = `History stack: ${this.historyStack.join(' -> ')}; Referrer: ${document.referrer}`;
      const prompt = `Detect redirection chains, redirect hijacking, and suspicious URL changes: ${evidences}`;
      const llmResult = await this.analyzeWithLLM(prompt, 'redirection_threats');
      const isThreat = llmResult.threat;
      if (isThreat) {
        const threatJson = await this.createThreatJson(this.currentUrl, evidences, 'redirection_hijack', 'high', null, null, llmResult.details);
        this.recordThreat(threatJson);
        return threatJson;
      }
    }
    return null;
  }

  async fullScan() {
    this.log('info', 'Executing full page scan');

    const dbThreat = await this.checkThreatInDB(this.currentUrl);
    if (dbThreat) {
      this.log('info', 'Threat report found in DB, skipping re-analysis:', dbThreat);
      try {
        dbThreat._registered = true;
        await this.handleThreatFound(dbThreat);
      } catch (e) {
        this.log('error', 'Failed to surface stored threat:', e.message);
      }
      return [dbThreat];
    }

    let evidenceBundle = [];

    const pageTitle = document.title;
    const pageContent = document.body?.textContent || '';

    const phishingResult = await this.detectPhishing(this.currentUrl, pageContent, pageTitle);
    if (phishingResult.isPhishing) {
      evidenceBundle.push({
        type: 'phishing',
        ...phishingResult
      });
    }

    const urlThreat = await this.scanUrl(this.currentUrl);
    if (urlThreat) evidenceBundle.push(urlThreat);

    const domThreat = await this.scanDomText();
    if (domThreat) evidenceBundle.push(domThreat);

    const elements = document.querySelectorAll(`script:not([data-gurftron="${this.gurftronId}"]), form, iframe, link[rel="stylesheet"], img, a, object, embed`);
    for (const el of elements) {
      let content = '';
      let threat;
      if (el.tagName === 'SCRIPT') {
        this.log('info', 'Full-scan detected SCRIPT - scanning', el.src || '[inline]');
        content = el.textContent || (el.src ? await this.fetchContent(el.src) : '');
        threat = await this.scanScript(content, el);
      } else if (el.tagName === 'LINK' && el.rel === 'stylesheet') {
        this.log('info', 'Full-scan detected LINK stylesheet - scanning', el.href);
        content = el.href ? await this.fetchContent(el.href) : '';
        threat = await this.scanCss(content, el);
      } else if (el.tagName === 'FORM') {
        this.log('info', 'Full-scan detected FORM - scanning form element');
        threat = await this.scanForm(el);
      } else if (el.tagName === 'IFRAME') {
        this.log('info', 'Full-scan detected IFRAME - scanning', el.src);
        threat = await this.scanUrl(el.src);
      } else if (el.tagName === 'IMG') {
        this.log('info', 'Full-scan detected IMG - scanning', el.src);
        threat = await this.scanImage(el.src, el);
      } else if (el.tagName === 'A') {
        this.log('info', 'Full-scan detected LINK element - scanning', el.href);
        threat = await this.scanLink(el.href, el);
      } else if (el.tagName === 'OBJECT' || el.tagName === 'EMBED') {
        this.log('info', 'Full-scan detected OBJECT/EMBED - scanning', el.data || el.src);
        threat = await this.scanFileResource(el.data || el.src, el);
      }
      if (threat) evidenceBundle.push(threat);
    }

    if (!window.gurftronDetector) window.gurftronDetector = this;

    const cryptoThreat = await this.detectCryptojacking();
    if (cryptoThreat) evidenceBundle.push(cryptoThreat);
    const trackerThreat = await this.detectTrackers();
    if (trackerThreat) evidenceBundle.push(trackerThreat);
    const redirectThreat = await this.detectHijackingRedirections();
    if (redirectThreat) evidenceBundle.push(redirectThreat);

    const threatScore = evidenceBundle.filter(e => e && e.severity && (e.severity === 'high' || e.severity === 'medium')).length / (evidenceBundle.length || 1);
    const isThreat = threatScore >= this.config.threatThreshold;
    const threatReport = {
      url: this.currentUrl,
      time: new Date().toISOString(),
      evidence: evidenceBundle,
      threatScore,
      isThreat,
      summary: isThreat ? 'Threat detected based on aggregated evidence.' : 'No significant threat detected.'
    };

    if (isThreat) {
      this.metrics.threatsDetected++;
      this.updateMetrics();
      chrome.runtime.sendMessage({ action: 'threat_notify', type: 'full_scan' });
      this.log('warn', 'Threat detected in full scan:', JSON.stringify(threatReport));
    }
    try {
      sendMessageSafe({ action: 'update_metrics', metrics: this.metrics }, (response) => {
        if (response && response.success) {
          this.log('debug', 'Metrics updated in IndexedDB:', response.metrics);
        } else {
          this.log('warn', 'Failed to update metrics:', response?.error);
        }
      });
    } catch (e) {
      this.log('error', 'Failed to send metrics update:', e.message);
    }
    return [threatReport];
  }

  async onDownloadScan(url, filePath) {
    let threats = [];
    const urlThreat = await this.scanUrl(url);
    if (urlThreat) threats.push(urlThreat);
    if (filePath) {
      const hash = 'computed_hash_if_accessible';
      const malware = await this.checkMalwareBazaar(hash);
      if (malware) {
        const threatJson = await this.createThreatJson(url, '', 'file_malware', 'high', hash, filePath);
        this.recordThreat(threatJson);
        threats.push(threatJson);
      }
    }
    if (threats.length > 0) {
      chrome.runtime.sendMessage({ action: 'threat_notify', type: 'download' });
      return threats;
    }
    return null;
  }

  async scanImage(url, element = null) {
    if (!url) return null;
    const evidences = [];
    const headerEvidence = await this.checkResourceHeaders(url, 'image');
    evidences.push(`Headers: ${JSON.stringify(headerEvidence)}`);
    const stegoEvidence = await this.offloadScan('image_stego_check', { url });
    evidences.push(`Stego analysis: ${JSON.stringify(stegoEvidence)}`);
    const evidenceText = evidences.join('\n');
    const prompt = `Detect steganography, tracking pixels, malicious metadata in images: ${evidenceText}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'image_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      const threatJson = await this.createThreatJson(url, evidenceText, 'image_threat', 'medium', null, null, llmResult.details);
      this.recordThreat(threatJson);
      return threatJson;
    }
    return null;
  }

  async scanLink(url, element = null) {
    if (!url) return null;
    const evidences = [];
    const isHidden = element && (element.style.display === 'none' || element.style.visibility === 'hidden' || element.style.opacity === '0' || element.offsetWidth === 0);
    evidences.push(`Visibility: ${isHidden ? 'Hidden (potential honeypot)' : 'Visible'}`);
    const headerEvidence = await this.checkResourceHeaders(url, 'link');
    evidences.push(`Headers: ${JSON.stringify(headerEvidence)}`);
    const snippet = await this.offloadScan('link_snippet', { url });
    evidences.push(`Content snippet: ${snippet}`);
    const evidenceText = evidences.join('\n');
    const prompt = `Analyze link for phishing, typosquatting, malicious redirect, spoofed domains: ${evidenceText}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'link_threats', { passFullQuoted: true });
    const isThreat = llmResult.threat;
    if (isThreat) {
      const threatJson = await this.createThreatJson(url, evidenceText, 'link_threat', 'medium', null, null, llmResult.details);
      this.recordThreat(threatJson);
      return threatJson;
    }
    return null;
  }

  async scanFileResource(url, element = null) {
    if (!url) return null;
    const evidences = [];
    const headerEvidence = await this.checkResourceHeaders(url, 'file');
    evidences.push(`Headers: ${JSON.stringify(headerEvidence)}`);
    const evidenceText = evidences.join('\n');
    const prompt = `Analyze embedded file for malware, suspicious MIME types, executable content: ${evidenceText}`;
    const llmResult = await this.analyzeWithLLM(prompt, 'file_threats');
    const isThreat = llmResult.threat;
    if (isThreat) {
      const threatJson = await this.createThreatJson(url, evidenceText, 'file_threat', 'high', null, null, llmResult.details);
      this.recordThreat(threatJson);
      return threatJson;
    }
    return null;
  }

  async checkResourceHeaders(url, resourceType) {
    const headers = await this.offloadScan('resource_headers', { url });
    if (!headers) return '';
    const contentType = headers['content-type'] || '';
    const extension = url.split('.').pop().toLowerCase();
    return { contentType, extension, resourceType };
  }

  async createThreatJson(url, detectedContent, type, severity, hash = null, filePath = null, evidenceSummary = '') {
    return {
      url,
      detectedContent: detectedContent.slice(0, 500),
      time: new Date().toISOString(),
      severity,
      fullContentHash: hash,
      filePath,
      type,
      evidenceSummary
    };
  }

  async handleThreatFound(threat) {
    try {
      const canonical = new URL(this.currentUrl, window.location.origin).href;
      threat.id = await computeSha256(canonical);
      try {
        const existing = await this.checkThreatInDB(canonical);
        if (existing && existing.id) {
          threat.alreadyRegistered = true;
          threat.id = existing.id || threat.id;
        }
      } catch (e) {
        console.warn('Pre-insert DB check failed:', e);
      }
      try {
        if (!threat.userSummary) {
          const summarySource = threat.evidenceSummary || threat.detectedContent || '';
          if (summarySource && summarySource.length > 32) {
            const llm = await this.analyzeWithLLM(summarySource, 'user_summary');
            threat.userSummary = llm.details;
            threat.confidence = llm.confidence || threat.confidence || 0;
          } else if (summarySource) {
            threat.userSummary = summarySource;
          } else {
            threat.userSummary = 'This page contains content that may try to steal data or run harmful code. We recommend leaving the site.';
          }
        }
      } catch (e) {
        threat.userSummary = threat.evidenceSummary || threat.detectedContent || 'Potentially harmful content detected';
      }

      try {
        const latest = Object.assign({}, threat, { page: this.currentUrl });
        try {
          sendMessageSafe({ action: 'GURFTRON_WHOAMI' }, (resp) => {
            try {
              if (resp && resp.tabId) latest.tabId = resp.tabId;
            } catch (e) {}
            chrome.storage.local.set({ latestThreat: latest }, () => {
              // Opening an extension page directly from the page context can
              // result in chrome-extension://invalid in some browsers or
              // be blocked by navigation policies. Instead, ask the
              // background script to open the results tab which is a
              // reliable and allowed operation for extensions.
              try {
                sendMessageSafe({ action: 'open_results_tab' });
              } catch (rErr) {
                // Could not ask background to open results tab. We avoid
                // navigating directly to an extension URL from page context
                // to prevent chrome-extension://invalid redirects.
                try { console.warn('open_results_tab message failed'); } catch (_) {}
              }
            });
          });
        } catch (e) {
          try{ chrome.storage.local.set({ latestThreat: latest }); } catch (_) {}
          // Use background to open the results page to avoid navigation
          // issues when setting the top window location to an extension URL.
          try {
            sendMessageSafe({ action: 'open_results_tab' });
          } catch (rErr) {
            try { console.warn('open_results_tab message failed'); } catch (_) {}
          }
        }
      } catch (e2) {
        this.log('error', 'Failed to persist/redirect to results page:', e2 && e2.message);
      }
    } catch (e) {
      this.log('error', 'Failed to show threat modal:', e.message);
    }
  }

  recordThreat(threatJson) {
    this.threatsLog.push(threatJson);
    this.metrics.threatsDetected++;
    this.updateMetrics();
    chrome.storage.local.get('threatsLog', (result) => {
      const log = result.threatsLog || [];
      log.push(threatJson);
      if (log.length > 500) log.shift();
      chrome.storage.local.set({ threatsLog: log });
    });
    this.log('warn', 'Threat detected:', JSON.stringify(threatJson));
    try { sendMessageSafe({ action: 'notify_threat', threat: threatJson }); } catch (e) {}
  }

  registerSignal(source, key, score = 0.5, details = '') {
    try {
      const now = Date.now();
      const bucketKey = `${source}::${key}`;
      const arr = this.signalStore.get(bucketKey) || [];
      arr.push({ score, source, details, ts: now });
      const ttl = this.signalTTL || 60000;
      const pruned = arr.filter(s => (now - s.ts) <= ttl);
      this.signalStore.set(bucketKey, pruned);
      this.log('debug', `Signal registered for ${bucketKey}: count=${pruned.length} score=${score}`);
      this.handleAggregatedSignals(source, key, pruned);
    } catch (e) {
      this.log('error', 'registerSignal failed:', e.message);
    }
  }

  async handleAggregatedSignals(source, key, signals) {
    try {
      if (!signals || signals.length === 0) return;
      const total = signals.reduce((s, v) => s + (v.score || 0), 0);
      const avg = total / signals.length;
      const minSignals = Number(this.minSignals || 1);
      const minAvg = 0.6;
      if (signals.length >= minSignals && avg >= minAvg) {
        this.log('warn', `Aggregated threat for ${key} (source ${source}): signals=${signals.length}, avg=${avg}`);
        const triggeredSignals = signals.map(s => ({ source: s.source, score: s.score, details: s.details }));
        this.log('debug', 'Triggered signals:', JSON.stringify(triggeredSignals));
        const combinedDetails = signals.map(s => `${s.source}: ${s.details}`).join('\n').slice(0, 1000);
        const userSummary = `Triggered by ${signals.length} signal(s): ${signals.map(s => s.source).join(', ')}. ${combinedDetails.slice(0, 200)}`;
        const threat = {
          url: key,
          detectedContent: combinedDetails.slice(0, 500),
          time: new Date().toISOString(),
          severity: avg > 0.8 ? 'high' : 'medium',
          fullContentHash: null,
          filePath: null,
          type: 'aggregated_signal',
          evidenceSummary: `Aggregated ${signals.length} signals, avg confidence ${avg.toFixed(2)}`,
          triggeredSignals,
          userSummary
        };
        this.signalStore.delete(`${source}::${key}`);
        await this.handleThreatFound(threat);
      } else {
        this.log('debug', `Aggregation for ${key} not yet met: ${signals.length} signals, avg=${avg}`);
      }
    } catch (e) {
      this.log('error', 'handleAggregatedSignals failed:', e.message);
    }
  }

  dumpStatus() {
    try {
      const signals = {};
      for (const [k, v] of this.signalStore.entries()) {
        signals[k] = v.map(s => ({ score: s.score, details: s.details ? s.details.slice(0, 200) : '', ts: s.ts }));
      }
      console.groupCollapsed('Gurftron Status Dump');
      console.log('Current URL:', this.currentUrl);
      console.log('Metrics:', this.metrics);
      console.log('Active monitors count:', this.monitors.size);
      console.log('Pending signals:', signals);
      console.groupEnd();
    } catch (e) {
      console.error('Failed to dump status:', e);
    }
  }
}

function getSecureGurftronId(callback) {
  const page = window.location.hostname + window.location.pathname;
  sendMessageSafe({ type: 'GURFTRON_GET_SECURE_ID', page }, (response) => {
    if (response && response.secureId) {
      callback(response.secureId);
    } else {
      callback('gurftron_fallback_' + btoa(page));
    }
  });
}

function injectScript() {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('gurftron.js');
  const injectedId = `gurftron-extension-injected-${window.gurftronPageId || 'unknown'}`;
  script.id = injectedId;
  try {
    sendMessageSafe({ type: 'GURFTRON_GET_INJECT_SIGNATURE', injectedId, secureId: window.gurftronPageId }, (resp) => {
      try {
        if (resp && resp.signature) {
          script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
          script.setAttribute('data-gurftron-sig', resp.signature);
          script.setAttribute('data-gurftron-ts', resp.ts);
        } else {
          script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
        }
      } catch (e) {
        script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
      }
      (document.head || document.documentElement).appendChild(script);
    });
  } catch (e) {
    script.setAttribute('data-gurftron', window.gurftronPageId || 'gurftron_unknown');
    (document.head || document.documentElement).appendChild(script);
  }
}

(function () {
  window.addEventListener('message', async function (event) {
    if (event.source !== window) return;
    const incomingToken = event.data?.pageToken || null;
    if (event.data && event.data.type && event.data.type.startsWith('starknet:')) {
      if (!incomingToken || incomingToken !== window.gurftronPageId) return;
    }

    if (event.data?.type === 'starknet:injected:ready') {
      console.log('[Gurftron] Injected script is ready!');
      checkAndTriggerConnect();
      return;
    }

    if (event.data && event.data.type && event.data.type.startsWith('starknet:')) {
      if (event.data.type !== 'starknet:threatAction') {
        const dataPayload = event.data?.response ?? null;
        if (dataPayload !== null) {
          const dataTransit = dataPayload?.data;
          if (dataTransit !== null && dataTransit !== undefined && dataTransit !== '') {
            const newTypeB = event.data.type.split(':');
            sendMessageSafe({ type: 'processed:' + newTypeB[1], payload: dataPayload }, function (response) {});
          }
        }
      }
    }
  });

  chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    try {
      if (request && request.type === 'CONTENT_SCRIPT_PING') {
        sendResponse({ ready: true });
        return false;
      }

      if (request && request.action === 'download_scan') {
        if (window.gurftronDetector && typeof window.gurftronDetector.onDownloadScan === 'function') {
          window.gurftronDetector.onDownloadScan(request.url, request.filePath).then(threats => sendResponse(threats));
          return true;
        }
        sendResponse(null);
        return false;
      }

      if (request && request.action === 'forward_block') {
        try {
          const traceId = request.payload && request.payload.traceId;
          chrome.storage.local.get('blockTraces', (store) => {
            const arr = Array.isArray(store.blockTraces) ? store.blockTraces : [];
            arr.unshift({ traceId: traceId || null, step: 'content:forward_received', time: Date.now(), payloadMeta: { threatPresent: !!(request.payload && request.payload.threat) } });
            if (arr.length > 500) arr.length = 500;
            chrome.storage.local.set({ blockTraces: arr });
          });
        } catch (e) {}
        window.postMessage({ type: 'starknet:threatAction', action: 'block', payload: request.payload, pageToken: window.gurftronPageId || null }, '*');
        sendResponse({ ok: true });
        return true;
      }

      if (request && request.type === 'starknet:connect') {
        window.postMessage({ type: 'starknet:getWalletStatus', pageToken: window.gurftronPageId || null }, '*');
        const walletStatusListener = (event) => {
          if (event.source !== window) return;
          if (event.data && event.data.type === 'starknet:getWalletStatus:response') {
            window.removeEventListener('message', walletStatusListener);
            const responseData = event.data.response?.data || {};
            sendResponse({
              connected: responseData.connected || false,
              wallet: responseData.wallet || 'none',
              network: responseData.network || null
            });
          }
        };
        window.addEventListener('message', walletStatusListener);
        setTimeout(() => {
          window.removeEventListener('message', walletStatusListener);
          sendResponse({ connected: false, wallet: 'none' });
        }, 2000);
        return true;
      }

      if (request && request.type === 'starknet:verify') {
        window.postMessage({ type: 'starknet:verifyWallet', pageToken: window.gurftronPageId || null }, '*');
        const verifyListener = (event) => {
          if (event.source !== window) return;
          if (event.data && event.data.type === 'starknet:verifyWallet:response') {
            window.removeEventListener('message', verifyListener);
            const responseData = event.data.response?.data || {};
            sendResponse({
              connected: responseData.connected || false,
              wallet: responseData.wallet || 'none',
              verified: responseData.verified || false
            });
          }
        };
        window.addEventListener('message', verifyListener);
        setTimeout(() => {
          window.removeEventListener('message', verifyListener);
          sendResponse({ connected: false, wallet: 'none', verified: false });
        }, 2000);
        return true;
      }

      if (request && request.type === 'STATE_UPDATE') {
        try {
          window.gurftronState = request.state || {};
          console.log('State updated in content script:', window.gurftronState);
        } catch (e) {
          console.error('Error updating state:', e);
        }
        return false;
      }
    } catch (e) {}
    return false;
  });

  getSecureGurftronId(function (gurftronPageId) {
    window.gurftronPageId = gurftronPageId;
    injectScript();
    window.gurftronDetector = new GurftronThreatDetector({ gurftronId: gurftronPageId });
  });

  function checkAndTriggerConnect() {
    chrome.runtime.sendMessage({ type: 'content:pageLoaded' }, function (response) {
      if (chrome.runtime.lastError) {
        console.warn('Error sending page load message:', chrome.runtime.lastError);
      }
      try {
        window.gurftronAccount = response?.result?.wallet || null;
      } catch (e) {
        window.gurftronAccount = null;
      }

      if (!response || response.to !== 'content') return;

      const isLoggedIn = response?.result?.isLoggedIn;
      const hasWallet = response?.result?.wallet;

      if (isLoggedIn !== true) {
        console.log('Gurftron: Not logged in, triggering wallet connection...');
        window.postMessage({ type: 'starknet:connect', payload: { account: hasWallet || null }, pageToken: window.gurftronPageId || null }, '*');
        return;
      }

      if (!hasWallet || hasWallet === 'none') {
        console.log('Gurftron: No wallet found, triggering wallet connection...');
        window.postMessage({ type: 'starknet:connect', payload: { account: hasWallet || null }, pageToken: window.gurftronPageId || null }, '*');
        return;
      }

      console.log('Gurftron: Wallet found in storage:', hasWallet, '- proceeding with monitoring');
      
      if (window.gurftronDetector && typeof window.gurftronDetector.checkThreatInDB === 'function') {
        window.gurftronDetector.checkThreatInDB(window.location.href).then(async (threat) => {
          if (threat) {
            await window.gurftronDetector.handleThreatFound(threat);
            return;
          }
          // Start monitoring first
          window.gurftronDetector.startMonitoring();
          
          // Then immediately run full scan to detect phishing
          try {
            const scanResults = await window.gurftronDetector.fullScan();
            if (scanResults && scanResults.length > 0) {
              const hasThreat = scanResults.some(r => r.isThreat || r.isPhishing);
              if (hasThreat) {
                console.log('Gurftron: Threat detected on initial scan');
              }
            }
          } catch (scanErr) {
            console.warn('Initial fullScan failed:', scanErr);
          }
        }).catch(err => {
          console.warn('Error checking DB for threats:', err);
          try { 
            window.gurftronDetector.startMonitoring();
            // Try to run scan even if DB check failed
            window.gurftronDetector.fullScan().catch(e => console.warn('fullScan failed:', e));
          } catch (e) { 
            console.warn('startMonitoring failed:', e); 
          }
        });
      }
    });
  }
})();