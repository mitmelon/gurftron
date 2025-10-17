import { StarknetManager } from './starknet.js';
import { SmartContractWriter } from './contract-writer.js';
import { shortString } from 'starknet';
import { LZString } from 'lz-string';

const gToast = new CustomToast();

(async function(){
  function el(id){return document.getElementById(id)}
  const setText=(id,t)=>{const e=el(id); if(e) e.textContent=t}
  function genId(){return 'trace_' + Math.random().toString(36).slice(2) + Date.now().toString(36)}
  try{
    const s = await new Promise(res=>chrome.storage.local.get('latestThreat', res));
    const threat = s && s.latestThreat;
    if(!threat){ setText('headline','No threat information available'); setText('summary','No data found.'); setText('details',''); return; }
    setText('headline', threat.title || 'Threat detected — take action');
    setText('summary', threat.userSummary || threat.evidenceSummary || threat.detectedContent || 'This page was flagged by Gurftron.');
    setText('details', (threat.details || threat.evidenceSummary || threat.detectedContent || JSON.stringify(threat, null, 2)));
    // Populate page domain and detection source
    try {
      const extractDomain = (u) => {
        try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) {
          if (!u) return '';
          return (u + '').replace(/^https?:\/\/(www\.)?/, '').split('/')[0];
        }
      };
      const rawUrl = threat.domain || threat.page || threat.url || '';
      const domain = rawUrl ? extractDomain(rawUrl) : '';

      // Build a user-friendly detected source label
      const sourceFromSignals = (threat.triggeredSignals && Array.isArray(threat.triggeredSignals)) ? threat.triggeredSignals.map(s => s.source).filter(Boolean) : [];
      const rawSource = threat.source || threat.detectedBy || (sourceFromSignals.length ? sourceFromSignals.join(',') : (threat.detectedSource || 'gurftron'));

      const SOURCE_PRETTY = {
        'google_safe_browsing': 'Google Safe Browsing',
        'brave_search_llm_analysis': 'Brave Deep Search',
        'llm_reasoning': 'LLM Reasoning',
        'llm_network_script': 'LLM Network Script Analysis',
        'llm_noisy_trackers': 'Tracker Heuristics',
        'domain_llm_analysis': 'Domain LLM Analysis',
        'content.js': 'Content Script',
        'gurftron': 'Gurftron Detector'
      };

      const prettyFromKey = (k) => {
        if (!k) return '';
        // If multiple keys comma-separated, map each
        return k.split(',').map(x => SOURCE_PRETTY[x] || // common mapping
          // fallback: prettify snake_case or dotted keys
          x.replace(/[_\.]/g, ' ').replace(/(^|\s)\S/g, s => s.toUpperCase())
        ).join(', ');
      };

      const prettySource = prettyFromKey(rawSource);

      // Set page link and domain text
      const pageLinkEl = document.getElementById('pageLink');
      const pageDomainEl = document.getElementById('pageDomain');
      if (pageDomainEl) pageDomainEl.textContent = domain || rawUrl || 'Unknown';
      if (pageLinkEl) {
        try {
          pageLinkEl.href = rawUrl || '#';
        } catch (e) {
          pageLinkEl.href = '#';
        }

        // When clicked, attempt to focus the original tab (if we have a tabId)
        pageLinkEl.addEventListener('click', (ev) => {
          try {
            ev.preventDefault();
            const targetUrl = rawUrl || threat.url || pageLinkEl.href || '';
            if (threat && typeof threat.tabId === 'number') {
              try {
                chrome.runtime.sendMessage({ action: 'focus_tab', tabId: threat.tabId }, (resp) => {
                  try {
                    if (!resp || !resp.ok) {
                      // Fallback: open in new tab
                      try { window.open(targetUrl || '_blank'); } catch (e) {}
                    }
                  } catch (e) {
                    try { window.open(targetUrl || '_blank'); } catch (err) {}
                  }
                });
                return;
              } catch (e) {
                // continue to fallback below
              }
            }
            try { window.open(targetUrl || '_blank'); } catch (e) {}
          } catch (e) { /* ignore click errors */ }
        });
      }

      // Set detected source text and tooltip
      setText('detectedSource', prettySource || 'Gurftron Detector');
      const srcIcon = document.getElementById('detectedSourceIcon');
      if (srcIcon) {
        const tooltipParts = [];
        tooltipParts.push('Detected sources:');
        // list normalized sources (raw and pretty)
        tooltipParts.push(`Raw: ${rawSource}`);
        tooltipParts.push(`Pretty: ${prettySource}`);
        srcIcon.title = tooltipParts.join('\n');
      }
    } catch (e) {
      // ignore UI population errors
    }

    try {
      if (threat && threat.id) {
        const stark = new StarknetManager('testnet');
        try {
          const onChain = await stark.getThreatById('threats', threat.id);
          if (onChain && onChain.id) {
            threat.alreadyRegistered = true;
          }
        } catch (chainErr) {
          console.error('Chain lookup failed (results page):', chainErr);
          try { gToast.warning('Chain lookup failed (results page): ' + (chainErr && chainErr.message)); } catch (_) {}
        }
      }
    } catch (e) {
      gToast.warning('Pre-check exception in results: ' + (e && e.message));
    }

    el('continueBtn')?.addEventListener('click', ()=>{
      try {
        try { chrome.runtime.sendMessage({ action: 'STOP_MONITORING' }); } catch(e){}
        if (threat && threat.url) {
          window.location.href = threat.url;
        } else if (history.length > 1) {
          history.back();
        } else {
          window.close();
        }
      } catch (e) {
        gToast.warning('Continue action failed: ' + (e && e.message ? e.message : e));
      }
    });
    if (threat.alreadyRegistered) {
      const btn = el('blockBtn'); if (btn) btn.style.display = 'none';
      // show a small paragraph below the details if element exists
      if (el('alreadyRegisteredNote')) {
        setText('alreadyRegisteredNote', 'This threat is already registered on-chain; blocking is not required.');
        el('alreadyRegisteredNote').style.display = 'block';
      } else {
        // fallback to statusMessage
        setText('statusMessage', 'This threat was already reported by another user; on-chain blocking is not required.');
      }
    }

    el('blockBtn')?.addEventListener('click', async ()=>{
      try {
        const btn = el('blockBtn');
        if (btn) {
          btn.disabled = true;
          btn.textContent = 'Submitting...';
        }

        if (el('blockStatus')) el('blockStatus').style.display = 'block';
        setText('statusMessage', 'Preparing on-chain submission...');

        const walletResp = await new Promise(r => chrome.runtime.sendMessage({ type: 'content:pageLoaded' }, r));
        const walletAddress = (walletResp && (walletResp.result || walletResp.data) && (walletResp.result?.wallet || walletResp.data?.wallet)) || null;
        if (!walletAddress || walletAddress === 'none') {
          gToast.error('No wallet connected. Please open the extension and connect your wallet before submitting a threat report.');
          try { window.location.href = 'login.html'; } catch(_){ }
          return;
        }
        try {
          // Prepare threat data for Cairo ByteArray format
          const threatData = {
            id: threat.id,
            url: threat.url,
            title: threat.title,
            userSummary: threat.userSummary,
            evidenceSummary: threat.evidenceSummary,
            fullContentHash: threat.fullContentHash,
            confidence: threat.confidence,
            reportedAt: Date.now()
          };
          
          // Compress data using LZString
          const compressed = LZString.compressToUTF16(JSON.stringify(threatData));
          
          // Check compressed data size (100KB limit)
          const compressedSizeBytes = compressed.length * 2; // UTF-16 = 2 bytes per char
          const maxSizeBytes = 1000 * 1024; // 100KB
          if (compressedSizeBytes > maxSizeBytes) {
            gToast.error(`Threat data too large (${(compressedSizeBytes / 1024).toFixed(2)}KB). Maximum allowed: 100KB. Please reduce content.`);
            setText('statusMessage', `Compressed data too large: ${(compressedSizeBytes / 1024).toFixed(2)}KB (max: 100KB)`);
            const btn = el('blockBtn');
            if (btn) {
              btn.disabled = false;
              btn.textContent = 'Block & Report This Threat';
            }
            return;
          }
          
          const fields = [
            [shortString.encodeShortString('threatId'), shortString.encodeShortString(threat.id)],
            [shortString.encodeShortString('threatType'), shortString.encodeShortString(threat.threatResults?.threatType || 'unknown')],
            [shortString.encodeShortString('severity'), shortString.encodeShortString(threat.threatResults?.severity || 'low')],
            [shortString.encodeShortString('confidence'), shortString.encodeShortString(String(threat.confidence || 0))],
            [shortString.encodeShortString('url'), shortString.encodeShortString(threat.url)],
            [shortString.encodeShortString('contentHash'), shortString.encodeShortString(threat.fullContentHash || '')]
          ];

          const writer = new SmartContractWriter('threat_insert_' + threat.id, 'threats');
          
          await writer.execute(
            'insert',          
            {                   
              collection: 'threats',
              compressed_data: compressed,
              fields: fields
            },
            {                   
              id: threat.id,
              url: threat.url,
              title: threat.title,
              userSummary: threat.userSummary,
              evidenceSummary: threat.evidenceSummary,
              detectedContent: threat.detectedContent,
              threatResults: threat.threatResults,
              fullContentHash: threat.fullContentHash,
              confidence: threat.confidence,
              reportedBy: walletAddress,
              reportedAt: Date.now(),
              validationStatus: 'pending',
              alreadyRegistered: true
            },
            threat.id,          // Storage key
            walletAddress,      // Wallet address
            (result) => {       // Success callback
              console.log('Threat inserted to blockchain successfully:', result);
              gToast.success(`Threat registered on-chain! TX Hash: ${result.transactionHash}`);
              gToast.info('Note: Your threat report is pending community approval.');
              
              // Display transaction hash
              if (el('txInfo')) el('txInfo').style.display = 'block';
              if (el('txHash')) setText('txHash', result.transactionHash || '');
              setText('statusMessage', 'Threat submitted to blockchain! Awaiting community approval...');
              
              // Update stored threat with blockchain data
              chrome.storage.local.get('latestThreat', (store) => {
                const updated = { 
                  ...store.latestThreat, 
                  transactionHash: result.transactionHash,
                  documentId: result.transactionHash,
                  requestId: result.requestId,
                  validationStatus: 'pending',  // Starts as pending in Cairo
                  alreadyRegistered: true 
                };
                chrome.storage.local.set({ latestThreat: updated });
              });
              
              if (btn) {
                btn.style.display = 'none';
              }
              if (el('alreadyRegisteredNote')) {
                setText('alreadyRegisteredNote', 
                  'Threat report submitted successfully to blockchain! Document ID: ' + 
                  (result.documentId || result.id) + '. Status: Pending community approval.');
                el('alreadyRegisteredNote').style.display = 'block';
              }
              
              // Navigate to dashboard after short delay
              setTimeout(() => {
                window.location.href = 'dashboard.html';
              }, 3000);
            },
            (error) => {        // Error callback
              console.error('Threat insertion to blockchain error:', error);
              
              // Handle common Cairo contract errors
              if (error.message && error.message.includes('not registered')) {
                gToast.error('You must register your account on the blockchain first. Redirecting to dashboard...');
                setTimeout(() => window.location.href = 'dashboard.html', 2000);
              } else if (error.message && error.message.includes('stake')) {
                gToast.error('You must stake STRK tokens before submitting threat reports. Please stake in dashboard.');
                setTimeout(() => window.location.href = 'dashboard.html', 2000);
              } else if (error.message && error.message.includes('reputation')) {
                gToast.error('Insufficient reputation score to submit reports. Improve your reputation first.');
              } else if (error.message && error.message.includes('cooldown')) {
                gToast.error('Cooldown period active. Please wait before submitting another report.');
              } else if (error.message && error.message.includes('rate limit')) {
                gToast.error('Rate limit exceeded. You have submitted too many reports recently.');
              } else {
                gToast.error('Blockchain submission failed: ' + error.message);
              }
              
              setText('statusMessage', 'Failed to submit to blockchain: ' + error.message);
              
              // Re-enable block button for retry
              if (btn) {
                btn.disabled = false;
                btn.textContent = 'Retry Blockchain Submission';
                btn.classList.add('retry-button');
              }
            }
          );
        } catch (writerErr) {
          console.error('SmartContractWriter error:', writerErr);
          gToast.error('Failed to prepare submission: ' + (writerErr && writerErr.message));
          setText('statusMessage', 'Failed to prepare on-chain submission: ' + (writerErr && writerErr.message));
          
          // Re-enable button
          const btn = el('blockBtn');
          if (btn) {
            btn.disabled = false;
            btn.textContent = 'Try Again';
          }
        }

      } catch (e) {
        console.error('Block button error:', e);
        gToast.error('Failed to submit threat: ' + (e && e.message));
        
        // Re-enable button
        const btn = el('blockBtn');
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Try Again';
        }
      }
    });

  }catch(e){
    setText('headline','Failed to load threat');
    setText('summary', e && e.message);
  }
})();
