import { StarknetManager } from './starknet.js';
import { SmartContractWriter } from './contract-writer.js';

const pageLoader = new PageLoader({
    timeout: 15000,
    executeScripts: true,
    loadStyles: true,
    sanitize: false
});
const ajax = new AjaxHandler();
const gToast = new CustomToast();
const router = new SimpleRoute();
const starknetManager = new StarknetManager('testnet');
let walletAddress = null;

const STATS_CACHE_KEY = 'gurftron_user_stats';
const STATS_HISTORY_KEY = 'gurftron_user_stats_history';
const STATS_CACHE_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

function saveStatsToHistory(stats) {
    try {
        const history = JSON.parse(localStorage.getItem(STATS_HISTORY_KEY) || '[]');

        history.push({
            stats,
            timestamp: Date.now()
        });

        // Keep only last 7 days of hourly data (168 entries max)
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        const filteredHistory = history.filter(entry => entry.timestamp > oneWeekAgo);

        // Keep max 200 entries to prevent localStorage bloat
        if (filteredHistory.length > 200) {
            filteredHistory.splice(0, filteredHistory.length - 200);
        }

        localStorage.setItem(STATS_HISTORY_KEY, JSON.stringify(filteredHistory));
    } catch (error) {
        console.warn('Failed to save stats history:', error);
    }
}

function getStatsFromOneHourAgo() {
    try {
        const history = JSON.parse(localStorage.getItem(STATS_HISTORY_KEY) || '[]');
        if (history.length === 0) return null;

        const oneHourAgo = Date.now() - STATS_CACHE_DURATION;

        // Find the closest entry to 1 hour ago
        let closest = null;
        let minDiff = Infinity;

        for (const entry of history) {
            const diff = Math.abs(entry.timestamp - oneHourAgo);
            if (diff < minDiff) {
                minDiff = diff;
                closest = entry;
            }
        }

        if (closest && minDiff < (30 * 60 * 1000)) {
            return closest.stats;
        }

        return null;
    } catch (error) {
        console.warn('Failed to get historical stats:', error);
        return null;
    }
}

function calculateTrend(currentValue, previousValue) {
    if (!previousValue || previousValue === 0) {
        return {
            percentage: 0,
            direction: 'neutral',
            arrow: '→',
            color: 'text-gray-500'
        };
    }

    const change = currentValue - previousValue;
    const percentage = ((change / previousValue) * 100).toFixed(1);

    let direction, arrow, color;

    if (change > 0) {
        direction = 'up';
        arrow = '↗';
        color = 'text-green-600';
    } else if (change < 0) {
        direction = 'down';
        arrow = '↓';
        color = 'text-red-600';
    } else {
        direction = 'neutral';
        arrow = '→';
        color = 'text-gray-500';
    }

    return {
        percentage: Math.abs(percentage),
        direction,
        arrow,
        color
    };
}

async function getUserStatistics() {
    try {
        const cachedData = localStorage.getItem(STATS_CACHE_KEY);
        if (cachedData) {
            const { stats, timestamp } = JSON.parse(cachedData);
            const now = Date.now();
            if (now - timestamp < STATS_CACHE_DURATION) {
                console.log('Using cached user statistics');
                return stats;
            }
        }
        console.log('Fetching user statistics from contract...');
        const stats = await starknetManager.getUserStatistics(walletAddress);
        console.log(stats);
        saveStatsToHistory(stats);

        localStorage.setItem(STATS_CACHE_KEY, JSON.stringify({
            stats,
            timestamp: Date.now()
        }));

        console.log('User statistics fetched and cached:', stats);
        return stats;

    } catch (error) {
        console.error('Failed to get user statistics:', error);
        gToast.error('Failed to load statistics: ' + error.message);

        // Return default values on error
        return {
            totalThreatBlocked: 0,
            activeThreat: 0,
            whitelist: 0
        };
    }
}

async function updateDashboardStats() {
    try {
        const currentStats = await getUserStatistics();
        const previousStats = getStatsFromOneHourAgo();

        const threatsBlockedTrend = calculateTrend(
            currentStats.totalThreatBlocked,
            previousStats?.totalThreatBlocked
        );

        const activeThreatsChange = calculateTrend(
            currentStats.activeThreat,
            previousStats?.activeThreat
        );

        const whitelistTrend = calculateTrend(
            currentStats.whitelist,
            previousStats?.whitelist
        );

        const threatsBlockedElement = document.querySelector('[data-stat="threats-blocked"]');
        if (threatsBlockedElement) {
            threatsBlockedElement.textContent = currentStats.totalThreatBlocked.toLocaleString();
        }

        const threatsBlockedTrendElement = document.querySelector('[data-trend="threats-blocked"]');
        if (threatsBlockedTrendElement) {
            threatsBlockedTrendElement.className = `${threatsBlockedTrend.color} text-sm font-medium`;
            threatsBlockedTrendElement.textContent = `${threatsBlockedTrend.arrow} ${threatsBlockedTrend.percentage}%`;
        }

        // Update Active Threats card
        const activeThreatsElement = document.querySelector('[data-stat="active-threats"]');
        if (activeThreatsElement) {
            activeThreatsElement.textContent = currentStats.activeThreat.toLocaleString();
        }
        const activeThreatsColor = activeThreatsChange.direction === 'up' ? 'text-red-600' :
            activeThreatsChange.direction === 'down' ? 'text-green-600' :
                'text-gray-500';

        const activeThreatsTrendElement = document.querySelector('[data-trend="active-threats"]');
        if (activeThreatsTrendElement) {
            activeThreatsTrendElement.className = `${activeThreatsColor} text-sm font-medium`;
            activeThreatsTrendElement.textContent = `${activeThreatsChange.arrow} ${activeThreatsChange.percentage}%`;
        }

        // Update the badge in sidebar
        const threatBadge = document.querySelector('.menu-item .bg-red-500');
        if (threatBadge) {
            threatBadge.textContent = currentStats.activeThreat;
        }

        // Update Whitelisted Sites card
        const whitelistElement = document.querySelector('[data-stat="whitelist"]');
        if (whitelistElement) {
            whitelistElement.textContent = currentStats.whitelist.toLocaleString();
        }

        const whitelistTrendElement = document.querySelector('[data-trend="whitelist"]');
        if (whitelistTrendElement) {
            whitelistTrendElement.className = `${whitelistTrend.color} text-sm font-medium`;
            whitelistTrendElement.textContent = `${whitelistTrend.arrow} ${whitelistTrend.percentage}%`;
        }

        console.log('Dashboard statistics updated successfully with trends');

    } catch (error) {
        console.error('Failed to update dashboard stats:', error);
    }
}
async function updateScansTodayCard() {
    try {
        // Request today's metrics from background
        const resp = await new Promise((resolve) => {
            try {
                chrome.runtime.sendMessage({ action: 'get_metrics' }, (r) => resolve(r));
            } catch (e) { resolve(null); }
        });

        const metrics = resp && resp.success && resp.metrics ? resp.metrics : { scans: 0, threatsDetected: 0, llmCalls: 0 };

        const scansCardValue = document.querySelector('.card p.text-3xl.font-bold.text-gray-900');
        let scansElement = null;
        document.querySelectorAll('.card').forEach(card => {
            const label = card.querySelector('p.text-sm.text-gray-600.mb-1');
            if (label && label.textContent && label.textContent.trim() === 'Scans Today') {
                scansElement = card.querySelector('p.text-3xl.font-bold.text-gray-900');
            }
        });

        if (scansElement) {
            scansElement.textContent = (metrics.scans || 0).toLocaleString();
        } else if (scansCardValue) {
            scansCardValue.textContent = (metrics.scans || 0).toLocaleString();
        }

        const yesterdayKey = (() => {
            const d = new Date();
            d.setDate(d.getDate() - 1);
            return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
        })();

        const respYesterday = await new Promise((resolve) => {
            try {
                chrome.runtime.sendMessage({ action: 'get_metrics', date: yesterdayKey }, (r) => resolve(r));
            } catch (e) { resolve(null); }
        });

        const yMetrics = respYesterday && respYesterday.success && respYesterday.metrics ? respYesterday.metrics : null;

        if (scansElement) {
            const trendSpan = scansElement.parentElement.querySelector('.flex.items-center.mt-2 span.text-sm.font-medium') || scansElement.parentElement.querySelector('span.text-green-600.text-sm.font-medium');
            if (trendSpan) {
                const previous = yMetrics ? (yMetrics.scans || 0) : 0;
                const current = metrics.scans || 0;
                let percent = 0;
                let arrow = '→';
                let colorClass = 'text-gray-500';
                if (previous > 0) {
                    const change = current - previous;
                    percent = Math.abs(((change / previous) * 100) || 0).toFixed(1);
                    if (change > 0) { arrow = '↗'; colorClass = 'text-green-600'; }
                    else if (change < 0) { arrow = '↓'; colorClass = 'text-red-600'; }
                }
                trendSpan.className = `${colorClass} text-sm font-medium`;
                trendSpan.textContent = `${arrow} ${percent}%`;
            }
        }

    } catch (e) {
        console.warn('Failed to update Scans Today card:', e && e.message);
    }
}

(async function checkWalletConnection() {
    try {
        
        const response = await chrome.runtime.sendMessage({
            type: 'content:pageLoaded'
        });

        console.log(response);
        const walletData = response?.result || response?.data;
        const isLoggedIn = walletData?.isLoggedIn || false;
        const hasWallet = walletData?.wallet && walletData?.wallet !== 'none';

        if (!isLoggedIn || !hasWallet) {
            console.log('No wallet connected, redirecting to login page...');
            window.location.href = 'login.html';
            return;
        }
        walletAddress = walletData.wallet;
        const stats = await starknetManager.getUserStatistics(walletData.wallet || walletAddress);
            console.log(stats);

        console.log('Wallet connected:', walletData.wallet);
        walletAddress = walletData.wallet;
        const checkResponse = await chrome.runtime.sendMessage({
            type: 'CHECK_USER_IN_INDEXDB',
            walletAddress: walletAddress
        });

        if (checkResponse && checkResponse.success && checkResponse.found) {
            return walletAddress;
        }
        const isRegisteredOnChain = await starknetManager.is_account_registered(walletAddress);

        if (isRegisteredOnChain) {
            await chrome.runtime.sendMessage({
                type: 'SAVE_USER_TO_INDEXDB',
                walletAddress: walletAddress,
                registrationTx: 'existing',
                account: walletAddress
            });
        }
        const writer = new SmartContractWriter('user_not_in_smart_contract', 'users');
        console.info('Registering your account on blockchain...');

        try {
            const response = await writer.execute(
                'register_account',
                [],
                {
                    walletAddress: walletAddress,
                    isRegistered: true,
                    registeredAt: Date.now()
                },
                walletAddress,
                walletAddress,
                (result) => {
                    console.log('Registration successful:', result);
                    gToast.success(`Account registered successfully! TX Hash: ${result.transactionHash}`);
                    
                    // Save to IndexedDB via background
                    chrome.runtime.sendMessage({
                        type: 'SAVE_USER_TO_INDEXDB',
                        walletAddress: walletAddress,
                        registrationTx: result.transactionHash,
                        account: walletAddress
                    });
                },
                (error) => {
                    console.error('Registration error:', error);
                    gToast.error('Registration failed: ' + error.message);
                }
            );
            
            console.log('Registration response:', response);
            
        } catch (error) {
            console.error('Failed to register account:', error);
            gToast.error('Unable to register account: ' + error.message);
        }

    } catch (error) {
        gToast.error('Error checking wallet connection: ' + error.message);
    } finally {
        await updateDashboardStats();
        await updatePointsCard();
        await updateStakeCard();
    }
})();

// Sidebar toggle functionality
const sidebar = document.getElementById('sidebar');
const mainContent = document.getElementById('main-content');
const sidebarToggle = document.getElementById('sidebar-toggle');
const logoText = document.getElementById('logo-text');
const menuTexts = document.querySelectorAll('.menu-text');
const aiStatusText = document.getElementById('ai-status-text');

let isCollapsed = false;

// Use class toggling so Tailwind / CSS rules can control the collapsed behavior
sidebarToggle.addEventListener('click', () => {
    isCollapsed = !isCollapsed;
    if (isCollapsed) {
        sidebar.classList.add('collapsed');
        mainContent.classList.add('collapsed');
    } else {
        sidebar.classList.remove('collapsed');
        mainContent.classList.remove('collapsed');
    }
});

const menuItems = document.querySelectorAll('.menu-item');
menuItems.forEach(item => {
    item.addEventListener('click', (e) => {
        try { e.preventDefault(); } catch (ignore) {}

        menuItems.forEach(menuItem => menuItem.classList.remove('active'));
        item.classList.add('active');
        try {
            const hrefAttr = item.getAttribute('href') || item.dataset.href;
            if (hrefAttr && hrefAttr !== '#' && hrefAttr.trim() !== '') {
                let target = hrefAttr.trim();
                if (!/^https?:\/\//i.test(target) && !target.startsWith('#') && !/\.html$/i.test(target)) {
                    if (!target.endsWith('/')) target = `${target}.html`;
                }
                window.location.href = target;
            }
        } catch (err) {
            console.warn('Navigation failed for menu item', err && err.message);
        }
    });
});
window.addEventListener('load', () => {
    updateDashboardStats();
    updateScansTodayCard();
    initLinks();
    initModalButtons();
    setTimeout(() => fetchAndRenderRecentThreats(), 500);
    updateSecuritySetupStatus();
    try { wireSettingsForms && wireSettingsForms(); } catch (e) {}
});
function wireSettingsForms() {
    try {
        const readStorage = (keys) => new Promise((resolve) => {
            try { chrome.storage.sync.get(keys, (r) => resolve(r)); } catch (e) {
                const out = {};
                for (const k of keys) out[k] = localStorage.getItem(k) || '';
                resolve(out);
            }
        });

        const writeStorage = (obj) => new Promise((resolve, reject) => {
            try { chrome.storage.sync.set(obj, () => resolve(true)); } catch (e) {
                try { for (const k of Object.keys(obj)) localStorage.setItem(k, obj[k]); resolve(true); } catch (err) { reject(err); }
            }
        });

        const showStatus = (id, msg, ok) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = msg;
            el.style.color = ok ? '#10b981' : '#ef4444';
            setTimeout(() => { el.textContent = ''; }, 2500);
        };

        // load existing values into inputs
        readStorage(['geminiApiKey', 'llmType', 'serverUrl', 'serverKey', 'braveSearchKey', 'googleSafeBrowsingKey', 'abuseIpDbKey']).then(cfg => {
            if (document.getElementById('geminiApiKey')) document.getElementById('geminiApiKey').value = cfg.geminiApiKey || '';
            if (document.getElementById('llmType')) document.getElementById('llmType').value = cfg.llmType || '';
            if (document.getElementById('serverUrl')) document.getElementById('serverUrl').value = cfg.serverUrl || '';
            if (document.getElementById('serverKey')) document.getElementById('serverKey').value = cfg.serverKey || '';
            if (document.getElementById('braveSearchKey')) document.getElementById('braveSearchKey').value = cfg.braveSearchKey || '';
            if (document.getElementById('googleSafeBrowsingKey')) document.getElementById('googleSafeBrowsingKey').value = cfg.googleSafeBrowsingKey || '';
            if (document.getElementById('abuseIpDbKey')) document.getElementById('abuseIpDbKey').value = cfg.abuseIpDbKey || '';
        }).catch(() => {});

        const bind = (formId, inputId, key, statusId) => {
            const form = document.getElementById(formId);
            if (!form) return;
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const val = (document.getElementById(inputId).value || '').trim();
                try { await writeStorage({ [key]: val }); showStatus(statusId, 'Saved', true); }
                catch (err) { showStatus(statusId, 'Save failed', false); }
                // refresh security status for immediate feedback
                try { updateSecuritySetupStatus(); } catch (ignore) {}
            });
        };

        bind('form-gemini', 'geminiApiKey', 'geminiApiKey', 'status-gemini');
        bind('form-llm', 'llmType', 'llmType', 'status-llm');
        bind('form-serverurl', 'serverUrl', 'serverUrl', 'status-server');
        bind('form-serverkey', 'serverKey', 'serverKey', 'status-serverkey');
        bind('form-brave', 'braveSearchKey', 'braveSearchKey', 'status-brave');
        bind('form-googlesafe', 'googleSafeBrowsingKey', 'googleSafeBrowsingKey', 'status-googlesafe');
        bind('form-abuseip', 'abuseIpDbKey', 'abuseIpDbKey', 'status-abuseip');
    } catch (e) { console.warn('wireSettingsForms failed', e && e.message); }
}

function initLinks() {
    const claimLink = document.getElementById('claim-points-link');
    if (claimLink) {
        claimLink.addEventListener('click', (e) => {
            e.preventDefault();
            const disabled = claimLink.getAttribute('aria-disabled') === 'true';
            if (disabled) {
                gToast.info('No points available to claim');
                return false;
            }
            const modal = document.getElementById('claimModal');
            if (modal) modal.classList.add('active');
            return false;
        });
    }

    const withdrawLink = document.getElementById('withdraw-stakes-link');
    if (withdrawLink) {
        withdrawLink.addEventListener('click', (e) => {
            e.preventDefault();
            const disabled = withdrawLink.getAttribute('aria-disabled') === 'true';
            if (disabled) {
                gToast.info('Stake is locked');
                return false;
            }
            const modal = document.getElementById('withdrawModal');
            if (modal) modal.classList.add('active');
            return false;
        });
    }
}

function openClaimModal() {
    const m = document.getElementById('claimModal'); if (m) m.classList.add('active');
}

function closeClaimModal() {
    document.getElementById('claimModal').classList.remove('active');
}

function openWithdrawModal() {
    const m = document.getElementById('withdrawModal'); if (m) m.classList.add('active');
}

function closeWithdrawModal() {
    document.getElementById('withdrawModal').classList.remove('active');
}

function confirmClaim() {
    (async () => {
        try {
            const res = await starknetManager.claimRewards();
            gToast.success('Claim submitted. TX: ' + (res && res.transactionHash ? res.transactionHash : 'submitted'));
        } catch (e) {
            gToast.error('Claim failed: ' + (e && e.message));
        }
        closeClaimModal();
    })();
}

function confirmWithdraw() {
    (async () => {
        try {
            const res = await starknetManager.withdrawStake();
            gToast.success('Withdraw submitted. TX: ' + (res && res.transactionHash ? res.transactionHash : 'submitted'));
        } catch (e) {
            gToast.error('Withdraw failed: ' + (e && e.message));
        }
        closeWithdrawModal();
    })();
}

function initModalButtons() {
    const claimClose = document.getElementById('claim-close-btn');
    const claimCancel = document.getElementById('claim-cancel-btn');
    const claimConfirm = document.getElementById('claim-confirm-btn');
    if (claimClose) claimClose.addEventListener('click', closeClaimModal);
    if (claimCancel) claimCancel.addEventListener('click', closeClaimModal);
    if (claimConfirm) claimConfirm.addEventListener('click', confirmClaim);

    const withdrawClose = document.getElementById('withdraw-close-btn');
    const withdrawCancel = document.getElementById('withdraw-cancel-btn');
    const withdrawConfirm = document.getElementById('withdraw-confirm-btn');
    if (withdrawClose) withdrawClose.addEventListener('click', closeWithdrawModal);
    if (withdrawCancel) withdrawCancel.addEventListener('click', closeWithdrawModal);
    if (withdrawConfirm) withdrawConfirm.addEventListener('click', confirmWithdraw);
}

function formatTokenAmount(amountStr, decimals = 18, displayDecimals = 4) {
    try {
        if (!amountStr || amountStr === '0') return '0';
        let bn = BigInt(amountStr.toString());
        const base = 10n ** BigInt(decimals);
        const whole = bn / base;
        const rem = bn % base;
        if (rem === 0n) return whole.toString();
        const frac = Number((rem * (10n ** BigInt(displayDecimals))) / base);
        let fracStr = String(frac).padStart(displayDecimals, '0');
        fracStr = fracStr.replace(/0+$/, '');
        return `${whole.toString()}.${fracStr}`;
    } catch (e) {
        return String(amountStr);
    }
}


function timeRemainingText(unlockTime) {
    try {
        if (!unlockTime) return '';
        // unlockTime may be seconds or milliseconds
        let ms = Number(unlockTime);
        if (ms < 1e12) ms = ms * 1000; // convert seconds->ms when necessary
        const now = Date.now();
        const diff = ms - now;
        if (diff <= 0) return 'Unlocked';
        const minutes = Math.floor(diff / (60 * 1000));
        if (minutes < 60) return `${minutes}m`; 
        const hours = Math.floor(minutes / 60);
        if (hours < 48) return `${hours}h`;
        const days = Math.floor(hours / 24);
        return `${days}d`;
    } catch (e) {
        return '';
    }
}

async function updatePointsCard() {
    try {
        const wallet = walletAddress || starknetManager.getWalletAddress?.();
        if (!wallet) {
            return;
        }

        const points = await starknetManager.getPoints(wallet);
        let pointsElement = null;
        document.querySelectorAll('.card').forEach(card => {
            const label = card.querySelector('p.text-sm.text-gray-600.mb-1');
            if (label && label.textContent && label.textContent.trim() === 'Point Balance') {
                pointsElement = card.querySelector('p.text-4xl.font-bold');
            }
        });

        if (pointsElement) {
            pointsElement.textContent = Number(points).toLocaleString();
        }

        // Update claim modal amount display
        const claimAmountEl = document.getElementById('claim-points-amount');
        if (claimAmountEl) claimAmountEl.textContent = Number(points || 0).toLocaleString();

        document.querySelectorAll('.card').forEach(card => {
            const label = card.querySelector('p.text-sm.text-gray-600.mb-1');
            if (label && label.textContent && label.textContent.trim() === 'Point Balance') {
                const link = card.querySelector('a[href][onclick*="openClaimModal"]');
                if (link) {
                    if ((points || 0) > 0) {
                        link.classList.remove('opacity-50', 'pointer-events-none');
                        link.setAttribute('aria-disabled', 'false');
                    } else {
                        link.classList.add('opacity-50', 'pointer-events-none');
                        link.setAttribute('aria-disabled', 'true');
                    }
                }
            }
        });

    } catch (e) {
        console.warn('Failed to update points card:', e && e.message);
    }
}

async function updateStakeCard() {
    try {
        const wallet = walletAddress || starknetManager.getWalletAddress?.();
        if (!wallet) return;

        const stake = await starknetManager.getStakeInfo(wallet);
        if (!stake) return;

        const amountDisplay = (() => {
            try {
                if (/^\d+$/.test(String(stake.amount))) {
                    const human = formatTokenAmount(stake.amount, 18, 4);
                    return `${human} STRKS`;
                }
                return String(stake.amount);
            } catch (e) { return String(stake.amount); }
        })();

        // Find Active Stakes card value
        let stakeElement = null;
        document.querySelectorAll('.card').forEach(card => {
            const label = card.querySelector('p.text-sm.text-gray-600.mb-1');
            if (label && label.textContent && label.textContent.trim() === 'Active Stakes') {
                stakeElement = card.querySelector('p.text-4xl.font-bold');
            }
        });

        if (stakeElement) {
            stakeElement.textContent = amountDisplay;
        }

        // Update withdraw modal current stakes display
        const withdrawCurrent = document.getElementById('withdraw-current-stakes');
        if (withdrawCurrent) withdrawCurrent.textContent = amountDisplay;

        const withdrawLink = document.getElementById('withdraw-stakes-link');
        const activeCard = Array.from(document.querySelectorAll('.card')).find(card => {
            const label = card.querySelector('p.text-sm.text-gray-600.mb-1');
            return label && label.textContent && label.textContent.trim() === 'Active Stakes';
        });
        const statusText = activeCard ? activeCard.querySelector('p.text-sm.text-gray-500') : null;

        if (stake.isLocked) {
            if (withdrawLink) {
                withdrawLink.classList.add('opacity-50', 'pointer-events-none');
                withdrawLink.setAttribute('aria-disabled', 'true');
                withdrawLink.onclick = (e) => { e.preventDefault(); gToast.info('Stake is locked until ' + new Date(Number(stake.unlockTime) * 1000).toLocaleString()); return false; };
            }
            if (statusText) {
                const rem = timeRemainingText(stake.unlockTime);
                statusText.textContent = rem === 'Unlocked' ? 'Unlocked' : `Locked • ${rem}`;
            }
        } else {
            if (withdrawLink) {
                withdrawLink.classList.remove('opacity-50', 'pointer-events-none');
                withdrawLink.setAttribute('aria-disabled', 'false');
                withdrawLink.onclick = (e) => { e.preventDefault(); const modal = document.getElementById('withdrawModal'); if (modal) modal.classList.add('active'); return false; };
            }
            if (statusText) {
                statusText.textContent = 'Earning rewards';
            }
        }

    } catch (e) {
        console.warn('Failed to update stake card:', e && e.message);
    }
}

// Recent Threats: fetch events from server and render merged rows
async function fetchRecentThreatEvents({ eventName = '', limit = 50, page = 1 } = {}) {
    try {
        const cfg = await new Promise((resolve) => chrome.storage.sync.get(['serverUrl', 'serverKey'], (r) => resolve(r)));
        const serverUrl = cfg.serverUrl || 'http://localhost:3000';
        const apiKey = cfg.serverKey || '';

        const q = new URL(`${serverUrl}/events`);
        if (eventName) q.searchParams.set('eventName', eventName);
        q.searchParams.set('limit', String(limit));
        q.searchParams.set('page', String(page));

        const res = await fetch(q.toString(), {
            headers: apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}
        });
        if (!res.ok) {
            console.warn('Failed to fetch events list', await res.text());
            return [];
        }
        const data = await res.json();
        return data.events || [];
    } catch (e) {
        console.warn('fetchRecentThreatEvents error', e && e.message);
        return [];
    }
}

function mergeEventsByDocument(events) {
    const map = new Map();
    for (const ev of events) {
        const indexed = ev.indexed || {};
        // event.indexed.keys may contain [caller, collection, document_id, ...]
        const keys = indexed.keys || [];
        const collection = keys[1] ? String(keys[1]) : (ev.eventData && ev.eventData.data && ev.eventData.data[1] ? String(ev.eventData.data[1]) : 'default');
        const docId = keys[2] ? String(keys[2]) : (ev.eventData && ev.eventData.data && ev.eventData.data[2] ? String(ev.eventData.data[2]) : null);
        if (!docId) continue;
        const key = `${collection}:${docId}`;
        if (!map.has(key)) {
            map.set(key, { collection, docId, events: [] });
        }
        map.get(key).events.push(ev);
    }
    return Array.from(map.values());
}

async function fetchAndRenderRecentThreats() {
    const tbody = document.getElementById('recent-threats-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr class="hover:bg-gray-50"><td class="px-6 py-4" colspan="6"><div class="text-sm text-gray-500">Loading recent threats...</div></td></tr>';

    const allEvents = [];
    const names = ['DocumentInserted', 'DocumentUpdated', 'DocumentApproved', 'DocumentVoteSubmitted'];
    for (const name of names) {
        try {
            const evs = await fetchRecentThreatEvents({ eventName: name, limit: 50, page: 1 });
            if (Array.isArray(evs) && evs.length) allEvents.push(...evs);
        } catch (e) {
            console.warn('Error fetching events by name', name, e && e.message);
        }
    }

    if (allEvents.length === 0) {
        tbody.innerHTML = '<tr class="hover:bg-gray-50"><td class="px-6 py-4" colspan="6"><div class="text-sm text-gray-500">No recent threats found</div></td></tr>';
        return;
    }

    const merged = mergeEventsByDocument(allEvents);
    const rows = [];
    for (const item of merged) {
        let title = `Document ${item.docId}`;
        let description = '';
        let source = 'on-chain';
        let risk = 'Unknown';
        let status = 'Pending';
        if (item.events.some(e => e.eventName === 'DocumentApproved')) {
            status = 'Approved';
        }
        const insertEv = item.events.find(e => e.eventName === 'DocumentInserted');
        if (insertEv && insertEv.eventData && insertEv.eventData.data) {
            description = String(insertEv.eventData.data[0] || '');
        }

        rows.push({ collection: item.collection, docId: item.docId, title, description, source, risk, status, events: item.events });
    }

    // Build DOM
    tbody.innerHTML = '';
    for (const row of rows) {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50';

        tr.innerHTML = `
            <td class="px-6 py-4">
                <div class="flex items-center">
                    <div class="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center mr-3">
                        <i class="fas fa-shield-virus text-red-600"></i>
                    </div>
                    <div>
                        <div class="text-sm font-medium text-gray-900">${escapeHtml(row.title)}</div>
                        <div class="text-sm text-gray-500">${escapeHtml(row.description)}</div>
                    </div>
                </div>
            </td>
            <td class="px-6 py-4"><span class="px-2 py-1 text-xs bg-red-100 text-red-800 rounded-full">On-chain</span></td>
            <td class="px-6 py-4 text-sm text-gray-900">${escapeHtml(row.source)}</td>
            <td class="px-6 py-4"><span class="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded-full">${escapeHtml(row.risk)}</span></td>
            <td class="px-6 py-4"><span class="px-2 py-1 text-xs bg-gray-100 text-gray-800 rounded-full">${escapeHtml(row.status)}</span></td>
            <td class="px-6 py-4">
                <button class="text-indigo-600 hover:text-indigo-800 recent-threat-view-btn" data-collection="${escapeHtml(row.collection)}" data-docid="${escapeHtml(row.docId)}"> <i class="fas fa-eye"></i> </button>
            </td>
        `;

        tbody.appendChild(tr);
    }

    // attach listeners
    document.querySelectorAll('.recent-threat-view-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const collection = btn.getAttribute('data-collection');
            const docId = btn.getAttribute('data-docid');
            await openThreatModal(collection, docId);
        });
    });
}

async function openThreatModal(collection, docId) {
    try {
        const modalId = 'threatDetailModal';
        let modal = document.getElementById(modalId);
        if (!modal) {
            // create modal markup dynamically
            modal = document.createElement('div');
            modal.id = modalId;
            modal.className = 'modal active';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h2 class="text-2xl font-bold text-gray-900">Threat Details</h2>
                        <button id="threat-close-btn" class="modal-close">×</button>
                    </div>
                    <div id="threat-detail-body" class="mb-4 text-sm text-gray-700"></div>
                    <div id="threat-vote-actions" class="mt-4 flex space-x-2"></div>
                </div>
            `;
            document.body.appendChild(modal);
            document.getElementById('threat-close-btn').addEventListener('click', () => modal.classList.remove('active'));
        } else {
            modal.classList.add('active');
        }

        const body = modal.querySelector('#threat-detail-body');
        const actions = modal.querySelector('#threat-vote-actions');
        body.textContent = 'Loading...';
        actions.innerHTML = '';

        let summary = null;
        try {
            const cfg = await new Promise((resolve) => chrome.storage.sync.get(['serverUrl', 'serverKey'], (r) => resolve(r)));
            const serverUrl = cfg.serverUrl || 'http://localhost:3000';
            const apiKey = cfg.serverKey || '';
            const url = `${serverUrl}/events/doc/${encodeURIComponent(collection)}/${encodeURIComponent(docId)}`;
            const resp = await fetch(url, { headers: apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {} });
            if (resp.ok) {
                const d = await resp.json();
                summary = d && d.summary ? d.summary : null;
            }
        } catch (e) {
            console.warn('Failed to fetch document summary from server', e && e.message);
        }

        let threat = null;
        if (starknetManager && typeof starknetManager.getThreatById === 'function') {
            try {
                threat = await starknetManager.getThreatById(collection, docId);
            } catch (e) {
                console.warn('Failed to fetch threat by id', e && e.message);
            }
        }

        // Render body with best available data
        const owner = (summary && summary.inserted && summary.inserted.caller) || (threat && threat.creator) || (summary && summary.inserted && summary.inserted.creator) || null;
        const positive_votes = summary && typeof summary.positive_votes === 'number' ? summary.positive_votes : (summary && summary.votes && summary.votes.length ? summary.votes.reduce((acc, v) => acc + (v.is_valid ? 1 : 0), 0) : 0);
        const negative_votes = summary && typeof summary.negative_votes === 'number' ? summary.negative_votes : 0;
        const approved = summary && summary.approved === true;

        if (!threat) {
            body.innerHTML = `<div>Document: ${escapeHtml(docId)} (collection: ${escapeHtml(collection)})</div>` +
                `<div class="mt-2 text-gray-500">No additional on-chain data available.</div>` +
                `<div class="mt-3 text-sm text-gray-700">Owner: ${escapeHtml(owner || 'unknown')}</div>` +
                `<div class="mt-1 text-sm text-gray-700">Votes: ${escapeHtml(String(positive_votes))} positive / ${escapeHtml(String(negative_votes))} negative</div>`;
        } else {
            body.innerHTML = `<div><strong>Document:</strong> ${escapeHtml(docId)}</div><div class="mt-2"><strong>Data:</strong> ${escapeHtml(JSON.stringify(threat))}</div>` +
                `<div class="mt-3 text-sm text-gray-700">Owner: ${escapeHtml(owner || 'unknown')}</div>` +
                `<div class="mt-1 text-sm text-gray-700">Votes: ${escapeHtml(String(positive_votes))} positive / ${escapeHtml(String(negative_votes))} negative</div>`;
        }

        const currentWallet = walletAddress || (starknetManager.getWalletAddress && starknetManager.getWalletAddress());

        if (currentWallet && owner && currentWallet.toLowerCase() === owner.toLowerCase()) {
            actions.innerHTML = '<div class="text-sm text-gray-500">You are the owner of this document.</div>';
        } else if (approved) {
            actions.innerHTML = '<div class="text-sm text-gray-500">Document already approved.</div>';
        } else {
            // allow voting
            const voteBtn = document.createElement('button');
            voteBtn.className = 'btn-primary';
            voteBtn.textContent = 'Vote to Approve';
            voteBtn.addEventListener('click', async () => {
                try {
                    const writer = new SmartContractWriter('vote_action', 'events');
                    const method = 'vote_on_document';
                    const args = [{ collection, doc_id: docId, is_valid: true }];
                    await writer.execute(method, args, {}, `${collection}:${docId}`, currentWallet, (res) => {
                        gToast.success('Vote submitted. TX: ' + (res.transactionHash || 'submitted'));
                        modal.classList.remove('active');
                        fetchAndRenderRecentThreats();
                    }, (err) => {
                        gToast.error('Vote failed: ' + (err && err.message));
                    });
                } catch (e) {
                    gToast.error('Vote failed: ' + (e && e.message));
                }
            });
            actions.appendChild(voteBtn);
        }

    } catch (e) {
        console.error('openThreatModal error', e && e.message);
    }
}

function escapeHtml(s) {
    if (!s) return '';
    return String(s).replace(/[&<>"']/g, function (c) {
        return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
}

// Initialize recent threats loader
window.addEventListener('load', () => {
    setTimeout(() => fetchAndRenderRecentThreats(), 500);
    updateSecuritySetupStatus();
});

// Watch for settings changes and update the Security Status UI
if (chrome && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'sync') return;
        const keys = ['geminiApiKey', 'llmType', 'serverUrl', 'serverKey', 'braveSearchKey', 'googleSafeBrowsingKey', 'abuseIpDbKey'];
        for (const k of Object.keys(changes)) {
            if (keys.includes(k)) {
                updateSecuritySetupStatus();
                break;
            }
        }
    });
}

async function updateSecuritySetupStatus() {
    try {
        // Read the seven settings
        const cfg = await new Promise((resolve) => {
            try {
                chrome.storage.sync.get(['geminiApiKey', 'llmType', 'serverUrl', 'serverKey', 'braveSearchKey', 'googleSafeBrowsingKey', 'abuseIpDbKey'], (r) => resolve(r));
            } catch (e) {
                // fallback to localStorage
                resolve({
                    geminiApiKey: localStorage.getItem('geminiApiKey'),
                    llmType: localStorage.getItem('llmType'),
                    serverUrl: localStorage.getItem('serverUrl'),
                    serverKey: localStorage.getItem('serverKey'),
                    braveSearchKey: localStorage.getItem('braveSearchKey'),
                    googleSafeBrowsingKey: localStorage.getItem('googleSafeBrowsingKey'),
                    abuseIpDbKey: localStorage.getItem('abuseIpDbKey')
                });
            }
        });

        const checks = [
            { key: 'geminiApiKey', label: 'Gemini Key', ok: !!cfg.geminiApiKey },
            { key: 'llmType', label: 'LLM Type', ok: !!cfg.llmType },
            { key: 'serverUrl', label: 'Server URL', ok: !!cfg.serverUrl },
            { key: 'serverKey', label: 'API Key', ok: !!cfg.serverKey },
            { key: 'braveSearchKey', label: 'Brave Search', ok: !!cfg.braveSearchKey },
            { key: 'googleSafeBrowsingKey', label: 'Google Safe Browsing', ok: !!cfg.googleSafeBrowsingKey },
            { key: 'abuseIpDbKey', label: 'AbuseIPDB', ok: !!cfg.abuseIpDbKey }
        ];

        // find security card and its items
        const securityCard = Array.from(document.querySelectorAll('.card')).find(card => card.querySelector('h3') && card.querySelector('h3').textContent && card.querySelector('h3').textContent.trim() === 'Security Status');
        if (securityCard) {
            const list = securityCard.querySelector('.space-y-3');
            if (list) {
                // Clear and rebuild rows to avoid duplication
                list.innerHTML = '';
                for (const c of checks) {
                    const row = document.createElement('div');
                    row.className = 'flex items-center justify-between p-3 bg-gray-50 rounded-lg';
                    const dotColor = c.ok ? 'bg-green-500' : 'bg-red-500';
                    const statusText = c.ok ? 'SET' : 'NOT SET';
                    const statusColorClass = c.ok ? 'text-green-600' : 'text-yellow-600';
                    row.innerHTML = `
                        <div class="flex items-center space-x-3">
                            <div class="w-3 h-3 ${dotColor} rounded-full status-dot ${c.ok ? 'green' : 'red'}"></div>
                            <span class="text-sm font-medium text-gray-700">${c.label}</span>
                        </div>
                        <span class="text-sm font-semibold ${statusColorClass}">${statusText}</span>
                    `;
                    list.appendChild(row);
                }
            }
        }

        // Compute percentage
        const setCount = checks.filter(c => c.ok).length;
        const percent = Math.round((setCount / checks.length) * 100);

        const scoreText = document.getElementById('security-score');
        const ring = document.getElementById('security-ring');
        const circumference = 2 * Math.PI * 56; // match SVG radius 56
        const offset = circumference - (percent / 100) * circumference;
        if (ring) {
            ring.style.strokeDashoffset = offset;
            // color the stroke based on percent (use gradient for 100%)
            if (percent === 100) {
                ring.style.stroke = 'url(#gradient)';
            } else if (percent >= 50) {
                ring.style.stroke = '#f59e0b'; // amber
            } else {
                ring.style.stroke = '#ef4444'; // red
            }
        }
        if (scoreText) {
            scoreText.textContent = `${percent}%`;
            if (percent === 100) {
                scoreText.className = 'text-2xl font-bold gradient-text';
            } else if (percent >= 50) {
                scoreText.className = 'text-2xl font-bold';
                scoreText.style.color = '#f59e0b';
            } else {
                scoreText.className = 'text-2xl font-bold';
                scoreText.style.color = '#ef4444';
            }
        }

        // Update the textual security label
        const labelEl = document.getElementById('security-label');
        if (labelEl) {
            if (percent === 100) {
                labelEl.textContent = 'SECURE';
                labelEl.className = 'text-sm text-green-600';
            } else if (percent >= 50) {
                labelEl.textContent = 'PARTIAL';
                labelEl.className = 'text-sm text-yellow-600';
            } else {
                labelEl.textContent = 'AT RISK';
                labelEl.className = 'text-sm text-red-600';
            }
        }

        const tooltip = document.getElementById('security-tooltip');
        const tooltipContent = document.getElementById('security-tooltip-content');
        if (tooltip && tooltipContent) {
            const missing = checks.filter(c => !c.ok).map(c => `• ${c.label}`);
            tooltipContent.innerHTML = missing.length ? `<strong>Missing:</strong><br/>${missing.join('<br/>')}` : '<strong>All set</strong>';

            const scoreContainer = document.querySelector('#security-score');
            if (scoreContainer && !scoreContainer.dataset.tooltipAttached) {
                scoreContainer.addEventListener('mouseenter', () => tooltip.classList.remove('hidden'));
                scoreContainer.addEventListener('mouseleave', () => tooltip.classList.add('hidden'));
                scoreContainer.dataset.tooltipAttached = 'true';
            }
            const labelEl2 = document.getElementById('security-label');
            if (labelEl2 && !labelEl2.dataset.tooltipAttached) {
                labelEl2.addEventListener('mouseenter', () => tooltip.classList.remove('hidden'));
                labelEl2.addEventListener('mouseleave', () => tooltip.classList.add('hidden'));
                labelEl2.dataset.tooltipAttached = 'true';
            }
        }

    } catch (e) {
        console.warn('updateSecuritySetupStatus error', e && e.message);
    }
}