(async () => {

    const ajax = new AjaxHandler();
    const gToast = new CustomToast();
    const router = new SimpleRoute();

    const EXTENSION_URL = `chrome-extension://${chrome.runtime.id}/dashboard.html`;
    const GURFTRON_URL = 'https://gurftron.work.gd';

    async function checkIfFirstInstall() {
        const response = await chrome.runtime.sendMessage({ type: 'GET_INSTALL_STATUS' });
        if (response && response.isNew) {
            chrome.runtime.getURL('install.html');
            return;
        }
    }
    checkIfFirstInstall();

    async function getActiveTab() {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
            throw new Error('No active tab found');
        }
        return tab;
    }

    async function openPage() {
        return new Promise(async (resolve) => {
            const activeTab = await getActiveTab();
            const tabId = activeTab.id;

            // Update the current tab to open page
            chrome.tabs.update(tabId, { url: GURFTRON_URL }, () => {
                if (chrome.runtime.lastError) {
                    console.error('Failed to update tab:', chrome.runtime.lastError);
                    resolve({ error: 'Navigation failed' });
                    return;
                }

                // Listen for the tab to finish loading
                const listener = (updatedTabId, changeInfo) => {
                    if (updatedTabId === tabId && changeInfo.status === 'complete') {
                        chrome.tabs.onUpdated.removeListener(listener);
                        resolve(tabId); // return the same tab ID
                    }
                };

                chrome.tabs.onUpdated.addListener(listener);
            });
        });
    }

    const installPage = document.querySelectorAll('.intall-page');
    const loginPage = document.querySelectorAll('.login-page');

    if (installPage) {
        const statsCards = document.querySelectorAll('.stats-card');
        statsCards.forEach(card => {
            card.addEventListener('mouseenter', function () {
                // Create sparkle effect
                for (let i = 0; i < 5; i++) {
                    const sparkle = document.createElement('div');
                    sparkle.style.cssText = `
                        position: absolute;
                        width: 4px;
                        height: 4px;
                        background: #fbbf24;
                        border-radius: 50%;
                        pointer-events: none;
                        animation: sparkle 1s ease-out forwards;
                        left: ${Math.random() * 100}%;
                        top: ${Math.random() * 100}%;
                    `;

                    this.appendChild(sparkle);

                    setTimeout(() => {
                        sparkle.remove();
                    }, 1000);
                }
            });
        });

        // Create continuous confetti
        function createConfetti() {
            const confettiContainer = document.querySelector('.fixed.inset-0.pointer-events-none.z-0');
            const colors = ['#fbbf24', '#3b82f6', '#ef4444', '#10b981', '#8b5cf6'];

            for (let i = 0; i < 3; i++) {
                const confetti = document.createElement('div');
                confetti.style.cssText = `
                    position: absolute;
                    width: ${Math.random() * 6 + 4}px;
                    height: ${Math.random() * 6 + 4}px;
                    background: ${colors[Math.floor(Math.random() * colors.length)]};
                    left: ${Math.random() * 100}%;
                    top: -20px;
                    border-radius: ${Math.random() > 0.5 ? '50%' : '2px'};
                    animation: confetti-fall ${Math.random() * 2 + 2}s linear forwards;
                    z-index: 1;
                `;

                confettiContainer.appendChild(confetti);

                setTimeout(() => {
                    confetti.remove();
                }, 4000);
            }
        }
        setInterval(createConfetti, 500);
        const sparkleCSS = document.createElement('style');
        sparkleCSS.textContent = `
            @keyframes sparkle {
                0% {
                    opacity: 1;
                    transform: translateY(0) scale(0);
                }
                50% {
                    opacity: 1;
                    transform: translateY(-20px) scale(1);
                }
                100% {
                    opacity: 0;
                    transform: translateY(-40px) scale(0);
                }
            }
        `;
        document.head.appendChild(sparkleCSS);

        function animateNumber(element, target) {
            let current = 0;
            const increment = target / 50;
            const timer = setInterval(() => {
                current += increment;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }

                if (target >= 1000000) {
                    element.textContent = (current / 1000000).toFixed(1) + 'M+';
                } else if (target >= 1000) {
                    element.textContent = (current / 1000).toFixed(0) + 'K+';
                } else {
                    element.textContent = current.toFixed(1) + '%';
                }
            }, 50);
        }

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const statsNumbers = entry.target.querySelectorAll('.text-3xl');

                    setTimeout(() => {
                        animateNumber(statsNumbers[0], 10000);
                    }, 200);

                    setTimeout(() => {
                        animateNumber(statsNumbers[1], 1000000);
                    }, 400);

                    setTimeout(() => {
                        animateNumber(statsNumbers[2], 99.9);
                    }, 600);

                    observer.unobserve(entry.target);
                }
            });
        });

        const statsContainer = document.querySelector('.grid.grid-cols-1.md\\:grid-cols-3.gap-6.mb-8.slide-up-delayed-3');
        if (statsContainer) {
            observer.observe(statsContainer);
        }

        document.addEventListener('mousemove', function (e) {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;

            const floatingElements = document.querySelectorAll('.float, .float-delayed, .float-delayed-2');
            floatingElements.forEach((element, index) => {
                const speed = (index + 1) * 0.3;
                const x = (mouseX - 0.5) * speed * 15;
                const y = (mouseY - 0.5) * speed * 15;

                element.style.transform += ` translate(${x}px, ${y}px)`;
            });
        });

        setTimeout(() => {
            const burstContainer = document.querySelector('.fixed.inset-0.pointer-events-none.z-0');
            const colors = ['#fbbf24', '#3b82f6', '#ef4444', '#10b981', '#8b5cf6'];

            for (let i = 0; i < 20; i++) {
                const confetti = document.createElement('div');
                confetti.style.cssText = `
                    position: absolute;
                    width: ${Math.random() * 8 + 6}px;
                    height: ${Math.random() * 8 + 6}px;
                    background: ${colors[Math.floor(Math.random() * colors.length)]};
                    left: ${45 + Math.random() * 10}%;
                    top: 50%;
                    border-radius: ${Math.random() > 0.5 ? '50%' : '2px'};
                    animation: confetti-burst 2s ease-out forwards;
                    z-index: 1;
                `;

                burstContainer.appendChild(confetti);

                setTimeout(() => {
                    confetti.remove();
                }, 2000);
            }
        }, 1000);

        const burstCSS = document.createElement('style');
        burstCSS.textContent = `
            @keyframes confetti-burst {
                0% {
                    opacity: 1;
                    transform: translate(0, 0) rotate(0deg) scale(0);
                }
                10% {
                    transform: translate(0, 0) rotate(0deg) scale(1);
                }
                100% {
                    opacity: 0;
                    transform: translate(${Math.random() * 400 - 200}px, ${Math.random() * 400 + 200}px) rotate(720deg) scale(0);
                }
            }
        `;
        document.head.appendChild(burstCSS);
    }

    if (loginPage) {
        document.addEventListener('mousemove', function (e) {
            const mouseX = e.clientX / window.innerWidth;
            const mouseY = e.clientY / window.innerHeight;

            const floatingElements = document.querySelectorAll('.security-icon');
            floatingElements.forEach((element, index) => {
                const speed = (index + 1) * 0.5;
                const x = (mouseX - 0.5) * speed * 20;
                const y = (mouseY - 0.5) * speed * 20;

                element.style.transform += ` translate(${x}px, ${y}px)`;
            });
        });

        // Feature cards hover effect
        const featureCards = document.querySelectorAll('.feature-card');
        featureCards.forEach(card => {
            card.addEventListener('mouseenter', function () {
                this.style.transform += ' scale(1.05)';
            });

            card.addEventListener('mouseleave', function () {
                this.style.transform = this.style.transform.replace(' scale(1.05)', '');
            });
        });
    }

    const connectBtn = document.getElementById('connectWalletBtn');
    if (connectBtn) {

        const spinnerStyle = document.createElement('style');
        spinnerStyle.textContent = `
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            .spinner-animation {
                animation: spin 1s linear infinite;
                display: inline-block;
            }
        `;
        document.head.appendChild(spinnerStyle);

        connectBtn.addEventListener('click', async () => {
            if (connectBtn.disabled) return;
            connectBtn.disabled = true;
            connectBtn.innerHTML = `<i class="fas fa-spinner spinner-animation text-lg"></i><span>Connecting Wallet...</span>`;

            try {
                connectBtn.innerHTML = `<i class="fas fa-spinner spinner-animation text-lg"></i><span>Preparing login...</span>`;
                
                chrome.runtime.sendMessage({ type: 'GURFTRON_PREPARE_LOGIN' }, async (prepResponse) => {
                    if (prepResponse?.error) {
                        gToast.error('Login preparation failed: ' + prepResponse.error);
                        connectBtn.innerHTML = `<i class="fas fa-wallet text-lg"></i><span>Connect Wallet</span><i class="fas fa-arrow-right"></i>`;
                        connectBtn.disabled = false;
                        return;
                    }

                    connectBtn.innerHTML = `<i class="fas fa-spinner spinner-animation text-lg"></i><span>Opening login page...</span>`;
                    
                    try {
                        const tabId = await openPage();
                        if (!tabId || tabId.error) {
                            throw new Error('Failed to open login page');
                        }

                        connectBtn.innerHTML = `<i class="fas fa-spinner spinner-animation text-lg"></i><span>Verifying wallet connection...</span>`;
                        
                        // Poll for connection status
                        let attempts = 0;
                        const maxAttempts = 15; // 15 seconds max
                        const checkInterval = setInterval(() => {
                            attempts++;
                            
                            chrome.runtime.sendMessage({ type: 'content:pageLoaded' }, function (checkResponse) {
                                if (checkResponse?.result?.isLoggedIn === true && checkResponse?.result?.wallet && checkResponse?.result?.wallet !== 'none') {
                                    // Success!
                                    clearInterval(checkInterval);
                                    connectBtn.innerHTML = `<i class="fas fa-check-circle text-lg"></i><span>Connected! Redirecting...</span>`;
                                    
                                    chrome.tabs.update(tabId, { url: chrome.runtime.getURL('install.html') }, () => {
                                        setTimeout(() => {
                                            window.location.href = chrome.runtime.getURL('dashboard.html');
                                        }, 500);
                                    });
                                } else if (attempts >= maxAttempts) {
                                    // Timeout
                                    clearInterval(checkInterval);
                                    gToast.error('Wallet connection timeout. Please try again and approve the wallet connection.');
                                    
                                    chrome.tabs.update(tabId, { url: chrome.runtime.getURL('install.html') }, () => {
                                        connectBtn.innerHTML = `<i class="fas fa-wallet text-lg"></i><span>Connect Wallet</span><i class="fas fa-arrow-right"></i>`;
                                        connectBtn.disabled = false;
                                    });
                                }
                            });
                        }, 1000);

                    } catch (error) {
                        gToast.error('Navigation error: ' + error.message);
                        connectBtn.innerHTML = `<i class="fas fa-wallet text-lg"></i><span>Connect Wallet</span><i class="fas fa-arrow-right"></i>`;
                        connectBtn.disabled = false;
                    }
                });

            } catch (error) {
                console.error('Wallet connection error:', error);
                gToast.error(error.message || 'Failed to connect wallet. Please try again.');
                connectBtn.innerHTML = `<i class="fas fa-wallet text-lg"></i><span>Connect Wallet</span><i class="fas fa-arrow-right"></i>`;
                connectBtn.disabled = false;
            }
        });
    }

})();