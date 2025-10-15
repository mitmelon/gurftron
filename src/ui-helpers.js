
/**
 * Custom Toast Notification System
 */
class CustomToast {
  constructor() {
    this.toastCounter = 0;
    this.toasts = new Map();
    this.defaultOptions = {
      duration: 5000,
      position: 'top-right', // top-right, top-left, bottom-right, bottom-left
      showProgress: true,
      closable: true
    };
  }

  success(message, options = {}) {
    return this.show(message, 'success', options);
  }

  error(message, options = {}) {
    return this.show(message, 'error', options);
  }

  warning(message, options = {}) {
    return this.show(message, 'warning', options);
  }

  info(message, options = {}) {
    return this.show(message, 'info', options);
  }

  show(message, type = 'info', options = {}) {
    const config = { ...this.defaultOptions, ...options };
    const toastId = ++this.toastCounter;
    
    // Create toast container if it doesn't exist
    this.ensureContainer(config.position);
    
    // Create toast element
    const toast = this.createToastElement(toastId, message, type, config);
    
    // Add to container
    const container = document.querySelector(`#toast-container-${config.position}`);
    container.appendChild(toast);
    
    // Store reference
    this.toasts.set(toastId, { element: toast, type, config });
    
    // Trigger entrance animation
    setTimeout(() => {
      toast.style.transform = this.getShowTransform(config.position);
      toast.style.opacity = '1';
    }, 10);
    
    // Auto remove after duration
    if (config.duration > 0) {
      setTimeout(() => {
        this.remove(toastId);
      }, config.duration);
    }
    
    return toastId;
  }

  remove(toastId) {
    const toastData = this.toasts.get(toastId);
    if (!toastData) return;
    
    const { element, config } = toastData;
    
    // Exit animation
    element.style.transform = this.getHideTransform(config.position);
    element.style.opacity = '0';
    
    setTimeout(() => {
      if (element.parentNode) {
        element.parentNode.removeChild(element);
      }
      this.toasts.delete(toastId);
    }, 300);
  }

  clear() {
    this.toasts.forEach((_, toastId) => this.remove(toastId));
  }

  ensureContainer(position) {
    const containerId = `toast-container-${position}`;
    let container = document.getElementById(containerId);
    
    if (!container) {
      container = document.createElement('div');
      container.id = containerId;
      container.style.cssText = this.getContainerStyles(position);
      document.body.appendChild(container);
    }
  }

  getContainerStyles(position) {
    const baseStyles = `
      position: fixed;
      z-index: 9999;
      max-width: 400px;
      pointer-events: none;
    `;
    
    const positions = {
      'top-right': 'top: 20px; right: 20px;',
      'top-left': 'top: 20px; left: 20px;',
      'bottom-right': 'bottom: 20px; right: 20px;',
      'bottom-left': 'bottom: 20px; left: 20px;'
    };
    
    return baseStyles + positions[position];
  }

  getShowTransform(position) {
    const transforms = {
      'top-right': 'translateX(0)',
      'top-left': 'translateX(0)',
      'bottom-right': 'translateX(0)',
      'bottom-left': 'translateX(0)'
    };
    return transforms[position];
  }

  getHideTransform(position) {
    const transforms = {
      'top-right': 'translateX(100%)',
      'top-left': 'translateX(-100%)',
      'bottom-right': 'translateX(100%)',
      'bottom-left': 'translateX(-100%)'
    };
    return transforms[position];
  }

  createToastElement(toastId, message, type, config) {
    const toast = document.createElement('div');
    toast.id = `toast-${toastId}`;
    
    const colors = {
      success: { bg: '#10b981', border: '#059669', icon: '✓' },
      error: { bg: '#ef4444', border: '#dc2626', icon: '✕' },
      warning: { bg: '#f59e0b', border: '#d97706', icon: '⚠' },
      info: { bg: '#3b82f6', border: '#2563eb', icon: 'ℹ' }
    };
    
    const color = colors[type];
    
    toast.style.cssText = `
      background: ${color.bg};
      color: white;
      padding: 16px 20px;
      margin-bottom: 12px;
      border-radius: 8px;
      border-left: 4px solid ${color.border};
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1), 0 4px 6px rgba(0, 0, 0, 0.05);
      display: flex;
      align-items: center;
      min-width: 300px;
      max-width: 400px;
      opacity: 0;
      transform: ${this.getHideTransform(config.position)};
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: auto;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      font-size: 14px;
      line-height: 1.4;
      position: relative;
      overflow: hidden;
    `;
    
    // Icon
    const icon = document.createElement('span');
    icon.style.cssText = `
      font-size: 16px;
      margin-right: 12px;
      font-weight: bold;
      flex-shrink: 0;
    `;
    icon.textContent = color.icon;
    
    // Message
    const messageEl = document.createElement('div');
    messageEl.style.cssText = `
      flex: 1;
      font-weight: 500;
    `;
    messageEl.textContent = message;
    
    toast.appendChild(icon);
    toast.appendChild(messageEl);
    
    // Close button
    if (config.closable) {
      const closeBtn = document.createElement('button');
      closeBtn.style.cssText = `
        background: none;
        border: none;
        color: white;
        font-size: 16px;
        cursor: pointer;
        padding: 4px;
        margin-left: 12px;
        opacity: 0.8;
        transition: opacity 0.2s;
        flex-shrink: 0;
      `;
      closeBtn.innerHTML = '×';
      closeBtn.onmouseover = () => closeBtn.style.opacity = '1';
      closeBtn.onmouseout = () => closeBtn.style.opacity = '0.8';
      closeBtn.onclick = () => this.remove(toastId);
      toast.appendChild(closeBtn);
    }
    
    // Progress bar
    if (config.showProgress && config.duration > 0) {
      const progressBar = document.createElement('div');
      progressBar.style.cssText = `
        position: absolute;
        bottom: 0;
        left: 0;
        height: 3px;
        background: rgba(255, 255, 255, 0.3);
        width: 100%;
        animation: toast-progress ${config.duration}ms linear;
      `;
      
      // Add progress animation keyframes
      this.addProgressAnimation();
      
      toast.appendChild(progressBar);
    }
    
    return toast;
  }

  addProgressAnimation() {
    if (document.getElementById('toast-progress-style')) return;
    
    const style = document.createElement('style');
    style.id = 'toast-progress-style';
    style.textContent = `
      @keyframes toast-progress {
        from { width: 100%; }
        to { width: 0%; }
      }
    `;
    document.head.appendChild(style);
  }
}

class AjaxHandler {
  constructor() {
    this.signal = null;
    this.controller = new AbortController();
    this.toast = new CustomToast();
    
    // Default loaders
    this.loaders = {
      default: `<div style="display: inline-flex; align-items: center;">
                  <div style="width: 16px; height: 16px; border: 2px solid #ffffff; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 8px;"></div>
                  Loading...
                </div>`,
      centerLoader: `<div style="display: flex; justify-content: center; align-items: center; padding: 20px;">
                      <div style="width: 24px; height: 24px; border: 3px solid #e5e7eb; border-top: 3px solid #3b82f6; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                    </div>`,
      themeLoader: `<div style="display: inline-flex; align-items: center;">
                      <div style="width: 14px; height: 14px; border: 2px solid currentColor; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 6px;"></div>
                      Please wait...
                    </div>`,
      pageLoader: `<div style="display: flex; align-items: center; justify-content: center; width: 100%;">
                     <div style="width: 20px; height: 20px; border: 2px solid #f3f4f6; border-top: 2px solid #6366f1; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                   </div>`
    };
    
    this.addSpinAnimation();
  }

  addSpinAnimation() {
    if (document.getElementById('ajax-spin-style')) return;
    
    const style = document.createElement('style');
    style.id = 'ajax-spin-style';
    style.textContent = `
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }

  storage = {
    get: (key) => localStorage.getItem(key) || '',
    set: (key, value) => localStorage.setItem(key, value)
  };

  // Progress bar helper (replace with your implementation or remove)
  NProgress = {
    start: () => console.log('Progress started'),
    done: () => console.log('Progress done')
  };

  // Animation helper (replace with your implementation)
  animateCSS = (element, animationName) => {
    const node = typeof element === 'string' ? document.querySelector(element) : element;
    if (node) {
      node.style.animation = `${animationName} 0.5s`;
      setTimeout(() => {
        node.style.animation = '';
      }, 500);
    }
  };

  async ajaxFormData(formID, type, url, data, btid = null, buttonName = null, successCallback = null, loader = 'default', toastPosition = 'top-right') {
    try {
      // Show loader
      data.append('latitude', this.storage.get('latitude'));
      data.append('longitude', this.storage.get('longitude'));
      
      if (btid !== null && buttonName !== null) {
        this.NProgress.start();
      }
      
      if (btid !== null && btid !== '' && typeof btid !== 'undefined') {
        const button = document.querySelector(btid);
        if (button) {
          button.classList.remove("btn-dim");
          button.disabled = true;
          button.style.opacity = '0.5';
          button.style.pointerEvents = "none";
          
          // Set loader content
          if (this.loaders[loader]) {
            button.innerHTML = this.loaders[loader];
          } else {
            button.innerHTML = loader; // Custom loader
          }
        }
      }
      
      this.controller = new AbortController();
      this.signal = this.controller.signal;
      
      const response = await fetch(url, {
        method: type,
        body: data,
        signal: this.signal,
      });
      
      const responseData = await response.json();
      
      if (response.ok && responseData.status === 200) {
        // Handle success response
        this.resetButton(btid, buttonName);
        
        if (typeof successCallback === 'function') {
          successCallback(responseData, buttonName);
        }
        
        if (formID !== null && buttonName !== null && btid !== null) {
          this.NProgress.done();
        }
        
      } else {
        // Handle error response
        this.resetButton(btid, buttonName);
        
        this.toast.error(responseData.error || 'An error occurred', { position: toastPosition });
        
        if (formID !== null) {
          this.animateCSS(formID, 'shake');
        }
        
        if (formID !== null && buttonName !== null && btid !== null) {
          this.NProgress.done();
        }
      }
      
    } catch (error) {
      this.resetButton(btid, buttonName);
      
      if (formID !== null) {
        this.animateCSS(formID, 'shake');
      }
      
      if (formID !== null && buttonName !== null && btid !== null) {
        this.NProgress.done();
      }
      
      if (error.name === 'AbortError') {
        // Request was cancelled
        return;
      } else if (error.name === 'TimeoutError') {
        this.toast.error('Timeout reached. Please try again', { position: toastPosition });
      } else {
        this.toast.error(error.message || 'System error occurred', { position: toastPosition });
      }
    }
  }

  resetButton(btid, buttonName) {
    if (btid !== null && btid !== '' && typeof btid !== 'undefined') {
      const button = document.querySelector(btid);
      if (button) {
        button.disabled = false;
        button.style.opacity = '1';
        button.style.pointerEvents = '';
        
        if (buttonName !== null && buttonName !== '' && typeof buttonName !== 'undefined') {
          button.innerHTML = buttonName;
        }
      }
    }
    
    // Remove any standalone loaders
    const loaders = document.querySelectorAll('#maloaders');
    loaders.forEach(loader => loader.remove());
  }

  // Method to cancel ongoing requests
  cancelRequest() {
    if (this.controller) {
      this.controller.abort();
    }
  }
}


/**
 * Page Loader
 * Loads HTML content and properly executes all scripts and styles
 */
class PageLoader {
  constructor(options = {}) {
    this.options = {
      timeout: 10000,
      executeScripts: true,
      loadStyles: true,
      sanitize: false,
      baseUrl: chrome?.runtime?.getURL('') || '',
      ...options
    };
    
    this.loadedScripts = new Set();
    this.loadedStyles = new Set();
    this.pageCache = new Map();
  }

  /**
   * Load a page and inject it into a target container
   * @param {string} pagePath - Path to the HTML file
   * @param {string|HTMLElement|null} targetContainer - Container to inject content (null = replace entire document)
   * @param {Object} options - Override default options
   * @returns {Promise<Object>} Load result with status and data
   */
  async loadPage(pagePath, targetContainer = null, options = {}) {
    try {
      const config = { ...this.options, ...options };
      
      // Handle full page replacement
      if (targetContainer === null) {
        return await this.loadFullPage(pagePath, config);
      }
      
      const container = typeof targetContainer === 'string' 
        ? document.querySelector(targetContainer) 
        : targetContainer;

      if (!container) {
        throw new Error(`Target container not found: ${targetContainer}`);
      }

      // Check cache first
      const cacheKey = `${pagePath}-${JSON.stringify(config)}`;
      if (this.pageCache.has(cacheKey) && !config.bypassCache) {
        console.log(`Loading page from cache: ${pagePath}`);
        return this.injectCachedContent(container, this.pageCache.get(cacheKey));
      }

      console.log(`Loading page: ${pagePath}`);
      
      // Fetch the page content
      const content = await this.fetchPageContent(pagePath, config.timeout);
      
      // Parse and process the content
      const processedContent = await this.processContent(content, pagePath, config);
      
      // Cache the processed content
      if (!config.bypassCache) {
        this.pageCache.set(cacheKey, processedContent);
      }
      
      // Inject into container
      return await this.injectContent(container, processedContent);
      
    } catch (error) {
      console.error(`Failed to load page ${pagePath}:`, error);
      
      if (window.core?.storage) {
        await window.core.storage.logError('PAGE_LOAD', `Failed to load ${pagePath}: ${error.message}`);
      }
      
      return {
        success: false,
        error: error.message,
        path: pagePath
      };
    }
  }

  /**
   * Fetch page content from the extension
   * @param {string} pagePath - Path to fetch
   * @param {number} timeout - Request timeout
   * @returns {Promise<string>} HTML content
   */
  async fetchPageContent(pagePath, timeout) {
    const url = pagePath.startsWith('http') 
      ? pagePath 
      : this.options.baseUrl + pagePath.replace(/^\//, '');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        signal: controller.signal,
        method: 'GET',
        headers: {
          'Content-Type': 'text/html',
        }
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.text();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        throw new Error('Request timeout');
      }
      throw error;
    }
  }

  /**
   * Process HTML content and extract scripts/styles
   * @param {string} content - Raw HTML content
   * @param {string} pagePath - Original page path for relative URL resolution
   * @param {Object} config - Configuration options
   * @returns {Promise<Object>} Processed content object
   */
  async processContent(content, pagePath, config) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(content, 'text/html');
    const basePath = pagePath.substring(0, pagePath.lastIndexOf('/') + 1);

    const processed = {
      html: '',
      inlineScripts: [],
      externalScripts: [],
      inlineStyles: [],
      externalStyles: [],
      meta: {},
      title: doc.title || ''
    };

    // Extract meta information
    const metaTags = doc.querySelectorAll('meta');
    metaTags.forEach(meta => {
      if (meta.name) processed.meta[meta.name] = meta.content;
      if (meta.property) processed.meta[meta.property] = meta.content;
    });

    // Process and extract styles
    if (config.loadStyles) {
      await this.extractStyles(doc, processed, basePath);
    }

    // Process and extract scripts
    if (config.executeScripts) {
      await this.extractScripts(doc, processed, basePath);
    }

    // Get the remaining HTML (body content typically)
    const bodyContent = doc.body ? doc.body.innerHTML : doc.documentElement.innerHTML;
    processed.html = config.sanitize ? this.sanitizeHTML(bodyContent) : bodyContent;

    return processed;
  }

  /**
   * Extract styles from document
   */
  async extractStyles(doc, processed, basePath) {
    // Extract inline styles
    const styleTags = doc.querySelectorAll('style');
    styleTags.forEach(style => {
      processed.inlineStyles.push(style.textContent);
      style.remove();
    });

    // Extract external stylesheets
    const linkTags = doc.querySelectorAll('link[rel="stylesheet"]');
    for (const link of linkTags) {
      const href = this.resolveURL(link.getAttribute('href'), basePath);
      processed.externalStyles.push({
        url: href,
        media: link.getAttribute('media') || 'all',
        integrity: link.getAttribute('integrity'),
        crossorigin: link.getAttribute('crossorigin')
      });
      link.remove();
    }
  }

  /**
   * Extract scripts from document
   */
  async extractScripts(doc, processed, basePath) {
    // Extract inline scripts
    const inlineScripts = doc.querySelectorAll('script:not([src])');
    inlineScripts.forEach(script => {
      if (script.textContent.trim()) {
        processed.inlineScripts.push({
          content: script.textContent,
          type: script.getAttribute('type') || 'text/javascript',
          async: script.hasAttribute('async'),
          defer: script.hasAttribute('defer')
        });
      }
      script.remove();
    });

    // Extract external scripts
    const externalScripts = doc.querySelectorAll('script[src]');
    externalScripts.forEach(script => {
      const src = this.resolveURL(script.getAttribute('src'), basePath);
      processed.externalScripts.push({
        url: src,
        type: script.getAttribute('type') || 'text/javascript',
        async: script.hasAttribute('async'),
        defer: script.hasAttribute('defer'),
        integrity: script.getAttribute('integrity'),
        crossorigin: script.getAttribute('crossorigin')
      });
      script.remove();
    });
  }

  /**
   * Inject processed content into container
   */
  async injectContent(container, processedContent) {
    try {
      // Load external styles first
      await this.loadExternalStyles(processedContent.externalStyles);

      // Inject inline styles
      this.injectInlineStyles(processedContent.inlineStyles);

      // Set page title if available
      if (processedContent.title && processedContent.title !== document.title) {
        document.title = processedContent.title;
      }

      // Clear and inject HTML content
      container.innerHTML = processedContent.html;

      // Load and execute scripts
      await this.loadExternalScripts(processedContent.externalScripts);
      await this.executeInlineScripts(processedContent.inlineScripts);

      return {
        success: true,
        content: processedContent,
        container: container,
        scriptsLoaded: processedContent.externalScripts.length + processedContent.inlineScripts.length,
        stylesLoaded: processedContent.externalStyles.length + processedContent.inlineStyles.length
      };

    } catch (error) {
      throw new Error(`Content injection failed: ${error.message}`);
    }
  }

  /**
   * Load a complete HTML page and replace the entire document
   * @param {string} pagePath - Path to the HTML file
   * @param {Object} config - Configuration options
   * @returns {Promise<Object>} Load result
   */
  async loadFullPage(pagePath, config) {
    try {
      console.log(`Loading full page: ${pagePath}`);
      
      // Fetch the complete page content
      const content = await this.fetchPageContent(pagePath, config.timeout);
      
      // Parse the full document
      const parser = new DOMParser();
      const doc = parser.parseFromString(content, 'text/html');
      
      // Process the entire document
      const processedContent = await this.processFullDocument(doc, pagePath, config);
      
      // Replace the current document
      return await this.replaceDocument(processedContent);
      
    } catch (error) {
      throw new Error(`Full page load failed: ${error.message}`);
    }
  }

  /**
   * Process a complete HTML document
   * @param {Document} doc - Parsed document
   * @param {string} pagePath - Original page path
   * @param {Object} config - Configuration
   * @returns {Promise<Object>} Processed document data
   */
  async processFullDocument(doc, pagePath, config) {
    const basePath = pagePath.substring(0, pagePath.lastIndexOf('/') + 1);
    
    const processed = {
      html: doc.documentElement.outerHTML,
      head: doc.head.innerHTML,
      body: doc.body.innerHTML,
      title: doc.title || '',
      inlineScripts: [],
      externalScripts: [],
      inlineStyles: [],
      externalStyles: [],
      meta: {}
    };

    // Extract meta information
    const metaTags = doc.querySelectorAll('meta');
    metaTags.forEach(meta => {
      if (meta.name) processed.meta[meta.name] = meta.content;
      if (meta.property) processed.meta[meta.property] = meta.content;
    });

    // Process styles if enabled
    if (config.loadStyles) {
      await this.extractStyles(doc, processed, basePath);
    }

    // Process scripts if enabled
    if (config.executeScripts) {
      await this.extractScripts(doc, processed, basePath);
    }

    return processed;
  }

  /**
   * Replace the entire current document with new content
   * @param {Object} processedContent - Processed document data
   * @returns {Promise<Object>} Result object
   */
  async replaceDocument(processedContent) {
    try {
      // Clear current document content
      document.documentElement.innerHTML = '';
      
      // Create new document structure
      const parser = new DOMParser();
      const newDoc = parser.parseFromString(processedContent.html, 'text/html');
      
      // Copy all attributes from new document to current
      Array.from(newDoc.documentElement.attributes).forEach(attr => {
        document.documentElement.setAttribute(attr.name, attr.value);
      });
      
      // Replace head content
      document.head.innerHTML = newDoc.head.innerHTML;
      
      // Replace body content and attributes
      document.body.innerHTML = newDoc.body.innerHTML;
      Array.from(newDoc.body.attributes).forEach(attr => {
        document.body.setAttribute(attr.name, attr.value);
      });
      
      // Set document title
      if (processedContent.title) {
        document.title = processedContent.title;
      }

      // Load external styles
      await this.loadExternalStyles(processedContent.externalStyles);
      
      // Inject inline styles
      this.injectInlineStyles(processedContent.inlineStyles);

      // Load and execute scripts
      await this.loadExternalScripts(processedContent.externalScripts);
      await this.executeInlineScripts(processedContent.inlineScripts);

      // Trigger DOMContentLoaded for scripts that depend on it
      const domContentLoadedEvent = new Event('DOMContentLoaded', {
        bubbles: true,
        cancelable: true
      });
      document.dispatchEvent(domContentLoadedEvent);

      return {
        success: true,
        fullPageReplacement: true,
        title: processedContent.title,
        scriptsLoaded: processedContent.externalScripts.length + processedContent.inlineScripts.length,
        stylesLoaded: processedContent.externalStyles.length + processedContent.inlineStyles.length
      };

    } catch (error) {
      throw new Error(`Document replacement failed: ${error.message}`);
    }
  }
  
  async injectCachedContent(container, processedContent) {
    // For cached content, only re-inject HTML and styles
    // Scripts should only run once to avoid side effects
    container.innerHTML = processedContent.html;
    this.injectInlineStyles(processedContent.inlineStyles);
    
    return {
      success: true,
      cached: true,
      content: processedContent,
      container: container
    };
  }

  /**
   * Load external stylesheets
   */
  async loadExternalStyles(externalStyles) {
    const promises = externalStyles.map(async (styleInfo) => {
      if (this.loadedStyles.has(styleInfo.url)) {
        console.log(`Style already loaded: ${styleInfo.url}`);
        return;
      }

      return new Promise((resolve, reject) => {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = styleInfo.url;
        link.media = styleInfo.media || 'all';
        
        if (styleInfo.integrity) link.integrity = styleInfo.integrity;
        if (styleInfo.crossorigin) link.crossOrigin = styleInfo.crossorigin;

        link.onload = () => {
          this.loadedStyles.add(styleInfo.url);
          resolve();
        };
        
        link.onerror = () => {
          console.warn(`Failed to load stylesheet: ${styleInfo.url}`);
          resolve(); // Don't fail the entire page load
        };

        document.head.appendChild(link);
      });
    });

    await Promise.allSettled(promises);
  }

  /**
   * Inject inline styles
   */
  injectInlineStyles(inlineStyles) {
    inlineStyles.forEach((styleContent, index) => {
      const styleId = `injected-style-${Date.now()}-${index}`;
      
      if (!document.getElementById(styleId)) {
        const style = document.createElement('style');
        style.id = styleId;
        style.textContent = styleContent;
        document.head.appendChild(style);
      }
    });
  }

  /**
   * Load external scripts
   */
  async loadExternalScripts(externalScripts) {
    // Sort scripts by execution order (defer scripts last)
    const immediateScripts = externalScripts.filter(s => !s.defer);
    const deferredScripts = externalScripts.filter(s => s.defer);

    // Load immediate scripts first
    for (const scriptInfo of immediateScripts) {
      if (!this.loadedScripts.has(scriptInfo.url)) {
        await this.loadSingleScript(scriptInfo);
      }
    }

    // Load deferred scripts
    for (const scriptInfo of deferredScripts) {
      if (!this.loadedScripts.has(scriptInfo.url)) {
        await this.loadSingleScript(scriptInfo);
      }
    }
  }

  /**
   * Load a single external script
   */
  loadSingleScript(scriptInfo) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = scriptInfo.url;
      script.type = scriptInfo.type;
      
      if (scriptInfo.async) script.async = true;
      if (scriptInfo.defer) script.defer = true;
      if (scriptInfo.integrity) script.integrity = scriptInfo.integrity;
      if (scriptInfo.crossorigin) script.crossOrigin = scriptInfo.crossorigin;

      script.onload = () => {
        this.loadedScripts.add(scriptInfo.url);
        console.log(`Script loaded: ${scriptInfo.url}`);
        resolve();
      };

      script.onerror = (error) => {
        console.error(`Failed to load script: ${scriptInfo.url}`, error);
        resolve(); // Don't fail entire page load
      };

      document.head.appendChild(script);
    });
  }

  /**
   * Execute inline scripts
   */
  async executeInlineScripts(inlineScripts) {
    for (const scriptInfo of inlineScripts) {
      try {
        if (scriptInfo.type === 'text/javascript' || !scriptInfo.type) {
          // Use indirect eval to execute in global scope
          (0, eval)(scriptInfo.content);
          console.log('Executed inline script');
        }
      } catch (error) {
        console.error('Inline script execution failed:', error);
        // Continue with other scripts
      }
    }
  }

  /**
   * Resolve relative URLs
   */
  resolveURL(url, basePath) {
    if (!url) return '';
    
    if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
      return url;
    }
    
    if (url.startsWith('/')) {
      return this.options.baseUrl + url.substring(1);
    }
    
    return this.options.baseUrl + basePath + url;
  }

  /**
   * Basic HTML sanitization (optional)
   */
  sanitizeHTML(html) {
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;
    
    // Remove potentially dangerous attributes
    const dangerousAttrs = ['onclick', 'onload', 'onerror', 'onmouseover'];
    const allElements = tempDiv.querySelectorAll('*');
    
    allElements.forEach(element => {
      dangerousAttrs.forEach(attr => {
        if (element.hasAttribute(attr)) {
          element.removeAttribute(attr);
        }
      });
    });
    
    return tempDiv.innerHTML;
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.pageCache.clear();
    console.log('Page loader cache cleared');
  }

  /**
   * Preload a page (fetch and cache but don't inject)
   */
  async preloadPage(pagePath, options = {}) {
    const config = { ...this.options, ...options };
    const content = await this.fetchPageContent(pagePath, config.timeout);
    const processedContent = await this.processContent(content, pagePath, config);
    
    const cacheKey = `${pagePath}-${JSON.stringify(config)}`;
    this.pageCache.set(cacheKey, processedContent);
    
    return processedContent;
  }
}

class SimpleRoute {
  constructor() {
    this.routes = new Map();
    this.registeredRoute = [];
  }

  route(action, callback) {
    if (typeof action !== 'string' || typeof callback !== 'function') {
      throw new TypeError('Action must be a string and callback must be a function');
    }
    const cleanAction = action.trim().replace(/^\/+|\/+$/g, '');
    this.registeredRoute.push(cleanAction);
    this.routes.set(cleanAction, callback);
  }

  dispatch(action) {
    if (typeof action !== 'string') {
      throw new TypeError('Action must be a string');
    }
    const cleanAction = action.trim().replace(/^\/+|\/+$/g, '');
    if (this.validateRoute(cleanAction)) {
      const callback = this.routes.get(cleanAction);
      return callback ? callback() : null;
    }
    return null;
  }

  validateRoute(action) {
    const cleanAction = action.trim().replace(/^\/+|\/+$/g, '');
    return this.registeredRoute.includes(cleanAction);
  }
}