class ContentScriptGuard {
  constructor() {
    // ALL input types monitored - not just password/email
    // This ensures global coverage across every website
    this.sensitiveSelectors = [
      'input[type=password]',
      'input[type=email]',
      'input[type=text]',
      'input[type=number]',
      'input[type=tel]',
      'input[type=search]',
      'input[name*=ssn]',
      'input[name*=social]',
      'input[name*=credit]',
      'input[name*=card]',
      'input[name*=cvv]',
      'input[name*=api]',
      'input[name*=account]',
      'input[name*=routing]',
      'input[name*=passport]',
      'input[name*=license]',
      'input[name*=dob]',
      'input[name*=birth]',
      'input[name*=phone]',
      'input[name*=mobile]',
      'input[name*=zip]',
      'input[name*=pin]',
      'select',
      'textarea'
    ];

    this.monitoredElements = new Set();
    this.currentAlerts = [];
    this.handleFormSubmissionBound = this.handleFormSubmission.bind(this);
    this.pageHostname = window.location.hostname;
    this.alertedFields = new Set(); // prevent repeat alerts on same field

    window.contentGuard = this;
    this.init();
  }

  isThirdPartyFormAction(formActionUrl) {
    try {
      const formDomain = new URL(formActionUrl, window.location.href).hostname;
      return formDomain !== this.pageHostname;
    } catch (e) {
      return false;
    }
  }

  async isTrustedFormActivity(formActionUrl) {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_WHITELIST' });
      const whitelist = Array.isArray(response) ? response : [];
      const actionHost = new URL(formActionUrl, window.location.href).hostname;
      return whitelist.includes(this.pageHostname) || whitelist.includes(actionHost);
    } catch (e) {
      return false;
    }
  }

  init() {
    // Check if real-time scanning is enabled before setting up monitoring
    chrome.storage.local.get(['settings'], (result) => {
      const settings = result.settings || {};
      // Only set up monitoring if real-time scanning is enabled
      if (settings.realTimeScanning !== false) {
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', () => this.setupMonitoring());
        } else {
          this.setupMonitoring();
        }
      }
    });

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'SCAN_PAGE') {
        // Check if real-time scanning is enabled before allowing manual scans
        chrome.storage.local.get(['settings'], (result) => {
          const settings = result.settings || {};
          if (settings.realTimeScanning === false) {
            // Real-time scanning is disabled, so manual scans are also disabled
            sendResponse({ safe: false, reasons: ['Extension is disabled. Enable Real-Time Scanning to use it.'] });
            return;
          }
          // Real-time scanning is enabled, proceed with scan
          this.runPageScan().then(result => sendResponse(result)).catch(() => {
            sendResponse({ safe: false, reasons: ['Scan failed due to an internal error.'] });
          });
        });
        return true;
      }
      switch (message.type) {
        case 'SHOW_ALERT':
          if (message.alert) this.showInPageAlert(message.alert);
          break;
        case 'HIGHLIGHT_RISKS':
          this.highlightRiskyElements();
          break;
      }
    });
  }

  async logDetectionEvent(eventType, sensitiveData, extra = {}) {
    try {
      await chrome.runtime.sendMessage({
        type: 'LOG_DETECTION_EVENT',
        payload: {
          eventType,
          sensitiveData,
          url: window.location.href,
          ...extra
        }
      });
    } catch (_) {}
  }

  setupMonitoring() {
    // Monitor all form submissions globally
    document.addEventListener('submit', this.handleFormSubmissionBound, true);

    // Monitor all input changes globally - catches every field on every website
    document.addEventListener('input', this.handleInputChange.bind(this), true);

    // Monitor paste globally
    document.addEventListener('paste', this.handlePaste.bind(this), true);

    // Monitor copy globally
    document.addEventListener('copy', this.handleCopy.bind(this), true);

    // Monitor autofill (change event on trusted inputs)
    document.addEventListener('change', this.handleAutofill.bind(this), true);

    // Watch for dynamically added fields (SPAs, popups, modals)
    this.setupMutationObserver();

    // Scan all fields already on the page
    this.scanExistingElements();
  }

  async handleFormSubmission(event) {
    const form = event.target;
    if (!form || form.tagName !== 'FORM') return;

    // Intercept the submission before it goes out
    event.preventDefault();

    const formAction = form.action || window.location.href;
    const isThirdPartyForm = this.isThirdPartyFormAction(formAction);

    // Collect ALL fields in the form
    const formData = new FormData(form);
    const dataString = Array.from(formData.entries())
      .map(([key, value]) => `${key}: ${value}`)
      .join(' ');

    // Also collect values directly from input elements
    const allInputs = form.querySelectorAll('input, textarea, select');
    const extraData = Array.from(allInputs)
      .map(el => `${el.name || el.id || el.type}: ${el.value}`)
      .join(' ');

    const combinedData = dataString + ' ' + extraData;

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: combinedData,
        url: window.location.href,
        isThirdPartyForm,
        formAction
      });

      const hasSensitiveData = result && result.sensitiveData && result.sensitiveData.length > 0;

      if (hasSensitiveData) {
        // Log to background for the alerts panel
        await this.logDetectionEvent(
          isThirdPartyForm ? 'third_party_data_leak' : 'data_transmission',
          result.sensitiveData,
          { formAction, isThirdParty: isThirdPartyForm, severity: 'medium' }
        );

        // Store alert silently - no popup shown to user
        // Let the submission proceed - alert is logged to background
        // (No visible warnings or blocking for seamless user experience)
      }

      // No sensitive data OR user chose "Continue Anyway" — submit normally
      form.removeEventListener('submit', this.handleFormSubmissionBound, true);
      form.submit();

    } catch (_) {
      // If background is unreachable, allow submission (fail open)
      form.removeEventListener('submit', this.handleFormSubmissionBound, true);
      form.submit();
    }
  }

  handleInputChange(event) {
    const input = event.target;
    // Monitor ALL input/textarea/select elements globally
    if (!input || !['INPUT', 'TEXTAREA', 'SELECT'].includes(input.tagName)) return;
    if (!input.value || input.value.length < 6) return;

    // Skip fields we have already alerted on with the same value
    const fieldKey = (input.name || input.id || input.type || 'field') + ':' + input.value;
    if (this.alertedFields.has(fieldKey)) return;

    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: input.value,
        url: window.location.href
      }).then(result => {
        if (result && result.sensitiveData && result.sensitiveData.length > 0) {
          this.alertedFields.add(fieldKey);
          // Prevent alertedFields from growing forever
          if (this.alertedFields.size > 200) this.alertedFields.clear();

          // Log to background silently - no visual indicators
          this.logDetectionEvent('input_detection', result.sensitiveData, { severity: 'medium' });
        }
      }).catch(() => {});
    } catch (_) {}
  }

  handlePaste(event) {
    const pastedText = event.clipboardData?.getData('text') || '';
    if (!pastedText) return;
    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: pastedText,
        url: window.location.href
      }).then(result => {
        if (result && result.sensitiveData && result.sensitiveData.length > 0) {
          // Log detection silently - no popup shown
          this.logDetectionEvent('paste_warning', result.sensitiveData, { severity: 'medium' });
        }
      }).catch(() => {});
    } catch (_) {}
  }

  handleCopy(event) {
    const selection = window.getSelection()?.toString() || '';
    if (selection.length < 10) return;
    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: selection,
        url: window.location.href
      }).then(result => {
        if (result && result.sensitiveData && result.sensitiveData.length > 0) {
          // Log detection silently - no popup shown
          this.logDetectionEvent('copy_warning', result.sensitiveData, { severity: 'low' });
        }
      }).catch(() => {});
    } catch (_) {}
  }

  handleAutofill(event) {
    const input = event.target;
    if (input.tagName !== 'INPUT' || !event.isTrusted) return;
    setTimeout(() => {
      if (!input.value) return;
      try {
        chrome.runtime.sendMessage({
          type: 'SCAN_DATA',
          data: input.value,
          url: window.location.href
        }).then(result => {
          if (result && result.sensitiveData && result.sensitiveData.length > 0) {
            // Log detection silently - no tooltip shown
            this.logDetectionEvent('autofill_detection', result.sensitiveData, { severity: 'medium' });
          }
        }).catch(() => {});
      } catch (_) {}
    }, 100);
  }

  setupMutationObserver() {
    const observer = new MutationObserver(mutations => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === 1) this.scanNewElement(node);
        });
      });
    });
    // Observe the whole document for dynamically loaded forms (SPAs, modals, iframes)
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  scanExistingElements() {
    this.sensitiveSelectors.forEach(sel => {
      document.querySelectorAll(sel).forEach(el => this.monitorElement(el));
    });
  }

  scanNewElement(node) {
    this.sensitiveSelectors.forEach(sel => {
      if (node.matches && node.matches(sel)) this.monitorElement(node);
      node.querySelectorAll && node.querySelectorAll(sel).forEach(el => this.monitorElement(el));
    });
  }

  monitorElement(el) {
    if (this.monitoredElements.has(el)) return;
    this.monitoredElements.add(el);
    this.addIndicator(el);
  }

  isSensitiveInput(el) {
    const sensitiveTypes = ['password', 'email', 'tel', 'number'];
    const sensitiveNames = [
      'ssn', 'social', 'credit', 'card', 'cvv', 'api',
      'account', 'routing', 'passport', 'license', 'dob',
      'birth', 'phone', 'mobile', 'pin', 'zip', 'secret', 'token'
    ];
    return sensitiveTypes.includes(el.type) || sensitiveNames.some(name =>
      (el.name && el.name.toLowerCase().includes(name)) ||
      (el.id && el.id.toLowerCase().includes(name)) ||
      (el.className && el.className.toLowerCase().includes(name))
    );
  }

  addIndicator(el) {
    const indicator = document.createElement('div');
    indicator.className = 'secureguard-indicator';
    indicator.textContent = '🛡️';
    indicator.style.cssText = `
      position: absolute;
      right: 5px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 12px;
      opacity: 0.6;
      pointer-events: none;
      z-index: 9999;
    `;
    const parent = el.parentElement;
    if (parent && getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }
    parent?.appendChild(indicator);
  }

  highlightElement(el, type) {
    const color = type === 'warning' ? '#FFC107' : '#F44336';
    el.style.border = `2px solid ${color}`;
    el.style.boxShadow = `0 0 8px ${color}aa`;
  }

  highlightRiskyElements() {
    this.sensitiveSelectors.forEach(sel => {
      document.querySelectorAll(sel).forEach(el => this.highlightElement(el, 'warning'));
    });
  }

  showTooltip(el, msg) {
    // Tooltips disabled - alerts stored silently
    return;
  }

  async showSubmissionWarning(scanResult, formAction) {
    // No warning modal shown - alert stored silently
    return Promise.resolve(false);
  }

  createWarningModal(scanResult, formAction, resolve) {
    document.querySelectorAll('.secureguard-modal').forEach(m => m.remove());
    const modal = document.createElement('div');
    modal.className = 'secureguard-modal';
    modal.style.cssText = `
      position: fixed;
      top: 0; left: 0;
      width: 100vw; height: 100vh;
      background: rgba(0,0,0,0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 100000;
      font-family: Arial, sans-serif;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white;
      border-radius: 8px;
      padding: 20px;
      max-width: 420px;
      width: 92vw;
      max-height: 80vh;
      overflow-y: auto;
      position: relative;
      color: #222;
    `;

    // Show only types, never raw values
    const dataList = scanResult.sensitiveData?.map(d => `<li>${d.type.replace(/_/g, ' ')}</li>`).join('') || '<li>Detected sensitive data.</li>';
    const recList = scanResult.recommendations?.map(r => `<li>${r}</li>`).join('') || '<li>Please review before proceeding.</li>';

    let destHost = formAction;
    try { destHost = new URL(formAction).hostname; } catch (_) {}

    content.innerHTML = `
      <h2 style="color:#d32f2f; margin:0 0 12px;">⚠️ Potential Data Leak Detected</h2>
      <p style="margin:0 0 8px;font-size:13px;color:#555;">Submitting to: <strong>${destHost}</strong></p>
      <p style="margin:0 0 6px;font-size:13px;font-weight:600;">Detected sensitive data types:</p>
      <ul style="margin:0 0 12px;padding-left:18px;font-size:13px;">${dataList}</ul>
      <p style="margin:0 0 6px;font-size:13px;font-weight:600;">Recommendations:</p>
      <ul style="margin:0 0 16px;padding-left:18px;font-size:13px;">${recList}</ul>
      <div style="text-align:right;">
        <button id="blockBtn" style="background:#d32f2f; color:white; margin-right:10px; padding:10px 20px; border:none; border-radius:4px; cursor:pointer; font-size:14px;">Block Submission</button>
        <button id="continueBtn" style="background:#4caf50; color:white; padding:10px 20px; border:none; border-radius:4px; cursor:pointer; font-size:14px;">Continue Anyway</button>
      </div>
      <button id="closeBtn" style="position:absolute; top:10px; right:10px; background:none; border:none; font-size:24px; cursor:pointer; color:#555;">&times;</button>
    `;

    content.querySelector('#blockBtn').onclick = () => { modal.remove(); resolve(true); };
    content.querySelector('#continueBtn').onclick = () => { modal.remove(); resolve(false); };
    content.querySelector('#closeBtn').onclick = () => { modal.remove(); resolve(true); };
    modal.onclick = e => { if (e.target === modal) { modal.remove(); resolve(true); } };
    modal.appendChild(content);
    return modal;
  }

  async runPageScan() {
    // Scan ALL field values on the current page
    let combinedData = '';
    document.querySelectorAll('input, textarea, select').forEach(el => {
      if (el.value && el.value.length > 0) {
        combinedData += `${el.name || el.id || el.type}: ${el.value} `;
      }
    });

    try {
      const result = await chrome.runtime.sendMessage({
        type: 'SCAN_DATA',
        data: combinedData,
        url: window.location.href
      });

      const sensitiveData = Array.isArray(result?.sensitiveData) ? result.sensitiveData : [];
      const recommendations = Array.isArray(result?.recommendations) ? result.recommendations : [];
      const hasSensitiveData = sensitiveData.length > 0;
      const hasMaliciousReputation = result?.reputation?.malicious === true;
      const isSecureTransport = window.location.protocol === 'https:';

      const reasons = [];
      if (hasSensitiveData) {
        const types = sensitiveData.map(d => d.type).filter(Boolean).join(', ');
        reasons.push(`Sensitive data detected: ${types}`);
      }
      if (hasMaliciousReputation) {
        reasons.push('Site reputation indicates potential malicious activity.');
      }
      if (!isSecureTransport) {
        reasons.push('Page is not using HTTPS.');
      }

      const safe = !(hasSensitiveData || hasMaliciousReputation || !isSecureTransport);

      if (!safe && hasSensitiveData) {
        this.logDetectionEvent('scan_result', sensitiveData, { severity: 'medium' });
      }

      return {
        safe,
        reasons: reasons.length ? reasons : recommendations,
        detectedTypes: sensitiveData.map(d => d.type).filter(Boolean),
        url: window.location.href
      };
    } catch (e) {
      console.error('SecureGuard scan error:', e);
      return {
        safe: false,
        reasons: ['Scan failed due to an internal error.'],
        detectedTypes: [],
        url: window.location.href
      };
    }
  }

  showInPageAlert(alert) {
    // In-page alerts disabled - all alerts stored silently only
    return;
  }
}

const contentGuard = new ContentScriptGuard();