/* public/app.js */
import { 
  t, setLocale, getLocale, 
  getCompactRoleName, getCompactModelName, 
  getCompactTemplateName, getCompactIntentName, getCompactArbitrationText 
} from './i18n.js?v=1791660000000';

function localToast(message, type = 'error') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

let user = null;
let selectedFiles = [];
const MAX_TOTAL_SIZE = 20 * 1024 * 1024; // 20MB
const MAX_FILES = 5;

function formatFileSize(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const size = bytes / Math.pow(1024, i);
  return `${size.toFixed(size < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

// --- Secure Markdown Sanitization Pipeline (DOMPurify + marked) ---
function safeRenderMarkdown(rawText) {
  if (!rawText) return '';
  let html = '';
  if (window.marked && typeof window.marked.parse === 'function') {
    try {
      html = window.marked.parse(rawText);
    } catch (e) {
      html = `<pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(rawText)}</pre>`;
    }
  } else {
    html = `<pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(rawText)}</pre>`;
  }

  // Sanitize with DOMPurify if present to eliminate any XSS vulnerability
  if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
    return window.DOMPurify.sanitize(html, {
      ADD_ATTR: ['target', 'rel'],
      FORBID_TAGS: ['style', 'script', 'iframe', 'object', 'embed', 'form'],
      FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur']
    });
  }

  // Fail-Closed: Never output unverified marked HTML if DOMPurify is unavailable
  console.warn('[Security] DOMPurify unavailable. Failing closed to escaped plain text.');
  return `<pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(rawText)}</pre>`;
}
window.safeRenderMarkdown = safeRenderMarkdown;
window.renderMarkdownToHtml = safeRenderMarkdown;

window.showModal = function(title, body, primaryText = null, primaryAction = null, showCancel = true) {
  document.getElementById('modal-title').innerHTML = `
    <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="var(--accent-color)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"></circle>
      <line x1="12" y1="16" x2="12" y2="12"></line>
      <line x1="12" y1="8" x2="12.01" y2="8"></line>
    </svg>
    <span>${title}</span>
  `;
  document.getElementById('modal-body').innerHTML = body;
  
  const primaryBtn = document.getElementById('modal-primary-btn');
  if (primaryBtn) {
    primaryBtn.textContent = primaryText || t('common.gotIt');
    primaryBtn.onclick = () => {
      if (primaryAction) primaryAction();
      else window.hideModal();
    };
  }
  
  const cancelBtn = document.querySelector('#modal-footer .btn-outline');
  if (cancelBtn) {
    cancelBtn.style.display = showCancel ? 'inline-block' : 'none';
  }
  
  document.getElementById('modal-overlay').classList.add('active');
}

window.hideModal = function() {
  document.getElementById('modal-overlay').classList.remove('active');
}

window.cachedOAuthBindings = [];

function setupBindButton(provider, currentBindings) {
  const btn = document.getElementById(`bind-${provider}-btn`);
  if (!btn) return;
  const isBound = Array.isArray(currentBindings) && currentBindings.includes(provider);
  
  const isEn = getLocale() === 'en';
  if (isBound) {
    btn.setAttribute('data-i18n', 'settings.account.unbind');
    btn.textContent = isEn ? 'Unlink' : '解绑';
    btn.className = 'oauth-btn-text unbind';
    btn.onclick = () => {
      window.showModal(
        isEn ? 'Confirm Unlink' : '确认解绑',
        `<p style="margin-bottom: 1rem; color: var(--text-secondary);">${isEn ? `Are you sure you want to unlink ${provider}? You may no longer be able to log in with this account.` : `您确定要解绑 ${provider} 吗？解绑后您可能无法通过该渠道登录。`}</p>`,
        isEn ? 'Unlink' : '确认解绑',
        async () => {
          window.hideModal();
          try {
            const res = await fetch(`/api/auth/oauth/${provider}`, { method: 'DELETE' });
            const data = await res.json();
            if (res.ok) {
              await window.refreshOAuthBindings();
            } else {
              setTimeout(() => {
                const errStr = data.error === 'Cannot unbind last login method without a password.' ? t('error.cannotUnbind') : (data.error || t('error.unbindFailed'));
                window.showModal(t('error.unbindFailedTitle'), `<p style="color: var(--error-color)">${errStr}</p>`, null, null, false);
              }, 300);
            }
          } catch (e) {
            setTimeout(() => {
              window.showModal(t('error.unbindFailedTitle'), `<p style="color: var(--error-color)">${t('error.unbindFailed')}</p>`, null, null, false);
            }, 300);
          }
        }
      );
    };
  } else {
    btn.setAttribute('data-i18n', 'settings.account.bind');
    btn.textContent = isEn ? 'Link' : '绑定';
    btn.className = 'oauth-btn-text bind';
    btn.onclick = () => {
      window.location.href = `/api/auth/${provider}?action=bind`;
    };
  }
}

window.refreshOAuthBindings = async function() {
  try {
    const bindRes = await fetch('/api/user/bindings');
    if (bindRes.ok) {
      const data = await bindRes.json();
      window.cachedOAuthBindings = Array.isArray(data.bindings) ? data.bindings : [];
      setupBindButton('github', window.cachedOAuthBindings);
      setupBindButton('google', window.cachedOAuthBindings);
    }
  } catch (e) {
    console.error('Failed to fetch bindings', e);
  }
};

// --- Passkey (WebAuthn) Management ---
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBuffer(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function getDefaultDeviceName() {
  const isEn = (localStorage.getItem('nanomesh-lang') || (window.i18n ? window.i18n.getLocale() : 'zh')) === 'en';
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua)) return isEn ? 'Apple Device' : '苹果设备';
  if (/Mac OS X/.test(ua)) return isEn ? 'MacBook / Mac' : 'Mac 设备';
  if (/Windows/.test(ua)) return 'Windows Hello';
  if (/Android/.test(ua)) return isEn ? 'Android Device' : '安卓设备';
  if (/Linux/.test(ua)) return isEn ? 'Linux Device' : 'Linux 设备';
  return isEn ? 'Passkey' : '通行密钥';
}

function promptPasskeyName(defaultName) {
  return new Promise((resolve) => {
    const isEn = (localStorage.getItem('nanomesh-lang') || (window.i18n ? window.i18n.getLocale() : 'zh')) === 'en';
    const title = isEn ? 'Name Your Passkey' : '设置密钥名称';
    const desc = isEn 
      ? 'Set a recognizable name for this device before registering:' 
      : '请在验证前为该通行密钥设置一个便于识别的备注名称：';
    const inputLabel = isEn ? 'Device Name' : '设备名称';
    const placeholder = isEn ? 'e.g. MacBook Touch ID, Windows Hello' : '例如：MacBook 指纹、Windows Hello';
    const confirmText = isEn ? 'Continue & Verify' : '下一步 · 验证硬件';
    const cancelText = isEn ? 'Cancel' : '取消';

    const bodyHtml = `
      <div style="margin: 0.25rem 0;">
        <p style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 0.85rem;">
          ${desc}
        </p>
        <div style="display: flex; flex-direction: column; gap: 0.4rem;">
          <label style="font-size: 0.75rem; font-weight: 600; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">${inputLabel}</label>
          <input type="text" id="modal-passkey-name-input" class="input-field" 
            value="${(defaultName || '').replace(/"/g, '&quot;')}" 
            placeholder="${placeholder}" 
            style="width: 100%; box-sizing: border-box; padding: 0.65rem 0.85rem; border-radius: 8px; font-size: 0.9rem;"
            maxlength="40"
          />
        </div>
      </div>
    `;

    const cancelBtn = document.querySelector('#modal-footer .btn-outline');
    if (cancelBtn) {
      cancelBtn.textContent = cancelText;
      cancelBtn.onclick = () => {
        window.hideModal();
        resolve(null);
      };
    }

    window.showModal(
      title,
      bodyHtml,
      confirmText,
      () => {
        const input = document.getElementById('modal-passkey-name-input');
        const val = input ? input.value.trim() : '';
        window.hideModal();
        resolve(val || defaultName);
      },
      true
    );

    setTimeout(() => {
      const input = document.getElementById('modal-passkey-name-input');
      if (input) {
        input.focus();
        input.select();
        input.onkeydown = (e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            const primaryBtn = document.getElementById('modal-primary-btn');
            if (primaryBtn) primaryBtn.click();
          }
        };
      }
    }, 60);
  });
}

function confirmPasskeyDelete(deviceName) {
  return new Promise((resolve) => {
    const isEn = (localStorage.getItem('nanomesh-lang') || (window.i18n ? window.i18n.getLocale() : 'zh')) === 'en';
    const title = isEn ? 'Delete Passkey' : '删除通行密钥';
    const safeName = (deviceName || (isEn ? 'Passkey' : '通行密钥')).replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const bodyHtml = `
      <p style="color: var(--text-secondary); font-size: 0.875rem; line-height: 1.5; margin: 0.25rem 0;">
        ${isEn 
          ? `Are you sure you want to delete passkey <strong>${safeName}</strong>? You will no longer be able to use this device to sign in.` 
          : `确定要删除通行密钥 <strong>${safeName}</strong> 吗？删除后将无法使用该设备进行免密登录。`}
      </p>
    `;
    const cancelBtn = document.querySelector('#modal-footer .btn-outline');
    if (cancelBtn) {
      cancelBtn.textContent = isEn ? 'Cancel' : '取消';
      cancelBtn.onclick = () => {
        window.hideModal();
        resolve(false);
      };
    }

    window.showModal(
      title,
      bodyHtml,
      isEn ? 'Delete' : '确认删除',
      () => {
        window.hideModal();
        resolve(true);
      },
      true
    );
  });
}

window.refreshPasskeys = async function() {
  const container = document.getElementById('passkey-list-container');
  if (!container) return;

  const isEn = (localStorage.getItem('nanomesh-lang') || (window.i18n ? window.i18n.getLocale() : 'zh')) === 'en';
  const emptyText = isEn ? 'No passkeys registered yet. Click the button above to add one.' : '暂未绑定通行密钥，点击右上角添加';
  const addedLabel = isEn ? 'Added' : '添加于';
  const lastUsedLabel = isEn ? 'Last used' : '最后使用';
  const defaultName = isEn ? 'My Passkey' : '我的通行密钥';
  const deleteTitle = isEn ? 'Delete Passkey' : '删除密钥';

  try {
    const res = await fetch('/api/auth/passkey/list');
    if (!res.ok) {
      container.innerHTML = `<div class="passkey-empty" style="text-align: center; padding: 1.25rem 0; color: var(--text-secondary); font-size: 0.85rem;">${emptyText}</div>`;
      return;
    }
    const data = await res.json();
    const passkeys = Array.isArray(data.passkeys) ? data.passkeys : [];

    if (passkeys.length === 0) {
      container.innerHTML = `<div class="passkey-empty" style="text-align: center; padding: 1.25rem 0; color: var(--text-secondary); font-size: 0.85rem;">${emptyText}</div>`;
      return;
    }

    container.innerHTML = passkeys.map(pk => {
      const addedDate = pk.created_at ? pk.created_at.split(' ')[0] : '-';
      const lastUsedDate = pk.last_used_at ? pk.last_used_at.split(' ')[0] : '-';
      const safeName = (pk.device_name || defaultName).replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `
        <div class="passkey-item">
          <div class="passkey-item-left">
            <div class="passkey-item-icon">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="7.5" cy="15.5" r="4.5"></circle>
                <path d="m21 2-9.6 9.6"></path>
                <path d="m15.5 7.5 3 3"></path>
              </svg>
            </div>
            <div class="passkey-item-info">
              <div class="passkey-item-name">${safeName}</div>
              <div class="passkey-item-meta">${addedLabel} ${addedDate} · ${lastUsedLabel} ${lastUsedDate}</div>
            </div>
          </div>
          <button class="passkey-btn-delete" data-id="${escapeHtml(pk.credential_id)}" data-name="${safeName}" title="${escapeHtml(deleteTitle)}">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
          </button>
        </div>
      `;
    }).join('');

    // Bind delete buttons using custom modal
    container.querySelectorAll('.passkey-btn-delete').forEach(btn => {
      btn.addEventListener('click', async () => {
        const credId = btn.getAttribute('data-id');
        const deviceName = btn.getAttribute('data-name');
        if (!credId) return;

        const confirmed = await confirmPasskeyDelete(deviceName);
        if (!confirmed) return;

        btn.disabled = true;
        btn.style.opacity = '0.5';

        try {
          const delRes = await fetch(`/api/auth/passkey/${encodeURIComponent(credId)}`, {
            method: 'DELETE'
          });
          const delData = await delRes.json().catch(() => ({}));

          if (delRes.ok) {
            localToast(isEn ? 'Passkey deleted' : '通行密钥已删除', 'success');
            await window.refreshPasskeys();
          } else {
            localToast(t(delData.error || 'error.deleteFailed'));
            btn.disabled = false;
            btn.style.opacity = '1';
          }
        } catch (err) {
          localToast(t('error.networkError'));
          btn.disabled = false;
          btn.style.opacity = '1';
        }
      });
    });
  } catch (err) {
    console.error('Failed to load passkeys:', err);
    container.innerHTML = `<div class="passkey-empty" style="text-align: center; padding: 1.25rem 0; color: var(--text-secondary); font-size: 0.85rem;">${emptyText}</div>`;
  }
};

window.handleAddPasskey = async function() {
  const isEn = (localStorage.getItem('nanomesh-lang') || (window.i18n ? window.i18n.getLocale() : 'zh')) === 'en';

  if (!window.PublicKeyCredential) {
    localToast(t('auth.passkeyUnsupported'));
    return;
  }

  // 1. Show custom modal for device name FIRST (no native prompt!)
  const chosenName = await promptPasskeyName(getDefaultDeviceName());
  if (chosenName === null) {
    // User cancelled modal
    return;
  }

  const addBtn = document.getElementById('btn-add-passkey');
  const originalHtml = addBtn ? addBtn.innerHTML : '';
  if (addBtn) {
    addBtn.disabled = true;
    addBtn.style.opacity = '0.6';
  }

  try {
    const optRes = await fetch('/api/auth/passkey/register/options', { method: 'POST' });
    if (!optRes.ok) {
      const err = await optRes.json().catch(() => ({}));
      localToast(t(err.error || 'error.networkError'));
      return;
    }

    const options = await optRes.json();
    options.challenge = base64UrlToBuffer(options.challenge);
    options.user.id = base64UrlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c,
        id: base64UrlToBuffer(c.id)
      }));
    }

    localToast(isEn ? 'Please complete biometric or key touch...' : '请在弹出的系统对话框中验证指纹或安全密钥...', 'info');

    const credential = await navigator.credentials.create({ publicKey: options });
    if (!credential) {
      localToast(t('auth.passkeyCancelled'));
      return;
    }

    const verifyPayload = {
      id: credential.id,
      rawId: bufferToBase64Url(credential.rawId),
      type: credential.type,
      deviceName: chosenName.trim(),
      response: {
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64Url(credential.response.attestationObject),
        publicKey: credential.response.getPublicKey ? bufferToBase64Url(credential.response.getPublicKey()) : null,
        publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm ? credential.response.getPublicKeyAlgorithm() : -7,
        transports: credential.response.getTransports ? credential.response.getTransports() : ['internal']
      }
    };

    const verifyRes = await fetch('/api/auth/passkey/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(verifyPayload)
    });

    if (verifyRes.ok) {
      localToast(isEn ? 'Passkey registered successfully' : '通行密钥已成功添加', 'success');
      await window.refreshPasskeys();
    } else {
      const err = await verifyRes.json().catch(() => ({}));
      localToast(t(err.error || 'error.networkError'));
    }
  } catch (err) {
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
      localToast(t('auth.passkeyCancelled'));
    } else {
      console.error('[Passkey] Registration error:', err);
      localToast(t('error.networkError'));
    }
  } finally {
    if (addBtn) {
      addBtn.disabled = false;
      addBtn.style.opacity = '1';
      if (originalHtml) addBtn.innerHTML = originalHtml;
    }
  }
};

// Global settings modal opener hoisted to top-level to prevent race conditions during early URL hash navigation
window.openSettingsModal = function(tabName = 'account') {
  const overlay = document.getElementById('settings-modal-overlay');
  if (!overlay) return;
  overlay.style.display = 'flex';
  const userMenu = document.getElementById('user-menu');
  if (userMenu) userMenu.style.display = 'none';
  const targetNav = document.querySelector(`.settings-nav-item[data-tab="${tabName}"]`);
  if (targetNav) targetNav.click();
  if (typeof window.fetchUserData === 'function') {
    window.fetchUserData();
  }
  if (window.refreshOAuthBindings) {
    window.refreshOAuthBindings();
  }
  if (window.refreshPasskeys) {
    window.refreshPasskeys();
  }
};

document.addEventListener('DOMContentLoaded', async () => {

  // Billing Filters
  const billingFilters = document.querySelectorAll('.billing-filter-pill');
  if (billingFilters.length > 0) {
    billingFilters.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetBtn = e.target.closest('.billing-filter-pill');
        if (!targetBtn) return;
        billingFilters.forEach(b => b.classList.remove('active'));
        targetBtn.classList.add('active');
        const filter = targetBtn.getAttribute('data-filter');
        window.currentBillingFilter = filter;
        window.loadBillingLedger(filter);
      });
    });
  }
  
  
  window.ledgerCache = {};
  
  function renderLedger(data) {
    const tbody = document.getElementById('billing-tbody');
    if (!tbody) return;
    
    const gasEl = document.querySelector('.billing-hero-metric .billing-metric-value.text-emerald');
    if (gasEl) {
      gasEl.innerHTML = '+' + data.gasEarnedTotal + ' ⚡';
    }
    
    tbody.innerHTML = '';
    if (data.items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; font-size: 0.85rem; color: var(--text-secondary); padding: 2.5rem 0;">' + t('billing.empty') + '</td></tr>';
      return;
    }
    
    data.items.forEach(item => {
      const isPos = item.amount >= 0;
      const deltaClass = isPos ? 'text-emerald' : 'text-rose';
      const sign = isPos ? '+' : '';
      
      let i18nCat = '';
      if (item.category === 'signup_bonus' || item.category === 'topup' || item.category === 'gift_redeem') i18nCat = t('billing.category.topup');
      else if (item.category === 'compute_cost') i18nCat = t('billing.category.compute_cost');
      else if (item.category === 'gas_earned' || item.category === 'referral_reward') i18nCat = t('billing.category.gas_earned');
      
      let i18nTitle = item.title;
      if (item.category === 'signup_bonus') i18nTitle = t('billing.title.signup_bonus');
      else if (item.category === 'referral_reward') i18nTitle = t('billing.title.referral_reward');
      else if (item.category === 'gift_redeem') i18nTitle = t('billing.title.gift_redeem');
      
      const tr = document.createElement('tr');
      tr.className = 'billing-row';
      tr.innerHTML = `
        <td class="col-desc">
          <div class="billing-desc-row1">${escapeHtml(i18nTitle || '')}</div>
          <div class="billing-desc-row2" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%;">${escapeHtml(item.detail || '')}</div>
        </td>
        <td class="col-category">
          <span class="models-status models-status-published" style="white-space: nowrap;">
            <span class="models-status-dot"></span>${escapeHtml(i18nCat || '')}
          </span>
        </td>
        <td class="col-time">
          <span class="billing-time">${escapeHtml((item.created_at || '').substring(0, 16))}</span>
        </td>
        <td class="col-delta" style="text-align: right;">
          <div class="billing-delta-val ${deltaClass}">${sign}${Number(item.amount) || 0} ⚡</div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.loadBillingLedger = async function(category = 'all', page = 1) {
    if (typeof window.fetchUserData === 'function') {
      window.fetchUserData();
    }
    const tbody = document.getElementById('billing-tbody');
    if (!tbody) return;
    
    const cacheKey = category + '_' + page;
    
    if (!window.ledgerCache[cacheKey]) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; font-size: 0.85rem; color: var(--text-secondary); padding: 2.5rem 0;">' + t('dag.processing') + '</td></tr>';
    } else {
      renderLedger(window.ledgerCache[cacheKey]);
    }
    
    try {
      const res = await fetch('/api/user/ledger?category=' + category + '&page=' + page);
      if (!res.ok) throw new Error('Failed to load ledger');
      const data = await res.json();
      
      window.ledgerCache[cacheKey] = data;
      renderLedger(data);
    } catch (e) {
      if (!window.ledgerCache[cacheKey]) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; font-size: 0.85rem; color: var(--error-color); padding: 2.5rem 0;">Error loading data</td></tr>';
      }
    }
  };

  window.showInviteBubble = function(btn, e) {
    e.stopPropagation();
    const existing = document.querySelector('.invite-copy-bubble');
    if (existing) existing.remove();

    const bubble = document.createElement('div');
    bubble.className = 'invite-copy-bubble';
    bubble.addEventListener('click', (ev) => ev.stopPropagation());

    const wrapper = document.createElement('div');
    wrapper.className = 'invite-copy-input-wrapper';

    const input = document.createElement('input');
    input.className = 'invite-copy-input';
    const refCode = window.currentUser?.referral_code || 'demo_invite';
    const originalUrl = window.location.origin + '/register.html?ref=' + refCode;
    input.value = originalUrl;
    input.readOnly = true;

    const copyBtn = document.createElement('button');
    copyBtn.className = 'invite-copy-icon-btn';
    const originalIcon = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
    const copiedIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    copyBtn.innerHTML = originalIcon;
    
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(originalUrl).then(() => {
        copyBtn.classList.add('copied');
        copyBtn.innerHTML = copiedIcon;
        input.style.color = '#10b981';
        input.style.transition = 'color 0.2s';
        const isEn = window.i18n && window.i18n.getLocale() === 'en';
        input.value = isEn ? '✨ Copied to clipboard' : '✨ 已复制到剪贴板';
        
        setTimeout(() => {
          copyBtn.classList.remove('copied');
          copyBtn.innerHTML = originalIcon;
          input.style.color = '';
          input.value = originalUrl;
          input.select();
        }, 2000);
      });
    });

    wrapper.appendChild(input);
    wrapper.appendChild(copyBtn);
    bubble.appendChild(wrapper);
    btn.appendChild(bubble);

    const outsideClick = () => {
      bubble.style.opacity = '0';
      bubble.style.transition = 'opacity 0.2s';
      setTimeout(() => bubble.remove(), 200);
      document.removeEventListener('click', outsideClick);
    };
    setTimeout(() => document.addEventListener('click', outsideClick), 0);

    input.select();
  };

  document.addEventListener('click', () => {
    const existing = document.querySelector('.invite-copy-bubble');
    if (existing) existing.remove();
  });

  // Theme & Lang
  const savedTheme = localStorage.getItem('nanomesh-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('nanomesh-theme', newTheme);
  });

  document.getElementById('lang-toggle')?.addEventListener('click', () => {
    setLocale(getLocale() === 'zh' ? 'en' : 'zh');
    if (typeof updateLocalInferenceToggleUI === 'function') updateLocalInferenceToggleUI();
    if (window.cachedOAuthBindings) {
      setupBindButton('github', window.cachedOAuthBindings);
      setupBindButton('google', window.cachedOAuthBindings);
    }
    if (window.refreshPasskeys) window.refreshPasskeys();
    if (window.fetchNotifications) window.fetchNotifications();
    if (window.loadMessagesTab && document.getElementById('settings-tab-messages')?.classList.contains('active')) {
      window.loadMessagesTab();
    }
  });

  window.addEventListener('nanomesh-locale-changed', () => {
    if (typeof window.refreshPasskeys === 'function') {
      window.refreshPasskeys();
    }
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    if (typeof updateEstimation === 'function') {
      updateEstimation();
    }
    if (typeof updateRerouteButtonState === 'function') {
      updateRerouteButtonState();
    }
    const macroLabel = document.getElementById('macro-label') || document.querySelector('.macro-label');
    if (macroLabel) {
      const lockIcon = document.getElementById('macro-lock-icon');
      const isSnapshot = lockIcon && lockIcon.style.display !== 'none';
      macroLabel.textContent = isSnapshot ? (isEn ? 'Snapshot:' : '快照:') : (isEn ? 'Route:' : '当前路由:');
    }
    const routeChain = document.getElementById('macro-route-chain');
    const nodesForChain = (typeof activeDagNodes !== 'undefined' && activeDagNodes && activeDagNodes.length > 0)
      ? activeDagNodes
      : window.lastDagNodesToRender;
    if (routeChain && nodesForChain && nodesForChain.length > 0) {
      routeChain.textContent = nodesForChain.map(n => getCompactRoleName(n.role_id, n.name_zh, n.name_en)).join(' ➔ ');
    }
    if (typeof renderDagNodesWithAnchors === 'function' && window.lastDagNodesToRender) {
      renderDagNodesWithAnchors(window.lastDagNodesToRender, window.lastDagOptions || {});
    }
  });

  // Fetch Me
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      user = await res.json();
      
      const oldPasswordInput = document.getElementById('settings-old-password');
      if (oldPasswordInput) {
        const group = oldPasswordInput.closest('.form-group');
        if (group) {
          group.style.display = user.has_password ? 'block' : 'none';
        }
      }
      
      // Top header avatar
      if (user.avatar_url) {
        document.getElementById('user-avatar').innerHTML = `<img src="${escapeHtml(user.avatar_url)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
      } else {
        document.getElementById('user-avatar').textContent = user.username.charAt(0).toUpperCase();
      }
      
      // Dropdown menu state
      document.getElementById('user-menu-guest').style.display = 'none';
      document.getElementById('user-menu-auth').style.display = 'block';
      
      // Identity
      if (user.avatar_url) {
        document.getElementById('dropdown-avatar-img').src = user.avatar_url;
        document.getElementById('dropdown-avatar-img').style.display = 'block';
        document.getElementById('dropdown-avatar-text').style.display = 'none';
      } else {
        document.getElementById('dropdown-avatar-img').style.display = 'none';
        document.getElementById('dropdown-avatar-text').textContent = user.username.charAt(0).toUpperCase();
        document.getElementById('dropdown-avatar-text').style.display = 'flex';
      }
      
      document.getElementById('dropdown-username').textContent = user.username;
      document.getElementById('dropdown-email').textContent = user.email;

      // Settings Modal population
      const settingsUsernameInput = document.getElementById('settings-username-input');
      const settingsUsernameDisplay = document.getElementById('settings-username-display');
      const settingsEmailDisplay = document.getElementById('settings-email-display');
      const settingsAvatarPreview = document.getElementById('settings-avatar-preview');
      
      if (settingsUsernameInput) settingsUsernameInput.value = user.username;
      if (settingsUsernameDisplay) settingsUsernameDisplay.textContent = user.username;
      if (settingsEmailDisplay) settingsEmailDisplay.textContent = user.email;
      
      if (settingsAvatarPreview && user.avatar_url) {
        settingsAvatarPreview.src = user.avatar_url;
      } else if (settingsAvatarPreview) {
        // Fallback transparent or default
        settingsAvatarPreview.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 72 72"><rect fill="rgba(0,0,0,0.1)" width="72" height="72"/><text x="50%" y="50%" font-size="24" text-anchor="middle" dy=".3em" fill="%23fff">' + user.username.charAt(0).toUpperCase() + '</text></svg>';
      }

      const avatarBtn = document.getElementById('avatar-upload-btn');
      if (avatarBtn && user.avatar_updated_at) {
        const lastUpdate = new Date(user.avatar_updated_at.replace(' ', 'T') + 'Z').getTime();
        if (Date.now() - lastUpdate < 24 * 60 * 60 * 1000) {
          avatarBtn.style.opacity = '0.5';
          avatarBtn.style.pointerEvents = 'none';
          avatarBtn.title = t('error.avatarCooldown');
        } else {
          avatarBtn.style.opacity = '1';
          avatarBtn.style.pointerEvents = 'auto';
          avatarBtn.title = '';
        }
      }
      
      // Quota
      window.currentUser = user;
      window.historyAccountId = user.user_id;
      document.getElementById('dropdown-points').textContent = (user.credits || 0);
      const settingsPoints = document.getElementById('settings-points-display');
      if (settingsPoints) settingsPoints.textContent = (user.credits || 0);
      
      const frozenDisplay = document.querySelector('.billing-hero-metric .billing-metric-value.text-muted');
      if (frozenDisplay) frozenDisplay.textContent = (user.frozen_credits || 0) + ' ⚡';
      
      // Credits pill on header
      const creditsDisplay = document.getElementById('credits-display');
      if (creditsDisplay) creditsDisplay.textContent = user.credits || 0;

      window.fetchUserData = async function() {
        try {
          const res = await fetch('/api/auth/me');
          if (res.ok) {
            const data = await res.json();
            if (window.historyAccountId !== data.user_id) {
              window.historyAccountId = null;
              renderHistoryList();
              window.location.reload();
              return;
            }
            window.currentUser = data;
            user = data;
            const cd = document.getElementById('credits-display');
            if (cd) cd.textContent = data.credits || 0;
            const dp = document.getElementById('dropdown-points');
            if (dp) dp.textContent = data.credits || 0;
            const sp = document.getElementById('settings-points-display');
            if (sp) sp.textContent = data.credits || 0;
            const fd = document.querySelector('.billing-hero-metric .billing-metric-value.text-muted');
            if (fd) fd.textContent = (data.frozen_credits || 0) + ' ⚡';
            return data;
          }
        } catch (err) {
          console.warn('Failed to fetch user data:', err);
        }
      };

      // Fetch bindings
      await window.refreshOAuthBindings();
      if (window.refreshPasskeys) {
        window.refreshPasskeys();
      }

      // Restore persistent chat history from cloud D1
      if (typeof fetchCloudHistory === 'function') {
        fetchCloudHistory();
      }
      
    } else {
      document.getElementById('user-menu-auth').style.display = 'none';
      document.getElementById('user-menu-guest').style.display = 'block';
      
      document.getElementById('login-btn-guest').addEventListener('click', (e) => {
        e.preventDefault();
        window.location.href = '/login.html';
      });
    }

  } catch (err) {
    console.error('Auth error', err);
  }

  // User Menu
  const menuBtn = document.getElementById('user-menu-btn');
  const menu = document.getElementById('user-menu');
  menuBtn.addEventListener('click', () => {
    menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
  });
  document.addEventListener('click', (e) => {
    if (!menuBtn.contains(e.target)) menu.style.display = 'none';
  });

  document.getElementById('logout-btn')?.addEventListener('click', async () => {
    window.historyAccountId = null;
    renderHistoryList();
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/login.html';
  });

  async function executeDeleteAccount() {
    const res = await fetch('/api/user/delete', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      if (data.error === 'error.hasFrozenCredits') {
        window.showModal(
          getLocale() === 'zh' ? '注销受阻' : 'Deletion Blocked',
          t(data.error),
          t('common.gotIt'),
          () => window.hideModal()
        );
      } else {
        localToast(t(data.error || 'error.networkError'));
      }
    } else {
      window.location.href = '/login.html';
    }
  }

  function showDeleteAccountWarning() {
    const html = `
      <div style="text-align: left; color: var(--text-secondary); font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.5rem;">
        <ul style="padding-left: 1.5rem; margin: 0; display: flex; flex-direction: column; gap: 0.75rem;">
          <li>${t('deleteAccount.warn1')}</li>
          <li>${t('deleteAccount.warn2')}</li>
          <li>${t('deleteAccount.warn3')}</li>
          <li>${t('deleteAccount.warn4')}</li>
        </ul>
      </div>
    `;
    window.showModal(
      t('deleteAccount.title'),
      html,
      t('deleteAccount.confirm'),
      () => {
        window.hideModal();
        executeDeleteAccount();
      }
    );
  }

  document.getElementById('delete-account-btn')?.addEventListener('click', showDeleteAccountWarning);
  document.getElementById('delete-account-modal-btn')?.addEventListener('click', showDeleteAccountWarning);

  // ==========================================
  // Zero Balance Guard & Client Shift-Left Engine
  // ==========================================

  window.showZeroBalanceModal = function() {
    const existing = document.getElementById('zero-balance-modal');
    if (existing) existing.remove();

    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    const overlay = document.createElement('div');
    overlay.id = 'zero-balance-modal';
    overlay.className = 'zero-balance-overlay';
    overlay.innerHTML = `
      <div class="zero-balance-card">
        <div class="zero-balance-icon">
          <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
          </svg>
        </div>
        <div class="zero-balance-title">${isEn ? 'Insufficient Quota' : '算力余额不足'}</div>
        <div class="zero-balance-desc">
          ${isEn 
            ? 'Your current balance is 0 ⚡. You cannot upload files or submit new tasks. Please top up or redeem a gift code.' 
            : '当前可用积分余额为 0 ⚡，无法上传附件或提交模型任务。请先充值额度或兑换卡密后再试。'}
        </div>
        <div class="zero-balance-actions">
          <button class="btn btn-outline" id="btn-zero-close">${isEn ? 'Cancel' : '取消'}</button>
          <button class="btn btn-primary glow" id="btn-zero-recharge" style="background:linear-gradient(135deg, #f59e0b, #d97706); border-color:#d97706;">${isEn ? 'Top Up Now ⚡' : '立即充值 ⚡'}</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('#btn-zero-close').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#btn-zero-recharge').addEventListener('click', () => {
      overlay.remove();
      if (window.openSettingsModal) {
        window.openSettingsModal('billing');
      }
    });
  };

  // ==========================================
  // Rate Limit Modal (Demo Environment Protection)
  // ==========================================
  window.showRateLimitModal = function(retryAfterSeconds = 5, customMessage = '') {
    const existing = document.getElementById('rate-limit-modal');
    if (existing) {
      if (existing._countdownTimer) clearInterval(existing._countdownTimer);
      existing.remove();
    }

    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    const totalDuration = Math.max(1, parseInt(retryAfterSeconds, 10) || 5);
    let remaining = totalDuration;

    const overlay = document.createElement('div');
    overlay.id = 'rate-limit-modal';
    overlay.className = 'rate-limit-overlay';
    overlay.innerHTML = `
      <div class="rate-limit-card">
        <div class="rate-limit-icon">
          <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
        </div>
        <div class="rate-limit-title">
          <span>⏱️</span>
          <span>${isEn ? 'Request Rate Limited · Demo Protection' : '请求过于频繁 · Demo 环境保护'}</span>
        </div>
        <div class="rate-limit-desc">
          ${isEn 
            ? 'NanoMesh is currently deployed on Cloudflare Workers Free Tier. To preserve community quota and prevent accidental burst abuse, a gentle cooldown is active.' 
            : '当前系统运行在 Cloudflare Workers 免费配额环境中。为保障所有体验者平稳使用并防止额度耗尽，系统启用了温和的频控保护机制。'}
        </div>
        <div class="rate-limit-timer-box">
          <div class="rate-limit-timer-number" id="rate-limit-counter">${remaining}s</div>
          <div class="rate-limit-progress-bar-bg">
            <div class="rate-limit-progress-bar-fill" id="rate-limit-progress" style="width: 100%;"></div>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px;">
            ${isEn ? 'Cooling down, ready soon...' : '正在冷却，倒计时结束后可继续提问...'}
          </div>
        </div>
        <div class="rate-limit-actions">
          <button class="btn btn-outline" id="btn-rate-limit-close" style="border-radius: 8px;">
            ${isEn ? 'Dismiss' : '稍后重试'}
          </button>
          <button class="btn btn-primary" id="btn-rate-limit-action" style="min-width: 140px; border-radius: 8px;">
            ${isEn ? 'Wait' : '请稍候'} (${remaining}s)
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const counterEl = overlay.querySelector('#rate-limit-counter');
    const progressEl = overlay.querySelector('#rate-limit-progress');
    const actionBtn = overlay.querySelector('#btn-rate-limit-action');
    const closeBtn = overlay.querySelector('#btn-rate-limit-close');

    const closeModal = () => {
      if (overlay._countdownTimer) clearInterval(overlay._countdownTimer);
      overlay.remove();
      const inputEl = document.getElementById('chat-input');
      if (inputEl) inputEl.focus();
    };

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (actionBtn) actionBtn.addEventListener('click', closeModal);

    overlay._countdownTimer = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(overlay._countdownTimer);
        overlay._countdownTimer = null;
        if (counterEl) counterEl.textContent = isEn ? 'Ready!' : '准备就绪!';
        if (progressEl) progressEl.style.width = '0%';
        if (actionBtn) {
          actionBtn.textContent = isEn ? 'Continue / Dismiss ➔' : '立即继续提问 ➔';
          actionBtn.style.background = 'var(--accent-primary, #00c9db)';
          actionBtn.style.color = '#000';
          actionBtn.style.fontWeight = '600';
        }
      } else {
        if (counterEl) counterEl.textContent = `${remaining}s`;
        if (progressEl) {
          const pct = Math.max(0, (remaining / totalDuration) * 100);
          progressEl.style.width = `${pct}%`;
        }
        if (actionBtn) {
          actionBtn.textContent = `${isEn ? 'Wait' : '请稍候'} (${remaining}s)`;
        }
      }
    }, 1000);
  };

  // Helper: Canvas Downsampling for Images (Max 2048px, JPEG 0.85)
  function downsampleImage(file, maxDimension = 2048) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          let { width, height } = img;
          if (width > maxDimension || height > maxDimension) {
            if (width > height) {
              height = Math.round((height * maxDimension) / width);
              width = maxDimension;
            } else {
              width = Math.round((width * maxDimension) / height);
              height = maxDimension;
            }
          }
          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, width, height);
          canvas.toBlob((blob) => {
            resolve(blob || file);
          }, 'image/jpeg', 0.85);
        };
        img.onerror = () => resolve(file);
        img.src = e.target.result;
      };
      reader.onerror = () => resolve(file);
      reader.readAsDataURL(file);
    });
  }

  // Helper: Parse CSV to Markdown table (RFC 4180 compliant with pipe escaping)
  function parseCsvToMarkdown(csvText) {
    const lines = csvText.trim().split(/\r?\n/).slice(0, 100);
    if (!lines.length) return '';

    function parseCsvLine(line) {
      const cells = [];
      const re = /(?:^|,)(?:"((?:[^"]|"")*)"|([^,]*))/g;
      let match;
      while ((match = re.exec(line)) !== null) {
        let val = match[1] !== undefined ? match[1].replace(/""/g, '"') : match[2];
        cells.push((val || '').trim().replace(/\|/g, '\\|'));
      }
      return cells;
    }

    const rows = lines.map(parseCsvLine);
    if (!rows.length || !rows[0].length) return '';
    let md = '| ' + rows[0].join(' | ') + ' |\n';
    md += '| ' + rows[0].map(() => '---').join(' | ') + ' |\n';
    for (let i = 1; i < rows.length; i++) {
      md += '| ' + rows[i].join(' | ') + ' |\n';
    }
    return md;
  }

  // Mozilla PDF.js Shift-Left Loader & Parser (Client-side 0-server-cost extraction, same-origin self-hosted)
  const PDF_LIB_URL = '/vendor/pdfjs/pdf.min.js';
  const PDF_WORKER_URL = '/vendor/pdfjs/pdf.worker.min.js';
  let pdfjsLibPromise = null;

  async function getPdfJsLib() {
    if (window.pdfjsLib) {
      if (window.pdfjsLib.GlobalWorkerOptions) {
        window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL;
      }
      return window.pdfjsLib;
    }
    if (pdfjsLibPromise) return pdfjsLibPromise;

    pdfjsLibPromise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = PDF_LIB_URL;
      script.onload = () => {
        if (window.pdfjsLib) {
          if (window.pdfjsLib.GlobalWorkerOptions) {
            window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL;
          }
          resolve(window.pdfjsLib);
        } else {
          pdfjsLibPromise = null;
          script.remove();
          reject(new Error('PDF.js failed to initialize'));
        }
      };
      script.onerror = () => {
        pdfjsLibPromise = null;
        script.remove();
        reject(new Error('Failed to load PDF.js from local vendor bundle'));
      };
      document.head.appendChild(script);
    });

    return pdfjsLibPromise;
  }

  async function parsePdfShiftLeft(file) {
    const pdfjs = await getPdfJsLib();
    const arrayBuffer = await file.arrayBuffer();
    const loadingTask = pdfjs.getDocument({ data: arrayBuffer });
    const pdf = await loadingTask.promise;
    const numPages = pdf.numPages;

    const pageTexts = [];
    const maxPagesToRead = Math.min(numPages, 40);

    for (let pageNum = 1; pageNum <= maxPagesToRead; pageNum++) {
      try {
        const page = await pdf.getPage(pageNum);
        const textContent = await page.getTextContent();
        const str = textContent.items.map(it => it.str || '').filter(Boolean).join(' ').trim();
        if (str) {
          pageTexts.push(`--- [ 第 ${pageNum} 页 / Page ${pageNum} ] ---\n${str}`);
        }
      } catch (pageErr) {
        console.warn(`Error reading PDF page ${pageNum}:`, pageErr);
      }
    }

    const fullText = pageTexts.join('\n\n').trim();

    // If extractable text was found (digital text PDF)
    if (fullText.length >= 40) {
      return {
        isScanned: false,
        text: fullText,
        pageCount: numPages
      };
    }

    // Scanned / Image-only PDF: render first 3 pages to JPEG images for Vision VLM OCR
    const scannedImages = [];
    const maxScanPages = Math.min(numPages, 3);

    for (let pageNum = 1; pageNum <= maxScanPages; pageNum++) {
      try {
        const page = await pdf.getPage(pageNum);
        const viewport = page.getViewport({ scale: 1.5 });
        const canvas = document.createElement('canvas');
        canvas.width = viewport.width;
        canvas.height = viewport.height;
        const ctx = canvas.getContext('2d');
        await page.render({ canvasContext: ctx, viewport }).promise;

        const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', 0.85));
        if (blob) {
          const imgFile = new File([blob], `${file.name.replace(/\.pdf$/i, '')}_p${pageNum}.jpg`, { type: 'image/jpeg' });
          scannedImages.push(imgFile);
        }
      } catch (renderErr) {
        console.warn(`Error rendering scanned PDF page ${pageNum}:`, renderErr);
      }
    }

    return {
      isScanned: true,
      images: scannedImages,
      pageCount: numPages
    };
  }

  // File Upload Logic with Pre-flight Quota Gatekeeper & Pipelined Uploading
  // File Upload Logic with Pre-flight Quota Gatekeeper & Pipelined Uploading
  const inputs = ['upload-image', 'upload-audio', 'upload-text'];
  inputs.forEach(id => {
    document.getElementById(id)?.addEventListener('change', (e) => {
      const files = Array.from(e.target.files);
      e.target.value = '';
      processUploadedFiles(files);
    });
  });

  // Global Drag & Drop Handler
  window.addEventListener('dragover', (e) => {
    e.preventDefault();
  });
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processUploadedFiles(Array.from(e.dataTransfer.files));
    }
  });

  // Global Clipboard Paste Handler
  document.addEventListener('paste', (e) => {
    if (e.clipboardData && e.clipboardData.files && e.clipboardData.files.length > 0) {
      processUploadedFiles(Array.from(e.clipboardData.files));
    }
  });

  async function processUploadedFiles(newFiles) {
    if (!newFiles || newFiles.length === 0) return;

    if (!user) {
      window.showModal(t('chat.loginRequired'), t('chat.loginToUse'), t('auth.goToLogin'), () => { window.location.href = '/login.html'; });
      return;
    }

    // Pre-flight check: If local cached balance is 0, block immediately
    if (user.credits <= 0) {
      window.showZeroBalanceModal();
      return;
    }

    if (selectedFiles.length + newFiles.length > MAX_FILES) {
      localToast(t('error.maxFiles', { n: MAX_FILES }));
      return;
    }

    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';

    for (const file of newFiles) {
      let modality = 'text_doc';
      if (file.type.startsWith('image/')) modality = 'image';
      else if (file.type.startsWith('audio/')) modality = 'audio';

      // 1. Shift-left pre-processing (Browser memory text/image normalization)
      let processedBlob = file;
      let inMemoryText = null;

      if (modality === 'image') {
        processedBlob = await downsampleImage(file);
      } else if (modality === 'audio') {
        const audioUrl = URL.createObjectURL(file);
        const tempAudio = new Audio(audioUrl);
        tempAudio.onloadedmetadata = () => {
          if (tempAudio.duration > 600) {
            localToast('音频时长超过 10 分钟，模型推理时可能会自动截断。', 'info');
          }
          URL.revokeObjectURL(audioUrl);
        };
      } else {
        // Document / Text / PDF
        const fileNameLower = (file.name || '').toLowerCase();
        if (fileNameLower.endsWith('.pdf') || file.type === 'application/pdf') {
          try {
            localToast(isEn ? 'Extracting PDF content (Shift-Left)...' : '正在解析 PDF 文档 (Shift-Left)...', 'info');
            const pdfRes = await parsePdfShiftLeft(file);
            if (pdfRes && !pdfRes.isScanned && pdfRes.text) {
              modality = 'text_doc';
              inMemoryText = pdfRes.text;
              localToast(isEn ? `PDF extracted successfully (${pdfRes.pageCount} pages)` : `已成功提取 PDF 文本 (${pdfRes.pageCount} 页)，就绪`, 'success');
            } else if (pdfRes && pdfRes.isScanned && pdfRes.images.length > 0) {
              localToast(isEn ? 'Scanned PDF detected. Converted to images for OCR.' : '检测到影印扫描版 PDF，已自动将页面转为图像进行视觉 OCR 解析', 'info');
              await processUploadedFiles(pdfRes.images);
              continue;
            }
          } catch (pdfErr) {
            console.error('PDF parsing error:', pdfErr);
            localToast(isEn ? 'PDF parse failed (encrypted or corrupted)' : '该 PDF 文档解析失败（可能受密码保护或文件损坏），已忽略', 'warning');
            continue;
          }
          if (!inMemoryText) {
            localToast(isEn ? 'PDF contains no readable text or scanned pages' : '该 PDF 未包含可提取的文本或页面，已忽略', 'warning');
            continue;
          }
        } else if (fileNameLower.endsWith('.csv')) {
          const rawText = await file.text();
          inMemoryText = parseCsvToMarkdown(rawText);
          modality = 'text_doc';
        } else if (fileNameLower.endsWith('.txt') || fileNameLower.endsWith('.md') || fileNameLower.endsWith('.json')) {
          inMemoryText = await file.text();
          modality = 'text_doc';
        }

        if (inMemoryText && inMemoryText.length > 30000) {
          inMemoryText = inMemoryText.slice(0, 30000) + '\n\n[...内容过长，已就地截取前 30,000 字符...]';
          localToast('文本总长超出 30,000 字软限制，已自动就地截断。', 'info');
        }
      }

      // 2. Pre-sign request with server quota validation
      let previewUrl = null;
      if (modality === 'image' || (file.type && file.type.startsWith('image/'))) {
        try {
          previewUrl = URL.createObjectURL(processedBlob || file);
        } catch (e) {}
      }

      const fileDesc = {
        name: file.name,
        size: processedBlob.size || file.size,
        type: file.type,
        modality,
        previewUrl,
        assetId: crypto.randomUUID(),
        r2Key: null,
        inMemoryText,
        rawFile: processedBlob || file,
        uploadStatus: inMemoryText ? 'ready' : 'uploading'
      };

      selectedFiles.push(fileDesc);
      renderFileChips();

      // If already parsed text, no remote upload needed
      if (inMemoryText) {
        fileDesc.uploadStatus = 'ready';
        renderFileChips();
        continue;
      }

      try {
        const uploadBlob = processedBlob || file;
        if (uploadBlob.size > 25 * 1024 * 1024) {
          localToast(isEn ? 'File exceeds maximum 25MB limit.' : '单文件超出 25MB 大小限制，请精简后重试。', 'error');
          selectedFiles = selectedFiles.filter(f => f.assetId !== fileDesc.assetId);
          renderFileChips();
          continue;
        }

        const isLargeFile = uploadBlob.size > 4 * 1024 * 1024;
        let uploadedDirectly = false;

        if (isLargeFile) {
          // Tier B: Presigned S3 direct upload for large files (> 4MB and <= 25MB)
          try {
            const presignRes = await fetch('/api/upload/presign', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                file_name: file.name,
                file_size: uploadBlob.size,
                mime_type: file.type || 'application/octet-stream',
                modality
              })
            });

            if (presignRes.status === 403) {
              selectedFiles = selectedFiles.filter(f => f.assetId !== fileDesc.assetId);
              renderFileChips();
              window.showZeroBalanceModal();
              return;
            }

            if (presignRes.ok) {
              const presignData = await presignRes.json();
              const putRes = await fetch(presignData.uploadUrl, {
                method: 'PUT',
                body: uploadBlob,
                headers: { 'Content-Type': file.type || 'application/octet-stream' }
              });

              if (putRes.ok) {
                fileDesc.r2Key = presignData.r2Key;
                fileDesc.assetId = presignData.assetId;
                uploadedDirectly = true;
              } else {
                console.warn(`S3 direct upload failed with status ${putRes.status}, falling back to worker proxy upload`);
              }
            } else {
              console.warn('Presign endpoint failed, falling back to worker proxy upload');
            }
          } catch (s3Err) {
            console.warn('S3 direct upload network exception, falling back to worker proxy upload:', s3Err);
          }
        }

        if (!uploadedDirectly) {
          // Tier A: Native same-origin direct upload (<= 25MB or fallback from failed S3 upload)
          const formData = new FormData();
          formData.append('file', uploadBlob, file.name);
          formData.append('modality', modality);

          const uploadRes = await fetch('/api/upload/file', {
            method: 'POST',
            body: formData
          });

          if (uploadRes.status === 403) {
            selectedFiles = selectedFiles.filter(f => f.assetId !== fileDesc.assetId);
            renderFileChips();
            window.showZeroBalanceModal();
            return;
          }

          if (!uploadRes.ok) {
            const errText = await uploadRes.text();
            throw new Error('Upload failed: ' + errText);
          }

          const uploadData = await uploadRes.json();
          fileDesc.r2Key = uploadData.r2Key;
          fileDesc.assetId = uploadData.assetId;
        }

        fileDesc.uploadStatus = 'ready';
        renderFileChips();
      } catch (uploadErr) {
        console.error('File upload error:', uploadErr);
        fileDesc.uploadStatus = 'error';
        renderFileChips();
        localToast(uploadErr.message || '附件存储失败，请重试', 'error');
      }
    }
  }

  function renderFileChips() {
    const container = document.getElementById('attachments-preview');
    if (!container) return;
    container.innerHTML = '';
    updateEstimation();
    
    if (selectedFiles.length === 0) {
      container.style.display = 'none';
      return;
    }
    container.style.display = 'flex';
    
    selectedFiles.forEach((file, index) => {
      const chip = document.createElement('div');
      chip.className = 'file-chip';
      const isReady = file.uploadStatus === 'ready';
      const isError = file.uploadStatus === 'error';
      const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';

      let statusBadge = '';
      if (isReady) {
        statusBadge = `<span class="local-parse-badge success-flash">${isEn ? '✓ Ready' : '✓ 已就绪'}</span>`;
      } else if (isError) {
        statusBadge = `<span class="local-parse-badge" style="background:rgba(239,68,68,0.15);color:#ef4444;">${isEn ? '⚠ Failed' : '⚠ 上传失败'}</span>`;
      } else {
        statusBadge = `<span class="local-parse-badge">${isEn ? '⏳ Uploading...' : '⏳ 存储中...'}</span>`;
      }

      chip.innerHTML = `
        ${statusBadge}
        <span style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:0.8rem;color:var(--text-primary);font-weight:500;">
          ${escapeHtml(file.name)}
        </span>
        <svg class="file-chip-close" data-index="${index}" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="cursor:pointer;margin-left:4px;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      `;
      container.appendChild(chip);
    });

    document.querySelectorAll('.file-chip-close').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idx = parseInt(e.target.closest('.file-chip-close').getAttribute('data-index'));
        selectedFiles.splice(idx, 1);
        renderFileChips();
      });
    });
  }

  // ==========================================
  // Interactive DAG Workstation & Chat Orchestration Engine
  // ==========================================

  function createEmptyGitState() {
    return {
      commits: {},
      commitOrder: [],
      branches: {
        main: {
          branchId: 'main',
          topic: '初始任务',
          headCommitId: null,
          isMediaBranch: false,
          lastValidSummary: '',
          lineageAssetIds: []
        }
      },
      activeBranchId: 'main',
      assetVault: {},
      perceptualCacheIndex: {}
    };
  }

  function syncLegacyGlobalsFromGitState() {
    const gs = window.gitState || createEmptyGitState();
    window.gitState = gs;
    window.activeBranchId = gs.activeBranchId || 'main';
    window.sessionBranches = {};
    Object.values(gs.branches || {}).forEach(b => {
      window.sessionBranches[b.branchId] = {
        branchId: b.branchId,
        topic: b.topic,
        isMediaBranch: !!b.isMediaBranch,
        lastValidSummary: b.lastValidSummary || '',
        assetIds: Array.isArray(b.lineageAssetIds) ? [...b.lineageAssetIds] : [],
        headCommitId: b.headCommitId || null
      };
    });
    window.sessionAssets = Object.values(gs.assetVault || {});
    window.lastHadMedia = window.sessionAssets.some(a => {
      const m = a.modality || (a.type && a.type.startsWith('image/') ? 'image' : (a.type && a.type.startsWith('audio/') ? 'audio' : ''));
      return m === 'image' || m === 'audio';
    });
  }

  function commitTurnTransaction(tx) {
    const gs = window.gitState || createEmptyGitState();
    window.gitState = gs;
    const commitId = tx.runId || ('commit-' + Date.now());
    // Idempotency & Acyclic Guard: duplicate completion receipt for the same runId must NEVER re-commit or form self-loops
    if (!commitId || gs.commits[commitId]) {
      return;
    }
    const trace = tx.trace || window._pendingRoundTrace || {};
    const intent = trace.intent_state || window.currentRoundIntentState || null;
    const promptSnippet = (tx.userPrompt || window.lastUserPrompt || '').slice(0, 50);
    const stagedUploads = Array.isArray(window._currentStagedNewFiles) ? window._currentStagedNewFiles : [];
    const generatedMedia = Array.isArray(window._currentRoundGeneratedAssets) ? window._currentRoundGeneratedAssets : [];
    const mountedAssets = Array.isArray(window.currentRoundAssets) ? window.currentRoundAssets : [];
    const hasMediaInTurn =
      mountedAssets.some(a => a.modality === 'image' || a.modality === 'audio') ||
      generatedMedia.length > 0;

    // 1. Determine final delivery branch AFTER execution succeeds (never on dag_plan)
    let targetBranchId = trace.target_branch_id || gs.activeBranchId || 'main';
    let parents = [];
    if (intent === 'DETACH_RESET') {
      const isInitialMainEmpty =
        Object.keys(gs.commits).length === 0 &&
        (!gs.branches.main || !gs.branches.main.headCommitId);
      if (isInitialMainEmpty) {
        targetBranchId = 'main';
      } else {
        targetBranchId = (hasMediaInTurn ? 'branch_media_' : 'branch_chat_') + Date.now();
      }
      parents = [];
    } else {
      if (!gs.branches[targetBranchId]) {
        gs.branches[targetBranchId] = {
          branchId: targetBranchId,
          topic: promptSnippet || (hasMediaInTurn ? '多模态媒体分析' : '常规任务对话'),
          headCommitId: null,
          isMediaBranch: hasMediaInTurn,
          lastValidSummary: '',
          lineageAssetIds: []
        };
      }
      const targetHead = gs.branches[targetBranchId].headCommitId;
      if (targetHead && targetHead !== commitId) parents.push(targetHead);
    }
    parents = Array.from(new Set(parents.filter(pid => pid && pid !== commitId)));
    const sourceRefs = (trace.mounted_asset_bindings || [])
      .filter(b => b && b.bind_mode !== 'DROP')
      .map(b => {
        const hist = gs.assetVault[b.asset_id];
        return hist ? {
          asset_id: b.asset_id,
          branch_id: hist.branchId || hist.branch_id || targetBranchId,
          commit_id: hist.introducedCommitId || hist.introduced_commit_id || null,
          bind_mode: b.bind_mode
        } : null;
      })
      .filter(Boolean);
    const introducedIds = [];
    const generatedIds = [];

    // 2. Commit staged uploads & generated media atomically to Asset Vault with exact provenance
    stagedUploads.forEach(f => {
      const aid = f.assetId || f.id;
      if (!aid) return;
      introducedIds.push(aid);
      gs.assetVault[aid] = {
        ...f,
        id: aid,
        assetId: aid,
        origin: 'upload',
        isNew: false,
        branchId: targetBranchId,
        introducedCommitId: commitId,
        introducedRound: window.chatRoundIndex || 1
      };
    });

    generatedMedia.forEach(g => {
      const aid = g.assetId || g.id;
      if (!aid) return;
      generatedIds.push(aid);
      gs.assetVault[aid] = {
        ...g,
        id: aid,
        assetId: aid,
        origin: 'generated',
        isNew: false,
        branchId: targetBranchId,
        introducedCommitId: commitId,
        introducedRound: window.chatRoundIndex || 1
      };
    });

    // 3. Merge perceptual L1 cache updates emitted by dispatcher
    if (Array.isArray(tx.perceptualEntries)) {
      tx.perceptualEntries.forEach(entry => {
        if (entry && entry.source_digest) {
          gs.perceptualCacheIndex[entry.source_digest] = entry;
          Object.values(gs.assetVault).forEach(va => {
            const vaDigest = va.sourceDigest || va.r2Key || va.r2_key;
            if (vaDigest === entry.source_digest) {
              va.summarySnippet = entry.summary_snippet;
              va.cachedPerceptualText = entry.extracted_text;
            }
          });
        }
      });
    }

    // 4. Compute branch lineage asset set (bounded by DETACH_RESET)
    const targetBranch = gs.branches[targetBranchId] || {
      branchId: targetBranchId,
      topic: promptSnippet || (hasMediaInTurn ? '多模态媒体分析' : '常规任务对话'),
      headCommitId: null,
      isMediaBranch: hasMediaInTurn,
      lastValidSummary: '',
      lineageAssetIds: []
    };
    const lineageSet = new Set(
      intent === 'DETACH_RESET'
        ? []
        : Array.isArray(targetBranch.lineageAssetIds)
          ? targetBranch.lineageAssetIds
          : []
    );
    (trace.mounted_asset_bindings || []).forEach(b => {
      if (b && b.bind_mode !== 'DROP' && gs.assetVault[b.asset_id]) {
        lineageSet.add(b.asset_id);
      }
    });
    introducedIds.forEach(id => lineageSet.add(id));
    generatedIds.forEach(id => lineageSet.add(id));

    const summaryText = tx.finalOutput ? tx.finalOutput.slice(0, 4000) : '';
    if (
      promptSnippet &&
      (!targetBranch.topic ||
        targetBranch.topic === '初始任务' ||
        targetBranch.topic === '常规任务对话' ||
        targetBranch.topic === '多模态媒体分析')
    ) {
      targetBranch.topic = promptSnippet;
    }
    if (hasMediaInTurn) targetBranch.isMediaBranch = true;
    if (summaryText) targetBranch.lastValidSummary = summaryText;
    targetBranch.headCommitId = commitId;
    targetBranch.lineageAssetIds = Array.from(lineageSet);
    gs.branches[targetBranchId] = targetBranch;

    // 5. Append CommitNode & advance active HEAD pointer
    gs.commits[commitId] = {
      commit_id: commitId,
      parents,
      branch_id: targetBranchId,
      evidence_source_branches: Array.isArray(trace.source_branch_ids) ? [...trace.source_branch_ids] : [],
      source_refs: sourceRefs,
      round_index: window.chatRoundIndex || 1,
      revision: tx.revision || 1,
      intent_op: intent,
      user_prompt: tx.userPrompt || '',
      mounted_assets: (trace.mounted_asset_bindings || []).filter(b => b.bind_mode !== 'DROP'),
      introduced_asset_ids: introducedIds,
      generated_asset_ids: generatedIds,
      template_id: window.currentRunningTemplateId || null,
      output_summary: summaryText,
      timestamp: Date.now()
    };
    if (!gs.commitOrder.includes(commitId)) {
      gs.commitOrder.push(commitId);
    }
    gs.activeBranchId = targetBranchId;

    if (summaryText) {
      window.lastRoundSummary = summaryText;
      window.currentDagBaseSummary = summaryText;
    }
    window._currentStagedNewFiles = [];
    window._currentRoundGeneratedAssets = [];
    window._pendingRoundTrace = null;
    syncLegacyGlobalsFromGitState();
  }

  // Canvas micro-tuning revision update ("continue from this version"):
  // Updates the displayed revision & active summary WITHOUT appending a new commit to commitOrder or changing parents[].
  function recordCanvasRevisionUpdate(revInfo) {
    const gs = window.gitState || createEmptyGitState();
    window.gitState = gs;
    const baseCommitId = revInfo.baseRunId;
    const summaryText = revInfo.finalOutput ? revInfo.finalOutput.slice(0, 4000) : '';
    const baseCommit = baseCommitId ? gs.commits[baseCommitId] : null;
    if (baseCommit) {
      baseCommit.revision = revInfo.revision || baseCommit.revision || 1;
      baseCommit.template_id = window.currentRunningTemplateId || baseCommit.template_id;
      if (summaryText) {
        baseCommit.output_summary = summaryText;
      }
      const targetBranch = gs.branches[baseCommit.branch_id];
      if (targetBranch && targetBranch.headCommitId === baseCommitId && summaryText) {
        targetBranch.lastValidSummary = summaryText;
      }
    } else if (gs.activeBranchId && gs.branches[gs.activeBranchId] && summaryText) {
      gs.branches[gs.activeBranchId].lastValidSummary = summaryText;
    }
    if (Array.isArray(revInfo.perceptualEntries)) {
      revInfo.perceptualEntries.forEach(entry => {
        if (entry && entry.source_digest) {
          gs.perceptualCacheIndex[entry.source_digest] = entry;
        }
      });
    }
    if (summaryText) {
      window.lastRoundSummary = summaryText;
      window.currentDagBaseSummary = summaryText;
    }
    window._currentStagedNewFiles = [];
    window._currentRoundGeneratedAssets = [];
    syncLegacyGlobalsFromGitState();
  }

  function hydrateGitStateFromServer(serverSnap) {
    if (!serverSnap || typeof serverSnap !== 'object') return false;
    const hasData =
      (serverSnap.commit_order && serverSnap.commit_order.length > 0) ||
      (serverSnap.branch_catalog && serverSnap.branch_catalog.length > 0) ||
      (serverSnap.session_asset_ledger && serverSnap.session_asset_ledger.length > 0) ||
      serverSnap.occupancy_phase === 'AWAITING_COMMIT';
    if (!hasData) return false;

    const gs = createEmptyGitState();
    gs.activeBranchId = serverSnap.active_branch_id || 'main';
    gs.commitOrder = Array.isArray(serverSnap.commit_order) ? [...serverSnap.commit_order] : [];
    gs.commits = serverSnap.commits ? JSON.parse(JSON.stringify(serverSnap.commits)) : {};
    if (serverSnap.branches && typeof serverSnap.branches === 'object') {
      Object.values(serverSnap.branches).forEach(b => {
        if (!b || !b.branch_id) return;
        gs.branches[b.branch_id] = {
          branchId: b.branch_id,
          topic: b.topic || '主线任务',
          headCommitId: b.head_commit_id || null,
          isMediaBranch: Array.isArray(b.dominant_modalities) && b.dominant_modalities.some(m => m === 'image' || m === 'audio' || m === 'text_doc'),
          lastValidSummary: b.last_summary || '',
          lineageAssetIds: Array.isArray(b.lineage_asset_ids) ? [...b.lineage_asset_ids] : []
        };
      });
    }
    if (Array.isArray(serverSnap.session_asset_ledger)) {
      serverSnap.session_asset_ledger.forEach(a => {
        if (!a || !a.asset_id) return;
        gs.assetVault[a.asset_id] = {
          id: a.asset_id,
          assetId: a.asset_id,
          name: a.filename || a.asset_id,
          filename: a.filename || a.asset_id,
          modality: a.modality,
          mime_type: a.mime_type,
          type: a.mime_type,
          file_size: a.file_size || 0,
          size: a.file_size || 0,
          r2_key: a.r2_key,
          r2Key: a.r2_key,
          source_digest: a.source_digest,
          sourceDigest: a.source_digest,
          origin: a.origin || 'upload',
          branchId: a.branch_id || gs.activeBranchId,
          introducedCommitId: a.introduced_commit_id,
          introducedRound: a.introduced_round || 1,
          summarySnippet: a.summary_snippet || '',
          cachedPerceptualText: a.cached_perceptual_text
        };
      });
    }
    if (serverSnap.perceptual_cache && typeof serverSnap.perceptual_cache === 'object') {
      gs.perceptualCacheIndex = JSON.parse(JSON.stringify(serverSnap.perceptual_cache));
    }
    window.gitState = gs;
    syncLegacyGlobalsFromGitState();

    // Reconcile active branch summary, round index, and frozen baseline revision (REV-04)
    const activeHeadId = gs.branches[gs.activeBranchId]?.headCommitId || gs.commitOrder[gs.commitOrder.length - 1] || null;
    const activeHeadCommit = activeHeadId ? gs.commits[activeHeadId] : null;
    const hydratedSummary =
      gs.branches[gs.activeBranchId]?.lastValidSummary ||
      activeHeadCommit?.output_summary ||
      '';
    if (hydratedSummary) {
      window.lastRoundSummary = hydratedSummary;
      window.currentDagBaseSummary = hydratedSummary;
    }
    if (gs.commitOrder.length > 0) {
      window.chatRoundIndex = Math.max(window.chatRoundIndex || 0, gs.commitOrder.length);
    }
    if (window._currentRoundFrozenInput && activeHeadCommit) {
      window._currentRoundFrozenInput.baseRunId = activeHeadId;
      window._currentRoundFrozenInput.committedRevision = Number(activeHeadCommit.revision || 1);
      window._currentRoundFrozenInput.revision = window._currentRoundFrozenInput.committedRevision;
      window._currentRoundFrozenInput.candidateRevision = null;
    }
    if (serverSnap.occupancy_phase === 'AWAITING_COMMIT' && serverSnap.awaiting_commit) {
      setAwaitingCommitResolutionState(true, serverSnap.awaiting_commit);
      if (typeof document !== 'undefined') {
        const flowEl = document.getElementById('messages-flow');
        if (flowEl && !flowEl.querySelector('.dag-awaiting-commit-recovery-banner')) {
          const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
          const banner = document.createElement('div');
          banner.className = 'dag-execution-error-banner dag-awaiting-commit-recovery-banner';
          banner.style.cssText = 'color:#f59e0b; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.35); padding:10px 14px; border-radius:8px; margin-top:10px; font-size:0.86rem;';
          banner.innerHTML = `<div>⚠️ ${isEn ? 'This session has a pending un-saved result from a previous run. Retry save or abandon before continuing.' : '检测到上一轮有未保存完成的待确认结果，请先重试提交状态或点击放弃后再继续对话。'}</div>`;
          const btnRow = document.createElement('div');
          btnRow.style.cssText = 'display:flex; gap:8px; margin-top:8px; flex-wrap:wrap;';
          const pendingRunId = serverSnap.awaiting_commit.run_id;
          if (serverSnap.awaiting_commit.can_retry_commit && window.chatSessionId) {
            const retryBtn = document.createElement('button');
            retryBtn.type = 'button';
            retryBtn.className = 'chat-action-btn';
            retryBtn.style.cssText = 'padding:4px 10px;';
            retryBtn.textContent = isEn ? 'Retry Save' : '重试提交状态';
            retryBtn.onclick = async () => {
              retryBtn.disabled = true;
              try {
                const r = await fetch('/api/session/' + encodeURIComponent(window.chatSessionId) + '/commit-retry', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ run_id: pendingRunId })
                });
                if (r.ok) {
                  const snap = await r.json().catch(() => null);
                  banner.remove();
                  setAwaitingCommitResolutionState(false);
                  if (snap) hydrateGitStateFromServer(snap);
                } else {
                  retryBtn.disabled = false;
                }
              } catch {
                retryBtn.disabled = false;
              }
            };
            btnRow.appendChild(retryBtn);
          }
          const abandonBtn = document.createElement('button');
          abandonBtn.type = 'button';
          abandonBtn.className = 'chat-action-btn';
          abandonBtn.style.cssText = 'padding:4px 10px; color:#ef4444;';
          abandonBtn.textContent = isEn ? 'Abandon Result' : '放弃此结果';
          abandonBtn.onclick = async () => {
            abandonBtn.disabled = true;
            const abRes = await abandonPendingCommit(pendingRunId);
            if (abRes?.ok) banner.remove();
            else abandonBtn.disabled = false;
          };
          btnRow.appendChild(abandonBtn);
          banner.appendChild(btnRow);
          flowEl.appendChild(banner);
        }
      }
    } else if (!serverSnap.occupancy_phase && isAwaitingCommitResolution) {
      setAwaitingCommitResolutionState(false);
    }
    return true;
  }

  window.chatSessionId = window.chatSessionId || crypto.randomUUID();
  window.chatRoundIndex = window.chatRoundIndex || 0;
  window.lastRoundSummary = window.lastRoundSummary || '';
  window.currentDagBaseSummary = window.currentDagBaseSummary || '';
  window.lastHadMedia = false;
  window.gitState = window.gitState || createEmptyGitState();
  syncLegacyGlobalsFromGitState();
  window._currentPreFlightSnapshot = null;
  window._currentStagedNewFiles = [];
  window._currentRoundGeneratedAssets = [];
  window._pendingRoundTrace = null;
  window._pendingClarificationContext = null;
  window.currentRunningTemplateId = window.currentRunningTemplateId || null;
  window.activeChatAbortController = null;
  let activeDagNodes = [];
  let currentCandidateTemplates = [];
  let currentActiveAssistantId = null;
  let currentActiveRunId = null;

  // Console Back Button & Workflow State Management
  let isWorkflowExecuting = false;
  let isAwaitingCommitResolution = false;
  window.isAwaitingCommitResolution = false;
  function setWorkflowExecutionLocked(isLocked) {
    const effectiveLocked = !!isLocked || !!isAwaitingCommitResolution;
    isWorkflowExecuting = !!isLocked;
    window.isWorkflowExecuting = effectiveLocked;
    const macroCapsuleBtn = document.getElementById('macro-capsule-btn');
    const macroDropdown = document.getElementById('macro-dropdown');
    const nodesContainer = document.getElementById('dag-nodes-container');
    const rerouteBtn = document.getElementById('macro-reroute-btn');
    const nodeInspector = document.getElementById('node-inspector-popover');
    const sendBtn = document.getElementById('send-btn');
    const chatInput = document.getElementById('chat-input');
    const inputArea = document.getElementById('input-area');
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';

    if (effectiveLocked) {
      if (macroCapsuleBtn) {
        macroCapsuleBtn.classList.add('is-locked');
        macroCapsuleBtn.setAttribute(
          'title',
          isAwaitingCommitResolution
            ? (isEn ? 'Pending commit must be saved or abandoned first' : '存在待保存结果，请先重试提交或放弃')
            : (isEn ? 'Workflow executing, route locked' : '工作流执行中，暂不可修改路线')
        );
      }
      if (macroDropdown) macroDropdown.style.display = 'none';
      if (nodesContainer) nodesContainer.classList.add('is-executing');
      const sinkAnchor = document.getElementById('dag-sink-anchor');
      if (sinkAnchor) {
        if (isLocked) sinkAnchor.classList.add('is-executing');
        sinkAnchor.classList.remove('completed');
      }
      if (rerouteBtn) rerouteBtn.disabled = true;
      if (nodeInspector) nodeInspector.style.display = 'none';
      if (sendBtn) sendBtn.disabled = true;
      if (chatInput) {
        chatInput.disabled = true;
        chatInput.placeholder = isAwaitingCommitResolution
          ? (isEn ? '⏳ Pending commit: Retry or Abandon before continuing...' : '⏳ 存在待保存结果，请先点击重试提交或放弃此结果...')
          : (isEn ? '⚡ Workflow executing, please wait...' : '⚡ 工作流执行中，请稍候...');
      }
      if (inputArea) inputArea.classList.add('is-locked-input');
      currentInspectedNodeRoleId = null;
    } else {
      if (macroCapsuleBtn) {
        macroCapsuleBtn.classList.remove('is-locked');
        macroCapsuleBtn.setAttribute('title', isEn ? 'Click to expand macro routes' : '点击展开宏观切换路线');
      }
      if (nodesContainer) nodesContainer.classList.remove('is-executing');
      const sinkAnchor = document.getElementById('dag-sink-anchor');
      if (sinkAnchor) sinkAnchor.classList.remove('is-executing');
      if (sendBtn) sendBtn.disabled = false;
      if (chatInput) {
        chatInput.disabled = false;
        chatInput.placeholder = isEn 
          ? 'Enter prompt to analyze image, audio or text...' 
          : '输入指令，分析图片，音频或文本。';
      }
      if (inputArea) inputArea.classList.remove('is-locked-input');
      if (typeof updateRerouteButtonState === 'function') updateRerouteButtonState();
    }
  }

  function setAwaitingCommitResolutionState(awaiting, pendingMeta = null) {
    isAwaitingCommitResolution = !!awaiting;
    window.isAwaitingCommitResolution = isAwaitingCommitResolution;
    window._awaitingCommitMeta = awaiting ? (pendingMeta || null) : null;
    if (isAwaitingCommitResolution) {
      setWorkflowExecutionLocked(true);
    } else {
      setWorkflowExecutionLocked(false);
    }
  }

  async function abandonPendingCommit(runId) {
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    const targetRunId = runId || window._awaitingCommitMeta?.run_id || window._activeServerRunId || '';
    if (!window.chatSessionId || !targetRunId) {
      setAwaitingCommitResolutionState(false);
      rollbackTurnToPreFlight();
      return { ok: true, localOnly: true };
    }
    const res = await fetch('/api/session/' + encodeURIComponent(window.chatSessionId) + '/abandon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ run_id: targetRunId })
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 409 && body.error === 'already_committed' && body.authoritative_git_state) {
      setAwaitingCommitResolutionState(false);
      window._isCurrentTurnRolledBack = false;
      hydrateGitStateFromServer(body.authoritative_git_state);
      localToast(isEn ? 'Result was already committed to server.' : '该结果此前已成功保存到服务端。', 'info');
      return { ok: true, alreadyCommitted: true };
    }
    if (!res.ok && res.status !== 404) {
      localToast(body.message || (isEn ? 'Failed to abandon pending result.' : '放弃待保存结果失败，请稍后重试。'), 'warning');
      return { ok: false, error: body.message || 'abandon_failed' };
    }
    setAwaitingCommitResolutionState(false);
    rollbackTurnToPreFlight();
    if (body.authoritative_git_state) {
      hydrateGitStateFromServer(body.authoritative_git_state);
    }
    localToast(isEn ? 'Pending result abandoned and restored to last saved revision.' : '已放弃未保存结果，并恢复到上一成功基线。', 'info');
    return { ok: true };
  }

  function triggerInputAttentionGlow() {
    const inputArea = document.getElementById('input-area');
    const input = document.getElementById('chat-input');
    if (inputArea) {
      inputArea.classList.remove('input-attention-pulse');
      void inputArea.offsetWidth; // Force DOM reflow
      inputArea.classList.add('input-attention-pulse');
      setTimeout(() => {
        inputArea.classList.remove('input-attention-pulse');
      }, 1600);
    }
    if (input) {
      input.focus();
    }
  }

  function setWorkflowActive(active) {
    const viewport = document.getElementById('workspace-viewport');
    const mobileSwitcher = document.getElementById('mobile-tab-switcher');
    if (viewport) {
      if (active) {
        viewport.classList.add('workflow-active');
        if (mobileSwitcher) {
          mobileSwitcher.classList.add('active');
          mobileSwitcher.style.display = '';
        }
        // Multi-frame measurement passes during and after workbench 500ms CSS split transition
        requestAnimationFrame(() => renderDagSvgConnectors());
        setTimeout(() => renderDagSvgConnectors(), 100);
        setTimeout(() => renderDagSvgConnectors(), 250);
        setTimeout(() => renderDagSvgConnectors(), 520);
      } else {
        viewport.classList.remove('workflow-active');
        if (mobileSwitcher) {
          mobileSwitcher.classList.remove('active');
          mobileSwitcher.style.display = 'none';
        }
      }
    }
  }

  function resetToRootInterface() {
    // 1. Abort active execution if running
    isAwaitingCommitResolution = false;
    window.isAwaitingCommitResolution = false;
    window._awaitingCommitMeta = null;
    setWorkflowExecutionLocked(false);
    if (window.activeChatAbortController) {
      try { window.activeChatAbortController.abort(); } catch (err) {}
    }
    // BUG-06: Explicitly terminate local worker thread and reset runner promise
    if (window._localWorker) {
      try { window._localWorker.terminate(); } catch (err) {}
      window._localWorker = null;
    }
    window._activeLocalRunnerPromise = null;

    // 2. Clear conversation messages flow completely so Stage 1 root view is pristine
    const messagesFlow = document.getElementById('messages-flow');
    if (messagesFlow) {
      messagesFlow.innerHTML = '';
    }

    // 3. Clear DAG canvas nodes and SVG lines
    const nodesContainer = document.getElementById('dag-nodes-container');
    if (nodesContainer) nodesContainer.innerHTML = '';
    const svgCanvas = document.getElementById('dag-svg-canvas');
    if (svgCanvas) svgCanvas.innerHTML = '';

    // 4. Hide Unified Control Bar & dropdown
    const controlBar = document.getElementById('unified-control-bar') || document.getElementById('macro-workflow-bar');
    if (controlBar) controlBar.style.display = 'none';
    const macroDropdown = document.getElementById('macro-dropdown');
    if (macroDropdown) macroDropdown.style.display = 'none';

    // 5. Hide arbitration and telemetry pills
    const arbBar = document.getElementById('arbitration-header-bar');
    if (arbBar) arbBar.style.display = 'none';
    const intentPill = document.getElementById('intent-pill');
    if (intentPill) intentPill.style.display = 'none';
    const cacheStreamPill = document.getElementById('cache-stream-pill');
    if (cacheStreamPill) cacheStreamPill.style.display = 'none';

    // 6. Hide Node Inspector
    const inspector = document.getElementById('node-inspector-popover');
    if (inspector) inspector.style.display = 'none';
    currentInspectedNodeRoleId = null;

    // 7. Clear user inputs & file attachments
    const input = document.getElementById('chat-input');
    if (input) {
      input.value = '';
      input.style.height = 'auto';
    }
    selectedFiles.length = 0;
    renderFileChips();
    if (typeof updateEstimation === 'function') updateEstimation();

    // 8. Cancel any active typewriter timer
    if (typewriterTimer) {
      clearInterval(typewriterTimer);
      typewriterTimer = null;
    }

    // 9. Re-enable send button
    const sendBtn = document.getElementById('send-btn');
    if (sendBtn) sendBtn.disabled = false;

    // 10. Reset runtime session states for a fresh round
    window.chatSessionId = crypto.randomUUID();
    window.chatRoundIndex = 0;
    window.lastRoundSummary = '';
    window.currentDagBaseSummary = '';
    window.lastHadMedia = false;
    window.gitState = createEmptyGitState();
    syncLegacyGlobalsFromGitState();
    window._currentPreFlightSnapshot = null;
    window._currentStagedNewFiles = [];
    window._currentRoundGeneratedAssets = [];
    window._pendingRoundTrace = null;
    window._pendingClarificationContext = null;
    window.currentRunningTemplateId = null;
    window.lastUserPrompt = '';
    currentActiveRunId = null;
    currentActiveAssistantId = null;
    activeDagNodes = [];
    currentCandidateTemplates = [];
    window.activeCustomRolePrompts = {};
    window.activeChosenRoleModels = {};
    window.originalNodeConfigs = {};

    // 11. Reset mobile tabs to default if switched
    const mobileSwitcher = document.getElementById('mobile-tab-switcher');
    if (mobileSwitcher) {
      mobileSwitcher.classList.remove('active');
      mobileSwitcher.style.display = 'none';
    }
    const tabBtnCanvas = document.getElementById('tab-btn-canvas');
    const tabBtnStream = document.getElementById('tab-btn-stream');
    const canvasPane = document.getElementById('workbench-canvas-pane');
    const streamPane = document.getElementById('stream-terminal-pane');
    if (tabBtnCanvas && tabBtnStream) {
      tabBtnCanvas.classList.add('active');
      tabBtnStream.classList.remove('active');
      canvasPane?.classList.add('tab-active');
      streamPane?.classList.remove('tab-active');
    }

    // 12. Switch viewport back to Stage 1 root interface
    setWorkflowActive(false);

    // 13. Focus input
    if (input) {
      input.focus();
    }
  }

  function initConsoleBackButton() {
    const handleBack = (e) => {
      e.stopPropagation();
      resetToRootInterface();
      triggerInputAttentionGlow();
    };
    const backBtn = document.getElementById('console-back-btn');
    if (backBtn) backBtn.addEventListener('click', handleBack);
    const mobileBackBtn = document.getElementById('mobile-back-to-home-btn');
    if (mobileBackBtn) mobileBackBtn.addEventListener('click', handleBack);
  }

  // Fixed Portal Popover Menu for History Drawer (Expands to the right)
  let currentMenuTraceId = null;

  function closeFixedTraceMenu() {
    const menu = document.getElementById('trace-menu-popover-fixed');
    if (menu) menu.style.display = 'none';
    document.querySelectorAll('.trace-actions').forEach(a => a.classList.remove('menu-open'));
    currentMenuTraceId = null;
  }

  function openFixedTraceMenu(traceId, moreBtn) {
    const menu = document.getElementById('trace-menu-popover-fixed');
    if (!menu || !moreBtn) return;

    if (currentMenuTraceId === traceId && menu.style.display !== 'none') {
      closeFixedTraceMenu();
      return;
    }

    currentMenuTraceId = traceId;
    const history = readLocalHistory();
    const item = history.find(x => x.id === traceId);
    if (!item) return;

    const pinText = document.getElementById('trace-menu-pin-text');
    if (pinText) {
      pinText.textContent = item.pinned
        ? (typeof t === 'function' ? t('history.unpin') : '取消固定')
        : (typeof t === 'function' ? t('history.pin') : '固定此条');
    }

    document.querySelectorAll('.trace-actions').forEach(a => a.classList.remove('menu-open'));
    moreBtn.closest('.trace-actions')?.classList.add('menu-open');

    // Measure and position to the right of moreBtn into the canvas
    menu.style.display = 'flex';
    menu.style.visibility = 'hidden';

    const rect = moreBtn.getBoundingClientRect();
    const menuWidth = menu.offsetWidth || 135;
    const menuHeight = menu.offsetHeight || 120;

    let left = rect.right + 8;
    if (left + menuWidth > window.innerWidth - 10) {
      left = Math.max(10, rect.left - menuWidth - 8);
    }

    let top = rect.top - 4;
    if (top + menuHeight > window.innerHeight - 10) {
      top = window.innerHeight - menuHeight - 10;
    }
    if (top < 10) top = 10;

    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    menu.style.visibility = 'visible';
  }

  function sanitizePromptLeakage(text) {
    if (!text) return '';
    return text.replace(
      /(?:\n+|\r\n)+(?:[#* -]*\**【?(?:铁律|输出语言|内容详略|系统守则|指令规则|全局预设|规则说明|交付铁律)】?\**[:：]?[\s\S]*)$/i,
      ''
    ).replace(
      /(?:\n+|\r\n)+[#* -]*(?:铁律|Ironclad Rule)[:：]?\s*[\s\S]*$/i,
      ''
    ).trim();
  }

  function readLocalHistory(accountId = window.historyAccountId) {
    if (!accountId) return [];
    return JSON.parse(localStorage.getItem('nanomesh_trace_history:' + accountId) || '[]');
  }

  function writeLocalHistory(history, accountId = window.historyAccountId) {
    if (!accountId || window.historyAccountId !== accountId) return;
    // Keep unsynced copies even when older synced conversations are evicted.
    const retained = history.filter((item, index) => index < 50 || item.pendingHistoryVersion);
    localStorage.setItem('nanomesh_trace_history:' + accountId, JSON.stringify(retained));
  }

  async function fetchCloudHistory() {
    const accountId = window.historyAccountId;
    if (!accountId) return;
    try {
      const res = await fetch('/api/history', { headers: { 'X-History-Account': accountId } });
      if (!res.ok) return;
      const data = await res.json();
      if (accountId !== window.historyAccountId || !Array.isArray(data?.sessions)) return;

      const localHistory = readLocalHistory(accountId);
      const merged = new Map(data.sessions.map(item => [item.sessionId, item]));
      for (const item of localHistory) {
        if (!merged.has(item.sessionId) || item.pendingHistoryVersion) {
          merged.set(item.sessionId, item);
        }
      }
      const sorted = [...merged.values()].sort((a, b) => {
        if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
        return (b.timestamp || 0) - (a.timestamp || 0);
      });
      writeLocalHistory(sorted, accountId);
      renderHistoryList();
    } catch (e) {
      console.warn('Failed to sync cloud history:', e);
    }
  }

  async function syncSaveHistoryToCloud(record) {
    const accountId = window.historyAccountId;
    if (!accountId || !record?.sessionId) return;
    const { pendingHistoryVersion, gitStateSnapshot: _localSnapshot, ...payload } = record;
    if (Array.isArray(payload.rounds)) {
      payload.rounds = payload.rounds.map(round => {
        if (!round || typeof round !== 'object') return round;
        const { gitStateSnapshot: _roundSnapshot, ...fields } = round;
        return fields;
      });
    }
    const isEn = getLocale() === 'en';
    try {
      const res = await fetch('/api/history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-History-Account': accountId },
        body: JSON.stringify(payload)
      });
      if (accountId !== window.historyAccountId) return;
      const history = readLocalHistory(accountId);
      const saved = history.find(item => item.sessionId === record.sessionId);
      if (!saved || saved.pendingHistoryVersion !== pendingHistoryVersion) return;

      if (res.ok) {
        delete saved.pendingHistoryVersion;
        writeLocalHistory(history, accountId);
      } else {
        localToast(isEn
          ? 'This conversation could not sync. The full copy is saved on this device.'
          : '本次未同步，完整对话已保留在此设备。', 'warning');
      }
      renderHistoryList();
    } catch (e) {
      console.warn('Failed to persist history to cloud:', e);
      if (accountId === window.historyAccountId) {
        localToast(isEn
          ? 'This conversation could not sync. The full copy is saved on this device.'
          : '本次未同步，完整对话已保留在此设备。', 'warning');
      }
    }
  }

  async function syncHistoryItemUpdate(sessionId, patchData) {
    const accountId = window.historyAccountId;
    if (!sessionId || !accountId) return;
    try {
      await fetch('/api/history/' + encodeURIComponent(sessionId), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'X-History-Account': accountId },
        body: JSON.stringify(patchData)
      });
    } catch (e) {
      console.warn('Failed to update history on cloud:', e);
    }
  }

  async function syncHistoryItemDelete(sessionId) {
    const accountId = window.historyAccountId;
    if (!sessionId || !accountId) return { ok: false, status: 401 };
    try {
      const res = await fetch('/api/history/' + encodeURIComponent(sessionId), {
        method: 'DELETE',
        headers: { 'X-History-Account': accountId }
      });
      if (accountId !== window.historyAccountId) return { ok: false, status: 409 };
      if (res.ok || res.status === 404) {
        return { ok: true, status: res.status };
      }
      const errBody = await res.json().catch(() => ({}));
      return {
        ok: false,
        status: res.status,
        error: errBody.error || 'delete_failed',
        message: errBody.message || (res.status === 409 ? '当前会话正在运行或等待保存，请完成或放弃后再删除。' : '删除会话失败，请稍后重试。')
      };
    } catch (e) {
      console.warn('Failed to delete history on cloud:', e);
      return {
        ok: false,
        status: 0,
        error: 'network_error',
        message: '网络异常，无法删除云端会话记录。'
      };
    }
  }

  function initFixedTraceMenuActions() {
    const pinBtn = document.getElementById('trace-menu-pin-btn');
    pinBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      const traceId = currentMenuTraceId;
      closeFixedTraceMenu();
      if (!traceId) return;
      const history = readLocalHistory();
      const target = history.find(x => x.id === traceId);
      if (target) {
        target.pinned = !target.pinned;
        writeLocalHistory(history);
        renderHistoryList();
        syncHistoryItemUpdate(target.sessionId || target.id, { pinned: target.pinned });
      }
    });

    const renameBtn = document.getElementById('trace-menu-rename-btn');
    renameBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      const traceId = currentMenuTraceId;
      closeFixedTraceMenu();
      if (!traceId) return;
      const history = readLocalHistory();
      const target = history.find(x => x.id === traceId);
      if (target) {
        const promptMsg = (typeof t === 'function' && t('history.renamePrompt')) || '重命名此条记录:';
        const newTitle = window.prompt(promptMsg, target.title || '');
        if (newTitle !== null && newTitle.trim() && newTitle.trim() !== target.title) {
          target.title = newTitle.trim();
          writeLocalHistory(history);
          renderHistoryList();
          syncHistoryItemUpdate(target.sessionId || target.id, { title: target.title });
        }
      }
    });

    const deleteBtn = document.getElementById('trace-menu-delete-btn');
    deleteBtn?.addEventListener('click', async (e) => {
      e.stopPropagation();
      const traceId = currentMenuTraceId;
      closeFixedTraceMenu();
      if (!traceId) return;
      const history = readLocalHistory();
      const itemToDelete = history.find(x => x.id === traceId);
      if (!itemToDelete) return;
      const deleteRes = await syncHistoryItemDelete(itemToDelete.sessionId || itemToDelete.id);
      if (!deleteRes.ok) {
        localToast(deleteRes.message || '当前会话正在运行中，请完成后再删除。', 'warning');
        return;
      }
      const nextHistory = readLocalHistory()
        .filter(x => x.id !== traceId);
      writeLocalHistory(nextHistory);
      if (itemToDelete.sessionId === window.chatSessionId || itemToDelete.id === window.chatSessionId) {
        resetToRootInterface();
      }
      renderHistoryList();
    });
  }

  // Stage 5: Off-canvas Trace History Drawer Logic
  function initHistoryDrawer() {
    const toggleBtn = document.getElementById('history-drawer-toggle');
    const drawer = document.getElementById('history-drawer');
    const closeBtn = document.getElementById('history-drawer-close');
    const listEl = document.getElementById('history-drawer-list');
    const newChatBtn = document.getElementById('history-new-chat-btn');
    if (!toggleBtn || !drawer) return;

    if (newChatBtn) {
      newChatBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        resetToRootInterface();
        closeHistoryDrawer();
        triggerInputAttentionGlow();
      });
    }

    // Toggle on click only (no hover timers to prevent accidental triggers)
    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (drawer.classList.contains('open')) {
        closeHistoryDrawer();
      } else {
        openHistoryDrawer();
      }
    });

    closeBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      closeHistoryDrawer();
    });

    // Close only when clicking anywhere outside of the drawer, toggle button, and fixed popover
    document.addEventListener('click', (e) => {
      if (drawer.classList.contains('open')) {
        if (!e.target.closest('#history-drawer') &&
            !e.target.closest('#history-drawer-toggle') &&
            !e.target.closest('#trace-menu-popover-fixed')) {
          closeHistoryDrawer();
        }
      }
      if (!e.target.closest('#trace-menu-popover-fixed') && !e.target.closest('.trace-more-btn')) {
        closeFixedTraceMenu();
      }
    });

    // Close fixed menu on drawer scroll
    listEl?.addEventListener('scroll', () => {
      closeFixedTraceMenu();
    }, { passive: true });

    initFixedTraceMenuActions();
    renderHistoryList();
    fetchCloudHistory();
  }

  function openHistoryDrawer() {
    const drawer = document.getElementById('history-drawer');
    if (drawer) {
      drawer.classList.add('open');
      renderHistoryList();
      fetchCloudHistory();
    }
  }

  function closeHistoryDrawer() {
    const drawer = document.getElementById('history-drawer');
    if (drawer) {
      drawer.classList.remove('open');
      closeFixedTraceMenu();
    }
  }

  function saveTraceToHistory(record) {
    if (!window.historyAccountId) return;
    try {
      let history = readLocalHistory();
      const sessId = record.sessionId || window.chatSessionId || ('session-' + Date.now());
      let existingIndex = history.findIndex(x => (x.sessionId && x.sessionId === sessId) || x.id === record.id);

      let targetRecord;
      if (existingIndex >= 0) {
        targetRecord = history[existingIndex];
        history.splice(existingIndex, 1);
        targetRecord.title = record.title || targetRecord.title;
        targetRecord.cost = record.cost || targetRecord.cost;
        targetRecord.duration = record.duration || targetRecord.duration;
        targetRecord.nodesCount = record.nodesCount || targetRecord.nodesCount;
        targetRecord.cached = record.cached !== undefined ? record.cached : targetRecord.cached;
        if (record.gitStateSnapshot) targetRecord.gitStateSnapshot = record.gitStateSnapshot;
        targetRecord.timestamp = Date.now();
        if (!targetRecord.rounds) targetRecord.rounds = [];
        if (record.round) {
          const { gitStateSnapshot: _dropRoundSnap, ...compactRound } = record.round;
          const rIdx = targetRecord.rounds.findIndex(r => r.runId && r.runId === compactRound.runId);
          if (rIdx >= 0) {
            targetRecord.rounds[rIdx] = compactRound;
          } else {
            targetRecord.rounds.push(compactRound);
          }
        }
      } else {
        const initialRound = record.round
          ? (() => {
              const { gitStateSnapshot: _dropRoundSnap, ...compactRound } = record.round;
              return compactRound;
            })()
          : null;
        targetRecord = {
          id: record.id || ('trace-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6)),
          sessionId: sessId,
          title: record.title || '多模态任务编排',
          cost: record.cost || '120',
          duration: record.duration || '2.8s',
          nodesCount: record.nodesCount || 1,
          cached: record.cached || false,
          pinned: record.pinned || false,
          gitStateSnapshot: record.gitStateSnapshot || null,
          timestamp: Date.now(),
          rounds: initialRound ? [initialRound] : []
        };
      }

      targetRecord.pendingHistoryVersion = crypto.randomUUID();
      history.unshift(targetRecord);

      // Sort pinned first, then timestamp descending
      history.sort((a, b) => {
        if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
        return (b.timestamp || 0) - (a.timestamp || 0);
      });

      // Maintain up to 50 conversations in history
      writeLocalHistory(history);
      renderHistoryList();
      syncSaveHistoryToCloud(targetRecord);
    } catch (e) {
      console.warn('Failed to save trace to history:', e);
      localToast(getLocale() === 'en' ? 'Could not save conversation history on this device.' : '本设备无法保存对话历史。', 'warning');
    }
  }

  function restoreConversationFromHistory(record) {
    if (!record) return;

    // 1. Abort any currently running chat stream
    if (window.activeChatAbortController) {
      try { window.activeChatAbortController.abort(); } catch (e) {}
    }

    // 2. Close drawer
    closeHistoryDrawer();

    // 3. Switch to workbench split view
    setWorkflowActive(true);

    // 4. Reveal Unified Control Bar
    const controlBar = document.getElementById('unified-control-bar') || document.getElementById('macro-workflow-bar');
    if (controlBar) controlBar.style.display = 'inline-flex';

    // 5. Empty messages flow
    const messagesFlow = document.getElementById('messages-flow');
    if (!messagesFlow) return;
    messagesFlow.innerHTML = '';

    // 6. User avatar
    const u = window.currentUser;
    let userAvatarHtml = '<span class="msg-avatar-initial">U</span>';
    if (u && u.avatar_url) {
      userAvatarHtml = `<img src="${escapeHtml(u.avatar_url)}" class="msg-avatar-img" alt="User">`;
    } else if (u && u.username) {
      userAvatarHtml = `<span class="msg-avatar-initial">${escapeHtml(u.username.charAt(0).toUpperCase())}</span>`;
    }

    // 7. Group rounds by baseRunId / original round (synthesize for legacy entries if needed)
    const rawRounds = (record.rounds && record.rounds.length > 0) ? record.rounds : [{
      runId: 'legacy-' + (record.id || Date.now()),
      userPrompt: record.title || '历史会话',
      assistantOutput: record.assistantOutput || '【历史归档记录】此记录创建于历史快照中，仅保留了路由摘要。',
      nodes: record.nodes || [],
      cost: record.cost,
      duration: record.duration,
      cached: record.cached,
      timestamp: record.timestamp || Date.now()
    }];

    const roundGroups = new Map();
    rawRounds.forEach(r => {
      const groupKey = r.baseRunId || ('round-' + (r.roundIndex || r.runId));
      if (!roundGroups.has(groupKey)) {
        roundGroups.set(groupKey, []);
      }
      roundGroups.get(groupKey).push(r);
    });

    // 8. Render each round group into messages-flow
    roundGroups.forEach((groupRounds) => {
      const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
      const baseRound = groupRounds[0];

      // 8a. User row rendered ONCE per round group
      const userRow = document.createElement('div');
      userRow.className = 'chat-msg-row user';
      userRow.id = 'user-row-' + baseRound.runId;

      let attachmentsHtml = '';
      if (baseRound.assets && baseRound.assets.length > 0) {
        attachmentsHtml = '<div class="user-attachments-grid">' + 
          baseRound.assets.map(f => {
            const sizeStr = formatFileSize(f.size);
            const isImg = (f.previewUrl && !f.previewUrl.startsWith('blob:')) || (f.type && f.type.startsWith('image/')) || f.modality === 'image';
            const imgUrl = (f.previewUrl && !f.previewUrl.startsWith('blob:')) ? f.previewUrl : (f.r2Key ? `/api/asset?key=${encodeURIComponent(f.r2Key)}` : '');
            const isSafeImgUrl = imgUrl && (/^https?:\/\//i.test(imgUrl) || imgUrl.startsWith('/api/') || imgUrl.startsWith('data:image/'));
            if (isImg && isSafeImgUrl) {
              return `
                <div class="user-asset-card" title="${escapeHtml(f.name)} (${sizeStr})" onclick="window.open('${escapeHtml(imgUrl)}', '_blank', 'noopener,noreferrer')" style="cursor:pointer;">
                  <div class="user-asset-thumb-box">
                    <img src="${escapeHtml(imgUrl)}" class="user-asset-thumb-img" alt="${escapeHtml(f.name)}" />
                  </div>
                  <div class="user-asset-meta-col">
                    <span class="user-asset-filename">${escapeHtml(f.name)}</span>
                    <span class="user-asset-filesize">${sizeStr}</span>
                  </div>
                </div>
              `;
            } else {
              const isPdf = (f.name || '').toLowerCase().endsWith('.pdf') || f.modality === 'pdf';
              const docIcon = isPdf ? '📄' : f.modality === 'audio' ? '🎙️' : '📎';
              return `
                <div class="user-asset-card" title="${escapeHtml(f.name)} (${sizeStr})">
                  <div class="user-asset-thumb-box is-doc">
                    <span class="user-asset-doc-icon">${docIcon}</span>
                  </div>
                  <div class="user-asset-meta-col">
                    <span class="user-asset-filename">${escapeHtml(f.name)}</span>
                    <span class="user-asset-filesize">${sizeStr}</span>
                  </div>
                </div>
              `;
            }
          }).join('') +
          '</div>';
      }

      let intentPillHtml = '';
      if (baseRound.intentState) {
        const compactIntent = getCompactIntentName(baseRound.intentState, isEn);
        const stateClass = baseRound.intentState === 'ANCHOR_TAIL' ? 'state-a' :
          baseRound.intentState === 'REBIND_ROOT' ? 'state-b' :
          baseRound.intentState === 'CROSS_FUSION' ? 'state-d' :
          baseRound.intentState === 'SWITCH_BRANCH' ? 'state-e' : 'state-c';
        const titleText = isEn 
          ? (baseRound.intentState === 'ANCHOR_TAIL' ? 'State A: Stripped raw media, inheriting prior turn text context' :
             baseRound.intentState === 'REBIND_ROOT' ? 'State B: Reset asset pointer, re-exploring raw media assets' :
             baseRound.intentState === 'CROSS_FUSION' ? 'State D: Cross-turn asset fusion and comparison' :
             baseRound.intentState === 'SWITCH_BRANCH' ? 'State E: Switched context to recalled historical task branch' :
             'State C: Detached historical context, independent clean orchestration')
          : (baseRound.intentState === 'ANCHOR_TAIL' ? '状态 A：已剥离原始媒体资产，装载上轮产物，精简重组文本润色图' :
             baseRound.intentState === 'REBIND_ROOT' ? '状态 B：重置资产指针，全链路重新探索原始素材' :
             baseRound.intentState === 'CROSS_FUSION' ? '状态 D：多源融合与跨轮对比，继承历史资产并结合新输入' :
             baseRound.intentState === 'SWITCH_BRANCH' ? '状态 E：已切回关联的历史任务分支，挂载该分支产物为基底' :
             '状态 C：断离历史上下文，全新任务独立编排');
        intentPillHtml = `<div class="telemetry-pill intent-telemetry-pill ${stateClass}" title="${titleText}">${compactIntent}</div>`;
      }

      const cachePillHtml = baseRound.cached ? `<div class="telemetry-pill cache-telemetry-pill"><span>${isEn ? '⚡ Cached · Fast-Pass' : '⚡ 节省算力: 命中直出'}</span></div>` : '';

      userRow.innerHTML = `
        <div class="msg-avatar-col">
          <div class="msg-avatar-badge user-avatar-badge">${userAvatarHtml}</div>
        </div>
        <div class="msg-content-col">
          <div class="telemetry-meta-bar" id="telemetry-bar-${baseRound.runId}">
            <div class="telemetry-pill arb-telemetry-pill locked" id="arb-pill-${baseRound.runId}">
              <span class="arb-text" id="arb-text-${baseRound.runId}">${getCompactArbitrationText(
                baseRound.nodes && baseRound.nodes.some(n => n.role_id === 'role_edge_firewall'),
                baseRound.nodes && baseRound.nodes.some(n => n.role_id === 'role_unreachable'),
                baseRound.duration || baseRound.latency_ms,
                isEn
              )}</span>
            </div>
            ${intentPillHtml}
            ${cachePillHtml}
          </div>
          <div class="chat-bubble-user">
            ${attachmentsHtml}
            <div class="chat-user-text">${escapeHtml(baseRound.userPrompt)}</div>
            <div class="user-action-row">
              <button class="chat-action-btn copy-btn" title="${isEn ? 'Copy' : '复制内容'}" aria-label="${isEn ? 'Copy' : '复制'}">
                <svg class="copy-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                <svg class="check-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#10b981" stroke-width="2.5" style="display:none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
                <span class="btn-text">${isEn ? 'Copy' : '复制'}</span>
              </button>
            </div>
          </div>
        </div>
      `;
      messagesFlow.appendChild(userRow);

      // 8b. Assistant row for each revision in this round group
      groupRounds.forEach((rnd, revIdx) => {
        const assistantRow = document.createElement('div');
        assistantRow.className = 'chat-msg-row assistant';
        const assistantId = 'assistant-msg-' + rnd.runId;
        assistantRow.id = assistantId;

      let stepsHtml = '';
      const sanitizeStepHtml = (rawHtml) => {
        if (!rawHtml) return '';
        if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
          return window.DOMPurify.sanitize(String(rawHtml), {
            ALLOWED_TAGS: ['span', 'b', 'strong', 'i', 'em', 'small'],
            ALLOWED_ATTR: ['class', 'style']
          });
        }
        return escapeHtml(String(rawHtml));
      };
      if (rnd.steps && rnd.steps.length > 0) {
        stepsHtml = rnd.steps.map(s => {
          if (typeof s === 'string') return escapeHtml(s);
          if (s && s.html) return `<div class="${escapeHtml(s.className || 'assistant-step-badge completed')}">${sanitizeStepHtml(s.html)}</div>`;
          const timeStr = s.cache_hit ? '⚡ 0ms' : (s.duration_ms ? `${Number(s.duration_ms) || 0}ms` : '');
          const roleLabel = isEn ? (s.role_name_en || getCompactRoleName(s.role_id, s.role_name)) : (s.role_name || '节点');
          return `<div class="assistant-step-badge completed"><span class="step-check">✓</span> <span>${escapeHtml(roleLabel)} ${isEn ? 'Done' : '完成'}</span> ${timeStr ? `<span class="step-time">${escapeHtml(timeStr)}</span>` : ''}</div>`;
        }).join('');
      } else if (rnd.nodes && rnd.nodes.length > 0) {
        stepsHtml = rnd.nodes.map(n => {
          const timeStr = n.cache_hit ? '⚡ 0ms' : (n.duration_ms ? `${Number(n.duration_ms) || 0}ms` : '');
          const roleLabel = isEn ? (n.name_en || getCompactRoleName(n.role_id, n.name_zh)) : (n.name_zh || '节点');
          return `<div class="assistant-step-badge completed"><span class="step-check">✓</span> <span>${escapeHtml(roleLabel)} ${isEn ? 'Done' : '完成'}</span> ${timeStr ? `<span class="step-time">${escapeHtml(timeStr)}</span>` : ''}</div>`;
        }).join('');
      }

      let parsedOutput = '';
      const isFirewallRun = (rnd.nodes && rnd.nodes.some(n => n.role_id === 'role_edge_firewall' || n.status === 'blocked'));
      const isUnreachableRun = (rnd.nodes && rnd.nodes.some(n => n.role_id === 'role_unreachable' || n.status === 'unreachable'));

      if (isFirewallRun) {
        parsedOutput = `
          <div class="security-guardrail-banner">
            <div class="guardrail-header">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span>${isEn ? '⚠️ NanoMesh Safety & Compliance Guardrail' : '⚠️ NanoMesh 安全合规防护'}</span>
            </div>
            <div class="guardrail-body">
              <p style="margin: 0 0 10px 0;">
                ${isEn
                  ? 'Sorry, your instruction was audited by the Edge Firewall and flagged for unauthorized system attacks, weaponized exploits, or intellectual property infringements. Execution has been terminated without consuming compute credits. Please refer to <a href="/terms" target="_blank" class="guardrail-link">NanoMesh Terms of Service</a>.'
                  : '抱歉，您的指令经安全网关审计，涉及未授权系统攻击、入侵工具武器化或侵犯版权等违规行为。该请求已被终止执行，未扣除算力点数。请参阅 <a href="/terms" target="_blank" class="guardrail-link">NanoMesh 服务条款</a>。'
                }
              </p>
              <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                ${isEn
                  ? 'If this was intended for defensive security configurations or academic research, please adjust your phrasing. Continued violations may lead to account suspension.'
                  : '如为您自建环境的防御性安全配置或学术分析，请调整表述明确防御上下文。如果您持续进行违规活动，您的账号可能被暂停。'
                }
              </p>
            </div>
          </div>
        `;
      } else if (isUnreachableRun) {
        parsedOutput = `
          <div class="capability-guardrail-banner">
            <div class="guardrail-header">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#818cf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
              </svg>
              <span>${isEn ? '∅ Intent Unreachable / Capability Boundary' : '∅ 意图不可达 / 能力边界熔断'}</span>
            </div>
            <div class="guardrail-body">
              <p style="margin: 0 0 10px 0;">
                ${isEn
                  ? 'No workflow template in the current catalog matches your specific intent. NanoMesh is currently specialized in multimodal visual understanding, entity extraction, cross-lingual translation, and structured polishing. The system has fast-failed to protect your compute credits with 0 charges.'
                  : '当前工作流库未检索到能够胜任该业务意图的编排链路。NanoMesh 目前专精于多模态图文解析、实体信息抽取、跨语言重构与结构化表达润色。系统已在极短时间内快速熔断本轮执行，未消耗您的任何算力点数。'
                }
              </p>
              <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                ${isEn
                  ? '*(Tip: Try uploading multimodal materials or refining your text analysis goals)*'
                  : '*(建议：您可以尝试上传多模态图文材料，或细化您在文字润色、文档抽取方面的诉求)*'
                }
              </p>
            </div>
          </div>
        `;
      } else if (rnd.assistantOutput) {
        const cleanOutput = sanitizePromptLeakage(rnd.assistantOutput);
        parsedOutput = safeRenderMarkdown(cleanOutput);
      }

      const actionsVisibility = (isFirewallRun || isUnreachableRun || !parsedOutput) ? 'style="display:none;"' : '';

      assistantRow.innerHTML = `
        <div class="msg-avatar-col">
          <div class="msg-avatar-badge mesh-avatar-badge" title="NanoMesh Engine">
            <span class="mesh-logo-glyph">◎</span>
          </div>
        </div>
        <div class="msg-content-col">
          <div class="chat-bubble-assistant">
            <div class="assistant-steps-stream" id="assistant-steps-${assistantId}">${stepsHtml}</div>
            <div class="chat-response-wrapper">
              <div class="chat-response-text" id="response-text-${assistantId}">${parsedOutput}</div>
              <div class="chat-response-actions is-visible" id="actions-${assistantId}" ${actionsVisibility}>
                <button class="chat-action-btn copy-btn" title="${isEn ? 'Copy' : '复制内容'}" aria-label="${isEn ? 'Copy' : '复制'}">
                  <svg class="copy-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  <svg class="check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#10b981" stroke-width="2.5" style="display:none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  <span class="btn-text">${isEn ? 'Copy' : '复制'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      `;
      messagesFlow.appendChild(assistantRow);
      });
    });

    // 9. Restore DAG canvas from the last SUCCESSFUL run (avoid restoring fast-failed/blocked revisions)
    const isRoundFailed = (r) => !!(
      r?.isFastFailed ||
      (Array.isArray(r?.nodes) && r.nodes.some(n =>
        n.role_id === 'role_edge_firewall' ||
        n.role_id === 'role_unreachable' ||
        n.status === 'blocked' ||
        n.status === 'unreachable'
      ))
    );
    const allGroups = Array.from(roundGroups.values());
    const lastGroup = allGroups[allGroups.length - 1] || [];
    const lastSuccessfulInGroup = [...lastGroup].reverse().find(r => !isRoundFailed(r));
    const lastSuccessfulOverall = [...rawRounds].reverse().find(r => !isRoundFailed(r));
    const lastRound = lastSuccessfulInGroup || lastSuccessfulOverall || lastGroup[lastGroup.length - 1] || {};
    const targetGroup = allGroups.find(g => g.includes(lastRound)) || lastGroup;
    const firstOfLastGroup = targetGroup[0] || lastRound;
    const nodesToRender = (lastRound.nodes && lastRound.nodes.length > 0) ? lastRound.nodes : (record.nodes || []);
    activeDagNodes = JSON.parse(JSON.stringify(nodesToRender || []));

    window.activeRoundPayload = {
      prompt: lastRound.userPrompt || record.title || '',
      files: lastRound.assets || []
    };
    window.currentRoundIntentState = lastRound.intentState || null;

    if (nodesToRender.length > 0) {
      renderDagNodesWithAnchors(nodesToRender, {
        prompt: lastRound.userPrompt || record.title || '',
        assets: lastRound.assets || [],
        intentState: lastRound.intentState || null,
        isFirewall: nodesToRender.some(n => n.role_id === 'role_edge_firewall'),
        isUnreachable: nodesToRender.some(n => n.role_id === 'role_unreachable'),
        isHistory: true
      });
      // Ensure curves are drawn across animation frames after history snapshot loads
      requestAnimationFrame(() => renderDagSvgConnectors());
      setTimeout(() => renderDagSvgConnectors(), 80);
      setTimeout(() => renderDagSvgConnectors(), 220);
      setTimeout(() => renderDagSvgConnectors(), 520);
    }

    const routeChain = document.getElementById('macro-route-chain');
    if (routeChain && nodesToRender.length > 0) {
      routeChain.textContent = nodesToRender.map(n => getCompactRoleName(n.role_id, n.name_zh, n.name_en)).join(' ➔ ');
    }

    // Set Macro Capsule to Snapshot mode for history viewing
    const macroLabel = document.getElementById('macro-label') || document.querySelector('.macro-label');
    const lockIcon = document.getElementById('macro-lock-icon');
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    if (macroLabel) {
      macroLabel.textContent = isEn ? 'Snapshot:' : '快照:';
    }
    if (lockIcon) {
      lockIcon.style.display = 'inline';
    }

    // 10. Restore candidate templates and macro route dropdown if present
    if (lastRound.candidateTemplates && lastRound.candidateTemplates.length > 0) {
      currentCandidateTemplates = lastRound.candidateTemplates;
      window.currentRunningTemplateId = lastRound.template?.template_id;
      const macroDropdown = document.getElementById('macro-dropdown');
      const macroCapsuleBtn = document.getElementById('macro-capsule-btn');
      if (macroCapsuleBtn && macroDropdown) {
        macroCapsuleBtn.onclick = (e) => {
          e.stopPropagation();
          if (isWorkflowExecuting || isAwaitingCommitResolution) return;
          macroDropdown.style.display = macroDropdown.style.display === 'none' ? 'block' : 'none';
        };
        macroDropdown.innerHTML = currentCandidateTemplates.map((t, idx) => {
          const tplTitle = isEn 
            ? `${idx === 0 ? '🏆' : (idx === 1 ? '⚡' : '🔍')} Route ${idx + 1}: ${escapeHtml(getCompactTemplateName(t.template_id, t.name_zh, t.name_en))}`
            : `${idx === 0 ? '🏆' : (idx === 1 ? '⚡' : '🔍')} 路线 ${idx + 1}: ${escapeHtml(t.name_zh)}`;
          const tplDesc = isEn
            ? (idx === 0 ? 'Optimal match · Recommended' : (idx === 1 ? 'Cost saver · Save 40% ⚡' : 'Low latency direct route'))
            : (idx === 0 ? '综合胜任度最高 · 智能推荐' : (idx === 1 ? '更省算力 · 预估节省 40% ⚡' : '低时延直出路线'));
          return `
            <div class="macro-dropdown-item ${t.template_id === window.currentRunningTemplateId ? 'active' : ''}" data-tpl-id="${t.template_id}">
              <div style="font-weight:600; font-size:0.85rem; color:var(--text-primary);">
                ${tplTitle}
              </div>
              <div style="font-size:0.74rem; color:var(--text-secondary); margin-top:2px;">
                ${tplDesc}
              </div>
            </div>
          `;
        }).join('');

        macroDropdown.querySelectorAll('.macro-dropdown-item').forEach(item => {
          item.onclick = (e) => {
            e.stopPropagation();
            if (isWorkflowExecuting || isAwaitingCommitResolution) return;
            const chosenId = item.getAttribute('data-tpl-id');
            macroDropdown.style.display = 'none';
            if (chosenId !== window.currentRunningTemplateId) {
              triggerTemplateSwitch(chosenId, window.lastUserPrompt || '切换工作流');
            }
          };
        });
      }
    }

    // 11. Restore session parameters & full Git tree topology for next follow-up round
    const successfulGroupsCount = allGroups.filter(g => g.some(r => !isRoundFailed(r))).length;
    window.chatSessionId = record.sessionId || record.id;
    window.chatRoundIndex = successfulGroupsCount || roundGroups.size;
    window.lastRoundSummary = lastRound.assistantOutput ? lastRound.assistantOutput.slice(0, 4000) : '';
    window.currentDagBaseSummary = window.lastRoundSummary;
    window.lastUserPrompt = lastRound.userPrompt || record.title || '';
    window._currentPreFlightSnapshot = null;
    window._currentStagedNewFiles = [];
    window._currentRoundGeneratedAssets = [];
    window._pendingRoundTrace = null;
    window._pendingClarificationContext = null;

    const restoredGitSnapshot = record.gitStateSnapshot || lastRound.gitStateSnapshot;
    if (restoredGitSnapshot && restoredGitSnapshot.branches && restoredGitSnapshot.assetVault) {
      window.gitState = JSON.parse(JSON.stringify(restoredGitSnapshot));
    } else {
      window.gitState = createEmptyGitState();
      window.gitState.branches.main.lastValidSummary = window.lastRoundSummary;
      rawRounds.forEach(r => {
        if (isRoundFailed(r)) return;
        const bid = r.branchId || 'main';
        if (r.assets && Array.isArray(r.assets)) {
          r.assets.forEach(a => {
            const aid = a.assetId || a.id || a.name;
            if (aid && !window.gitState.assetVault[aid]) {
              window.gitState.assetVault[aid] = { ...a, id: aid, assetId: aid, branchId: bid };
            }
          });
        }
        window.gitState.branches[bid] = {
          branchId: bid,
          topic: (r.userPrompt || '历史分支').slice(0, 50),
          headCommitId: r.runId || null,
          isMediaBranch: !!(r.assets && r.assets.some(a => a.modality === 'image' || a.modality === 'audio')),
          lastValidSummary: r.assistantOutput ? r.assistantOutput.slice(0, 4000) : '',
          lineageAssetIds: (r.assets || []).map(a => a.assetId || a.id || a.name).filter(Boolean)
        };
        window.gitState.activeBranchId = bid;
      });
    }
    syncLegacyGlobalsFromGitState();
    // Refresh from server-authoritative Git session state asynchronously when available
    if (window.chatSessionId && typeof fetch === 'function') {
      const targetRestoreSessId = window.chatSessionId;
      fetch('/api/session/' + encodeURIComponent(targetRestoreSessId) + '/state')
        .then(r => (r.ok ? r.json() : null))
        .then(snap => {
          if (snap && window.chatSessionId === targetRestoreSessId) {
            hydrateGitStateFromServer(snap);
          }
        })
        .catch(() => {});
    }

    // Reconstitute frozen input baseline from last successful round group
    window._currentRoundFrozenInput = {
      userText: firstOfLastGroup.userPrompt || window.lastUserPrompt || '',
      selectedFiles: JSON.parse(JSON.stringify(firstOfLastGroup.assets || [])),
      frozenAssets: JSON.parse(JSON.stringify(firstOfLastGroup.assets || [])),
      targetLanguage: lastRound.targetLanguage || firstOfLastGroup.targetLanguage || localStorage.getItem('nanomesh_lang') || 'auto',
      outputStyle: lastRound.outputStyle || firstOfLastGroup.outputStyle || localStorage.getItem('nanomesh_style') || 'concise',
      baseSummary: window.currentDagBaseSummary || '',
      roundIndex: window.chatRoundIndex,
      baseRunId: firstOfLastGroup.baseRunId || firstOfLastGroup.runId,
      revision: lastRound.revision || 1,
      committedRevision: lastRound.revision || 1,
      frozenResolvedPlan: lastRound.resolvedPlan || null
    };

    window.originalNodeConfigs = {};
    window.activeChosenRoleModels = {};
    window.activeCustomRolePrompts = {};
    (nodesToRender || []).forEach(n => {
      const nKey = n && (n.node_id || n.role_id);
      if (nKey) {
        window.originalNodeConfigs[nKey] = {
          model_id: n.selected_model?.model_id || '',
          custom_prompt: n.custom_prompt || ''
        };
        window.activeChosenRoleModels[nKey] = n.selected_model?.model_id || '';
        window.activeCustomRolePrompts[nKey] = n.custom_prompt || '';
      }
    });
    if (window.pendingModifiedRoleIds) {
      window.pendingModifiedRoleIds.clear();
    }
    updateRerouteButtonState();

    const sendBtn = document.getElementById('send-btn');
    if (sendBtn) sendBtn.disabled = false;

    // 12. Re-render drawer list to mark active card
    renderHistoryList();

    // 13. Scroll to bottom
    const scrollContainer = document.getElementById('chat-messages');
    if (scrollContainer) scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }

  function renderHistoryList() {
    const listEl = document.getElementById('history-drawer-list');
    if (!listEl) return;
    try {
      let history = readLocalHistory();
      let updated = false;
      history.forEach((item, idx) => {
        if (!item.id) {
          item.id = 'trace-' + (item.timestamp || (Date.now() - idx * 1000)) + '-' + idx;
          updated = true;
        }
      });
      if (updated) {
        writeLocalHistory(history);
      }

      // Sort pinned items to the very top, then descending by timestamp
      history.sort((a, b) => {
        if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
        return (b.timestamp || 0) - (a.timestamp || 0);
      });

      if (history.length === 0) {
        listEl.innerHTML = '<div class="history-empty" data-i18n="history.empty">暂无历史记录</div>';
        return;
      }

      listEl.innerHTML = history.map(item => {
        const isActive = (window.chatSessionId && item.sessionId === window.chatSessionId);
        return `
        <div class="history-trace-card ${item.pinned ? 'is-pinned' : ''} ${isActive ? 'is-active' : ''}" data-trace-id="${escapeHtml(item.id)}" data-session-id="${escapeHtml(item.sessionId || '')}">
          <div class="trace-dot ${item.cached ? 'amber' : 'green'}"></div>
          <div class="trace-body">
            <div class="trace-title-row">
              <span class="trace-title" title="${escapeHtml(item.title || '多模态任务编排')}">${escapeHtml(item.title || '多模态任务编排')}</span>
              ${item.pinned ? '<span class="trace-pin-icon" title="已固定置顶">📌</span>' : ''}
            </div>
            <div class="trace-meta">
              <span class="cost">${escapeHtml(item.cost || '120')} ⚡</span>
              <span>·</span>
              <span>${escapeHtml(item.duration || '2.1s')}</span>
              <span>·</span>
              <span>${item.nodesCount || 1} 节点</span>
            </div>
          </div>
          <div class="trace-actions" id="trace-actions-${escapeHtml(item.id)}">
            <button class="trace-more-btn" title="更多操作" aria-label="更多操作" data-id="${escapeHtml(item.id)}">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                <circle cx="12" cy="5" r="2.2"></circle>
                <circle cx="12" cy="12" r="2.2"></circle>
                <circle cx="12" cy="19" r="2.2"></circle>
              </svg>
            </button>
          </div>
        </div>
      `;
      }).join('');

      // Bind actions & interactions for each trace card
      listEl.querySelectorAll('.history-trace-card').forEach(card => {
        const traceId = card.getAttribute('data-trace-id');
        const moreBtn = card.querySelector('.trace-more-btn');

        // 3-dots button trigger: opens fixed portal popover menu to the right
        if (moreBtn) {
          moreBtn.onclick = (e) => {
            e.stopPropagation();
            openFixedTraceMenu(traceId, moreBtn);
          };
        }

        // Clicking card restores entire conversation into chat view and DAG canvas
        card.onclick = (e) => {
          if (e.target.closest('.trace-actions') || e.target.closest('.trace-more-btn')) return;
          const hList = readLocalHistory();
          const target = hList.find(x => x.id === traceId);
          if (target) {
            restoreConversationFromHistory(target);
          }
        };
      });

    } catch (e) {
      console.warn('Failed to render history list:', e);
    }
  }

  // ==========================================================
  // Stage 3: Industrial-Grade DAG Dataflow Engine
  // ==========================================================

  window.stateAConsecutiveCount = 0;
  window.isStackExpanded = false;

  function renderDagNodesWithAnchors(nodesToRender, options = {}) {
    window.lastDagNodesToRender = nodesToRender;
    window.lastDagOptions = options;
    const nodesContainer = document.getElementById('dag-nodes-container');
    if (!nodesContainer) return;

    const isFirewall = options.isFirewall || false;
    const isUnreachable = options.isUnreachable || false;
    const intentState = options.intentState || window.currentRoundIntentState || null;
    const promptText = options.prompt || window.lastUserPrompt || '';
    const assets = options.assets || (window.activeRoundPayload && window.activeRoundPayload.files) || [];
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';

    // State C: Smooth Canvas Sweep Transition
    if (options.doSweep) {
      nodesContainer.classList.add('dag-sweep-exit');
      setTimeout(() => {
        nodesContainer.classList.remove('dag-sweep-exit');
        nodesContainer.classList.add('dag-sweep-enter');
        setTimeout(() => nodesContainer.classList.remove('dag-sweep-enter'), 350);
      }, 300);
    }

    const isStateA = intentState === 'ANCHOR_TAIL';
    const isStateB = intentState === 'REBIND_ROOT';
    const hasSupplements = assets && assets.some(a => a.isNew);

    // 1. Build Origin Anchor (Head Node: Input Payload)
    let promptSnippet = promptText.trim().replace(/\s+/g, ' ');
    if (promptSnippet.length > 20) promptSnippet = promptSnippet.slice(0, 19) + '…';

    let inventoryItemsHtml = '';
    if (isStateA) {
      // State A: Local tweak on previous output. Raw media was stripped, consuming previous text context (0 image tokens)
      const textDocItems = (assets || []).filter(a => a.modality === 'text' || a.modality === 'text_doc').map(f => {
        const sizeStr = formatFileSize(f.size);
        return `
          <div class="origin-payload-item is-supplemented" title="${isEn ? 'Supplement Doc: ' : '补充文档: '}${escapeHtml(f.name)} (${sizeStr})">
            <span class="payload-badge file-badge">📄</span>
            <span class="payload-filename">${escapeHtml(f.name)}</span>
            <span class="payload-filesize font-mono">${sizeStr}</span>
          </div>
        `;
      }).join('');

      inventoryItemsHtml = `
        <div class="origin-payload-item" title="${isEn ? 'Inherited Previous Output Context (Text)' : '继承上轮模型交付物基底'}">
          <span class="payload-badge">📄</span>
          <span class="payload-filename">${isEn ? 'Upstream Turn Output' : '上轮产物基底'}</span>
          <span class="payload-filesize font-mono">${isEn ? 'Ready' : '基底就绪'}</span>
        </div>
        ${textDocItems}
      `;
    } else if (isStateB && hasSupplements) {
      // State B with supplemented assets: Fusion of previous context + new media!
      const assetCards = (assets || []).map(f => {
        const sizeStr = formatFileSize(f.size);
        const isImg = f.previewUrl || (f.type && f.type.startsWith('image/')) || f.modality === 'image';
        const isPdf = (f.name || '').toLowerCase().endsWith('.pdf') || f.modality === 'pdf';
        const isAudio = (f.name || '').toLowerCase().endsWith('.mp3') || (f.name || '').toLowerCase().endsWith('.wav') || f.modality === 'audio';
        const badgeIcon = isImg ? '🖼️' : isPdf ? '📄' : isAudio ? '🎙️' : '📎';
        const prefix = f.isNew ? (isEn ? 'New: ' : '补充: ') : (isEn ? 'Prior: ' : '原素材: ');
        return `
          <div class="origin-payload-item ${f.isNew ? 'is-supplemented' : ''}" title="${escapeHtml(f.name)} (${sizeStr})">
            <span class="payload-badge file-badge">${f.isNew ? '➕ ' : ''}${badgeIcon}</span>
            <span class="payload-filename">${prefix}${escapeHtml(f.name)}</span>
            <span class="payload-filesize font-mono">${sizeStr}</span>
          </div>
        `;
      }).join('');

      inventoryItemsHtml = `
        <div class="origin-payload-item" title="${isEn ? 'Inherited Previous Output Summary for cross-asset fusion' : '继承上轮交付基底，用于跨素材联合比对/推理'}">
          <span class="payload-badge">📄</span>
          <span class="payload-filename">${isEn ? 'Prior Turn Context' : '上轮产物基底'}</span>
          <span class="payload-filesize font-mono">${isEn ? 'Ready' : '基底就绪'}</span>
        </div>
        ${assetCards}
      `;
    } else if (assets && assets.length > 0) {
      inventoryItemsHtml = assets.map(f => {
        const sizeStr = formatFileSize(f.size);
        const isImg = f.previewUrl || (f.type && f.type.startsWith('image/')) || f.modality === 'image';
        const isPdf = (f.name || '').toLowerCase().endsWith('.pdf') || f.modality === 'pdf';
        const isAudio = (f.name || '').toLowerCase().endsWith('.mp3') || (f.name || '').toLowerCase().endsWith('.wav') || f.modality === 'audio';
        const badgeIcon = isImg ? '🖼️' : isPdf ? '📄' : isAudio ? '🎙️' : '📎';
        return `
          <div class="origin-payload-item" title="${escapeHtml(f.name)} (${sizeStr})">
            <span class="payload-badge file-badge">${badgeIcon}</span>
            <span class="payload-filename">${escapeHtml(f.name)}</span>
            <span class="payload-filesize font-mono">${sizeStr}</span>
          </div>
        `;
      }).join('');
    } else {
      inventoryItemsHtml = `
        <div class="origin-payload-item muted">
          <span class="payload-badge">📎</span>
          <span class="payload-filename">${isEn ? 'Plain Text' : '纯文本无多模态'}</span>
        </div>
      `;
    }

    const originAnchorHtml = `
      <div class="dag-origin-anchor ${intentState === 'REBIND_ROOT' ? 'origin-rebind-active' : ''}" id="dag-origin-anchor" title="${isEn ? 'Origin Input Payload (Immutable)' : '初始输入载荷清单 (不可修改既定事实)'}">
        <div class="origin-header">
          <span class="origin-title">
            <span>📥</span>
            <span>${isEn ? 'Input Payload' : '初始载荷'}</span>
          </span>
          <span class="origin-meta font-mono">${isEn ? 'P₀ Root' : 'P₀ 源头'}</span>
        </div>
        <div class="origin-payload-inventory">
          <div class="origin-payload-item" title="${escapeHtml(promptText)}">
            <span class="payload-badge">💬</span>
            <span class="payload-text-preview">${isStateA ? (isEn ? 'Delta: ' : '增量诉求: ') : (isStateB && hasSupplements ? (isEn ? 'Fusion: ' : '联合诉求: ') : '')}${escapeHtml(promptSnippet || (isEn ? 'Directive' : '原始指令'))}</span>
          </div>
          ${inventoryItemsHtml}
        </div>
      </div>
    `;

    // 2. Build Work Nodes
    let workNodesHtml = '';
    if (isFirewall) {
      workNodesHtml = `
        <div class="dag-node-card dag-work-node is-firewall" id="dag-node-role_edge_firewall" data-role-id="role_edge_firewall">
          <span class="dag-blocked-stamp">🛑 BLOCKED</span>
          <div class="node-card-header">
            <span class="node-card-title">
              <span class="status-dot"></span>
              ${isEn ? 'Edge Firewall' : '边界防御网关'}
            </span>
            <span class="node-card-meta" id="node-meta-role_edge_firewall">${isEn ? 'BLOCKED' : '拦截阻断'}</span>
          </div>
          <div class="dag-consumption-receipt font-mono">
            ↳ ${isEn ? 'Safety audit: Request Terminated' : '安全审计阻断：执行已终止'}
          </div>
          <div class="node-card-model" id="node-model-label-role_edge_firewall">
            🛡️ ${isEn ? 'Edge Security Firewall' : '边界防御网关'}
          </div>
        </div>
      `;
    } else if (isUnreachable) {
      workNodesHtml = `
        <div class="dag-node-card dag-work-node is-unreachable" id="dag-node-role_unreachable" data-role-id="role_unreachable">
          <span class="dag-zero-cost-stamp">0 ⚡ 零消耗</span>
          <div class="node-card-header">
            <span class="node-card-title">
              <span class="status-dot"></span>
              ${isEn ? 'Capability Boundary' : '意图不可达'}
            </span>
            <span class="node-card-meta" id="node-meta-role_unreachable">0ms</span>
          </div>
          <div class="dag-consumption-receipt font-mono">
            ↳ ${isEn ? '0 Tokens Consumed · Fast-Failed' : '零消耗快速熔断 · 未扣除算力'}
          </div>
          <div class="node-card-model" id="node-model-label-role_unreachable">
            ∅ ${isEn ? 'Capability Boundary' : '能力边界拦截'}
          </div>
        </div>
      `;
    } else {
      const isExecuting = !!(window.isWorkflowExecuting || isWorkflowExecuting);
      const isStateA = intentState === 'ANCHOR_TAIL';
      const consecutiveA = window.stateAConsecutiveCount || 0;
      const shouldCollapse = isStateA && consecutiveA >= 2 && !window.isStackExpanded;

      let collapseCardHtml = '';
      const nodesArray = nodesToRender || [];

      if (shouldCollapse && nodesArray.length > 1) {
        collapseCardHtml = `
          <div class="dag-stack-collapse-card" id="dag-stack-collapse" title="${isEn ? 'Click to expand historical revisions' : '点击展开前序历史修正'}">
            <span>🗂️</span>
            <span>${isEn ? `${consecutiveA} Revisions Folded` : `${consecutiveA} 次历史修正已折叠`}</span>
          </div>
        `;
      }

      const buildWorkNodeCardHtml = (n, idx) => {
        const nodeKey = n.node_id || n.role_id;
        const isNodeFirewall = (n.role_id === 'role_edge_firewall') || n.status === 'blocked';
        const isNodeUnreachable = (n.role_id === 'role_unreachable') || n.status === 'unreachable';
        const isPending = !isNodeFirewall && !isNodeUnreachable && window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.has(nodeKey);
        const isCached = !isNodeFirewall && !isNodeUnreachable && !isPending && (!!n.cache_hit || !!n.perceptual_cache_hit);
        const isGhost = isStateA && idx < nodesArray.length - 1;
        const isParallelCapable = !!n.parallel_group;
        const isWaiting = !isCached && !n.duration_ms && n.status !== 'completed' && isExecuting && Array.isArray(n.depends_on) && n.depends_on.some(d => d !== '__ORIGIN__');

        let stampHtml = '';
        let cardClasses = 'dag-node-card dag-work-node';
        if (n.is_reducer && n.stage_group === 'reducer_merge') cardClasses += ' is-reducer-card';
        if (isWaiting) cardClasses += ' is-waiting-resource';
        let metaText = isCached ? '⚡ 0ms' : (n.duration_ms ? `${n.duration_ms}ms` : (isWaiting ? (isEn ? 'Waiting' : '等待资源') : (isEn ? 'Wait' : '待执行')));

        if (isPending) {
          cardClasses += ' is-pending';
          stampHtml = `<span class="dag-node-pending-stamp">${isEn ? 'Pending' : '待更新 (Pending)'}</span>`;
        } else if (isCached) {
          cardClasses += ' cached';
          stampHtml = '<span class="dag-cache-hit-stamp">⚡ HIT</span>';
        } else if (n.status === 'completed' || n.duration_ms) {
          cardClasses += ' completed';
        }

        if (isGhost) {
          cardClasses += ' is-ghost-card';
        }

        // Dynamic Asset Consumption Receipt
        let receiptText = '';
        if (Array.isArray(n.bound_assets) && n.bound_assets.length > 0) {
          const labels = n.bound_assets.map(ba => {
            const ic = ba.modality === 'image' ? '🖼️' : ba.modality === 'audio' ? '🎙️' : '📄';
            return `${ic} ${ba.filename || ba.asset_id}`;
          });
          receiptText = (isEn ? 'Inputs: ' : '依赖: ') + labels.join(' · ');
        } else if (n.is_reducer && n.stage_group === 'reducer_merge') {
          const depCount = Array.isArray(n.depends_on) ? n.depends_on.length : 0;
          receiptText = isEn ? `Converging ${depCount} evidence streams` : `汇入 ${depCount} 路准备证据`;
        } else if (isStateA) {
          const hasDoc = assets && assets.some(a => a.modality === 'text_doc' || a.modality === 'text');
          receiptText = isEn
            ? (hasDoc ? 'Inputs: 📄 Upstream Output · 📄 Supplement Doc' : 'Inputs: 📄 Upstream Output · 💬 Tweak Directive')
            : (hasDoc ? '依赖: 📄 上轮产物基底 · 📄 补充文本文档' : '依赖: 📄 上轮产物基底 · 💬 增量指令');
        } else if (idx === 0) {
          const hasNewSupplement = assets && assets.some(a => a.isNew);
          if (isStateB && hasNewSupplement) {
            receiptText = isEn
              ? 'Inputs: 📄 Prior Output · 🖼️ Supplement Asset · 💬 Fusion Directive'
              : '依赖: 📄 上轮基底 · 🖼️ 补充素材 · 💬 联合指令';
          } else if (isStateB) {
            receiptText = isEn
              ? 'Inputs: 🖼️ Raw Assets · 💬 Re-inspection Directive'
              : '依赖: 🖼️ 原始素材 · 💬 回溯重探指令';
          } else {
            const hasImg = assets.some(a => a.previewUrl || (a.type && a.type.startsWith('image/')) || a.modality === 'image');
            const hasPdf = assets.some(a => (a.name || '').toLowerCase().endsWith('.pdf') || a.modality === 'pdf' || a.modality === 'text_doc');
            const hasAudio = assets.some(a => (a.name || '').toLowerCase().endsWith('.mp3') || a.modality === 'audio');

            if (hasImg) {
              receiptText = isEn ? 'Inputs: 🖼️ Raw Image · 💬 Directive' : '依赖: 🖼️ 原始图片 · 💬 提取指令';
            } else if (hasPdf) {
              receiptText = isEn ? 'Inputs: 📄 Document · 💬 Directive' : '依赖: 📄 原始文档 · 💬 提取指令';
            } else if (hasAudio) {
              receiptText = isEn ? 'Inputs: 🎙️ Audio · 💬 Directive' : '依赖: 🎙️ 原始音频 · 💬 提取指令';
            } else {
              receiptText = isEn ? 'Inputs: 💬 Raw Directive' : '依赖: 💬 原始指令';
            }
          }
        } else {
          receiptText = isEn
            ? 'Inputs: 📄 Upstream Draft'
            : '依赖: 📄 上游结构化草稿';
        }

        const rawModelId = (n.selected_model && (n.selected_model.id || n.selected_model.model_id)) || n.model_id || '';
        const rawDisplayName = (n.selected_model && n.selected_model.display_name) || n.model_name || '';
        const isBrowserModel = (n.selected_model && n.selected_model.inference_target === 'browser') || rawModelId.startsWith('browser-');
        const modelIcon = n.is_reducer ? '🔀' : (isBrowserModel ? '💻' : '⚙️');
        const modelName = getCompactModelName(rawModelId, rawDisplayName);
        const displayName = getCompactRoleName(n.role_id, n.name_zh, n.name_en);
        const stateTagHtml = isCached
          ? `<span class="dag-state-badge is-cached">${isEn ? 'Cached' : '缓存命中'}</span>`
          : (isParallelCapable ? `<span class="dag-state-badge is-parallel">${isEn ? 'Parallel' : '可并发'}</span>` : '');
        const microBadgeHtml = isBrowserModel 
          ? `<span class="dag-card-micro-badge font-mono" title="${isEn ? 'Downloaded once, cached locally' : '仅首次需下载，随后持久化至浏览器本地'}">⚡ ${isEn ? 'Cached locally on device' : '仅首次需下载，随后持久化至本地'}</span>` 
          : '';

        const depsJson = escapeHtml(JSON.stringify(n.depends_on || []));
        return `
          <div class="${cardClasses}" id="dag-node-${nodeKey}" data-node-id="${escapeHtml(nodeKey)}" data-role-id="${escapeHtml(n.role_id)}" data-stage-group="${escapeHtml(n.stage_group || '')}" data-depends-on="${depsJson}" ${shouldCollapse && isGhost ? 'style="display:none;"' : ''}>
            ${stampHtml}
            <div class="node-card-header">
              <span class="node-card-title">
                <span class="status-dot"></span>
                ${escapeHtml(displayName || n.role_id)}${stateTagHtml}
              </span>
              <span class="node-card-meta" id="node-meta-${nodeKey}">${metaText}</span>
            </div>
            <div class="dag-consumption-receipt font-mono" title="↳ ${escapeHtml(receiptText)}">
              ↳ ${escapeHtml(receiptText)}
            </div>
            <div class="node-card-model" id="node-model-label-${nodeKey}">
              ${modelIcon} ${escapeHtml(modelName)}
            </div>
            ${microBadgeHtml}
          </div>
        `;
      };

      const prepNodes = nodesArray.filter(n => n.stage_group === 'evidence_prep');
      const reducerNodes = nodesArray.filter(n => n.stage_group === 'reducer_merge');
      const synthNodes = nodesArray.filter(n => n.stage_group !== 'evidence_prep' && n.stage_group !== 'reducer_merge');
      const useTopologicalGrouping = prepNodes.length > 1 || reducerNodes.length > 0;

      if (useTopologicalGrouping) {
        const canvasContainerEl = document.getElementById('dag-canvas-container');
        const isNarrow = !!(canvasContainerEl && canvasContainerEl.clientWidth > 0 && canvasContainerEl.clientWidth < 760);
        const isCollapsed = !!window.isEvidenceGroupCollapsed;
        const prepCardsHtml = prepNodes.map((n, idx) => buildWorkNodeCardHtml(n, idx)).join('');
        const reducerHtml = reducerNodes.map((n, idx) => buildWorkNodeCardHtml(n, prepNodes.length + idx)).join('');
        const synthHtml = synthNodes.map((n, idx) => buildWorkNodeCardHtml(n, prepNodes.length + reducerNodes.length + idx)).join('');

        const prepGroupHtml = `
          <div class="dag-stage-group is-evidence-prep ${isNarrow ? 'is-narrow-stack' : ''} ${isCollapsed ? 'is-collapsed' : ''}" id="dag-group-evidence-prep" data-stage-group="evidence_prep" data-depends-on='["__ORIGIN__"]'>
            <div class="dag-stage-group-header" id="dag-group-prep-toggle" title="${isEn ? 'Toggle Evidence Prep details' : '展开/折叠证据准备细节'}">
              <span>🗂️ ${isEn ? `Evidence Prep (${prepNodes.length})` : `证据准备 (${prepNodes.length}路)`} ${isCollapsed ? '▸' : '▾'}</span>
              <span class="dag-stage-group-summary" id="dag-group-prep-status">${isEn ? 'Ready' : '拓扑就绪'}</span>
            </div>
            <div class="dag-stage-group-children">
              ${prepCardsHtml}
            </div>
          </div>
        `;
        workNodesHtml = collapseCardHtml + prepGroupHtml + reducerHtml + synthHtml;
      } else {
        workNodesHtml = collapseCardHtml + nodesArray.map((n, idx) => buildWorkNodeCardHtml(n, idx)).join('');
      }
    }

    // 3. Build Output Sink Anchor
    const isExecuting = !!(window.isWorkflowExecuting || isWorkflowExecuting);
    const isFirewallOrUnreachable = isFirewall || isUnreachable;
    const allWorkDone = !isFirewallOrUnreachable && nodesToRender && nodesToRender.length > 0 && nodesToRender.every(n => n.status === 'completed' || n.duration_ms || n.cache_hit);
    const isSinkCompleted = !isExecuting && !isFirewallOrUnreachable && (options.isHistory || allWorkDone);

    const sinkAnchorHtml = `
      <div class="dag-sink-anchor ${isExecuting ? 'is-executing' : ''} ${isSinkCompleted ? 'completed' : ''}" id="dag-sink-anchor" title="${isEn ? 'Final Convergence: Render to terminal stream' : '终局汇聚：平滑渲染至终端对话流'}">
        <span class="sink-funnel-icon">➔</span>
        <span class="sink-label">${isEn ? 'Terminal Stream' : '渲染至终端'}</span>
      </div>
    `;

    nodesContainer.innerHTML = originAnchorHtml + workNodesHtml + sinkAnchorHtml;

    // Bind evidence prep group expand/collapse toggle
    const prepToggleBtn = document.getElementById('dag-group-prep-toggle');
    if (prepToggleBtn) {
      prepToggleBtn.onclick = (e) => {
        e.stopPropagation();
        window.isEvidenceGroupCollapsed = !window.isEvidenceGroupCollapsed;
        const grp = document.getElementById('dag-group-evidence-prep');
        if (grp) grp.classList.toggle('is-collapsed', !!window.isEvidenceGroupCollapsed);
        const label = prepToggleBtn.querySelector('span');
        if (label) {
          const count = nodesContainer.querySelectorAll('.dag-stage-group .dag-work-node').length;
          label.textContent = `🗂️ ${isEn ? `Evidence Prep (${count})` : `证据准备 (${count}路)`} ${window.isEvidenceGroupCollapsed ? '▸' : '▾'}`;
        }
        requestAnimationFrame(() => renderDagSvgConnectors());
      };
    }

    // Bind stack collapse card toggle
    const collapseBtn = document.getElementById('dag-stack-collapse');
    if (collapseBtn) {
      collapseBtn.onclick = (e) => {
        e.stopPropagation();
        window.isStackExpanded = !window.isStackExpanded;
        renderDagNodesWithAnchors(nodesToRender, options);
      };
    }

    // Bind click on work nodes to open Node Inspector
      nodesContainer.querySelectorAll('.dag-work-node').forEach(card => {
      card.onclick = (e) => {
        e.stopPropagation();
        if (window.isWorkflowExecuting || window.isAwaitingCommitResolution) return;
        const nodeId = card.getAttribute('data-node-id');
        const roleId = card.getAttribute('data-role-id');
        if (roleId === 'role_edge_firewall' || roleId === 'role_unreachable' || roleId === 'role_branch_clarification' || roleId === 'role_evidence_reducer' || roleId === 'role_doc_reader') return;
        const nodeData = activeDagNodes.find(nd => (nd.node_id || nd.role_id) === nodeId || nd.role_id === roleId);
        if (nodeData) openNodeInspector(card, nodeData);
      };
    });

    refreshEvidencePrepGroupSummary();

    // Multi-phase measurement passes to guarantee connector curves across layout & animation frames
    requestAnimationFrame(() => renderDagSvgConnectors());
    setTimeout(() => renderDagSvgConnectors(), 60);
    setTimeout(() => renderDagSvgConnectors(), 200);
    setTimeout(() => renderDagSvgConnectors(), 520);
  }

  function refreshEvidencePrepGroupSummary() {
    const grp = document.getElementById('dag-group-evidence-prep');
    const summaryEl = document.getElementById('dag-group-prep-status');
    if (!grp || !summaryEl) return;
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    const childCards = Array.from(grp.querySelectorAll('.dag-work-node'));
    const parallelCount = childCards.filter(c => c.classList.contains('is-parallel-running')).length;
    const cachedCount = childCards.filter(c => c.classList.contains('cached')).length;
    const waitingCount = childCards.filter(c => c.classList.contains('is-waiting-resource')).length;
    const doneCount = childCards.filter(c => c.classList.contains('completed') || c.classList.contains('cached')).length;

    if (parallelCount > 0) {
      summaryEl.textContent = isEn ? `${parallelCount} parallel` : `⚡ ${parallelCount}路并行中`;
    } else if (doneCount === childCards.length && childCards.length > 0) {
      summaryEl.textContent = cachedCount > 0
        ? (isEn ? `${doneCount} done (${cachedCount} cached)` : `✅ 全部就绪 (${cachedCount}路缓存)`)
        : (isEn ? 'All ready' : '✅ 全部就绪');
    } else if (cachedCount > 0 || waitingCount > 0) {
      const parts = [];
      if (cachedCount > 0) parts.push(isEn ? `${cachedCount} cached` : `${cachedCount}缓存`);
      if (waitingCount > 0) parts.push(isEn ? `${waitingCount} wait` : `${waitingCount}等待`);
      summaryEl.textContent = parts.join(' · ');
    }
  }

  // Stage 3: Smooth Cubic Bézier Connectors on DAG Canvas (Supports Fan-Out & Fan-In Convergence)
  function renderDagSvgConnectors(isReverse = false) {
    const svg = document.getElementById('dag-svg-canvas');
    const container = document.getElementById('dag-nodes-container');
    const canvasContainer = document.getElementById('dag-canvas-container');
    if (!svg || !container) return;

    // Responsive narrow-canvas vertical stack toggle for evidence_prep group
    const prepGroup = document.getElementById('dag-group-evidence-prep');
    if (prepGroup && canvasContainer) {
      const isNarrow = canvasContainer.clientWidth > 0 && canvasContainer.clientWidth < 760;
      prepGroup.classList.toggle('is-narrow-stack', isNarrow);
    }

    const originAnchor = document.getElementById('dag-origin-anchor');
    const visibleWorkCards = Array.from(container.querySelectorAll('.dag-work-node:not([style*="display: none"]):not([style*="display:none"])'));
    const sinkAnchor = document.getElementById('dag-sink-anchor');

    const chain = [];
    if (originAnchor) chain.push(originAnchor);
    chain.push(...visibleWorkCards);
    if (sinkAnchor) chain.push(sinkAnchor);

    if (chain.length < 2) {
      svg.innerHTML = '';
      return;
    }

    // Match SVG dimensions to canvas container's scroll size so edges don't clip on horizontal scroll
    if (canvasContainer) {
      const scrollW = Math.max(canvasContainer.scrollWidth, canvasContainer.clientWidth);
      const scrollH = Math.max(canvasContainer.scrollHeight, canvasContainer.clientHeight);
      if (scrollW > 0 && scrollH > 0) {
        svg.style.width = scrollW + 'px';
        svg.style.height = scrollH + 'px';
      }
    }

    const svgRect = svg.getBoundingClientRect();
    if (svgRect.width === 0 || svgRect.height === 0) {
      if (!window._dagRetryScheduled) {
        window._dagRetryScheduled = true;
        requestAnimationFrame(() => {
          window._dagRetryScheduled = false;
          renderDagSvgConnectors(isReverse);
        });
      }
      return;
    }

    const firstRect = chain[0].getBoundingClientRect();
    const lastRect = chain[chain.length - 1].getBoundingClientRect();
    if (firstRect.width === 0 || lastRect.width === 0) {
      if (!window._dagRetryScheduled) {
        window._dagRetryScheduled = true;
        setTimeout(() => {
          window._dagRetryScheduled = false;
          renderDagSvgConnectors(isReverse);
        }, 50);
      }
      return;
    }

    const isGroupCollapsed = !!(prepGroup && prepGroup.classList.contains('is-collapsed'));
    const hasExplicitDeps = !!(prepGroup || visibleWorkCards.some(c => {
      try {
        const deps = JSON.parse(c.getAttribute('data-depends-on') || '[]');
        return Array.isArray(deps) && deps.length > 0;
      } catch { return false; }
    }));

    const edges = [];
    if (hasExplicitDeps) {
      const elById = new Map();
      if (originAnchor) elById.set('__ORIGIN__', originAnchor);
      visibleWorkCards.forEach(card => {
        const nid = card.getAttribute('data-node-id');
        if (!nid) return;
        const insideCollapsedGroup = isGroupCollapsed && card.closest('#dag-group-evidence-prep');
        elById.set(nid, insideCollapsedGroup ? prepGroup : card);
      });

      const seenEdgeKeys = new Set();
      const pushEdge = (srcEl, tgtEl) => {
        if (!srcEl || !tgtEl || srcEl === tgtEl) return;
        const srcKey = srcEl.id || srcEl.getAttribute('data-node-id');
        const tgtKey = tgtEl.id || tgtEl.getAttribute('data-node-id');
        const key = `${srcKey}->${tgtKey}`;
        if (seenEdgeKeys.has(key)) return;
        seenEdgeKeys.add(key);
        edges.push([srcEl, tgtEl]);
      };

      const outgoingCounts = new Map();
      visibleWorkCards.forEach(card => {
        const tgtEl = (isGroupCollapsed && card.closest('#dag-group-evidence-prep')) ? prepGroup : card;
        let deps = [];
        try {
          deps = JSON.parse(card.getAttribute('data-depends-on') || '[]');
        } catch { deps = []; }
        if (!Array.isArray(deps) || deps.length === 0) {
          deps = ['__ORIGIN__'];
        }
        deps.forEach(depId => {
          const srcEl = elById.get(depId) || originAnchor;
          pushEdge(srcEl, tgtEl);
          if (srcEl) outgoingCounts.set(srcEl, (outgoingCounts.get(srcEl) || 0) + 1);
        });
      });

      // Connect leaf work card(s) to Sink Anchor
      if (sinkAnchor) {
        const leafCards = visibleWorkCards.filter(c => !outgoingCounts.has(c));
        const finalSources = leafCards.length > 0 ? leafCards : [visibleWorkCards[visibleWorkCards.length - 1]];
        finalSources.forEach(src => {
          const srcEl = (isGroupCollapsed && src.closest('#dag-group-evidence-prep')) ? prepGroup : src;
          pushEdge(srcEl, sinkAnchor);
        });
      }
    } else {
      for (let i = 0; i < chain.length - 1; i++) {
        edges.push([chain[i], chain[i + 1]]);
      }
    }

    // Track fan-in counts so converging edges spread cleanly on target port
    const targetEdgeCounts = new Map();
    const targetEdgeIndex = new Map();
    edges.forEach(([, c2]) => targetEdgeCounts.set(c2, (targetEdgeCounts.get(c2) || 0) + 1));

    let paths = '';
    for (const [c1, c2] of edges) {
      const r1 = c1.getBoundingClientRect();
      const r2 = c2.getBoundingClientRect();
      if (r1.width === 0 || r2.width === 0) continue;

      const fanInTotal = targetEdgeCounts.get(c2) || 1;
      const fanInIdx = targetEdgeIndex.get(c2) || 0;
      targetEdgeIndex.set(c2, fanInIdx + 1);
      const ySpreadOffset = fanInTotal > 1 ? ((fanInIdx - (fanInTotal - 1) / 2) * Math.min(10, (r2.height * 0.5) / fanInTotal)) : 0;

      const x1 = r1.right - svgRect.left;
      const y1 = r1.top + r1.height / 2 - svgRect.top;
      const x2 = r2.left - svgRect.left;
      const y2 = r2.top + r2.height / 2 - svgRect.top + ySpreadOffset;

      const dx = Math.max(32, Math.abs(x2 - x1) * 0.45);
      const cp1x = x1 + dx;
      const cp1y = y1;
      const cp2x = x2 - dx;
      const cp2y = y2;

      const d = `M ${x1} ${y1} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${x2} ${y2}`;

      const isTargetExecuting = c2.classList.contains('running') || c2.classList.contains('is-parallel-running') || c2.classList.contains('is-executing');
      const isTargetPending = c2.classList.contains('is-pending') || c2.classList.contains('is-waiting-resource');
      const isTargetCompleted = c2.classList.contains('completed') || c2.classList.contains('cached');
      const isTargetGhost = c2.classList.contains('is-ghost-card');

      let groupClass = 'dag-edge-group';
      if (isTargetExecuting) {
        groupClass += ' is-executing';
      } else if (isTargetPending) {
        groupClass += ' is-pending';
      } else if (isTargetCompleted) {
        groupClass += ' is-completed';
      }

      if (isTargetGhost) {
        paths += `
          <g class="${groupClass}">
            <path class="dag-edge-ghost" d="${d}" />
          </g>
        `;
      } else {
        paths += `
          <g class="${groupClass}">
            <path class="dag-edge-base" d="${d}" />
            <path class="dag-edge-flow" d="${d}" />
          </g>
        `;
      }
    }

    // State B Branching Edge: Downward-curved branch from Origin Anchor
    if (window.currentRoundIntentState === 'REBIND_ROOT' && originAnchor && visibleWorkCards.length > 0) {
      const r0 = originAnchor.getBoundingClientRect();
      const targetCard = visibleWorkCards[0];
      const rt = targetCard.getBoundingClientRect();
      const bx1 = r0.right - svgRect.left;
      const by1 = r0.top + r0.height * 0.75 - svgRect.top;
      const bx2 = rt.left - svgRect.left;
      const by2 = rt.top + rt.height * 0.75 - svgRect.top;
      const bdx = Math.max(40, (bx2 - bx1) * 0.5);
      const bd = `M ${bx1} ${by1} C ${bx1 + bdx} ${by1 + 25}, ${bx2 - bdx} ${by2 + 25}, ${bx2} ${by2}`;
      paths += `
        <g class="dag-edge-group">
          <path class="dag-branch-edge" d="${bd}" />
        </g>
      `;
    }

    svg.innerHTML = paths;
  }
  window.addEventListener('resize', () => renderDagSvgConnectors());

  let dagResizeObserver = null;
  function initDagResizeObserver() {
    const container = document.getElementById('dag-nodes-container');
    const canvasContainer = document.getElementById('dag-canvas-container');
    const workbenchPane = document.querySelector('.workbench-canvas-pane');
    if (dagResizeObserver) return;
    if (window.ResizeObserver) {
      dagResizeObserver = new ResizeObserver(() => {
        requestAnimationFrame(() => renderDagSvgConnectors());
      });
      if (container) dagResizeObserver.observe(container);
      if (canvasContainer) dagResizeObserver.observe(canvasContainer);
      if (workbenchPane) dagResizeObserver.observe(workbenchPane);
    }
    if (workbenchPane) {
      workbenchPane.addEventListener('transitionend', (e) => {
        if (e.propertyName === 'width' || e.propertyName === 'opacity') {
          renderDagSvgConnectors();
        }
      });
    }
    if (canvasContainer) {
      canvasContainer.addEventListener('scroll', () => {
        renderDagSvgConnectors();
      }, { passive: true });
    }
  }

  let currentInspectedNodeRoleId = null;
  window.originalNodeConfigs = window.originalNodeConfigs || {};
  window.pendingModifiedRoleIds = window.pendingModifiedRoleIds || new Set();

  function updateNodeDirtyState(roleId) {
    const orig = window.originalNodeConfigs?.[roleId] || {};
    const currentModel = window.activeChosenRoleModels?.[roleId] || orig.model_id;
    const currentPrompt = (window.activeCustomRolePrompts?.[roleId] !== undefined)
      ? window.activeCustomRolePrompts[roleId]
      : (orig.custom_prompt || '');

    const isDirty = (orig.model_id && currentModel !== orig.model_id) ||
                    (currentPrompt !== (orig.custom_prompt || ''));

    const card = document.getElementById('dag-node-' + roleId);
    if (isDirty) {
      window.pendingModifiedRoleIds.add(roleId);
      if (card) {
        card.classList.add('is-pending');
        // Hide/remove green cache hit stamp if any
        const hitStamp = card.querySelector('.dag-cache-hit-stamp');
        if (hitStamp) hitStamp.remove();
        // Add pending stamp if not exists
        if (!card.querySelector('.dag-node-pending-stamp')) {
          const stamp = document.createElement('span');
          stamp.className = 'dag-node-pending-stamp';
          stamp.textContent = (typeof getLocale === 'function' && getLocale() === 'en') ? 'Pending' : '待更新 (Pending)';
          card.appendChild(stamp);
        }
      }
    } else {
      window.pendingModifiedRoleIds.delete(roleId);
      if (card) {
        card.classList.remove('is-pending');
        const pendingStamp = card.querySelector('.dag-node-pending-stamp');
        if (pendingStamp) pendingStamp.remove();
      }
    }

    updateRerouteButtonState();
  }

  function updateRerouteButtonState() {
    const rerouteBtn = document.getElementById('macro-reroute-btn');
    const labelEl = document.getElementById('macro-reroute-label');
    const inputArea = document.getElementById('input-area');
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-btn');
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';

    const hasPending = Boolean(window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.size > 0);

    if (hasPending) {
      if (rerouteBtn) {
        rerouteBtn.disabled = false;
        rerouteBtn.classList.add('active');
        if (labelEl) labelEl.textContent = isEn ? 'Apply & Rerun' : '应用并重跑';
      }
      if (inputArea) {
        inputArea.classList.add('pending-canvas-sync');
      }
      if (chatInput) {
        chatInput.disabled = true;
        chatInput.placeholder = isEn ? '⚡ Please apply canvas changes first...' : '⚡ 请先应用左侧画布的修改...';
      }
      if (sendBtn) {
        sendBtn.classList.add('btn-morph-pending');
        sendBtn.innerHTML = `
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
          </svg>
        `;
        sendBtn.setAttribute('title', isEn ? 'Run Canvas Changes' : '运行画布更改');
      }
    } else {
      if (rerouteBtn) {
        const retry = canRetryFailedCanvas();
        rerouteBtn.disabled = !retry;
        rerouteBtn.classList.toggle('active', retry);
        if (labelEl) labelEl.textContent = retry
          ? (isEn ? 'Retry this run' : '按原配置重试')
          : (isEn ? 'Reroute' : '重新路由');
      }
      if (inputArea) {
        inputArea.classList.remove('pending-canvas-sync');
      }
      if (chatInput && !isWorkflowExecuting) {
        chatInput.disabled = false;
        chatInput.placeholder = isEn 
          ? 'Enter prompt to analyze image, audio or text...' 
          : '输入指令，分析图片，音频或文本。';
      }
      if (sendBtn) {
        sendBtn.classList.remove('btn-morph-pending');
        sendBtn.innerHTML = `
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="22" y1="2" x2="11" y2="13"></line>
            <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
          </svg>
        `;
        sendBtn.setAttribute('title', isEn ? 'Send' : '发送');
      }
    }
  }

  function captureCanvasSnapshotDraft(mode) {
    return {
      mode,
      pendingRoleIds: new Set(window.pendingModifiedRoleIds || []),
      chosenRoleModels: { ...(window.activeChosenRoleModels || {}) },
      customRolePrompts: { ...(window.activeCustomRolePrompts || {}) },
      prevTemplateId: window.currentRunningTemplateId,
      prevTemplateObj: window.currentRunningTemplateObj || null,
      prevCandidateTemplates: Array.isArray(currentCandidateTemplates) ? [...currentCandidateTemplates] : [],
      prevOriginalNodeConfigs: JSON.parse(JSON.stringify(window.originalNodeConfigs || {})),
      prevActiveDagNodes: JSON.parse(JSON.stringify(activeDagNodes || [])),
      prevRoundPayload: window.activeRoundPayload ? JSON.parse(JSON.stringify(window.activeRoundPayload)) : null,
      prevIntentState: window.currentRoundIntentState ?? null
    };
  }

  function rollbackStagedCanvasDraft() {
    if (window._stagedCanvasDraft) {
      const draft = window._stagedCanvasDraft;
      if (draft.prevTemplateId !== undefined) {
        window.currentRunningTemplateId = draft.prevTemplateId;
        window.currentRunningTemplateObj = draft.prevTemplateObj || null;
      }
      if (Array.isArray(draft.prevCandidateTemplates) && draft.prevCandidateTemplates.length > 0) {
        currentCandidateTemplates = draft.prevCandidateTemplates;
      }
      if (draft.prevOriginalNodeConfigs) {
        window.originalNodeConfigs = JSON.parse(JSON.stringify(draft.prevOriginalNodeConfigs));
      }
      if (Array.isArray(draft.prevActiveDagNodes) && draft.prevActiveDagNodes.length > 0) {
        const currentIds = (activeDagNodes || []).map(n => n.role_id).join(',');
        const prevIds = draft.prevActiveDagNodes.map(n => n.role_id).join(',');
        activeDagNodes = JSON.parse(JSON.stringify(draft.prevActiveDagNodes));
        window.currentRoundIntentState = draft.prevIntentState ?? null;
        if ((currentIds !== prevIds || draft.didRenderDagPlan) && typeof renderDagNodesWithAnchors === 'function') {
          renderDagNodesWithAnchors(activeDagNodes, {
            prompt: draft.prevRoundPayload?.prompt || window._currentRoundFrozenInput?.userText || '',
            assets: draft.prevRoundPayload?.files || window._currentRoundFrozenInput?.frozenAssets || [],
            intentState: draft.prevIntentState || null,
            isHistory: false
          });
          requestAnimationFrame(() => renderDagSvgConnectors());
        }
        const routeChain = document.getElementById('macro-route-chain');
        if (routeChain) {
          routeChain.textContent = activeDagNodes.map(n => getCompactRoleName(n.role_id, n.name_zh, n.name_en)).join(' ➔ ');
        }
        const macroCapsuleBtn = document.getElementById('macro-capsule-btn');
        if (macroCapsuleBtn) {
          macroCapsuleBtn.style.pointerEvents = '';
          macroCapsuleBtn.style.opacity = '1';
        }
        const macroDropdown = document.getElementById('macro-dropdown');
        if (macroDropdown && draft.prevTemplateId) {
          macroDropdown.querySelectorAll('.macro-dropdown-item').forEach(item => {
            item.classList.toggle('active', item.getAttribute('data-tpl-id') === draft.prevTemplateId);
          });
        }
      }

      window.pendingModifiedRoleIds = new Set(draft.pendingRoleIds || []);
      window.activeChosenRoleModels = { ...(draft.chosenRoleModels || {}) };
      window.activeCustomRolePrompts = { ...(draft.customRolePrompts || {}) };
      if (window.pendingModifiedRoleIds) {
        window.pendingModifiedRoleIds.forEach(roleId => {
          const card = document.getElementById('dag-node-' + roleId);
          if (card) {
            card.classList.add('is-pending');
            if (!card.querySelector('.dag-node-pending-stamp')) {
              const stamp = document.createElement('span');
              stamp.className = 'dag-node-pending-stamp';
              const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
              stamp.textContent = isEn ? 'Pending' : '待更新 (Pending)';
              card.appendChild(stamp);
            }
          }
        });
      }
      window._stagedCanvasDraft = null;
      updateRerouteButtonState();
    }
    if (window._currentRoundFrozenInput) {
      window._currentRoundFrozenInput.candidateRevision = null;
      const baseId = window._currentRoundFrozenInput.baseRunId;
      if (baseId && !window.gitState?.commits?.[baseId]) {
        window._currentRoundFrozenInput.baseRunId = null;
        window._currentRoundFrozenInput.frozenResolvedPlan = null;
      }
    }
  }

  function commitStagedCanvasDraft(nodes) {
    window.originalNodeConfigs = {};
    window.activeChosenRoleModels = {};
    window.activeCustomRolePrompts = {};
    (nodes || activeDagNodes || []).forEach(n => {
      const nodeKey = n && (n.node_id || n.role_id);
      if (nodeKey) {
        const committedModelId = n.selected_model?.model_id || '';
        const committedPrompt = n.custom_prompt || '';
        window.originalNodeConfigs[nodeKey] = {
          model_id: committedModelId,
          custom_prompt: committedPrompt
        };
        window.activeChosenRoleModels[nodeKey] = committedModelId;
        window.activeCustomRolePrompts[nodeKey] = committedPrompt;
      }
    });
    if (window.pendingModifiedRoleIds) {
      window.pendingModifiedRoleIds.forEach(roleId => {
        const card = document.getElementById('dag-node-' + roleId);
        if (card) {
          card.classList.remove('is-pending');
          const stamp = card.querySelector('.dag-node-pending-stamp');
          if (stamp) stamp.remove();
        }
      });
      window.pendingModifiedRoleIds.clear();
    }
    window._stagedCanvasDraft = null;
    updateRerouteButtonState();
  }

  function triggerTemplateSwitch(chosenId, promptFallback) {
    if (isWorkflowExecuting || isAwaitingCommitResolution || !chosenId || chosenId === window.currentRunningTemplateId) return;
    if (window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.size > 0) {
      const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
      const msg = isEn
        ? 'Switching workflow routes will discard unsaved node modifications. Proceed?'
        : '切换工作流路线将放弃当前节点未应用的微调，是否确认切换？';
      if (!confirm(msg)) return;
    }

    // 2-Phase Commit: capture old template draft & canvas snapshot before clearing for switch_template
    window._stagedCanvasDraft = captureCanvasSnapshotDraft('switch_template');

    // Reset old canvas customizations to isolate new template
    if (window.pendingModifiedRoleIds) window.pendingModifiedRoleIds.clear();
    window.activeChosenRoleModels = {};
    window.activeCustomRolePrompts = {};
    updateRerouteButtonState();
    sendChatMessage({
      isSwitch: true,
      reRouteMode: 'switch_template',
      chosenTemplateId: chosenId,
      customPrompt: (window._currentRoundFrozenInput?.userText) || promptFallback || window.lastUserPrompt || '切换工作流'
    });
  }

  function canRetryFailedCanvas() {
    return !!(currentActiveAssistantId && window.currentRunningTemplateId &&
      window._currentRoundFrozenInput?.failedAssistantId === currentActiveAssistantId &&
      !isWorkflowExecuting && !isAwaitingCommitResolution);
  }

  function applyPendingCanvasChanges() {
    if (isWorkflowExecuting || isAwaitingCommitResolution ||
        (!window.pendingModifiedRoleIds?.size && !canRetryFailedCanvas())) return;

    // 2-Phase Commit Step 1: Stash draft copy before in-flight dispatch
    window._stagedCanvasDraft = captureCanvasSnapshotDraft('switch_model');

    // Ensure ALL active DAG nodes have their model ID captured
    const completeRoleModels = { ...(window.activeChosenRoleModels || {}) };
    activeDagNodes.forEach(n => {
      const nodeKey = n.node_id || n.role_id;
      if (!completeRoleModels[nodeKey] && n.selected_model?.model_id) {
        completeRoleModels[nodeKey] = n.selected_model.model_id;
      }
    });

    // Trigger execution with active customizations (Re-running frozen input)
    sendChatMessage({
      isSwitch: true,
      reRouteMode: 'switch_model',
      chosenTemplateId: window.currentRunningTemplateId,
      chosenRoleModels: completeRoleModels,
      customRolePrompts: window.activeCustomRolePrompts,
      customPrompt: (window._currentRoundFrozenInput?.userText) || window.lastUserPrompt || '执行任务'
    });
  }

  function initMacroRerouteButton() {
    const rerouteBtn = document.getElementById('macro-reroute-btn');
    if (!rerouteBtn) return;
    rerouteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      applyPendingCanvasChanges();
    });
  }

  // Stage 3: Node Inspector Popover (Lightweight Properties Panel with Auto-save)
  function openNodeInspector(cardEl, nodeData) {
    if (isWorkflowExecuting || isAwaitingCommitResolution) return;
    const popover = document.getElementById('node-inspector-popover');
    if (!popover) return;

    const nodeKey = nodeData.node_id || nodeData.role_id;
    currentInspectedNodeRoleId = nodeKey;

    // Prevent clicks inside inspector from bubbling to document and closing itself
    if (!popover._hasStopPropagation) {
      popover.addEventListener('click', (e) => e.stopPropagation());
      popover.addEventListener('mousedown', (e) => e.stopPropagation());
      popover._hasStopPropagation = true;
    }

    const titleEl = document.getElementById('inspector-node-title');
    const statusEl = document.getElementById('inspector-save-status');
    const selectEl = document.getElementById('inspector-model-select');
    const promptEl = document.getElementById('inspector-prompt-input');
    const closeBtn = document.getElementById('inspector-close-btn');

    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    if (titleEl) titleEl.textContent = isEn ? getCompactRoleName(nodeData.role_id, nodeData.name_zh, nodeData.name_en) : (nodeData.name_zh || '综合理解与生成');
    if (statusEl) {
      statusEl.style.display = 'none';
      statusEl.textContent = '';
      statusEl.className = 'inspector-save-status';
    }

    let statusTimer = null;
    function showSaveStatus(type) {
      if (!statusEl) return;
      clearTimeout(statusTimer);
      if (type === 'editing') {
        statusEl.style.display = 'inline-block';
        statusEl.className = 'inspector-save-status editing';
        statusEl.textContent = isEn ? '(Editing...)' : '(编辑中...)';
      } else if (type === 'saved') {
        statusEl.style.display = 'inline-block';
        statusEl.className = 'inspector-save-status saved';
        statusEl.textContent = isEn ? '✓ Staged' : '✓ 已暂存';
        statusTimer = setTimeout(() => {
          statusEl.style.display = 'none';
        }, 1600);
      }
    }

    // Populate immutable deduplicated candidate models pool for that role
    if (!Array.isArray(nodeData._allCandidateModels) || nodeData._allCandidateModels.length === 0) {
      const seenModelIds = new Set();
      nodeData._allCandidateModels = [nodeData.selected_model, ...(nodeData.standby_models || [])]
        .filter(Boolean)
        .filter(m => {
          if (!m.model_id || seenModelIds.has(m.model_id)) return false;
          seenModelIds.add(m.model_id);
          return true;
        });
    }
    const allModels = nodeData._allCandidateModels;
    const currentModelId = window.activeChosenRoleModels?.[nodeKey] || nodeData.selected_model?.model_id || '';
    if (selectEl) {
      selectEl.innerHTML = allModels.map((m, idx) => {
        const isLocal = m.inference_target === 'browser' || (m.model_id && m.model_id.startsWith('browser-'));
        const icon = isLocal ? '💻' : '☁️';
        const mLabel = isEn ? getCompactModelName(m.model_id, m.display_name) : (m.display_name || m.model_id);
        const tag = isLocal 
          ? (isEn ? 'Local 0-pt' : '本地 0点') 
          : (idx === 0 ? (isEn ? 'Recommended' : '智能推荐') : (isEn ? 'Standby' : '备选'));
        return `
          <option value="${escapeHtml(m.model_id)}" ${m.model_id === currentModelId ? 'selected' : ''}>
            ${icon} ${escapeHtml(mLabel)} (${tag})
          </option>
        `;
      }).join('');
    }

    if (promptEl) {
      promptEl.value = (window.activeCustomRolePrompts?.[nodeKey] !== undefined)
        ? window.activeCustomRolePrompts[nodeKey]
        : (nodeData.custom_prompt || '');
    }

    function autoSaveNodeConfig() {
      const chosenModelId = selectEl ? selectEl.value : currentModelId;
      const customPrompt = promptEl ? promptEl.value.trim() : '';

      window.activeCustomRolePrompts = window.activeCustomRolePrompts || {};
      window.activeCustomRolePrompts[nodeKey] = customPrompt;
      nodeData.custom_prompt = customPrompt;

      window.activeChosenRoleModels = window.activeChosenRoleModels || {};
      window.activeChosenRoleModels[nodeKey] = chosenModelId;

      const chosenModelObj = allModels.find(m => m.model_id === chosenModelId);
      if (chosenModelObj) {
        nodeData.selected_model = chosenModelObj;
        const modelLabel = document.getElementById('node-model-label-' + nodeKey);
        if (modelLabel) {
          const compactMName = isEn ? getCompactModelName(chosenModelObj.model_id, chosenModelObj.display_name) : (chosenModelObj.display_name || chosenModelObj.model_id);
          const isLocal = chosenModelObj.inference_target === 'browser' || (chosenModelObj.model_id && chosenModelObj.model_id.startsWith('browser-'));
          const modelIcon = isLocal ? '💻' : '⚙️';
          modelLabel.innerHTML = `${modelIcon} ${escapeHtml(compactMName)}`;
        }
      }

      updateNodeDirtyState(nodeKey);
    }

    if (selectEl) {
      selectEl.onchange = (e) => {
        e.stopPropagation();
        autoSaveNodeConfig();
        showSaveStatus('saved');
      };
    }

    if (promptEl) {
      promptEl.oninput = () => {
        autoSaveNodeConfig();
        if (window.pendingModifiedRoleIds?.has(nodeKey)) {
          showSaveStatus('editing');
        } else if (statusEl) {
          clearTimeout(statusTimer);
          statusEl.style.display = 'none';
        }
      };
      promptEl.onblur = () => {
        autoSaveNodeConfig();
        if (window.pendingModifiedRoleIds?.has(nodeKey)) {
          showSaveStatus('saved');
        } else if (statusEl) {
          clearTimeout(statusTimer);
          statusEl.style.display = 'none';
        }
      };
    }

    // Smart Viewport & Clamping Position Calculation for compact popover panel
    const cardRect = cardEl.getBoundingClientRect();
    const canvasPane = document.getElementById('workbench-canvas-pane');
    const parentRect = canvasPane ? canvasPane.getBoundingClientRect() : { top: 0, left: 0, width: 600, height: 600 };

    const popoverWidth = 310;
    const popoverHeight = 210;

    let leftPos = (cardRect.left - parentRect.left) + (cardRect.width - popoverWidth) / 2;
    leftPos = Math.max(16, Math.min(parentRect.width - popoverWidth - 16, leftPos));

    const spaceBelow = parentRect.height - (cardRect.bottom - parentRect.top);
    const spaceAbove = cardRect.top - parentRect.top;
    let topPos;

    if (spaceBelow >= popoverHeight + 15) {
      topPos = (cardRect.bottom - parentRect.top) + 10;
    } else if (spaceAbove >= popoverHeight + 15) {
      topPos = (cardRect.top - parentRect.top) - popoverHeight - 10;
    } else {
      topPos = Math.max(16, parentRect.height - popoverHeight - 16);
    }

    topPos = Math.max(16, Math.min(parentRect.height - popoverHeight - 16, topPos));

    if (window.innerWidth <= 768) {
      popover.style.left = '';
      popover.style.top = '';
    } else {
      popover.style.left = `${Math.round(leftPos)}px`;
      popover.style.top = `${Math.round(topPos)}px`;
    }
    popover.style.display = 'flex';

    if (closeBtn) {
      closeBtn.onclick = (e) => {
        e.stopPropagation();
        autoSaveNodeConfig();
        popover.style.display = 'none';
        currentInspectedNodeRoleId = null;
      };
    }
  }

  function rollbackTurnToPreFlight() {
    window._isCurrentTurnRolledBack = true;
    if (window._currentPreFlightSnapshot) {
      if (window._currentPreFlightSnapshot.gitStateSnapshot) {
        window.gitState = window._currentPreFlightSnapshot.gitStateSnapshot;
      }
      window.sessionAssets = window._currentPreFlightSnapshot.sessionAssets;
      window.currentRoundAssets = window._currentPreFlightSnapshot.currentRoundAssets;
      window.lastRoundSummary = window._currentPreFlightSnapshot.lastRoundSummary;
      window.currentDagBaseSummary = window._currentPreFlightSnapshot.currentDagBaseSummary;
      window.activeBranchId = window._currentPreFlightSnapshot.activeBranchId;
      window.sessionBranches = window._currentPreFlightSnapshot.sessionBranches;
    }
    if (window._currentRoundFrozenInput) {
      window._currentRoundFrozenInput.candidateRevision = null;
      const baseId = window._currentRoundFrozenInput.baseRunId;
      if (baseId && !window.gitState?.commits?.[baseId]) {
        window._currentRoundFrozenInput.baseRunId = null;
        window._currentRoundFrozenInput.frozenResolvedPlan = null;
      }
    }
    window._currentStagedNewFiles = [];
    window._currentRoundGeneratedAssets = [];
    window._pendingRoundTrace = null;
    window._pendingClientTailCommit = null;
    rollbackStagedCanvasDraft();
    syncLegacyGlobalsFromGitState();
  }

  // Stage 1 & 2: Chat Sending & Panic Transition
  async function sendChatMessage(reRouteOptions = {}) {
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    if (!user) {
      if (reRouteOptions.isSwitch) rollbackStagedCanvasDraft();
      window.showModal(t('chat.loginRequired'), t('chat.loginToSend'), t('auth.goToLogin'), () => { window.location.href = '/login.html'; });
      return;
    }

    if (user.credits <= 0) {
      if (reRouteOptions.isSwitch) rollbackStagedCanvasDraft();
      window.showZeroBalanceModal();
      return;
    }

    if (isWorkflowExecuting || isAwaitingCommitResolution) {
      return;
    }
    if (!reRouteOptions.isSwitch && window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.size > 0) {
      localToast(isEn ? 'Please run canvas changes first before starting a new turn' : '请先点击运行画布修改，再进行新一轮对话', 'info');
      return;
    }

    const input = document.getElementById('chat-input');
    let rawInputText = reRouteOptions.isSwitch
      ? (window._currentRoundFrozenInput?.userText ?? reRouteOptions.customPrompt ?? window.lastUserPrompt ?? '')
      : (reRouteOptions.customPrompt || input.value.trim() || window.lastUserPrompt || '');

    // If user is replying to an active branch-delivery clarification via the existing input box,
    // restore their original prompt + staged attachments cleanly and pass resolvedClarificationTargetBranchId!
    let resolvedClarificationTargetBranchId = reRouteOptions.resolvedClarificationTargetBranchId || null;
    if (!reRouteOptions.isSwitch && window._pendingClarificationContext && rawInputText) {
      const clarCtx = window._pendingClarificationContext;
      const replyLower = rawInputText.toLowerCase();
      const matchedTarget = (clarCtx.candidateTargets || []).find(ct =>
        replyLower.includes((ct.branch_id || '').toLowerCase()) ||
        (ct.topic && replyLower.includes(ct.topic.toLowerCase())) ||
        (ct.relation === 'historical' && /(回到|历史|原分支|旧分支|branch a|return)/i.test(rawInputText)) ||
        (ct.relation === 'current' && /(当前|留在|本分支|branch b|stay|current)/i.test(rawInputText))
      );
      if (matchedTarget) {
        resolvedClarificationTargetBranchId = matchedTarget.branch_id;
      } else if (clarCtx.candidateTargets && clarCtx.candidateTargets[0]) {
        resolvedClarificationTargetBranchId = clarCtx.candidateTargets[0].branch_id;
      }
      if (Array.isArray(clarCtx.stagedFiles) && clarCtx.stagedFiles.length > 0 && selectedFiles.length === 0) {
        selectedFiles = clarCtx.stagedFiles;
      }
      if (clarCtx.originalPrompt) {
        rawInputText = clarCtx.originalPrompt;
      }
      window._pendingClarificationContext = null;
    }
    const userText = rawInputText;
    if (reRouteOptions.isSwitch) {
      const frozenAssetsCount = window._currentRoundFrozenInput?.frozenAssets?.length || window.currentRoundAssets?.length || 0;
      if (!userText && frozenAssetsCount === 0) {
        rollbackStagedCanvasDraft();
        return;
      }
    } else {
      if (!userText && selectedFiles.length === 0) {
        return;
      }
      if (selectedFiles.some(f => f.uploadStatus === 'uploading')) {
        localToast(isEn ? 'Attachments are uploading, please wait...' : '附件正在上传中，请稍候...', 'info');
        return;
      }
      if (selectedFiles.some(f => f.uploadStatus === 'error')) {
        localToast(isEn ? 'Some attachments failed to upload. Please remove or retry before submitting.' : '部分附件上传失败，请移除或重新上传后再提交。', 'warning');
        return;
      }
    }

    const clientOpId = reRouteOptions.retryClientOpId || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : ('op-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8)));
    window._activeServerRunId = null;
    window._pendingClientTailCommit = null;

    const gsAtPreflight = window.gitState || createEmptyGitState();
    const activeBranchHeadAtPreflight = gsAtPreflight.branches?.[gsAtPreflight.activeBranchId || 'main']?.headCommitId || null;
    const currentRoundBaseId = window._currentRoundFrozenInput?.baseRunId || null;
    const resolvedSwitchBaseCommitId =
      currentRoundBaseId && gsAtPreflight.commits?.[currentRoundBaseId]
        ? currentRoundBaseId
        : (!currentRoundBaseId && activeBranchHeadAtPreflight && gsAtPreflight.commits?.[activeBranchHeadAtPreflight] && !window._isCurrentTurnRolledBack)
          ? activeBranchHeadAtPreflight
          : undefined;
    const effectiveSwitchIsReRun = !!(reRouteOptions.isSwitch && resolvedSwitchBaseCommitId);

    if (!reRouteOptions.isSwitch) {
      window._stagedCanvasDraft = null;
      window.originalNodeConfigs = {};
      window.activeChosenRoleModels = {};
      window.activeCustomRolePrompts = {};
      if (window.pendingModifiedRoleIds) window.pendingModifiedRoleIds.clear();
      updateRerouteButtonState();
      window.lastUserPrompt = userText;
      window.currentDagBaseSummary = window.lastRoundSummary || '';
      const currentTargetLang = localStorage.getItem('nanomesh_lang') || 'auto';
      const currentOutputStyle = localStorage.getItem('nanomesh_style') || 'concise';
      // Freeze input baseline for potential re-runs / micro-tuning revisions on this exact round
      window._currentRoundFrozenInput = {
        userText: userText,
        selectedFiles: JSON.parse(JSON.stringify(selectedFiles || [])),
        frozenAssets: [], // will be sealed once currentAssets is constructed below
        targetLanguage: currentTargetLang,
        outputStyle: currentOutputStyle,
        baseSummary: window.currentDagBaseSummary,
        roundIndex: (window.chatRoundIndex || 0) + 1,
        baseRunId: null, // populated authoritatively by server dag_plan.run_id
        committedRevision: 1,
        revision: 1
      };
    } else if (window._currentRoundFrozenInput) {
      if (effectiveSwitchIsReRun) {
        // In-flight candidate revision (NOT committed yet until execution completes successfully)
        const nextRev = (window._currentRoundFrozenInput.committedRevision || window._currentRoundFrozenInput.revision || 1) + 1;
        window._currentRoundFrozenInput.candidateRevision = nextRev;
      } else {
        window._currentRoundFrozenInput.baseRunId = null;
        window._currentRoundFrozenInput.candidateRevision = null;
        window._currentRoundFrozenInput.committedRevision = 1;
        window._currentRoundFrozenInput.revision = 1;
      }
    }

    // Trigger Stage 2: The "Panic" Split Transition
    setWorkflowActive(true);
    setWorkflowExecutionLocked(true);

    // Local UI Run ID for scoping DOM rows before server mints authoritative run_id
    const candidateRev = (effectiveSwitchIsReRun && window._currentRoundFrozenInput)
      ? (window._currentRoundFrozenInput.candidateRevision || (window._currentRoundFrozenInput.revision || 1) + 1)
      : 1;
    const runId = (effectiveSwitchIsReRun && resolvedSwitchBaseCommitId)
      ? `${resolvedSwitchBaseCommitId}-rev${candidateRev}`
      : 'run-' + Date.now();
    currentActiveRunId = runId;

    // Show Unified Control Bar (bound to current active route)
    const controlBar = document.getElementById('unified-control-bar') || document.getElementById('macro-workflow-bar');
    if (controlBar) controlBar.style.display = 'inline-flex';
    const macroLabel = document.getElementById('macro-label') || document.querySelector('.macro-label');
    const lockIcon = document.getElementById('macro-lock-icon');
    if (lockIcon) lockIcon.style.display = 'none';
    if (macroLabel) macroLabel.textContent = (typeof getLocale === 'function' && getLocale() === 'en') ? 'Route:' : '当前路由:';

    const messagesFlow = document.getElementById('messages-flow');

    // Resolve User Avatar
    const u = window.currentUser;
    let userAvatarHtml = '<span class="msg-avatar-initial">U</span>';
    if (u && u.avatar_url) {
      userAvatarHtml = `<img src="${escapeHtml(u.avatar_url)}" class="msg-avatar-img" alt="User">`;
    } else if (u && u.username) {
      userAvatarHtml = `<span class="msg-avatar-initial">${escapeHtml(u.username.charAt(0).toUpperCase())}</span>`;
    }

    // 1. Render User Message Row (Strict Left Aligned with Avatar & Ghost Surface)
    if (!reRouteOptions.isSwitch) {
      const userRow = document.createElement('div');
      userRow.className = 'chat-msg-row user';
      userRow.id = 'user-row-' + runId;
      
      let attachmentsHtml = '';
      if (selectedFiles.length > 0) {
        attachmentsHtml = '<div class="user-attachments-grid">' + 
          selectedFiles.map(f => {
            const sizeStr = formatFileSize(f.size);
            const isImg = f.previewUrl || (f.type && f.type.startsWith('image/')) || f.modality === 'image';
            if (isImg && f.previewUrl) {
              return `
                <div class="user-asset-card" title="${escapeHtml(f.name)} (${sizeStr})">
                  <div class="user-asset-thumb-box">
                    <img src="${escapeHtml(f.previewUrl)}" class="user-asset-thumb-img" alt="${escapeHtml(f.name)}" />
                  </div>
                  <div class="user-asset-meta-col">
                    <span class="user-asset-filename">${escapeHtml(f.name)}</span>
                    <span class="user-asset-filesize">${sizeStr}</span>
                  </div>
                </div>
              `;
            } else {
              const isPdf = (f.name || '').toLowerCase().endsWith('.pdf') || f.modality === 'pdf';
              const docIcon = isPdf ? '📄' : f.modality === 'audio' ? '🎙️' : '📎';
              return `
                <div class="user-asset-card" title="${escapeHtml(f.name)} (${sizeStr})">
                  <div class="user-asset-thumb-box is-doc">
                    <span class="user-asset-doc-icon">${docIcon}</span>
                  </div>
                  <div class="user-asset-meta-col">
                    <span class="user-asset-filename">${escapeHtml(f.name)}</span>
                    <span class="user-asset-filesize">${sizeStr}</span>
                  </div>
                </div>
              `;
            }
          }).join('') +
          '</div>';
      }

      userRow.innerHTML = `
        <div class="msg-avatar-col">
          <div class="msg-avatar-badge user-avatar-badge">${userAvatarHtml}</div>
        </div>
        <div class="msg-content-col">
          <!-- Inline Telemetry Metadata Bar: rendered directly above current user prompt bubble -->
          <div class="telemetry-meta-bar" id="telemetry-bar-${runId}">
            <div class="telemetry-pill arb-telemetry-pill" id="arb-pill-${runId}">
              <span class="arb-text" id="arb-text-${runId}">${isEn ? '⌛ Routing...' : '⚡ 正在路由仲裁...'}</span>
            </div>
            <div class="telemetry-pill intent-telemetry-pill" id="intent-pill-${runId}" style="display:none;"></div>
            <div class="telemetry-pill cache-telemetry-pill" id="cache-pill-${runId}" style="display:none;">
              <span>${isEn ? '⚡ Cached · Fast-Pass' : '⚡ 节省算力: 命中直出'}</span>
            </div>
          </div>
          <!-- Ghost Surface User Bubble -->
          <div class="chat-bubble-user">
            ${attachmentsHtml}
            <div class="chat-user-text">${escapeHtml(userText)}</div>
            <div class="user-action-row">
              <button class="chat-action-btn copy-btn" title="${isEn ? 'Copy' : '复制提问'}" aria-label="${isEn ? 'Copy' : '复制'}">
                <svg class="copy-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                <svg class="check-icon" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#10b981" stroke-width="2.5" style="display:none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
                <span class="btn-text">${isEn ? 'Copy' : '复制'}</span>
              </button>
            </div>
          </div>
        </div>
      `;
      messagesFlow.appendChild(userRow);
    }

    // 2. Render Assistant Message Row (Strict Left Aligned with NanoMesh Logo Avatar)
    const assistantRow = document.createElement('div');
    assistantRow.className = 'chat-msg-row assistant';
    const assistantId = 'assistant-msg-' + Date.now();
    assistantRow.id = assistantId;
    currentActiveAssistantId = assistantId;

    assistantRow.innerHTML = `
      <div class="msg-avatar-col">
        <div class="msg-avatar-badge mesh-avatar-badge" title="NanoMesh Engine">
          <span class="mesh-logo-glyph">◎</span>
        </div>
      </div>
      <div class="msg-content-col">
        <div class="chat-bubble-assistant">
          <div class="assistant-steps-stream" id="assistant-steps-${assistantId}"></div>
          <div class="chat-response-wrapper">
            <div class="chat-response-text" id="response-text-${assistantId}">
              <span style="color:var(--text-secondary); font-size:0.85rem; animation: pulseGlow 1.5s infinite;">⚡ ${isEn ? 'NanoMesh Orchestrating...' : 'NanoMesh 调度执行中...'}</span>
            </div>
            <div class="chat-response-actions" id="actions-${assistantId}">
              <button class="chat-action-btn copy-btn" title="${isEn ? 'Copy' : '复制内容'}" aria-label="${isEn ? 'Copy' : '复制'}">
                <svg class="copy-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                <svg class="check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#10b981" stroke-width="2.5" style="display:none;"><polyline points="20 6 9 17 4 12"></polyline></svg>
                <span class="btn-text">${isEn ? 'Copy' : '复制'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    messagesFlow.appendChild(assistantRow);
    const scrollContainer = document.getElementById('chat-messages');
    if (scrollContainer) scrollContainer.scrollTop = scrollContainer.scrollHeight;

    // Persist attached assets into session vault and identify newly supplemented files
    // Canvas micro-tuning (isSwitch: true) must NEVER ingest unsubmitted attachments from the right-side chat input.
    window.sessionAssets = window.sessionAssets || [];
    const newlySelectedFiles = reRouteOptions.isSwitch
      ? []
      : ((selectedFiles && selectedFiles.length > 0) ? [...selectedFiles] : []);
    const hasNewUploads = newlySelectedFiles.length > 0;

    const resolveModality = (f) => {
      let modality = f.modality;
      if (!modality) {
        if (f.inMemoryText) modality = 'text_doc';
        else {
          const mime = (f.type || f.mime_type || '').toLowerCase();
          if (mime.startsWith('image/')) modality = 'image';
          else if (mime.startsWith('audio/')) modality = 'audio';
          else modality = 'text_doc';
        }
      }
      return modality === 'pdf' ? 'text_doc' : modality;
    };

    const newUploadModalities = newlySelectedFiles.map(resolveModality);

    // 1. Pre-flight Snapshot for Atomic Rollback on Fast-Failed / Error / Clarification
    window._currentPreFlightSnapshot = {
      gitStateSnapshot: JSON.parse(JSON.stringify(window.gitState || createEmptyGitState())),
      sessionAssets: JSON.parse(JSON.stringify(window.sessionAssets || [])),
      currentRoundAssets: JSON.parse(JSON.stringify(window.currentRoundAssets || [])),
      lastRoundSummary: window.lastRoundSummary,
      currentDagBaseSummary: window.currentDagBaseSummary,
      activeBranchId: window.activeBranchId || 'main',
      sessionBranches: JSON.parse(JSON.stringify(window.sessionBranches || { 'main': { branchId: 'main', isMediaBranch: false, lastValidSummary: '' } }))
    };

    // 2. Stage new files WITHOUT prematurely assigning branchId (wait for JEV & atomic commit)
    window._currentStagedNewFiles = newlySelectedFiles.map(f => ({
      ...f,
      isNew: true,
      modality: resolveModality(f),
      introducedRound: window.chatRoundIndex + 1
    }));
    window._currentRoundGeneratedAssets = [];
    window._pendingRoundTrace = null;
    window._isCurrentTurnRolledBack = false;
    window._isCurrentTurnClarification = false;

    // In this round, build activeAssets list:
    // - On canvas micro-tuning re-runs (isSwitch: true), isolate strictly to the frozen round input baseline.
    // - On committed multi-round turns, send ONLY newly submitted attachments in assets_manifest (server ledger supplies historical lineage).
    const gsAtBuild = window.gitState || createEmptyGitState();
    const hasCommittedHistory = Array.isArray(gsAtBuild.commitOrder) && gsAtBuild.commitOrder.length > 0;
    let currentAssets;
    if (reRouteOptions.isSwitch && window._currentRoundFrozenInput && Array.isArray(window._currentRoundFrozenInput.frozenAssets)) {
      currentAssets = JSON.parse(JSON.stringify(window._currentRoundFrozenInput.frozenAssets)).map(f => ({
        ...f,
        isNew: effectiveSwitchIsReRun ? false : !!f.isNew
      }));
    } else if (reRouteOptions.isSwitch && Array.isArray(window.currentRoundAssets)) {
      currentAssets = window.currentRoundAssets.map(f => ({
        ...f,
        isNew: effectiveSwitchIsReRun ? false : !!f.isNew,
        modality: resolveModality(f)
      }));
    } else if (hasCommittedHistory) {
      currentAssets = [...window._currentStagedNewFiles];
    } else {
      const baseAssetSource = window.sessionAssets || [];
      const historicalAssets = baseAssetSource.map(f => ({
        ...f,
        isNew: false,
        modality: resolveModality(f)
      }));
      currentAssets = [...historicalAssets, ...window._currentStagedNewFiles];
    }

    // Snapshot assets for current dialogue round persistence
    window.currentRoundAssets = currentAssets.map(f => ({
      name: f.name || 'attachment',
      size: f.size ?? f.file_size ?? 0,
      type: f.type || f.mime_type || '',
      modality: f.modality || resolveModality(f),
      assetId: f.assetId || f.id,
      r2Key: f.r2Key || f.r2_key,
      previewUrl: f.previewUrl || f.url || '',
      inMemoryText: f.inMemoryText,
      isNew: effectiveSwitchIsReRun ? false : !!f.isNew
    }));

    // Seal frozen assets baseline for new round
    if (!reRouteOptions.isSwitch && window._currentRoundFrozenInput) {
      window._currentRoundFrozenInput.frozenAssets = JSON.parse(JSON.stringify(window.currentRoundAssets));
    }

    window.activeRoundPayload = {
      prompt: userText,
      files: [...window.currentRoundAssets]
    };

    if (!reRouteOptions.isSwitch) {
      input.value = '';
      input.style.height = 'auto';
      selectedFiles = [];
      renderFileChips();
    }

    // Build Cross-Branch Session Asset Ledger from immutable Asset Vault
    const gs = window.gitState || createEmptyGitState();
    const vaultAssets = Object.values(gs.assetVault || {});
    const ledgerSource = vaultAssets.length > 0 ? vaultAssets : (window.sessionAssets || []);
    const sessionAssetLedger = ledgerSource.map(a => ({
      asset_id: a.assetId || a.id || a.name,
      filename: a.name || a.filename || 'attachment',
      modality: a.modality || resolveModality(a),
      mime_type: a.mime_type || a.type,
      file_size: a.file_size ?? a.size ?? 0,
      introduced_round: a.introducedRound || a.introduced_round || 1,
      introduced_commit_id: a.introducedCommitId || a.introduced_commit_id,
      branch_id: a.branchId || a.branch_id || 'main',
      r2_key: a.r2_key || a.r2Key,
      source_digest: a.sourceDigest || a.source_digest || a.r2Key || a.r2_key || a.assetId || a.id,
      origin: a.origin || 'upload',
      summary_snippet: a.summarySnippet || a.summary_snippet,
      cached_perceptual_text: a.cachedPerceptualText || a.cached_perceptual_text
    }));

    // Build Branch Catalog from Git Branches (no hardcoded media overrides)
    const activeBranchId = gs.activeBranchId || window.activeBranchId || 'main';
    const activeBranch = gs.branches[activeBranchId] || window.sessionBranches?.[activeBranchId];
    const activeBranchSummary = effectiveSwitchIsReRun
      ? undefined
      : ((activeBranch && activeBranch.lastValidSummary)
          || window.currentDagBaseSummary
          || window.lastRoundSummary
          || undefined);

    const branchCatalog = Object.values(gs.branches || window.sessionBranches || {}).map(b => ({
      branch_id: b.branchId,
      topic: b.topic || (b.isMediaBranch ? '多模态媒体分析' : '常规任务对话'),
      is_media: !!b.isMediaBranch,
      last_summary: b.lastValidSummary || '',
      is_active: b.branchId === activeBranchId,
      lineage_asset_ids: Array.isArray(b.lineageAssetIds) ? b.lineageAssetIds : [],
      head_commit_id: b.headCommitId || null
    }));

    const effectiveUserText = (reRouteOptions.isSwitch && window._currentRoundFrozenInput)
      ? window._currentRoundFrozenInput.userText
      : userText;
    const effectiveBaseSummary = (effectiveSwitchIsReRun && window._currentRoundFrozenInput)
      ? ''
      : (window.currentDagBaseSummary || '');
    const effectiveTargetLang = (reRouteOptions.isSwitch && window._currentRoundFrozenInput?.targetLanguage)
      ? window._currentRoundFrozenInput.targetLanguage
      : (localStorage.getItem('nanomesh_lang') || 'auto');
    const effectiveOutputStyle = (reRouteOptions.isSwitch && window._currentRoundFrozenInput?.outputStyle)
      ? window._currentRoundFrozenInput.outputStyle
      : (localStorage.getItem('nanomesh_style') || 'concise');
    const currentRoundIdx = reRouteOptions.isSwitch
      ? (window.chatRoundIndex || 1)
      : (++window.chatRoundIndex);

    // Build Unified Protocol Envelope
    const envelope = {
      envelope_id: crypto.randomUUID(),
      session_id: window.chatSessionId,
      round_index: currentRoundIdx,
      instruction_payload: effectiveUserText,
      assets_manifest: currentAssets.map(f => ({
        asset_id: f.assetId || f.id || crypto.randomUUID(),
        modality: f.modality || resolveModality(f),
        mime_type: f.type || f.mime_type || 'text/plain',
        file_size: f.size ?? f.file_size ?? 0,
        r2_key: f.r2Key || f.r2_key || null,
        in_memory_text: f.inMemoryText || null,
        in_memory_data: null,
        consumed: false,
        source_digest: f.r2Key || f.r2_key || (f.name + '-' + (f.inMemoryText ? f.inMemoryText.length : (f.size ?? f.file_size ?? 0))),
        is_new: !!f.isNew,
        filename: f.name || 'attachment'
      })),
      constraint_context: {
        target_language: effectiveTargetLang,
        output_style: effectiveOutputStyle
      },
      metadata: {
        client_timestamp: Date.now(),
        char_count_total: effectiveUserText.length,
        estimated_input_tokens: Math.ceil(effectiveUserText.length / 2) + 200,
        has_new_upload: hasNewUploads,
        new_upload_count: newlySelectedFiles.length,
        new_upload_modalities: newUploadModalities
      }
    };

    const sendBtn = document.getElementById('send-btn');
    sendBtn.disabled = true;

    // Abort previous running stream if switching
    if (window.activeChatAbortController) {
      try { window.activeChatAbortController.abort(); } catch (e) {}
    }
    window.activeChatAbortController = new AbortController();

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: window.activeChatAbortController.signal,
        body: JSON.stringify({
          clientOpId,
          isReRun: effectiveSwitchIsReRun,
          baseCommitId: effectiveSwitchIsReRun ? resolvedSwitchBaseCommitId : undefined,
          envelope,
          disableBrowserInference: !!window.disableLocalInference,
          reRouteMode: reRouteOptions.reRouteMode || 'normal',
          chosenTemplateId: reRouteOptions.chosenTemplateId || (reRouteOptions.isSwitch ? window.currentRunningTemplateId : undefined),
          chosenRoleModels: reRouteOptions.reRouteMode === 'switch_template' 
            ? undefined 
            : (reRouteOptions.chosenRoleModels || (reRouteOptions.isSwitch ? window.activeChosenRoleModels : undefined)),
          customRolePrompts: reRouteOptions.reRouteMode === 'switch_template' 
            ? undefined 
            : (reRouteOptions.customRolePrompts || (reRouteOptions.isSwitch ? window.activeCustomRolePrompts : undefined)),
          customNodePrompt: reRouteOptions.customNodePrompt,
          hasPreviousRound: effectiveSwitchIsReRun
            ? false
            : ((gs.commitOrder || []).length > 0 || !!effectiveBaseSummary),
          previousRoundSummary: effectiveBaseSummary || undefined,
          hadMediaAssets: (window.sessionAssets || []).some(a => {
            const m = resolveModality(a);
            return m === 'image' || m === 'audio' || m === 'pdf';
          }),
          hasNewUploads,
          newUploadModalities,
          sessionAssetLedger,
          activeBranchId: activeBranchId,
          activeBranchSummary,
          branchCatalog,
          perceptualCache: gs.perceptualCacheIndex || {},
          resolvedClarificationTargetBranchId: resolvedClarificationTargetBranchId || undefined,
          frozenResolvedPlan: effectiveSwitchIsReRun ? (window._currentRoundFrozenInput?.frozenResolvedPlan || undefined) : undefined,
          capabilities: {
            webgpu_handover_v3: true
          }
        })
      });

      // Cache snapshot for potential multi-step WebGPU continuation
      window._lastChatEnvelope = envelope;
      window._lastOrchestrationOptions = {
        reRouteMode: reRouteOptions.reRouteMode || 'normal',
        chosenTemplateId: reRouteOptions.chosenTemplateId || (reRouteOptions.isSwitch ? window.currentRunningTemplateId : undefined),
        chosenRoleModels: reRouteOptions.chosenRoleModels || (reRouteOptions.isSwitch ? window.activeChosenRoleModels : undefined),
        customRolePrompts: reRouteOptions.customRolePrompts || (reRouteOptions.isSwitch ? window.activeCustomRolePrompts : undefined),
        customNodePrompt: reRouteOptions.customNodePrompt,
        hasPreviousRound: !!(window.currentDagBaseSummary || window.lastRoundSummary),
        previousRoundSummary: (window.currentDagBaseSummary || window.lastRoundSummary) || undefined,
        hadMediaAssets: (window.sessionAssets || []).some(a => {
          const m = resolveModality(a);
          return m === 'image' || m === 'audio' || m === 'pdf';
        }),
        hasNewUploads,
        newUploadModalities,
        sessionAssetLedger,
        activeBranchId: activeBranchId,
        activeBranchSummary,
        branchCatalog,
        perceptualCache: gs.perceptualCacheIndex || {},
        disableBrowserInference: !!window.disableLocalInference
      };

      if (res.status === 403) {
        rollbackStagedCanvasDraft();
        window.showZeroBalanceModal();
        assistantRow.remove();
        sendBtn.disabled = false;
        return;
      }

      if (res.status === 429) {
        rollbackStagedCanvasDraft();
        const rateLimitData = await res.json().catch(() => ({}));
        const retryAfter = rateLimitData.retry_after || 5;
        if (typeof window.showRateLimitModal === 'function') {
          window.showRateLimitModal(retryAfter, rateLimitData.message);
        } else {
          alert(rateLimitData.message || `请求过于频繁，请稍候 ${retryAfter} 秒后再试`);
        }
        // Restore user prompt in chat input so input text is not lost
        const inputEl = document.getElementById('chat-input');
        if (inputEl && !inputEl.value.trim() && userText) {
          inputEl.value = userText;
          inputEl.style.height = 'auto';
        }
        assistantRow.remove();
        sendBtn.disabled = false;
        return;
      }

      if (res.status === 410) {
        rollbackStagedCanvasDraft();
        assistantRow.remove();
        sendBtn.disabled = false;
        localToast(isEn ? 'This conversation has been deleted.' : '该会话已被删除，无法继续提交。', 'warning');
        if (typeof resetToRootInterface === 'function') resetToRootInterface();
        return;
      }

      if (res.status === 409 || res.status === 503) {
        rollbackStagedCanvasDraft();
        const errJson = await res.json().catch(() => ({}));
        if (errJson.error === 'session_busy' && errJson.awaiting_commit && errJson.active_run_id) {
          setAwaitingCommitResolutionState(true, {
            run_id: errJson.active_run_id,
            can_retry_commit: true
          });
        }
        throw new Error(errJson.message || (res.status === 409 ? '请求存在并发冲突，请刷新状态后重试' : '状态存储暂不可用，请稍后重试'));
      }

      if (!res.ok) {
        rollbackStagedCanvasDraft();
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.message || '调度失败');
      }

      // Idempotent first-submit replay (REV-02): server already completed this client_op_id
      const respContentType = (res.headers.get('content-type') || '').toLowerCase();
      if (respContentType.includes('application/json')) {
        const jsonRes = await res.json().catch(() => ({}));
        if (jsonRes && jsonRes.already_completed) {
          if (jsonRes.run_id) {
            window._activeServerRunId = jsonRes.run_id;
            if (!reRouteOptions.isSwitch && window._currentRoundFrozenInput) {
              window._currentRoundFrozenInput.baseRunId = jsonRes.run_id;
            }
          }
          const respEl = document.getElementById('response-text-' + assistantId);
          if (respEl && jsonRes.final_output) {
            respEl.innerHTML = safeRenderMarkdown(sanitizePromptLeakage(jsonRes.final_output));
          }
          const actionsEl = document.getElementById('actions-' + assistantId);
          if (actionsEl) actionsEl.classList.add('is-visible');
          commitStagedCanvasDraft(activeDagNodes);
          if (jsonRes.authoritative_git_state) {
            hydrateGitStateFromServer(jsonRes.authoritative_git_state);
          }
          setWorkflowExecutionLocked(false);
          sendBtn.disabled = false;
          return;
        }
      }

      async function pumpSSEStream(stream, targetAssistantId, targetUserText, streamOptions = {}) {
        const reader = stream.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let streamedOutput = '';
        let currentEvent = 'message';

        const processSSELine = async (rawLine) => {
          const line = rawLine.replace(/\r$/, '');
          if (line === '') {
            currentEvent = 'message';
            return;
          }
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim() || 'message';
          } else if (line.startsWith('data: ')) {
            const dataStr = line.slice(6).trim();
            if (!dataStr) return;
            const eventToDispatch = currentEvent;
            let data;
            try {
              data = JSON.parse(dataStr);
            } catch (parseErr) {
              console.warn('SSE JSON parse warning:', parseErr);
              return;
            }
            if (eventToDispatch === 'text_chunk' && data.chunk) {
              streamedOutput += data.chunk;
            } else if (eventToDispatch === 'dag_complete' && data.final_output) {
              streamedOutput = data.final_output;
            }
            await handleSSEMessage(eventToDispatch, data, targetAssistantId, targetUserText, pumpSSEStream, streamOptions);
          }
        };

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? ''; // keep last incomplete line

          for (const rawLine of lines) {
            await processSSELine(rawLine);
          }
        }
        buffer += decoder.decode();
        if (buffer.trim()) {
          await processSSELine(buffer);
        }
        return streamedOutput;
      }

      let fullOutput = await pumpSSEStream(res.body, assistantId, userText, { isSwitch: !!reRouteOptions.isSwitch, isReRun: effectiveSwitchIsReRun });

      // Await in-browser local execution if dispatched
      if (window._activeLocalRunnerPromise) {
        try {
          const clientOutput = await window._activeLocalRunnerPromise;
          if (clientOutput) fullOutput = clientOutput;
        } catch (clientErr) {
          console.error('Local runner execution error:', clientErr);
          rollbackTurnToPreFlight();
        } finally {
          window._activeLocalRunnerPromise = null;
        }
      }

      // If stream ended without emitting dag_complete or dag_error, ensure staged draft rolls back
      if (window._stagedCanvasDraft) {
        rollbackStagedCanvasDraft();
      }

      if (fullOutput && !window._isCurrentTurnRolledBack && !window._isCurrentTurnClarification) {
        window.lastRoundSummary = fullOutput.slice(0, 4000);
      }
      window.lastHadMedia = (window.sessionAssets || []).some(a => {
        const m = a.modality || (a.type && a.type.startsWith('image/') ? 'image' : (a.type && a.type.startsWith('audio/') ? 'audio' : ''));
        return m === 'image' || m === 'audio';
      });

    } catch (err) {
      rollbackTurnToPreFlight();
      if (err.name !== 'AbortError' && window._currentRoundFrozenInput && assistantId === currentActiveAssistantId && window.currentRunningTemplateId) {
        window._currentRoundFrozenInput.failedAssistantId = assistantId;
      }
      setWorkflowExecutionLocked(false);
      if (streamingRafMap.has(assistantId)) {
        cancelAnimationFrame(streamingRafMap.get(assistantId));
        streamingRafMap.delete(assistantId);
      }
      streamingTextBuffers.delete(assistantId);
      if (err.name === 'AbortError') return;
      console.error('Chat stream error:', err);
      const respEl = document.getElementById('response-text-' + assistantId);
      if (respEl) {
        respEl.innerHTML = `<span style="color:var(--error-color)">❌ 任务调度失败: ${escapeHtml(err.message)}</span>`;
      }
    } finally {
      if (!isAwaitingCommitResolution) {
        sendBtn.disabled = false;
        setWorkflowExecutionLocked(false);
      } else {
        setWorkflowExecutionLocked(true);
      }
      if (typeof fetchUserData === 'function') fetchUserData();
    }
  }

  // --- Virtual Closure Patch for Streaming Markdown & Smart Auto-Scroll ---
  function patchUnclosedMarkdown(raw) {
    if (!raw) return '';
    let patched = raw;

    // 1. Check code blocks with triple backticks ```
    const codeBlockMatches = patched.match(/```/g);
    const codeBlockCount = codeBlockMatches ? codeBlockMatches.length : 0;
    if (codeBlockCount % 2 === 1) {
      return patched + '\n```';
    }

    // 2. Check inline code backticks ` (outside code blocks)
    const inlineTicks = patched.match(/(?<!`)`(?!`)/g);
    if (inlineTicks && inlineTicks.length % 2 === 1) {
      patched += '`';
    }

    // 3. Check bold syntax **
    const boldMatches = patched.match(/\*\*/g);
    if (boldMatches && boldMatches.length % 2 === 1) {
      patched += '**';
    }

    // 4. Check strikethrough ~~
    const strikeMatches = patched.match(/~~/g);
    if (strikeMatches && strikeMatches.length % 2 === 1) {
      patched += '~~';
    }

    return patched;
  }

  function smartScrollToBottom(scrollContainer) {
    if (!scrollContainer) return;
    const distanceToBottom = scrollContainer.scrollHeight - scrollContainer.scrollTop - scrollContainer.clientHeight;
    // Smart auto-scroll: pin to bottom unless user has manually scrolled up > 90px
    if (distanceToBottom <= 90) {
      scrollContainer.scrollTop = scrollContainer.scrollHeight;
    }
  }

  const streamingTextBuffers = new Map();
  const streamingRafMap = new Map();

  function scheduleStreamingMarkdownRender(assistantId) {
    if (streamingRafMap.has(assistantId)) return;

    const rafId = requestAnimationFrame(() => {
      streamingRafMap.delete(assistantId);
      const respEl = document.getElementById('response-text-' + assistantId);
      if (!respEl) return;

      const rawText = sanitizePromptLeakage(streamingTextBuffers.get(assistantId) || '');
      if (!rawText) return;

      const patched = patchUnclosedMarkdown(rawText);
      const parsed = safeRenderMarkdown(patched);

      if (parsed.includes('</p>')) {
        respEl.innerHTML = parsed.replace(/<\/p>(\s*)$/, '<span class="streaming-cursor"></span></p>$1');
      } else {
        respEl.innerHTML = parsed + '<span class="streaming-cursor"></span>';
      }

      smartScrollToBottom(document.getElementById('chat-messages'));
    });

    streamingRafMap.set(assistantId, rafId);
  }

  // Stage 3 & 4: SSE Message Dispatcher & DAG State Synchronization
  function handleSSEMessage(event, data, assistantId, userPrompt = '', pumpSSEStream = null, streamOptions = {}) {
    const respEl = document.getElementById('response-text-' + assistantId);
    const arbPill = document.getElementById('arbitration-pill');
    const arbText = document.getElementById('arb-text');

    if (event === 'dag_resume') {
      const resumedStep = Number(data.resumed_step || 0);
      if (Array.isArray(activeDagNodes)) {
        activeDagNodes.forEach((n, idx) => {
          if (idx < resumedStep) {
            const nodeKey = n.node_id || n.role_id;
            const card = document.getElementById('dag-node-' + nodeKey);
            if (card) {
              card.classList.remove('running', 'is-downloading');
              card.classList.add('completed');
            }
            const meta = document.getElementById('node-meta-' + nodeKey);
            if (meta && !meta.textContent.includes('✓')) {
              meta.textContent = '✓ 已完成';
            }
          }
        });
      }
      // FINDING-NEW-03: Synchronize DAG card model names and activeDagNodes from server resumed state
      if (Array.isArray(data.nodes)) {
        data.nodes.forEach(n => {
          const nodeKey = n.node_id || n.role_id;
          const card = document.getElementById('dag-node-' + nodeKey);
          if (card && n.selected_model) {
            const modelNameEl = card.querySelector('.dag-card-model-name');
            if (modelNameEl) {
              modelNameEl.textContent = n.selected_model.display_name;
            }
          }
          const activeNode = (activeDagNodes || []).find(an => (an.node_id || an.role_id) === nodeKey || an.role_id === n.role_id || an.role?.role_id === n.role_id);
          if (activeNode && n.selected_model) {
            activeNode.selected_model = n.selected_model;
          }
        });
      }
      requestAnimationFrame(() => renderDagSvgConnectors());
      return;
    }

    if (event === 'dag_plan') {
      if (window._stagedCanvasDraft) {
        window._stagedCanvasDraft.didRenderDagPlan = true;
      }
      if (data.run_id) {
        window._activeServerRunId = data.run_id;
        if (!streamOptions?.isReRun && window._currentRoundFrozenInput && !data.is_clarification_required) {
          window._currentRoundFrozenInput.baseRunId = data.run_id;
        }
      }
      activeDagNodes = (data.nodes || []).map(n => {
        if (window.activeCustomRolePrompts && window.activeCustomRolePrompts[n.role_id] !== undefined) {
          n.custom_prompt = window.activeCustomRolePrompts[n.role_id];
        }
        const seenModelIds = new Set();
        n._allCandidateModels = [n.selected_model, ...(n.standby_models || [])]
          .filter(Boolean)
          .filter(m => {
            if (!m.model_id || seenModelIds.has(m.model_id)) return false;
            seenModelIds.add(m.model_id);
            return true;
          });
        return n;
      });
      currentCandidateTemplates = data.candidate_templates || [];
      window.currentRunningTemplateId = data.template?.template_id;
      window.currentRunningTemplateObj = data.template || null;
      window.currentRoundIntentState = data.reasoning_trace?.intent_state || null;

      const isFirewall = !!data.is_security_violation;
      const isUnreachable = !!data.is_unreachable;
      const isEn = getLocale() === 'en';

      // Record baseline executed configuration when there is no active staged micro-tuning draft
      if (!window._stagedCanvasDraft) {
        window.originalNodeConfigs = {};
        window.activeChosenRoleModels = {};
        window.activeCustomRolePrompts = {};
        (data.nodes || []).forEach(n => {
          const nKey = n.node_id || n.role_id;
          window.originalNodeConfigs[nKey] = {
            model_id: n.selected_model.model_id,
            custom_prompt: n.custom_prompt || ''
          };
          window.activeChosenRoleModels[nKey] = n.selected_model.model_id;
          window.activeCustomRolePrompts[nKey] = n.custom_prompt || '';
        });
      }
      updateRerouteButtonState();

      // 1. Lock arbitration feedback pill (Stage 2)
      const currentArbPill = (currentActiveRunId && document.getElementById('arb-pill-' + currentActiveRunId)) || arbPill;
      const currentArbText = (currentActiveRunId && document.getElementById('arb-text-' + currentActiveRunId)) || arbText;
      if (currentArbPill) currentArbPill.classList.add('locked');
      const latency = data.reasoning_trace?.duration_ms || Math.floor(Math.random() * 80 + 130);
      if (currentArbText) {
        currentArbText.textContent = getCompactArbitrationText(isFirewall, isUnreachable, latency, isEn);
      }

      // 2. Intent Tracking: stash pending trace (NEVER flip activeBranchId before commitTurnTransaction!)
      const currentIntentPill = (currentActiveRunId && document.getElementById('intent-pill-' + currentActiveRunId)) || document.getElementById('intent-pill');
      const isMultiRound = Boolean(data.reasoning_trace?.is_multi_round && data.reasoning_trace?.intent_state);
      const intentState = data.reasoning_trace?.intent_state;
      window._pendingRoundTrace = data.reasoning_trace || null;
      if (!streamOptions?.isReRun && window._currentRoundFrozenInput && !data.is_clarification_required) {
        window._currentRoundFrozenInput.frozenResolvedPlan = {
          intent_state: intentState || null,
          target_branch_id: data.reasoning_trace?.target_branch_id,
          source_branch_ids: data.reasoning_trace?.source_branch_ids || [],
          inherited_context_slices: data.reasoning_trace?.inherited_context_slices || [],
          mounted_asset_bindings: data.reasoning_trace?.mounted_asset_bindings || []
        };
      }

      if (currentIntentPill) {
        if (!isMultiRound || !intentState || isFirewall) {
          currentIntentPill.style.display = 'none';
        } else {
          currentIntentPill.style.display = 'inline-flex';
          const compactIntent = getCompactIntentName(intentState, isEn);
          const stateClass = intentState === 'ANCHOR_TAIL' ? 'state-a' :
            intentState === 'REBIND_ROOT' ? 'state-b' :
            intentState === 'CROSS_FUSION' ? 'state-d' :
            intentState === 'SWITCH_BRANCH' ? 'state-e' : 'state-c';
          const titleText = isEn 
            ? (intentState === 'ANCHOR_TAIL' ? 'State A: Stripped raw media, inheriting prior turn text context' :
               intentState === 'REBIND_ROOT' ? 'State B: Reset asset pointer, re-exploring raw media assets' :
               intentState === 'CROSS_FUSION' ? 'State D: Cross-turn asset fusion and comparison' :
               intentState === 'SWITCH_BRANCH' ? 'State E: Switched context to recalled historical task branch' :
               'State C: Detached historical context, independent clean orchestration')
            : (intentState === 'ANCHOR_TAIL' ? '状态 A：已剥离原始媒体资产，装载上轮产物，精简重组文本润色图' :
               intentState === 'REBIND_ROOT' ? '状态 B：重置资产指针，全链路重新探索原始素材' :
               intentState === 'CROSS_FUSION' ? '状态 D：多源融合与跨轮对比，继承历史资产并结合新输入' :
               intentState === 'SWITCH_BRANCH' ? '状态 E：已切回关联的历史任务分支，挂载该分支产物为基底' :
               '状态 C：断离历史上下文，全新任务独立编排');
          currentIntentPill.className = `telemetry-pill intent-telemetry-pill ${stateClass}`;
          currentIntentPill.textContent = compactIntent;
          currentIntentPill.title = titleText;
        }
      }

      // 3. Macro Route Switcher (Step 2 Mapping)
      const routeChain = document.getElementById('macro-route-chain');
      const macroDropdown = document.getElementById('macro-dropdown');
      const macroCapsuleBtn = document.getElementById('macro-capsule-btn');
      const macroLabel = document.getElementById('macro-label') || document.querySelector('.macro-label');
      const lockIcon = document.getElementById('macro-lock-icon');

      if (macroLabel) {
        macroLabel.textContent = isEn ? 'Route:' : '当前路由:';
      }
      if (lockIcon) {
        lockIcon.style.display = 'none';
      }

      if (routeChain && data.nodes) {
        if (isFirewall) {
          routeChain.textContent = isEn ? '🛡️ Edge Firewall (Blocked)' : '🛡️ 边界防御网关 (已拦截)';
        } else if (isUnreachable) {
          routeChain.textContent = isEn ? '∅ Unreachable (No Matching Pipeline)' : '∅ 意图不可达 (未匹配到流水线)';
        } else {
          routeChain.textContent = data.nodes.map(n => getCompactRoleName(n.role_id, n.name_zh, n.name_en)).join(' ➔ ');
        }
      }

      if (macroCapsuleBtn) {
        if (isFirewall || isUnreachable) {
          macroCapsuleBtn.style.pointerEvents = 'none';
          macroCapsuleBtn.style.opacity = '0.6';
        } else {
          macroCapsuleBtn.style.pointerEvents = '';
          macroCapsuleBtn.style.opacity = '1';
        }
      }

      if (macroCapsuleBtn && macroDropdown && currentCandidateTemplates.length > 0 && !isFirewall && !isUnreachable) {
        macroCapsuleBtn.onclick = (e) => {
          e.stopPropagation();
          if (isWorkflowExecuting || isAwaitingCommitResolution) return;
          macroDropdown.style.display = macroDropdown.style.display === 'none' ? 'block' : 'none';
        };

        macroDropdown.innerHTML = currentCandidateTemplates.map((t, idx) => {
          const tplTitle = isEn 
            ? `${idx === 0 ? '🏆' : (idx === 1 ? '⚡' : '🔍')} Route ${idx + 1}: ${escapeHtml(getCompactTemplateName(t.template_id, t.name_zh, t.name_en))}`
            : `${idx === 0 ? '🏆' : (idx === 1 ? '⚡' : '🔍')} 路线 ${idx + 1}: ${escapeHtml(t.name_zh)}`;
          const tplDesc = isEn
            ? (idx === 0 ? 'Optimal match · Recommended' : (idx === 1 ? 'Cost saver · Save 40% ⚡' : 'Low latency direct route'))
            : (idx === 0 ? '综合胜任度最高 · 智能推荐' : (idx === 1 ? '更省算力 · 预估节省 40% ⚡' : '低时延直出路线'));
          return `
            <div class="macro-dropdown-item ${t.template_id === data.template?.template_id ? 'active' : ''}" data-tpl-id="${t.template_id}">
              <div style="font-weight:600; font-size:0.85rem; color:var(--text-primary);">
                ${tplTitle}
              </div>
              <div style="font-size:0.74rem; color:var(--text-secondary); margin-top:2px;">
                ${tplDesc}
              </div>
            </div>
          `;
        }).join('');

        macroDropdown.querySelectorAll('.macro-dropdown-item').forEach(item => {
          item.onclick = (e) => {
            e.stopPropagation();
            if (isWorkflowExecuting || isAwaitingCommitResolution) return;
            const chosenId = item.getAttribute('data-tpl-id');
            macroDropdown.style.display = 'none';
            if (chosenId !== data.template?.template_id) {
              triggerTemplateSwitch(chosenId, userPrompt || '切换工作流');
            }
          };
        });
      }

      // 4. Render Left 65% Whitebox DAG Nodes with Intent-Resolved Mounted Assets
      const intentStateVal = data.reasoning_trace?.intent_state || null;
      window.currentRoundIntentState = intentStateVal;

      let activeAssets = (window.activeRoundPayload && window.activeRoundPayload.files) || [];
      const bindingsList = data.reasoning_trace?.mounted_asset_bindings;

      if (intentStateVal === 'ANCHOR_TAIL') {
        window.stateAConsecutiveCount = (window.stateAConsecutiveCount || 0) + 1;
      } else {
        window.stateAConsecutiveCount = 0;
        window.isStackExpanded = false;
      }

      if (Array.isArray(bindingsList) && bindingsList.length > 0 && !streamOptions?.isSwitch) {
        const keepIds = new Set(bindingsList.filter(b => b.bind_mode !== 'DROP').map(b => b.asset_id));
        activeAssets = activeAssets.filter(a => a.isNew || keepIds.has(a.assetId || a.id || a.name));
      } else if (intentStateVal === 'DETACH_RESET' && !streamOptions?.isSwitch) {
        activeAssets = activeAssets.filter(a => a.isNew);
      }

      if (window.activeRoundPayload) window.activeRoundPayload.files = activeAssets;
      window.currentRoundAssets = activeAssets;

      if (data.is_clarification_required) {
        return;
      }

      renderDagNodesWithAnchors(data.nodes || [], {
        isFirewall,
        isUnreachable,
        intentState: intentStateVal,
        prompt: userPrompt || window.lastUserPrompt || '',
        assets: activeAssets,
        doSweep: intentStateVal === 'DETACH_RESET'
      });

      // Clear response text placeholder
      if (respEl) {
        respEl.innerHTML = '';
      }
    } else if (event === 'clarification_required') {
      const isEn = getLocale() === 'en';
      window._isCurrentTurnClarification = true;
      if (window._currentPreFlightSnapshot) {
        if (window._currentPreFlightSnapshot.gitStateSnapshot) {
          window.gitState = window._currentPreFlightSnapshot.gitStateSnapshot;
        }
        syncLegacyGlobalsFromGitState();
      }
      const stagedRawFiles = Array.isArray(window._currentStagedNewFiles) ? [...window._currentStagedNewFiles] : [];
      window._currentStagedNewFiles = [];
      window._currentRoundGeneratedAssets = [];
      window._pendingClarificationContext = {
        originalPrompt: userPrompt,
        stagedFiles: stagedRawFiles,
        candidateTargets: data.candidate_targets || []
      };

      const targetsHtml = (data.candidate_targets || []).map(ct => `
        <button type="button" class="clarification-choice-btn" data-branch-id="${escapeHtml(ct.branch_id)}">
          ${ct.relation === 'current' ? (isEn ? 'Stay on current:' : '留在当前分支:') : (isEn ? 'Return to:' : '回到历史分支:')} ${escapeHtml(ct.topic || ct.branch_id)}
        </button>
      `).join('');

      if (respEl) {
        respEl.innerHTML = `
          <div class="clarification-banner">
            <div style="font-weight:600; margin-bottom:6px;">🔀 ${escapeHtml(isEn ? data.reason_en : data.reason_zh)}</div>
            <div style="font-size:0.84rem; color:var(--text-secondary);">
              ${isEn ? 'Reply in the input box below or select a target branch to proceed without re-uploading attachments:' : '请在下方输入框回复目标分支，或直接点选下方分支继续（已暂存您刚才的附件，0 算力预扣）：'}
            </div>
            <div class="clarification-actions">${targetsHtml}</div>
          </div>
        `;
        respEl.querySelectorAll('.clarification-choice-btn').forEach(btn => {
          btn.onclick = () => {
            const chosenBid = btn.getAttribute('data-branch-id');
            const clarCtx = window._pendingClarificationContext;
            if (!clarCtx) return;
            window._pendingClarificationContext = null;
            if (Array.isArray(clarCtx.stagedFiles) && clarCtx.stagedFiles.length > 0) {
              selectedFiles = clarCtx.stagedFiles;
              renderFileChips();
            }
            sendChatMessage({
              customPrompt: clarCtx.originalPrompt,
              resolvedClarificationTargetBranchId: chosenBid
            });
          };
        });
      }
    } else if (event === 'billing_status') {
      const isEn = getLocale() === 'en';
      const pending = data.status === 'pending';
      localToast(pending
        ? (isEn ? 'Billing is pending. The server will retry it.' : '积分待结算，服务端会重试。')
        : (isEn ? 'Billing could not be confirmed for this run.' : '本次积分结算暂无法确认。'), 'warning');
    } else if (event === 'node_status') {
      const isEn = getLocale() === 'en';
      const targetNodeId = data.node_id || data.role_id;
      const nodeCard = document.getElementById('dag-node-' + targetNodeId);
      const meta = document.getElementById('node-meta-' + targetNodeId);
      if (nodeCard && data.status === 'waiting_resource') {
        nodeCard.classList.remove('running', 'is-parallel-running', 'completed');
        nodeCard.classList.add('is-waiting-resource');
      }
      if (meta && data.status === 'waiting_resource') {
        meta.textContent = isEn ? '⏳ Queued (concurrency slot)...' : '⏳ 等待并发槽位...';
      }
      refreshEvidencePrepGroupSummary();
    } else if (event === 'node_start') {
      const isEn = getLocale() === 'en';
      const targetNodeId = data.node_id || data.role_id;
      // Execution has officially started: clear visible pending stamps from cards
      if (window._stagedCanvasDraft && window._stagedCanvasDraft.pendingRoleIds) {
        window._stagedCanvasDraft.pendingRoleIds.forEach(roleId => {
          const card = document.getElementById('dag-node-' + roleId);
          if (card) {
            card.classList.remove('is-pending');
            const pendingStamp = card.querySelector('.dag-node-pending-stamp');
            if (pendingStamp) pendingStamp.remove();
          }
        });
      }
      const nodeCard = document.getElementById('dag-node-' + targetNodeId);
      const meta = document.getElementById('node-meta-' + targetNodeId);
      if (nodeCard) {
        nodeCard.classList.remove('cached', 'completed', 'is-waiting-resource');
        const oldStamp = nodeCard.querySelector('.dag-cache-hit-stamp');
        if (oldStamp) oldStamp.remove();
        if (data.inference_target === 'browser') {
          nodeCard.classList.add('is-downloading');
          let progressBar = nodeCard.querySelector('.dag-card-progress-bar');
          if (!progressBar) {
            progressBar = document.createElement('div');
            progressBar.className = 'dag-card-progress-bar';
            progressBar.style.width = '0%';
            nodeCard.appendChild(progressBar);
          }
        } else if (data.exec_mode === 'parallel') {
          nodeCard.classList.add('is-parallel-running', 'running');
        } else {
          nodeCard.classList.add('running');
        }
      }
      if (meta) {
        meta.textContent = data.inference_target === 'browser'
          ? (isEn ? '📥 Fetching weights...' : '📥 准备权重...')
          : data.exec_mode === 'parallel'
            ? (isEn ? '⚡ Parallel...' : '⚡ 并行执行...')
            : (isEn ? 'Running...' : '执行中...');
      }
      refreshEvidencePrepGroupSummary();
      requestAnimationFrame(() => renderDagSvgConnectors());

      // Render Step Indicator Badge (decoupling execution step progress from streaming text content)
      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-' + targetNodeId);
        const roleName = isEn 
          ? (data.role_name_en || getCompactRoleName(data.role_id, data.role_name)) 
          : (data.role_name || (activeDagNodes.find(n => (n.node_id || n.role_id) === targetNodeId)?.name_zh) || '处理');
        if (!stepBadge) {
          stepBadge = document.createElement('div');
          stepBadge.className = 'assistant-step-badge running';
          stepBadge.id = 'step-badge-' + currentActiveAssistantId + '-' + targetNodeId;
          stepsContainer.appendChild(stepBadge);
        }
        stepBadge.innerHTML = `<span class="step-spinner">⠋</span> <span>${escapeHtml(roleName)} ${data.exec_mode === 'parallel' ? (isEn ? 'Parallel...' : '并行执行中...') : (isEn ? 'Processing...' : '执行中...')}</span>`;
      }
    } else if (event === 'client_exec_request' || event === 'dag_handover') {
      const isEn = getLocale() === 'en';
      const isTailNode = event === 'client_exec_request' || !!data.is_tail_node;
      if (event === 'client_exec_request' || data.client_commit_token) {
        window._pendingClientTailCommit = {
          runId: data.run_id || window._activeServerRunId || currentActiveRunId,
          clientCommitToken: data.client_commit_token || ''
        };
      }
      const roleId = data.role_id;
      const targetNodeId = data.node_id || roleId;
      const modelName = data.model_name || 'SmolLM2-135M 本地极速';
      const nodeCard = document.getElementById('dag-node-' + targetNodeId);
      const meta = document.getElementById('node-meta-' + targetNodeId);

      // 1. Right 35% Chat Flow: Immediate System Preflight Diagnostics Log below user bubble
      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        let diagEl = document.getElementById('preflight-diag-' + currentActiveAssistantId);
        if (!diagEl) {
          diagEl = document.createElement('div');
          diagEl.id = 'preflight-diag-' + currentActiveAssistantId;
          diagEl.className = 'system-preflight-diagnostics';
          diagEl.innerHTML = `
            <div class="preflight-title">⚡ [NanoMesh Dispatcher]</div>
            <div class="preflight-line">✓ ${isEn ? 'Routing and safety checks passed' : '已通过编排与安全校验'}</div>
            <div class="preflight-line">${isEn ? 'Attempting in-browser inference' : '正在尝试端侧推理'}: ${escapeHtml(modelName)}</div>
            <div class="preflight-line" id="diag-actual-executor-${currentActiveAssistantId}" hidden></div>
            <div class="preflight-line" id="diag-worker-status-${currentActiveAssistantId}">⚙️ ${isEn ? 'Initializing WebGPU sandbox (Transformers.js)...' : '初始化 WebGPU 推理沙箱 (Transformers.js)...'}</div>
          `;
          stepsContainer.parentNode.insertBefore(diagEl, stepsContainer);
        }
        diagEl.dataset.browserNodeId = targetNodeId;
      }

      // 2. Step Badge in right chat flow
      if (stepsContainer) {
        let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-' + targetNodeId);
        if (!stepBadge) {
          stepBadge = document.createElement('div');
          stepBadge.className = 'assistant-step-badge running';
          stepBadge.id = 'step-badge-' + currentActiveAssistantId + '-' + targetNodeId;
          stepsContainer.appendChild(stepBadge);
        }
        stepBadge.innerHTML = `<span class="step-spinner">⠋</span> <span>${escapeHtml(modelName)} ${isEn ? 'Local Inference...' : '本地推理中...'}</span>`;
      }

      // 3. Canvas Node Card: is-downloading state and 1.5px pulse progress bar
      if (nodeCard) {
        nodeCard.classList.remove('running', 'completed', 'cached');
        nodeCard.classList.add('is-downloading');

        let progressBar = nodeCard.querySelector('.dag-card-progress-bar');
        if (!progressBar) {
          progressBar = document.createElement('div');
          progressBar.className = 'dag-card-progress-bar';
          progressBar.style.width = '0%';
          nodeCard.appendChild(progressBar);
        }
      }
      if (meta) {
        meta.textContent = isEn ? '📥 Fetching weights...' : '📥 准备权重...';
      }
      requestAnimationFrame(() => renderDagSvgConnectors());

      // 4. Dedicated Web Worker Execution
      window._activeLocalRunnerPromise = new Promise((resolve, reject) => {
        try {
          if (!window._localWorker) {
            window._localWorker = new Worker('/local-runner.js?v=20261127-runtime', { type: 'module' });
          }
          const worker = window._localWorker;

          // 4. Dedicated Web Worker Execution & Watchdog (BUG-06)
          let watchdogTimer = null;
          const resetWatchdog = () => {
            if (watchdogTimer) clearTimeout(watchdogTimer);
            watchdogTimer = setTimeout(() => {
              console.warn('[LocalRunner] Watchdog timeout: no progress from worker for 45s');
              if (window._localWorker) {
                try { window._localWorker.terminate(); } catch (e) {}
                window._localWorker = null;
              }
              const timeoutErr = new Error('Local WebGPU worker timeout (45s silence)');
              if (worker && typeof worker.onerror === 'function') {
                worker.onerror(timeoutErr);
              }
            }, 45000);
          };
          resetWatchdog();

          let workerCrashed = false;
          worker.onerror = (err) => {
            if (workerCrashed) return;
            workerCrashed = true;
            if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
            if (window._localWorker === worker) {
              worker.terminate();
              window._localWorker = null;
            }
            console.error('[LocalRunner] Worker thread error:', err);
            const meta = document.getElementById('node-meta-' + targetNodeId);
            if (meta) meta.textContent = '❌ 本地推理异常';
            const workerDiag = document.getElementById('diag-worker-status-' + currentActiveAssistantId);
            if (workerDiag) workerDiag.textContent = `❌ ${escapeHtml(err.message || 'Worker thread execution error')}`;
            if (data.continuation_token) {
              (async () => {
                try {
                  const failoverRes = await fetch('/api/chat/continue', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    signal: window.activeChatAbortController?.signal,
                    body: JSON.stringify({
                      continuation_token: data.continuation_token,
                      status: 'candidate_failed',
                      failed_model_id: data.model_id,
                      error_reason: err.message || 'Worker thread execution error',
                      upstream_context: data.user_prompt || '',
                      capabilities: { webgpu_handover_v3: true },
                      envelope: window._lastChatEnvelope,
                      orchestration_options: window._lastOrchestrationOptions
                    })
                  });
                  if (failoverRes.ok && pumpSSEStream) {
                    const failoverOutput = await pumpSSEStream(failoverRes.body, assistantId, userPrompt, { isContinuation: true, isSwitch: !!streamOptions.isSwitch, isReRun: !!streamOptions.isReRun });
                    resolve(failoverOutput);
                    return;
                  }
                } catch (fErr) {}
                window._isCurrentTurnRolledBack = true;
                setWorkflowExecutionLocked(false);
                const sendBtn = document.getElementById('send-btn');
                if (sendBtn) sendBtn.disabled = false;
                reject(new Error(err.message || 'Local worker crashed'));
              })();
            } else {
              window._isCurrentTurnRolledBack = true;
              setWorkflowExecutionLocked(false);
              const sendBtn = document.getElementById('send-btn');
              if (sendBtn) sendBtn.disabled = false;
              reject(new Error(err.message || 'Local worker crashed'));
            }
          };

          worker.onmessage = (e) => {
            const msg = e.data || {};
            const workerDiag = document.getElementById('diag-worker-status-' + currentActiveAssistantId);

            if (msg.type === 'DOWNLOAD_PROGRESS') {
              resetWatchdog();
              if (meta) {
                meta.textContent = `📥 拉取权重 ${msg.loadedMB}/${msg.totalMB}MB (${msg.speedMBps} MB/s)`;
              }
              const pBar = nodeCard?.querySelector('.dag-card-progress-bar');
              if (pBar) {
                pBar.classList.remove('is-compiling');
                pBar.style.width = `${msg.percent}%`;
              }
              if (workerDiag) {
                workerDiag.textContent = `📥 ${isEn ? 'Pulling Weights' : '拉取权重'}: ${msg.loadedMB}/${msg.totalMB}MB (${msg.percent}%) @ ${msg.speedMBps} MB/s`;
              }
            } else if (msg.type === 'COMPILING_PIPELINE') {
              resetWatchdog();
              const devName = msg.device === 'webgpu' ? 'WebGPU' : 'Wasm CPU';
              if (meta) {
                meta.textContent = `⚙️ 正在编译 ${devName} 管线... (${msg.duration_ms || 32}ms)`;
              }
              const pBar = nodeCard?.querySelector('.dag-card-progress-bar');
              if (pBar) {
                pBar.classList.add('is-compiling');
                pBar.style.width = '100%';
              }
              if (workerDiag) {
                workerDiag.textContent = `⚙️ ${isEn ? `Compiling ${devName} Pipeline...` : `正在编译 ${devName} 计算管线...`} (${msg.duration_ms || 32}ms)`;
              }
            } else if (msg.type === 'TEXT_CHUNK') {
              resetWatchdog();
              // Transition to Local running
              if (nodeCard) {
                nodeCard.classList.remove('is-downloading');
                nodeCard.classList.add('running');
              }
              if (meta && !meta.textContent.includes('💻')) {
                meta.textContent = isEn ? '💻 Local Ready' : '💻 Local 就绪';
              }
              const pBar = nodeCard?.querySelector('.dag-card-progress-bar');
              if (pBar) {
                pBar.style.opacity = '0';
                setTimeout(() => pBar.remove(), 300);
              }
              if (workerDiag && !workerDiag.textContent.includes('✓ 管线就绪')) {
                const devName = msg.device === 'webgpu' ? 'WebGPU' : 'Wasm CPU';
                workerDiag.textContent = `✓ ${isEn ? `${devName} pipeline ready, streaming...` : `${devName} 管线就绪，正在高速流式推理...`}`;
              }

              // Append streamed chunk ONLY if tail node!
              if (isTailNode) {
                const rawChunk = msg.chunk || '';
                const prev = streamingTextBuffers.get(assistantId) || '';
                streamingTextBuffers.set(assistantId, prev + rawChunk);
                scheduleStreamingMarkdownRender(assistantId);
              }

            } else if (msg.type === 'GENERATE_COMPLETE') {
              if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
              // Complete execution
              if (nodeCard) {
                nodeCard.classList.remove('is-downloading', 'running');
                nodeCard.classList.add('completed');
              }
              if (meta) {
                meta.textContent = `⚡ 本地 ${msg.duration_ms}ms`;
              }

              // Step badge completed
              if (stepsContainer) {
                let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-' + targetNodeId);
                if (stepBadge) {
                  stepBadge.className = 'assistant-step-badge completed';
                  stepBadge.innerHTML = `<span class="step-check">✓</span> <span>${escapeHtml(modelName)} ${isEn ? 'Done' : '完成'}</span> <span class="step-time">⚡ 0点 · ${msg.duration_ms}ms</span>`;
                }
              }

              if (workerDiag) {
                workerDiag.textContent = `✓ ${isEn ? 'Local Inference Completed' : '本地端侧推理完成'} (${msg.duration_ms}ms · ⚡ 0点)`;
              }

              if (!isTailNode) {
                requestAnimationFrame(() => renderDagSvgConnectors());
                // Intermediate node: Call /api/chat/continue
                (async () => {
                  try {
                    const continueRes = await fetch('/api/chat/continue', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      signal: window.activeChatAbortController?.signal,
                      body: JSON.stringify({
                        continuation_token: data.continuation_token,
                        status: 'success',
                        client_step_output: msg.output || '',
                        capabilities: { webgpu_handover_v3: true },
                        envelope: window._lastChatEnvelope,
                        orchestration_options: window._lastOrchestrationOptions
                      })
                    });

                    if (continueRes.status === 409) {
                      if (respEl) {
                        respEl.innerHTML = `<span style="color:var(--color-danger, #ef4444);font-size:13px;">⚠️ 该任务步骤已被消费或已超时，请刷新重试。</span>`;
                      }
                      setWorkflowExecutionLocked(false);
                      window._isCurrentTurnRolledBack = true;
                      const sendBtn = document.getElementById('send-btn');
                      if (sendBtn) sendBtn.disabled = false;
                      resolve('');
                      return;
                    }

                    if (!continueRes.ok) {
                      const errJson = await continueRes.json().catch(() => ({}));
                      throw new Error(errJson.message || '接力调度失败');
                    }

                    if (pumpSSEStream) {
                      const contOutput = await pumpSSEStream(continueRes.body, assistantId, userPrompt, { isContinuation: true, isSwitch: !!streamOptions.isSwitch, isReRun: !!streamOptions.isReRun });
                      resolve(contOutput);
                    } else {
                      resolve(msg.output || '');
                    }
                  } catch (contErr) {
                    console.error('[Handover] Continuation failed:', contErr);
                    window._isCurrentTurnRolledBack = true;
                    if (respEl) {
                      respEl.innerHTML = `<span style="color:var(--color-danger, #ef4444);font-size:13px;">❌ 接力调度失败: ${escapeHtml(contErr.message)}</span>`;
                    }
                    setWorkflowExecutionLocked(false);
                    const sendBtn = document.getElementById('send-btn');
                    if (sendBtn) sendBtn.disabled = false;
                    reject(contErr);
                  }
                })();
              } else {
                // Mark Sink Anchor completed
                const sink = document.getElementById('dag-sink-anchor');
                if (sink) {
                  sink.classList.remove('is-executing');
                  sink.classList.add('completed');
                }
                requestAnimationFrame(() => renderDagSvgConnectors());

                // Finalize markdown render
                const fullText = msg.output || streamingTextBuffers.get(assistantId) || '';
                if (respEl) {
                  respEl.innerHTML = safeRenderMarkdown(fullText);
                }
                if (streamingRafMap.has(assistantId)) {
                  cancelAnimationFrame(streamingRafMap.get(assistantId));
                  streamingRafMap.delete(assistantId);
                }
                streamingTextBuffers.delete(assistantId);

                const totalNodes = activeDagNodes?.length || 1;
                const promptText = window.lastUserPrompt || userPrompt || '';
                const tailCreds = window._pendingClientTailCommit || {};
                const serverRunId = tailCreds.runId || window._activeServerRunId || window._currentRoundFrozenInput?.baseRunId || currentActiveRunId || ('run-' + Date.now());
                const candidateRev = (window._currentRoundFrozenInput?.candidateRevision || window._currentRoundFrozenInput?.committedRevision || window._currentRoundFrozenInput?.revision || 1);
                const isReRun = Boolean(candidateRev > 1);
                const baseRunId = window._currentRoundFrozenInput?.baseRunId || serverRunId;

                const finalizeCommittedClientTail = (serverSnap) => {
                  if (window._currentRoundFrozenInput) {
                    if (window._currentRoundFrozenInput.candidateRevision) {
                      window._currentRoundFrozenInput.committedRevision = window._currentRoundFrozenInput.candidateRevision;
                      window._currentRoundFrozenInput.revision = window._currentRoundFrozenInput.committedRevision;
                      window._currentRoundFrozenInput.candidateRevision = null;
                    }
                  }
                  const committedRev = window._currentRoundFrozenInput?.committedRevision || window._currentRoundFrozenInput?.revision || candidateRev;
                  if (Array.isArray(window.currentRoundAssets)) {
                    window.currentRoundAssets.forEach(a => { a.isNew = false; });
                  }
                  if (window._currentRoundFrozenInput && Array.isArray(window._currentRoundFrozenInput.frozenAssets)) {
                    window._currentRoundFrozenInput.frozenAssets.forEach(a => { a.isNew = false; });
                  }
                  window._currentStagedNewFiles = [];
                  commitStagedCanvasDraft(activeDagNodes);
                  const hydrated = serverSnap ? hydrateGitStateFromServer(serverSnap) : false;
                  if (!hydrated) {
                    if (isReRun) {
                      recordCanvasRevisionUpdate({ baseRunId, revision: committedRev, finalOutput: fullText });
                    } else {
                      commitTurnTransaction({ runId: serverRunId, revision: committedRev, userPrompt: promptText, finalOutput: fullText, trace: window._pendingRoundTrace });
                    }
                  }
                  const actionsEl = document.getElementById('actions-' + assistantId);
                  if (actionsEl) {
                    actionsEl.style.display = 'flex';
                    actionsEl.classList.add('is-visible');
                  }
                  setWorkflowExecutionLocked(false);
                  const sendBtn = document.getElementById('send-btn');
                  if (sendBtn) sendBtn.disabled = false;
                  const gitSnap = JSON.parse(JSON.stringify(window.gitState || createEmptyGitState()));
                  saveTraceToHistory({
                    sessionId: window.chatSessionId,
                    title: promptText.slice(0, 30) || '端侧 WebGPU 任务',
                    cost: '0',
                    duration: (msg.duration_ms ? (msg.duration_ms / 1000).toFixed(1) + 's' : '1.2s'),
                    nodesCount: totalNodes,
                    cached: false,
                    gitStateSnapshot: gitSnap,
                    round: {
                      runId: serverRunId,
                      baseRunId: baseRunId,
                      revision: committedRev,
                      isReRun: isReRun,
                      roundIndex: window.chatRoundIndex || 1,
                      userPrompt: promptText,
                      assets: window.currentRoundAssets || [],
                      targetLanguage: window._currentRoundFrozenInput?.targetLanguage || window._lastChatEnvelope?.constraint_context?.target_language || (localStorage.getItem('nanomesh_lang') || 'auto'),
                      outputStyle: window._currentRoundFrozenInput?.outputStyle || window._lastChatEnvelope?.constraint_context?.output_style || (localStorage.getItem('nanomesh_style') || 'concise'),
                      assistantOutput: fullText,
                      template: window.currentRunningTemplateObj || null,
                      candidateTemplates: currentCandidateTemplates || [],
                      nodes: JSON.parse(JSON.stringify(activeDagNodes || [])),
                      steps: [],
                      intentState: window.currentRoundIntentState || null,
                      branchId: window.activeBranchId,
                      resolvedPlan: window._currentRoundFrozenInput?.frozenResolvedPlan || null,
                      isFastFailed: false,
                      cost: '0',
                      duration: (msg.duration_ms ? (msg.duration_ms / 1000).toFixed(1) + 's' : '1.2s'),
                      cached: false,
                      timestamp: Date.now()
                    }
                  });
                };

                // Defer unlock & local Git commit UNTIL authoritative D1 /api/session/:id/commit succeeds!
                if (window.chatSessionId && typeof fetch === 'function') {
                  (async () => {
                    const attemptClientTailCommit = async () => {
                      return fetch('/api/session/' + encodeURIComponent(window.chatSessionId) + '/commit', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          run_id: serverRunId,
                          client_commit_token: tailCreds.clientCommitToken || '',
                          final_output: fullText
                        })
                      });
                    };
                    const showTailRetryAbandonBanner = (rawMsg, allowAbandon) => {
                      window._isCurrentTurnRolledBack = true;
                      setAwaitingCommitResolutionState(true, {
                        run_id: serverRunId,
                        exec_owner: 'BROWSER_TAIL',
                        can_retry_commit: true
                      });
                      if (respEl) {
                        const existingBanner = respEl.querySelector('.dag-execution-error-banner');
                        if (existingBanner) existingBanner.remove();

                        const banner = document.createElement('div');
                        banner.className = 'dag-execution-error-banner';
                        banner.style.cssText = 'color:#f59e0b; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.35); padding:10px 14px; border-radius:8px; margin-top:10px; font-size:0.86rem;';
                        banner.innerHTML = `<div>⚠️ 状态暂存冲突或存储暂时繁忙（本地状态未提交）：${escapeHtml(rawMsg || (allowAbandon ? '请点击重试保存或放弃此结果' : '请点击重试保存'))}</div>`;
                        const btnRow = document.createElement('div');
                        btnRow.style.cssText = 'display:flex; gap:8px; margin-top:8px; flex-wrap:wrap;';
                        const retryBtn = document.createElement('button');
                        retryBtn.type = 'button';
                        retryBtn.className = 'chat-action-btn';
                        retryBtn.style.cssText = 'padding:4px 10px;';
                        retryBtn.textContent = isEn ? 'Retry Commit' : '重试提交状态';

                        let abandonBtn = null;
                        if (allowAbandon) {
                          abandonBtn = document.createElement('button');
                          abandonBtn.type = 'button';
                          abandonBtn.className = 'chat-action-btn';
                          abandonBtn.style.cssText = 'padding:4px 10px; color:#ef4444;';
                          abandonBtn.textContent = isEn ? 'Abandon Result' : '放弃此结果';
                          abandonBtn.onclick = async () => {
                            retryBtn.disabled = true;
                            if (abandonBtn) abandonBtn.disabled = true;
                            const abRes = await abandonPendingCommit(serverRunId);
                            if (abRes?.ok) {
                              banner.remove();
                              if (!abRes.alreadyCommitted && respEl) {
                                respEl.innerHTML = `<div class="dag-execution-error-banner" style="color:#6b7280; background:rgba(107,114,128,0.1); border:1px solid rgba(107,114,128,0.3); padding:10px 14px; border-radius:8px; margin-top:8px; font-size:0.86rem;">ℹ️ ${isEn ? 'Pending result abandoned. Restored to previous saved commit.' : '已放弃未保存结果，已回滚至上一成功基线。'}</div>`;
                              }
                            } else {
                              retryBtn.disabled = false;
                              if (abandonBtn) abandonBtn.disabled = false;
                            }
                          };
                        }

                        retryBtn.onclick = async () => {
                          retryBtn.disabled = true;
                          if (abandonBtn) abandonBtn.disabled = true;
                          try {
                            const r2 = await attemptClientTailCommit();
                            if (r2.ok) {
                              const s2 = await r2.json().catch(() => null);
                              banner.remove();
                              window._isCurrentTurnRolledBack = false;
                              setAwaitingCommitResolutionState(false);
                              finalizeCommittedClientTail(s2);
                            } else {
                              const e2 = await r2.json().catch(() => ({}));
                              if (r2.status >= 500 || r2.status === 408 || r2.status === 429 || e2.can_retry_commit || e2.awaiting_commit) {
                                showTailRetryAbandonBanner(e2.message, e2.awaiting_commit === true);
                              } else {
                                banner.remove();
                                setAwaitingCommitResolutionState(false);
                                rollbackTurnToPreFlight();
                                if (respEl) {
                                  respEl.innerHTML = `<div class="dag-execution-error-banner" style="color:#ef4444; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:10px 14px; border-radius:8px; margin-top:8px; font-size:0.88rem;">⚠️ ${escapeHtml(e2.message || '服务端状态已变更或已被接管，当前端侧结果未提交。')}</div>`;
                                }
                                const sendBtn = document.getElementById('send-btn');
                                if (sendBtn) sendBtn.disabled = false;
                              }
                            }
                          } catch {
                            retryBtn.disabled = false;
                            if (abandonBtn) abandonBtn.disabled = false;
                          }
                        };

                        btnRow.appendChild(retryBtn);
                        if (abandonBtn) btnRow.appendChild(abandonBtn);
                        banner.appendChild(btnRow);
                        respEl.appendChild(banner);
                      }
                    };

                    try {
                      const commitRes = await attemptClientTailCommit();
                      if (commitRes.ok) {
                        const serverSnap = await commitRes.json().catch(() => null);
                        finalizeCommittedClientTail(serverSnap);
                        resolve(fullText);
                        return;
                      }
                      const errJson = await commitRes.json().catch(() => ({}));
                      const isRetryableStatus = commitRes.status >= 500 || commitRes.status === 408 || commitRes.status === 429;
                      if ((errJson.can_retry_commit || isRetryableStatus) && tailCreds.clientCommitToken) {
                        showTailRetryAbandonBanner(errJson.message, errJson.awaiting_commit === true);
                        resolve('');
                        return;
                      }
                      setAwaitingCommitResolutionState(false);
                      rollbackTurnToPreFlight();
                      if (respEl) {
                        respEl.innerHTML = `<div class="dag-execution-error-banner" style="color:#ef4444; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:10px 14px; border-radius:8px; margin-top:8px; font-size:0.88rem;">⚠️ ${escapeHtml(errJson.message || '服务端状态已变更或已被接管，当前端侧结果未提交。')}</div>`;
                      }
                      const sendBtn = document.getElementById('send-btn');
                      if (sendBtn) sendBtn.disabled = false;
                      resolve('');
                    } catch (commitErr) {
                      if (tailCreds.clientCommitToken) {
                        showTailRetryAbandonBanner(
                          commitErr?.message || (isEn ? 'Network error during save. Please retry committing.' : '网络连接中断或断线，请点击重试保存状态'),
                          false
                        );
                        resolve('');
                        return;
                      }
                      setAwaitingCommitResolutionState(false);
                      rollbackTurnToPreFlight();
                      const sendBtn = document.getElementById('send-btn');
                      if (sendBtn) sendBtn.disabled = false;
                      resolve('');
                    }
                  })();
                } else {
                  finalizeCommittedClientTail(null);
                  resolve(fullText);
                }
              }
            } else if (msg.type === 'ERROR') {
              if (watchdogTimer) { clearTimeout(watchdogTimer); watchdogTimer = null; }
              if (nodeCard) nodeCard.classList.remove('is-downloading', 'running');
              if (meta) meta.textContent = '❌ 本地推理异常';
              if (workerDiag) workerDiag.textContent = `❌ ${escapeHtml(msg.error)}`;

              if (data.continuation_token) {
                (async () => {
                  try {
                    const failoverRes = await fetch('/api/chat/continue', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      signal: window.activeChatAbortController?.signal,
                      body: JSON.stringify({
                        continuation_token: data.continuation_token,
                        status: 'candidate_failed',
                        failed_model_id: data.model_id,
                        error_reason: msg.error || 'Local execution failed',
                        upstream_context: data.user_prompt || '',
                        capabilities: { webgpu_handover_v3: true },
                        envelope: window._lastChatEnvelope,
                        orchestration_options: window._lastOrchestrationOptions
                      })
                    });

                    if (failoverRes.ok && pumpSSEStream) {
                      const failoverOutput = await pumpSSEStream(failoverRes.body, assistantId, userPrompt, { isContinuation: true, isSwitch: !!streamOptions.isSwitch, isReRun: !!streamOptions.isReRun });
                      resolve(failoverOutput);
                      return;
                    }
                  } catch (fErr) {}
                  window._isCurrentTurnRolledBack = true;
                  setWorkflowExecutionLocked(false);
                  const sendBtn = document.getElementById('send-btn');
                  if (sendBtn) sendBtn.disabled = false;
                  reject(new Error(msg.error || 'Local execution failed'));
                })();
              } else {
                window._isCurrentTurnRolledBack = true;
                // Clear partially streamed text buffer if error occurred during generation
                if (respEl) {
                  streamingTextBuffers.delete(assistantId);
                  respEl.innerHTML = `<span style="color:var(--color-danger, #ef4444);font-size:13px;">❌ ${escapeHtml(msg.error)}</span>`;
                }
                setWorkflowExecutionLocked(false);
                const sendBtn = document.getElementById('send-btn');
                if (sendBtn) sendBtn.disabled = false;
                reject(new Error(msg.error || 'Local execution failed'));
              }
            }
          };

          // Post generation command to worker
          worker.postMessage({
            type: 'GENERATE',
            payload: {
              role_id: data.role_id,
              model_id: data.model_id,
              endpoint: data.endpoint,
              system_prompt: data.system_prompt,
              user_prompt: data.user_prompt,
              claimed_assets: data.claimed_assets || []
            }
          });
        } catch (workerErr) {
          reject(workerErr);
        }
      });
    } else if (event === 'asset_chunk') {
      const isEn = getLocale() === 'en';
      const roleId = data.role_id;
      const assetId = data.asset_id;
      const modality = data.modality;
      const r2Key = data.r2_key;
      const previewUrl = data.preview_url || `/api/assets/${assetId}?key=${encodeURIComponent(r2Key || '')}`;

      // Stage generated media artifact in current round buffer (committed atomically on turn completion)
      window._currentRoundGeneratedAssets = window._currentRoundGeneratedAssets || [];
      if (!window._currentRoundGeneratedAssets.some(a => (a.assetId || a.id) === assetId)) {
        window._currentRoundGeneratedAssets.push({
          id: assetId,
          assetId: assetId,
          name: data.role_name ? `${data.role_name}_产物.png` : (isEn ? `Generated_${assetId.slice(0, 8)}.png` : `生成资产_${assetId.slice(0, 8)}.png`),
          modality: modality || 'image',
          type: data.mime_type || (modality === 'image' ? 'image/png' : 'audio/wav'),
          mime_type: data.mime_type || (modality === 'image' ? 'image/png' : 'audio/wav'),
          size: data.file_size || 0,
          file_size: data.file_size || 0,
          url: previewUrl,
          previewUrl: previewUrl,
          r2Key: r2Key,
          r2_key: r2Key,
          sourceDigest: `${assetId}-${data.file_size || 0}`,
          origin: 'generated',
          introducedRound: window.chatRoundIndex || 1,
          isNew: false
        });
      }

      // 1. Locate the text container and find its enclosing response wrapper / assistant bubble
      const textEl = document.getElementById('response-text-' + assistantId);
      const outerRow = document.getElementById(assistantId);
      const responseWrapper = textEl?.closest('.chat-response-wrapper') || 
                              outerRow?.querySelector('.chat-response-wrapper') || 
                              outerRow;

      if (responseWrapper) {
        let mediaGallery = responseWrapper.querySelector('.chat-multimodal-gallery');
        if (!mediaGallery) {
          mediaGallery = document.createElement('div');
          mediaGallery.className = 'chat-multimodal-gallery';
          mediaGallery.id = `gallery-${assistantId}`;
          mediaGallery.style.marginTop = '12px';
          mediaGallery.style.marginBottom = '12px';
          mediaGallery.style.display = 'flex';
          mediaGallery.style.flexWrap = 'wrap';
          mediaGallery.style.gap = '8px';

          // Insert gallery right after the text container (before the action buttons) to protect from markdown innerHTML rewrites
          const actionsEl = responseWrapper.querySelector('.chat-response-actions');
          if (actionsEl) {
            responseWrapper.insertBefore(mediaGallery, actionsEl);
          } else {
            responseWrapper.appendChild(mediaGallery);
          }
        }

        if (modality === 'image') {
          const imgCard = document.createElement('div');
          imgCard.className = 'generated-image-card';
          imgCard.style.maxWidth = '360px';
          imgCard.style.borderRadius = '8px';
          imgCard.style.overflow = 'hidden';
          imgCard.style.border = '1px solid var(--border-color, #e2e8f0)';
          imgCard.innerHTML = `
            <img src="${escapeHtml(previewUrl)}" alt="Generated Image" style="width:100%;height:auto;display:block;" loading="lazy" />
            <div style="padding:6px 10px;font-size:11px;color:var(--text-secondary,#64748b);background:var(--bg-secondary,#f8fafc);display:flex;justify-content:space-between;align-items:center;">
              <span>🖼️ ${escapeHtml(data.role_name || (isEn ? 'AI Image' : 'AI 生成图片'))}</span>
              <a href="${escapeHtml(previewUrl)}" target="_blank" download="generated-${assetId.slice(0, 8)}.png" style="color:var(--color-primary,#3b82f6);text-decoration:none;">${isEn ? 'Download' : '下载'}</a>
            </div>
          `;
          mediaGallery.appendChild(imgCard);
        } else if (modality === 'audio') {
          const audioEl = document.createElement('audio');
          audioEl.controls = true;
          audioEl.src = previewUrl;
          audioEl.style.width = '100%';
          mediaGallery.appendChild(audioEl);
        }
      }
    } else if (event === 'text_chunk') {
      const rawChunk = data.chunk || '';
      const cleanChunk = rawChunk.replace(/【执行输出】\s*/g, '');
      const prev = streamingTextBuffers.get(assistantId) || '';
      streamingTextBuffers.set(assistantId, prev + cleanChunk);

      scheduleStreamingMarkdownRender(assistantId);

      if (data.cache_hit) {
        const runCachePill = (currentActiveRunId && document.getElementById('cache-pill-' + currentActiveRunId)) || document.getElementById('cache-stream-pill');
        if (runCachePill) runCachePill.style.display = 'inline-flex';
      }
    } else if (event === 'node_complete') {
      const isEn = getLocale() === 'en';
      const targetNodeId = data.node_id || data.role_id;
      const diag = document.getElementById('preflight-diag-' + currentActiveAssistantId);
      const actualExecutor = document.getElementById('diag-actual-executor-' + currentActiveAssistantId);
      if (diag?.dataset.browserNodeId === targetNodeId && actualExecutor && !data.cache_hit && data.execution_backend) {
        const backend = data.execution_backend === 'workers_ai'
          ? 'Workers AI'
          : (isEn ? 'External inference endpoint' : '外部推理节点');
        actualExecutor.textContent = `✓ ${isEn ? 'Fallback completed on' : '备用算力已完成'} ${backend}: ${data.model_name || data.model_id}`;
        actualExecutor.hidden = false;
      }
      const nodeCard = document.getElementById('dag-node-' + targetNodeId);
      const meta = document.getElementById('node-meta-' + targetNodeId);
      if (nodeCard) {
        nodeCard.classList.remove('running', 'is-parallel-running', 'is-waiting-resource');
        const oldStamp = nodeCard.querySelector('.dag-cache-hit-stamp');
        if (oldStamp) oldStamp.remove();
        nodeCard.classList.remove('cached', 'completed');

        if (data.cache_hit) {
          nodeCard.classList.add('cached');
          const stamp = document.createElement('span');
          stamp.className = 'dag-cache-hit-stamp';
          stamp.textContent = '⚡ HIT';
          nodeCard.appendChild(stamp);
        } else {
          nodeCard.classList.add('completed');
        }
      }
      if (meta) {
        meta.textContent = data.cache_hit ? '⚡ 0ms' : `${data.duration_ms}ms`;
      }
      refreshEvidencePrepGroupSummary();
      requestAnimationFrame(() => renderDagSvgConnectors());

      // Record metrics into activeDagNodes
      const completedNode = activeDagNodes.find(n => (n.node_id || n.role_id) === targetNodeId);
      if (completedNode) {
        completedNode.duration_ms = data.duration_ms;
        completedNode.cache_hit = !!data.cache_hit;
        if (data.output) completedNode.output = data.output;
      }

      // Update Step Indicator Badge with completed status and latency
      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-' + targetNodeId);
        const roleName = isEn 
          ? (data.role_name_en || getCompactRoleName(data.role_id, data.role_name)) 
          : (data.role_name || (activeDagNodes.find(n => (n.node_id || n.role_id) === targetNodeId)?.name_zh) || '节点');
        const timeStr = data.cache_hit ? '⚡ 0ms' : `${data.duration_ms}ms`;
        if (!stepBadge) {
          stepBadge = document.createElement('div');
          stepBadge.id = 'step-badge-' + currentActiveAssistantId + '-' + targetNodeId;
          stepsContainer.appendChild(stepBadge);
        }
        stepBadge.className = 'assistant-step-badge completed';
        stepBadge.innerHTML = `<span class="step-check">✓</span> <span>${escapeHtml(roleName)} ${isEn ? 'Done' : '完成'}</span> <span class="step-time">${timeStr}</span>`;
      }
    } else if (event === 'node_failover') {
      const isEn = getLocale() === 'en';
      const targetNodeId = data.node_id || data.role_id;
      const nodeCard = document.getElementById('dag-node-' + targetNodeId);
      if (nodeCard) {
        const modelEl = document.getElementById('node-model-label-' + targetNodeId) || nodeCard.querySelector('.dag-node-model') || nodeCard.querySelector('.node-model');
        if (modelEl && data.fallback_model) {
          const compactName = isEn ? getCompactModelName(data.fallback_model_id || '', data.fallback_model) : data.fallback_model;
          const isLocal = data.fallback_model_id && data.fallback_model_id.startsWith('browser-');
          modelEl.innerHTML = `${isLocal ? '💻' : '⚙️'} ${escapeHtml(compactName)}`;
        }
      }
      if (data.fallback_model_id && Array.isArray(activeDagNodes)) {
        const targetNode = activeDagNodes.find(n => (n.node_id || n.role_id) === targetNodeId);
        if (targetNode) {
          targetNode.selected_model = {
            ...(targetNode.selected_model || {}),
            model_id: data.fallback_model_id,
            display_name: data.fallback_model || data.fallback_model_id
          };
        }
      }
      if (data.fallback_model_id && targetNodeId) {
        window.originalNodeConfigs = window.originalNodeConfigs || {};
        const prevPrompt = window.originalNodeConfigs[targetNodeId]?.custom_prompt ?? '';
        window.originalNodeConfigs[targetNodeId] = {
          model_id: data.fallback_model_id,
          custom_prompt: prevPrompt
        };
        if (!window.pendingModifiedRoleIds || !window.pendingModifiedRoleIds.has(targetNodeId)) {
          window.activeChosenRoleModels = window.activeChosenRoleModels || {};
          window.activeChosenRoleModels[targetNodeId] = data.fallback_model_id;
        }
        updateNodeDirtyState(targetNodeId);
      }
      const failoverStepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (failoverStepsContainer && data.fallback_model) {
        const failoverBadge = document.createElement('div');
        failoverBadge.className = 'assistant-step-badge warning';
        const fromLabel = data.failed_model || data.failed_model_id || '';
        const toLabel = data.fallback_model;
        failoverBadge.innerHTML = `<span>⚠️</span> <span>${escapeHtml(fromLabel ? `${fromLabel} → ${toLabel}` : toLabel)}</span>`;
        failoverStepsContainer.appendChild(failoverBadge);
      }
      if (typeof showToast === 'function') {
        showToast(isEn ? (data.reason_en || 'Failover to standby node') : (data.reason_zh || '故障转移至备选节点'), 'warning');
      }
    } else if (event === 'security_blocked') {
      if (streamingRafMap.has(assistantId)) {
        cancelAnimationFrame(streamingRafMap.get(assistantId));
        streamingRafMap.delete(assistantId);
      }
      streamingTextBuffers.delete(assistantId);

      const isEn = getLocale() === 'en';
      const duration = data.duration_ms || 24;

      const currentArbPill = (currentActiveRunId && document.getElementById('arb-pill-' + currentActiveRunId)) || arbPill;
      const currentArbText = (currentActiveRunId && document.getElementById('arb-text-' + currentActiveRunId)) || arbText;
      if (currentArbPill) {
        currentArbPill.className = 'telemetry-pill arb-telemetry-pill locked';
        currentArbPill.style.borderColor = '#f59e0b';
        currentArbPill.style.color = '#f59e0b';
      }
      if (currentArbText) {
        currentArbText.textContent = isEn
          ? `🛑 Edge Firewall: Policy Violation Intercepted (${duration}ms · Terminated)`
          : `🛑 安全审计: 违规指令已拦截 (${duration}ms · 拦截执行)`;
      }

      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-firewall');
        if (!stepBadge) {
          stepBadge = document.createElement('div');
          stepBadge.id = 'step-badge-' + currentActiveAssistantId + '-firewall';
          stepsContainer.appendChild(stepBadge);
        }
        stepBadge.className = 'assistant-step-badge completed';
        stepBadge.style.borderColor = 'rgba(245, 158, 11, 0.4)';
        stepBadge.style.color = '#f59e0b';
        stepBadge.innerHTML = `<span style="color:#ef4444;">🛑</span> <span>${isEn ? 'Edge Firewall Policy Intercepted' : '安全合规网关介入拦截'}</span> <span class="step-time">${duration}ms</span>`;
      }

      if (respEl) {
        respEl.innerHTML = `
          <div class="security-guardrail-banner">
            <div class="guardrail-header">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#f59e0b" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
              </svg>
              <span>${isEn ? '⚠️ NanoMesh Safety & Compliance Guardrail' : '⚠️ NanoMesh 安全合规防护'}</span>
            </div>
            <div class="guardrail-body">
              <p style="margin: 0 0 10px 0;">
                ${isEn
                  ? 'Sorry, your instruction was audited by the Edge Firewall and flagged for unauthorized system attacks, weaponized exploits, or intellectual property infringements. Execution has been terminated without consuming compute credits. Please refer to <a href="/terms" target="_blank" class="guardrail-link">NanoMesh Terms of Service</a>.'
                  : '抱歉，您的指令经安全网关审计，涉及未授权系统攻击、入侵工具武器化或侵犯版权等违规行为。该请求已被终止执行，未扣除算力点数。请参阅 <a href="/terms" target="_blank" class="guardrail-link">NanoMesh 服务条款</a>。'
                }
              </p>
              <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                ${isEn
                  ? 'If this was intended for defensive security configurations or academic research, please adjust your phrasing. Continued violations may lead to account suspension.'
                  : '如为您自建环境的防御性安全配置或学术分析，请调整表述明确防御上下文。如果您持续进行违规活动，您的账号可能被暂停。'
                }
              </p>
            </div>
          </div>
        `;
      }

      const actionsEl = document.getElementById('actions-' + assistantId);
      if (actionsEl) actionsEl.style.display = 'none';

      smartScrollToBottom(document.getElementById('chat-messages'));
    } else if (event === 'capability_unreachable') {
      if (streamingRafMap.has(assistantId)) {
        cancelAnimationFrame(streamingRafMap.get(assistantId));
        streamingRafMap.delete(assistantId);
      }
      streamingTextBuffers.delete(assistantId);

      const isEn = getLocale() === 'en';
      const duration = data.duration_ms || 32;

      const currentArbPill = (currentActiveRunId && document.getElementById('arb-pill-' + currentActiveRunId)) || arbPill;
      const currentArbText = (currentActiveRunId && document.getElementById('arb-text-' + currentActiveRunId)) || arbText;
      if (currentArbPill) {
        currentArbPill.className = 'telemetry-pill arb-telemetry-pill locked';
        currentArbPill.style.borderColor = 'rgba(161, 161, 170, 0.4)';
        currentArbPill.style.color = '#a1a1aa';
      }
      if (currentArbText) {
        currentArbText.textContent = isEn
          ? `🛡️ Compute Guard: Fast-Failed (${duration}ms · 100% Saved)`
          : `🛡️ 算力防护: 触发快速熔断 (${duration}ms · 节省算力 100%)`;
      }

      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        let stepBadge = document.getElementById('step-badge-' + currentActiveAssistantId + '-unreachable');
        if (!stepBadge) {
          stepBadge = document.createElement('div');
          stepBadge.id = 'step-badge-' + currentActiveAssistantId + '-unreachable';
          stepsContainer.appendChild(stepBadge);
        }
        stepBadge.className = 'assistant-step-badge completed';
        stepBadge.style.borderColor = 'rgba(161, 161, 170, 0.3)';
        stepBadge.style.color = '#a1a1aa';
        stepBadge.innerHTML = `<span style="color:#71717a;">∅</span> <span>${isEn ? 'Catalog Capability Out of Bounds (Fast-Failed)' : '候选模板胜任度未达标 (Fast-Failed)'}</span> <span class="step-time">${duration}ms</span>`;
      }

      if (respEl) {
        respEl.innerHTML = `
          <div class="capability-guardrail-banner">
            <div class="guardrail-header">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#818cf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
              </svg>
              <span>${isEn ? '∅ Intent Unreachable / Capability Boundary' : '∅ 意图不可达 / 能力边界熔断'}</span>
            </div>
            <div class="guardrail-body">
              <p style="margin: 0 0 10px 0;">
                ${isEn
                  ? 'No workflow template in the current catalog matches your specific intent. NanoMesh is currently specialized in multimodal visual understanding, entity extraction, cross-lingual translation, and structured polishing. The system has fast-failed to protect your compute credits with 0 charges.'
                  : '当前工作流库未检索到能够胜任该业务意图的编排链路。NanoMesh 目前专精于多模态图文解析、实体信息抽取、跨语言重构与结构化表达润色。系统已在极短时间内快速熔断本轮执行，未消耗您的任何算力点数。'
                }
              </p>
              <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                ${isEn
                  ? '*(Tip: Try uploading multimodal materials or refining your text analysis goals)*'
                  : '*(建议：您可以尝试上传多模态图文材料，或细化您在文字润色、文档抽取方面的诉求)*'
                }
              </p>
            </div>
          </div>
        `;
      }

      const actionsEl = document.getElementById('actions-' + assistantId);
      if (actionsEl) actionsEl.style.display = 'none';

    } else if (event === 'dag_complete') {
      const awaitsClientTailCommit =
        data.tail_requires_client_commit !== undefined
          ? !!data.tail_requires_client_commit
          : (!!data.has_client_exec && !!window._activeLocalRunnerPromise);
      if (awaitsClientTailCommit && window._activeLocalRunnerPromise) {
        // Handed off to browser local worker; keep workflow locked until local worker + /commit finishes!
        return;
      }
      const isFastFailed = !!(data.is_security_violation || data.is_unreachable);
      const commitFailed = !isFastFailed && data.state_committed === false;
      const awaitsRetryResolution = commitFailed && !!data.can_retry_commit;
      if (awaitsRetryResolution) {
        setAwaitingCommitResolutionState(true, {
          run_id: data.run_id || window._activeServerRunId || currentActiveRunId,
          exec_owner: 'CLOUD',
          can_retry_commit: true
        });
      } else {
        setAwaitingCommitResolutionState(false);
      }
      const sink = document.getElementById('dag-sink-anchor');
      if (sink) {
        sink.classList.remove('is-executing');
        if (!awaitsRetryResolution) {
          sink.classList.add('completed');
        }
      }
      requestAnimationFrame(() => renderDagSvgConnectors());

      if (streamingRafMap.has(assistantId)) {
        cancelAnimationFrame(streamingRafMap.get(assistantId));
        streamingRafMap.delete(assistantId);
      }

      if (data.is_clarification_required) {
        return;
      }

      window._isCurrentTurnRolledBack = isFastFailed || commitFailed;

      const rawFinal = isFastFailed
        ? ''
        : (data.final_output || streamingTextBuffers.get(assistantId) || (respEl ? respEl.textContent.trim() : ''));
      const finalAssistantOutput = sanitizePromptLeakage(rawFinal);
      streamingTextBuffers.delete(assistantId);

      if (isFastFailed) {
        rollbackTurnToPreFlight();
        window.lastHadMedia = (window.sessionAssets || []).some(a => {
          const m = a.modality || (a.type && a.type.startsWith('image/') ? 'image' : (a.type && a.type.startsWith('audio/') ? 'audio' : ''));
          return m === 'image' || m === 'audio';
        });
      } else if (commitFailed) {
        if (!data.can_retry_commit) {
          rollbackTurnToPreFlight();
        } else {
          rollbackStagedCanvasDraft();
        }
      } else {
        if (window._currentRoundFrozenInput) {
          window._currentRoundFrozenInput.failedAssistantId = null;
        }
        commitStagedCanvasDraft(data.nodes || activeDagNodes);
      }

      // Render clean Markdown if marked is available (skip if fast-failed to protect banner)
      if (!isFastFailed && respEl && finalAssistantOutput) {
        respEl.innerHTML = safeRenderMarkdown(finalAssistantOutput);

        const actionsEl = document.getElementById('actions-' + assistantId);
        if (actionsEl) actionsEl.classList.add('is-visible');
      }

      const totalNodes = activeDagNodes.length || 1;
      const anyCached = activeDagNodes.some(n => n.cache_hit);
      const costStr = isFastFailed ? '0' : (data.total_cost !== undefined ? String(data.total_cost) : (anyCached ? '35' : '120'));
      const durStr = data.total_duration_ms ? (data.total_duration_ms / 1000).toFixed(1) + 's' : '2.8s';
      const promptText = window.lastUserPrompt || userPrompt || '';

      const stepsList = [];
      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        stepsContainer.querySelectorAll('.assistant-step-badge').forEach(b => {
          stepsList.push({
            html: b.innerHTML,
            className: b.className
          });
        });
      }

      const buildRoundRecord = (revNum, runIdForRound, baseRunIdForRound) => ({
        runId: runIdForRound,
        baseRunId: baseRunIdForRound,
        revision: revNum,
        isReRun: Boolean(revNum > 1),
        roundIndex: window.chatRoundIndex || 1,
        userPrompt: promptText,
        assets: window.currentRoundAssets || [],
        targetLanguage: window._currentRoundFrozenInput?.targetLanguage || window._lastChatEnvelope?.constraint_context?.target_language || (localStorage.getItem('nanomesh_lang') || 'auto'),
        outputStyle: window._currentRoundFrozenInput?.outputStyle || window._lastChatEnvelope?.constraint_context?.output_style || (localStorage.getItem('nanomesh_style') || 'concise'),
        assistantOutput: finalAssistantOutput,
        template: window.currentRunningTemplateObj || (currentCandidateTemplates.find(t => t.template_id === window.currentRunningTemplateId)) || null,
        candidateTemplates: currentCandidateTemplates || [],
        nodes: JSON.parse(JSON.stringify(activeDagNodes || [])),
        steps: stepsList,
        intentState: window.currentRoundIntentState || null,
        branchId: window.activeBranchId,
        resolvedPlan: window._currentRoundFrozenInput?.frozenResolvedPlan || null,
        isFastFailed: isFastFailed,
        cost: costStr,
        duration: durStr,
        cached: anyCached,
        timestamp: Date.now()
      });

      if (commitFailed && respEl) {
        const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
        const banner = document.createElement('div');
        banner.className = 'dag-execution-error-banner';
        banner.style.cssText = 'color:#f59e0b; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.35); padding:10px 14px; border-radius:8px; margin-top:10px; font-size:0.86rem;';
        banner.innerHTML = `<div>⚠️ ${escapeHtml(data.commit_error || (isEn ? 'Execution completed, but session state could not be saved.' : '计算已完成，但状态持久化失败（未提交到本地会话树）。'))}</div>`;
        if (data.can_retry_commit && data.run_id && window.chatSessionId) {
          const btnRow = document.createElement('div');
          btnRow.style.cssText = 'display:flex; gap:8px; margin-top:8px; flex-wrap:wrap;';
          const retryBtn = document.createElement('button');
          retryBtn.type = 'button';
          retryBtn.className = 'chat-action-btn';
          retryBtn.style.cssText = 'padding:4px 10px;';
          retryBtn.textContent = isEn ? 'Retry Save' : '重试提交状态';
          const abandonBtn = document.createElement('button');
          abandonBtn.type = 'button';
          abandonBtn.className = 'chat-action-btn';
          abandonBtn.style.cssText = 'padding:4px 10px; color:#ef4444;';
          abandonBtn.textContent = isEn ? 'Abandon Result' : '放弃此结果';
          retryBtn.onclick = async () => {
            retryBtn.disabled = true;
            abandonBtn.disabled = true;
            try {
              const r = await fetch('/api/session/' + encodeURIComponent(window.chatSessionId) + '/commit-retry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ run_id: data.run_id })
              });
              if (r.ok) {
                const snap = await r.json().catch(() => null);
                banner.remove();
                window._isCurrentTurnRolledBack = false;
                setAwaitingCommitResolutionState(false);
                if (window._currentRoundFrozenInput?.candidateRevision) {
                  window._currentRoundFrozenInput.committedRevision = window._currentRoundFrozenInput.candidateRevision;
                  window._currentRoundFrozenInput.revision = window._currentRoundFrozenInput.committedRevision;
                  window._currentRoundFrozenInput.candidateRevision = null;
                }
                if (snap) hydrateGitStateFromServer(snap);
                if (Array.isArray(window.currentRoundAssets)) {
                  window.currentRoundAssets.forEach(a => { a.isNew = false; });
                }
                if (window._currentRoundFrozenInput && Array.isArray(window._currentRoundFrozenInput.frozenAssets)) {
                  window._currentRoundFrozenInput.frozenAssets.forEach(a => { a.isNew = false; });
                }
                window._currentStagedNewFiles = [];
                const revAfter = window._currentRoundFrozenInput?.committedRevision || 1;
                const bRun = window._currentRoundFrozenInput?.baseRunId || data.run_id;
                saveTraceToHistory({
                  sessionId: window.chatSessionId,
                  title: promptText.slice(0, 30) || '多模态任务编排',
                  cost: costStr,
                  duration: durStr,
                  nodesCount: totalNodes,
                  cached: anyCached,
                  gitStateSnapshot: JSON.parse(JSON.stringify(window.gitState || createEmptyGitState())),
                  round: buildRoundRecord(revAfter, data.run_id, bRun)
                });
              } else {
                const retryError = await r.json().catch(() => ({}));
                retryBtn.disabled = false;
                abandonBtn.disabled = false;
                if (retryError.awaiting_commit === true) banner.appendChild(abandonBtn);
                else abandonBtn.remove();
              }
            } catch {
              retryBtn.disabled = false;
              abandonBtn.disabled = false;
            }
          };
          abandonBtn.onclick = async () => {
            retryBtn.disabled = true;
            abandonBtn.disabled = true;
            const abRes = await abandonPendingCommit(data.run_id);
            if (abRes?.ok) {
              banner.remove();
              if (!abRes.alreadyCommitted && respEl) {
                respEl.innerHTML = `<div class="dag-execution-error-banner" style="color:#6b7280; background:rgba(107,114,128,0.1); border:1px solid rgba(107,114,128,0.3); padding:10px 14px; border-radius:8px; margin-top:8px; font-size:0.86rem;">ℹ️ ${isEn ? 'Pending result abandoned. Restored to previous saved commit.' : '已放弃未保存结果，已回滚至上一成功基线。'}</div>`;
              }
            } else {
              retryBtn.disabled = false;
              abandonBtn.disabled = false;
            }
          };
          btnRow.appendChild(retryBtn);
          btnRow.appendChild(abandonBtn);
          banner.appendChild(btnRow);
        }
        respEl.appendChild(banner);
        return;
      }

      const scrollContainer = document.getElementById('chat-messages');
      if (scrollContainer) scrollContainer.scrollTop = scrollContainer.scrollHeight;

      let committedRev = 1;
      if (window._currentRoundFrozenInput) {
        if (!isFastFailed && window._currentRoundFrozenInput.candidateRevision) {
          window._currentRoundFrozenInput.committedRevision = window._currentRoundFrozenInput.candidateRevision;
          window._currentRoundFrozenInput.revision = window._currentRoundFrozenInput.committedRevision;
          window._currentRoundFrozenInput.candidateRevision = null;
        }
        committedRev = window._currentRoundFrozenInput.committedRevision || window._currentRoundFrozenInput.revision || 1;
      }
      const isReRun = Boolean(committedRev > 1);
      const committedRunId = data.run_id || window._activeServerRunId || currentActiveRunId || ('run-' + Date.now());
      const baseRunId = window._currentRoundFrozenInput?.baseRunId || committedRunId;

      if (!isFastFailed && !awaitsClientTailCommit) {
        if (Array.isArray(window.currentRoundAssets)) {
          window.currentRoundAssets.forEach(a => { a.isNew = false; });
        }
        if (window._currentRoundFrozenInput && Array.isArray(window._currentRoundFrozenInput.frozenAssets)) {
          window._currentRoundFrozenInput.frozenAssets.forEach(a => { a.isNew = false; });
        }
        window._currentStagedNewFiles = [];
        if (data.authoritative_git_state) {
          hydrateGitStateFromServer(data.authoritative_git_state);
        } else if (isReRun) {
          recordCanvasRevisionUpdate({
            baseRunId,
            revision: committedRev,
            finalOutput: finalAssistantOutput,
            perceptualEntries: data.perceptual_entries || []
          });
        } else {
          commitTurnTransaction({
            runId: committedRunId,
            revision: committedRev,
            userPrompt: promptText,
            finalOutput: finalAssistantOutput,
            perceptualEntries: data.perceptual_entries || [],
            trace: window._pendingRoundTrace
          });
        }
      }
      const gitSnap = !isFastFailed
        ? JSON.parse(JSON.stringify(window.gitState || createEmptyGitState()))
        : null;

      const currentRoundData = buildRoundRecord(committedRev, committedRunId, baseRunId);

      saveTraceToHistory({
        sessionId: window.chatSessionId,
        title: promptText.slice(0, 30) || '多模态任务编排',
        cost: costStr,
        duration: durStr,
        nodesCount: totalNodes,
        cached: anyCached,
        gitStateSnapshot: gitSnap,
        round: currentRoundData
      });
    } else if (event === 'dag_error') {
      rollbackTurnToPreFlight();
      if (window._currentRoundFrozenInput && assistantId === currentActiveAssistantId) {
        window._currentRoundFrozenInput.failedAssistantId = assistantId;
      }
      setWorkflowExecutionLocked(false);
      requestAnimationFrame(() => renderDagSvgConnectors());
      if (streamingRafMap.has(assistantId)) {
        cancelAnimationFrame(streamingRafMap.get(assistantId));
        streamingRafMap.delete(assistantId);
      }
      streamingTextBuffers.delete(assistantId);

      const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
      const errText = data.error || (isEn ? 'Workflow execution interrupted' : '工作流执行异常中断');
      if (respEl) {
        respEl.innerHTML = `<div class="dag-execution-error-banner" style="color:#ef4444; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:10px 14px; border-radius:8px; margin-top:8px; font-size:0.88rem;">
          <div style="font-weight:600; margin-bottom:4px;">⚠️ ${isEn ? 'Task Interrupted' : '任务执行中断'}</div>
          <div>${escapeHtml(errText)}</div>
        </div>`;
      }
      // Remove running spinner from any active node card and mark as error
      document.querySelectorAll('.dag-node-card.running, .dag-node-card.is-parallel-running').forEach(card => {
        card.classList.remove('running', 'is-parallel-running');
        card.classList.add('error');
        const targetNodeId = card.getAttribute('data-node-id') || card.getAttribute('data-role-id');
        const meta = document.getElementById('node-meta-' + targetNodeId);
        if (meta) meta.textContent = isEn ? 'Aborted' : '异常中断';
      });
      // Update step badge to error
      const stepsContainer = document.getElementById('assistant-steps-' + currentActiveAssistantId);
      if (stepsContainer) {
        const runningBadge = stepsContainer.querySelector('.assistant-step-badge.running');
        if (runningBadge) {
          runningBadge.className = 'assistant-step-badge error';
          runningBadge.innerHTML = `<span style="color:#ef4444">⚠️</span> <span style="color:#ef4444">${isEn ? 'Aborted' : '执行中断'}</span>`;
        }
      }
    }
  }

  // Close dropdowns & popovers on outside click
  document.addEventListener('click', (e) => {
    const macroDropdown = document.getElementById('macro-dropdown');
    if (macroDropdown && !e.target.closest('#macro-capsule-btn') && !e.target.closest('#macro-dropdown')) {
      macroDropdown.style.display = 'none';
    }
    const inspector = document.getElementById('node-inspector-popover');
    if (inspector && !e.target.closest('#node-inspector-popover') && !e.target.closest('.dag-node-card')) {
      if (inspector.style.display !== 'none') {
        if (currentInspectedNodeRoleId) {
          const selectEl = document.getElementById('inspector-model-select');
          const promptEl = document.getElementById('inspector-prompt-input');
          if (selectEl && promptEl) {
            window.activeCustomRolePrompts = window.activeCustomRolePrompts || {};
            window.activeCustomRolePrompts[currentInspectedNodeRoleId] = promptEl.value.trim();
            window.activeChosenRoleModels = window.activeChosenRoleModels || {};
            window.activeChosenRoleModels[currentInspectedNodeRoleId] = selectEl.value;
            updateNodeDirtyState(currentInspectedNodeRoleId);
          }
          currentInspectedNodeRoleId = null;
        }
        inspector.style.display = 'none';
      }
    }
  });

  // Typewriter effect for card prompt injection
  let typewriterTimer = null;

  function typewriteIntoInput(text) {
    const input = document.getElementById('chat-input');
    if (!input || !text) return;

    if (typewriterTimer) {
      clearInterval(typewriterTimer);
      typewriterTimer = null;
    }

    input.value = '';
    input.focus();
    let idx = 0;
    // Smooth, snappy typing speed (~12ms per char)
    const speed = 12;

    typewriterTimer = setInterval(() => {
      if (idx < text.length) {
        input.value += text[idx];
        idx++;
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 180) + 'px';
        if (typeof updateEstimation === 'function') updateEstimation();
      } else {
        clearInterval(typewriterTimer);
        typewriterTimer = null;
        input.focus();
        input.selectionStart = input.selectionEnd = input.value.length;
      }
    }, speed);
  }

  // Clear typewriter if user starts manual typing
  document.getElementById('chat-input')?.addEventListener('input', () => {
    if (typewriterTimer) {
      clearInterval(typewriterTimer);
      typewriterTimer = null;
    }
  });

  // Stage 1: Bind Suggested Prompt Cards Click Handler (Typewriter fill only, submit enters console)
  document.querySelectorAll('.suggested-prompts-grid .prompt-card').forEach(card => {
    card.addEventListener('click', (e) => {
      e.stopPropagation();
      const promptKey = card.getAttribute('data-i18n-prompt');
      let prompt = '';
      if (promptKey && typeof t === 'function') {
        const translated = t(promptKey);
        if (translated && translated !== promptKey) {
          prompt = translated;
        }
      }
      if (!prompt) {
        prompt = card.getAttribute('data-prompt') || '';
      }
      if (prompt) {
        typewriteIntoInput(prompt);
      }
    });
  });

  // Responsive Mobile Tab Switcher (< 1024px)
  const tabBtnCanvas = document.getElementById('tab-btn-canvas');
  const tabBtnStream = document.getElementById('tab-btn-stream');
  const canvasPane = document.getElementById('workbench-canvas-pane');
  const streamPane = document.getElementById('stream-terminal-pane');

  if (tabBtnCanvas && tabBtnStream) {
    tabBtnCanvas.onclick = () => {
      tabBtnCanvas.classList.add('active');
      tabBtnStream.classList.remove('active');
      canvasPane?.classList.add('tab-active');
      streamPane?.classList.remove('tab-active');
      requestAnimationFrame(() => renderDagSvgConnectors());
      setTimeout(() => renderDagSvgConnectors(), 50);
      setTimeout(() => renderDagSvgConnectors(), 200);
    };
    tabBtnStream.onclick = () => {
      tabBtnStream.classList.add('active');
      tabBtnCanvas.classList.remove('active');
      streamPane?.classList.add('tab-active');
      canvasPane?.classList.remove('tab-active');
    };
  }

  // Initialize Stage 5 History Drawer & Console Back Button & Macro Reroute Button & Observers
  initHistoryDrawer();
  initConsoleBackButton();
  initMacroRerouteButton();
  initDagResizeObserver();
  initContextConstraintsPopover();
  initLocalInferenceToggle();
  initMessageCopyHandler();

  // Stage 4: Context Constraints Settings Popover Logic (Language & Style)
  function initContextConstraintsPopover() {
    const settingsBtn = document.getElementById('settings-btn');
    const settingsMenu = document.getElementById('settings-menu');
    const popoverWrapper = document.getElementById('settings-popover-wrapper');
    const langTrigger = document.getElementById('lang-trigger');
    const langOptions = document.getElementById('lang-options');
    const langDisplay = document.getElementById('lang-display');
    const styleTrigger = document.getElementById('style-trigger');
    const styleOptions = document.getElementById('style-options');
    const styleDisplay = document.getElementById('style-display');

    if (!settingsBtn || !settingsMenu) return;

    // Load initial preferences
    const savedLang = localStorage.getItem('nanomesh_lang') || 'auto';
    const savedStyle = localStorage.getItem('nanomesh_style') || 'concise';

    function updateLangDisplay(val) {
      if (!langDisplay) return;
      const opt = langOptions?.querySelector(`.select-option[data-value="${val}"]`);
      if (opt) {
        langDisplay.textContent = opt.textContent;
        const i18nKey = opt.getAttribute('data-i18n');
        if (i18nKey) langDisplay.setAttribute('data-i18n', i18nKey);
      }
    }

    function updateStyleDisplay(val) {
      if (!styleDisplay) return;
      const opt = styleOptions?.querySelector(`.select-option[data-value="${val}"]`);
      if (opt) {
        styleDisplay.textContent = opt.textContent;
        const i18nKey = opt.getAttribute('data-i18n');
        if (i18nKey) styleDisplay.setAttribute('data-i18n', i18nKey);
      }
    }

    updateLangDisplay(savedLang);
    updateStyleDisplay(savedStyle);

    // Toggle popover visibility
    settingsBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = settingsMenu.style.display !== 'none';
      if (isVisible) {
        settingsMenu.style.display = 'none';
        settingsBtn.classList.remove('active');
      } else {
        settingsMenu.style.display = 'flex';
        settingsBtn.classList.add('active');
      }
      if (langOptions) langOptions.style.display = 'none';
      if (styleOptions) styleOptions.style.display = 'none';
    });

    // Language dropdown toggle
    if (langTrigger && langOptions) {
      langTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = langOptions.style.display === 'block';
        langOptions.style.display = isOpen ? 'none' : 'block';
        if (styleOptions) styleOptions.style.display = 'none';
      });

      langOptions.querySelectorAll('.select-option').forEach(opt => {
        opt.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = opt.getAttribute('data-value') || 'auto';
          localStorage.setItem('nanomesh_lang', val);
          updateLangDisplay(val);
          langOptions.style.display = 'none';
        });
      });
    }

    // Style dropdown toggle
    if (styleTrigger && styleOptions) {
      styleTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = styleOptions.style.display === 'block';
        styleOptions.style.display = isOpen ? 'none' : 'block';
        if (langOptions) langOptions.style.display = 'none';
      });

      styleOptions.querySelectorAll('.select-option').forEach(opt => {
        opt.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = opt.getAttribute('data-value') || 'auto';
          localStorage.setItem('nanomesh_style', val);
          updateStyleDisplay(val);
          styleOptions.style.display = 'none';
        });
      });
    }

    // Close on click outside
    document.addEventListener('click', (e) => {
      if (popoverWrapper && !popoverWrapper.contains(e.target)) {
        settingsMenu.style.display = 'none';
        settingsBtn.classList.remove('active');
        if (langOptions) langOptions.style.display = 'none';
        if (styleOptions) styleOptions.style.display = 'none';
      } else {
        // Clicked inside wrapper but outside specific select
        if (langOptions && !document.getElementById('lang-custom-select')?.contains(e.target)) {
          langOptions.style.display = 'none';
        }
        if (styleOptions && !document.getElementById('style-custom-select')?.contains(e.target)) {
          styleOptions.style.display = 'none';
        }
      }
    });
  }

  // Stage 4.5: Local Model Inference Toggle Button Logic (Disable Local Inference)
  window.disableLocalInference = localStorage.getItem('nanomesh_disable_local_inference') === 'true';

  function updateLocalInferenceToggleUI() {
    window.updateLocalInferenceToggleUI = updateLocalInferenceToggleUI;
    const btn = document.getElementById('local-inference-toggle-btn');
    if (!btn) return;
    const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
    const enabledSvg = btn.querySelector('.icon-local-enabled');
    const disabledSvg = btn.querySelector('.icon-local-disabled');

    if (window.disableLocalInference) {
      btn.classList.add('is-disabled-local', 'active');
      btn.setAttribute('title', isEn 
        ? (typeof t === 'function' ? t('chat.local_inference.disabled_tip') : 'Local inference disabled (Cloud only, click to enable)')
        : (typeof t === 'function' ? t('chat.local_inference.disabled_tip') : '已开启：不使用本地模型推理（强制仅使用云端模型，点击恢复）'));
      if (enabledSvg) enabledSvg.style.display = 'none';
      if (disabledSvg) disabledSvg.style.display = 'block';
    } else {
      btn.classList.remove('is-disabled-local', 'active');
      btn.setAttribute('title', isEn 
        ? (typeof t === 'function' ? t('chat.local_inference.enabled_tip') : 'Local inference enabled (Click to disable)')
        : (typeof t === 'function' ? t('chat.local_inference.enabled_tip') : '端侧本地推理已启用（点击开启：不使用本地模型推理）'));
      if (enabledSvg) enabledSvg.style.display = 'block';
      if (disabledSvg) disabledSvg.style.display = 'none';
    }
  }

  function initLocalInferenceToggle() {
    const btn = document.getElementById('local-inference-toggle-btn');
    if (!btn) return;
    updateLocalInferenceToggleUI();

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      window.disableLocalInference = !window.disableLocalInference;
      localStorage.setItem('nanomesh_disable_local_inference', window.disableLocalInference ? 'true' : 'false');
      updateLocalInferenceToggleUI();

      const isEn = (typeof getLocale === 'function' ? getLocale() : 'zh') === 'en';
      const msg = window.disableLocalInference
        ? (typeof t === 'function' ? t('chat.local_inference.toast_disabled') : (isEn ? 'Local inference disabled (Cloud only)' : '已开启：不使用本地模型推理（仅云端调度）'))
        : (typeof t === 'function' ? t('chat.local_inference.toast_enabled') : (isEn ? 'Local inference enabled' : '已恢复：允许本地模型推理'));
      localToast(msg, 'info');
    });
  }

  // Stage 6: Chat Message Bubble Copy Handler (User & Assistant)
  function initMessageCopyHandler() {
    const messagesFlow = document.getElementById('messages-flow');
    if (!messagesFlow) return;

    messagesFlow.addEventListener('click', (e) => {
      const copyBtn = e.target.closest('.copy-btn, .chat-bubble-copy-btn, .chat-action-btn');
      if (!copyBtn) return;
      e.stopPropagation();

      let targetText = '';
      const userBubble = copyBtn.closest('.chat-bubble-user');
      if (userBubble) {
        const textEl = userBubble.querySelector('.chat-user-text');
        targetText = textEl ? textEl.innerText.trim() : '';
      } else {
        const responseWrapper = copyBtn.closest('.chat-response-wrapper') || copyBtn.closest('.chat-bubble-assistant');
        if (responseWrapper) {
          const textEl = responseWrapper.querySelector('.chat-response-text');
          targetText = textEl ? textEl.innerText.trim() : '';
        }
      }

      if (!targetText || targetText.startsWith('⚡ NanoMesh 调度执行中') || targetText.startsWith('⚡ NanoMesh Orchestrating')) return;

      const isEn = getLocale() === 'en';
      const onCopied = () => {
        const copyIcon = copyBtn.querySelector('.copy-icon');
        const checkIcon = copyBtn.querySelector('.check-icon');
        const btnText = copyBtn.querySelector('.btn-text');
        if (copyIcon && checkIcon) {
          copyIcon.style.display = 'none';
          checkIcon.style.display = 'block';
          if (btnText) btnText.textContent = isEn ? 'Copied' : '已复制';
          copyBtn.classList.add('copied');
          setTimeout(() => {
            copyIcon.style.display = 'block';
            checkIcon.style.display = 'none';
            if (btnText) btnText.textContent = isEn ? 'Copy' : '复制';
            copyBtn.classList.remove('copied');
          }, 1500);
        }
      };

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(targetText).then(onCopied).catch(() => {
          fallbackCopyText(targetText, onCopied);
        });
      } else {
        fallbackCopyText(targetText, onCopied);
      }
    });
  }

  function fallbackCopyText(text, cb) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.top = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
      document.execCommand('copy');
      if (cb) cb();
    } catch (err) {
      console.error('Fallback copy failed', err);
    }
    document.body.removeChild(ta);
  }

  // Bind Send button & Enter key (with Button Morphing operational closure)
  document.getElementById('send-btn').addEventListener('click', () => {
    if (isWorkflowExecuting || isAwaitingCommitResolution) return;
    if (window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.size > 0) {
      applyPendingCanvasChanges();
      return;
    }
    sendChatMessage();
  });
  document.getElementById('chat-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (isWorkflowExecuting || isAwaitingCommitResolution) return;
      if (window.pendingModifiedRoleIds && window.pendingModifiedRoleIds.size > 0) {
        applyPendingCanvasChanges();
        return;
      }
      sendChatMessage();
    }
  });


  // Credits Dropdown
  const creditsMenuBtn = document.getElementById('credits-menu-btn');
  const creditsMenu = document.getElementById('credits-menu');
  if (creditsMenuBtn && creditsMenu) {
    creditsMenuBtn.addEventListener('click', (e) => {
      // Prevent triggering if clicked inside menu
      if (!creditsMenu.contains(e.target)) {
        creditsMenu.style.display = creditsMenu.style.display === 'none' ? 'block' : 'none';
      }
    });
    document.addEventListener('click', (e) => {
      if (!creditsMenuBtn.contains(e.target)) creditsMenu.style.display = 'none';
    });
  }

  // Upload Popover
  const attachBtn = document.getElementById('attach-btn');
  const attachMenu = document.getElementById('attach-menu');
  if (attachBtn && attachMenu) {
    attachBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      attachBtn.classList.toggle('active');
      attachMenu.style.display = attachMenu.style.display === 'none' ? 'flex' : 'none';
    });
    document.addEventListener('click', (e) => {
      if (!attachBtn.contains(e.target) && !attachMenu.contains(e.target)) {
        attachBtn.classList.remove('active');
        attachMenu.style.display = 'none';
      }
    });
  }

  // Auto-resize textarea & Cost Estimation
  const chatInput = document.getElementById('chat-input');
  function updateEstimation() {
    if (!chatInput) return;
    const textLen = chatInput.value.length;
    const filesCount = selectedFiles ? selectedFiles.length : 0;
    const est = Math.max(0, Math.ceil(textLen / 50)) + (filesCount * 15);
    const estEl = document.getElementById('est-cost');
    if (estEl && typeof t === 'function') {
      estEl.textContent = t('chat.estCost', { n: est });
    }
  }

  if (chatInput) {
    chatInput.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = (this.scrollHeight) + 'px';
      updateEstimation();
    });
  }

  // --- Settings Modal Logic ---
  const personalSettingsBtn = document.getElementById('settings-menu-btn');
  const settingsModalOverlay = document.getElementById('settings-modal-overlay');
  const settingsCloseBtn = document.getElementById('settings-close-btn');

  if (personalSettingsBtn && settingsModalOverlay && settingsCloseBtn) {
    personalSettingsBtn.addEventListener('click', () => {
      window.openSettingsModal('account');
    });

    settingsCloseBtn.addEventListener('click', () => {
      settingsModalOverlay.style.display = 'none';
    });

    // Close on overlay click
    settingsModalOverlay.addEventListener('click', (e) => {
      if (e.target === settingsModalOverlay) {
        settingsModalOverlay.style.display = 'none';
      }
    });

    // Tab Switching
    document.querySelectorAll('.settings-nav-item').forEach(item => {
      item.addEventListener('click', () => {
        // Remove active class from all nav items
        document.querySelectorAll('.settings-nav-item').forEach(nav => nav.classList.remove('active'));
        // Add active class to clicked item
        item.classList.add('active');

        // Hide all panes
        document.querySelectorAll('.settings-tab-pane').forEach(pane => pane.classList.remove('active'));
        
        // Show target pane
        const tabId = item.getAttribute('data-tab');
        document.getElementById('settings-tab-' + tabId).classList.add('active');
        if (tabId === 'account') { 
          if (window.refreshOAuthBindings) window.refreshOAuthBindings(); 
          if (window.refreshPasskeys) window.refreshPasskeys();
        }
        if (tabId === 'billing') { if (window.loadBillingLedger) window.loadBillingLedger(window.currentBillingFilter || 'all'); }
        if (tabId === 'messages') { if (window.loadMessagesTab) window.loadMessagesTab('all'); }
      });
    });

    // Sub-tab switching for Billing
    document.querySelectorAll('.settings-tab-sub').forEach(subItem => {
      subItem.addEventListener('click', () => {
        document.querySelectorAll('.settings-tab-sub').forEach(el => el.classList.remove('active'));
        subItem.classList.add('active');
      });
    });

    // Profile UI Interactions
    const usernameInput = document.getElementById('settings-username-input');
    const saveUsernameBtn = document.getElementById('save-username-btn');
    if (usernameInput && saveUsernameBtn && user) {
      usernameInput.addEventListener('input', () => {
        if (usernameInput.value.trim() !== user.username && usernameInput.value.trim() !== '') {
          saveUsernameBtn.disabled = false;
          saveUsernameBtn.classList.add('btn-primary');
          saveUsernameBtn.classList.remove('btn-outline');
        } else {
          saveUsernameBtn.disabled = true;
          saveUsernameBtn.classList.remove('btn-primary');
          saveUsernameBtn.classList.add('btn-outline');
        }
      });
    }
    
    // Avatar Upload Logic
    const avatarInput = document.getElementById('avatar-upload-input');
    const avatarBtn = document.getElementById('avatar-upload-btn');
    if (avatarInput && user) {
      avatarInput.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        
        avatarBtn.style.opacity = '0.5';
        avatarBtn.style.pointerEvents = 'none';
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
          const res = await fetch('/api/user/avatar', {
            method: 'POST',
            body: formData
          });
          const data = await res.json();
          if (!res.ok) {
            localToast(t(data.error || 'error.uploadFailed'));
          } else {
            localToast(t('success.avatarUpdated'), 'success');
            // Update preview
            document.getElementById('settings-avatar-preview').src = data.avatar_url;
            const dropdownImg = document.getElementById('dropdown-avatar-img');
            if(dropdownImg) {
              dropdownImg.src = data.avatar_url;
              dropdownImg.style.display = 'block';
              document.getElementById('dropdown-avatar-text').style.display = 'none';
            }
            const headerAvatar = document.getElementById('user-avatar');
            if (headerAvatar) {
              headerAvatar.innerHTML = `<img src="${escapeHtml(data.avatar_url)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
            }
            avatarInput.value = ''; // Reset
            
            // Also disable it until next reload (or simulate 24h)
            avatarBtn.style.opacity = '0.5';
            avatarBtn.style.pointerEvents = 'none';
            avatarBtn.title = t('error.avatarCooldown');
            return; // Skip the 'finally' block re-enabling it
          }
        } catch (err) {
          localToast(t('error.networkError'));
        }
        
        avatarBtn.style.opacity = '1';
        avatarBtn.style.pointerEvents = 'auto';
      });
    }

    // Security Accordion
    const togglePasswordBtn = document.getElementById('toggle-password-btn');
    const passwordAccordion = document.getElementById('password-accordion');
    const cancelPasswordBtn = document.getElementById('cancel-password-btn');
    
    if (togglePasswordBtn && passwordAccordion && cancelPasswordBtn) {
      togglePasswordBtn.addEventListener('click', () => {
        passwordAccordion.classList.add('active');
        togglePasswordBtn.style.display = 'none';
      });
      cancelPasswordBtn.addEventListener('click', () => {
        passwordAccordion.classList.remove('active');
        togglePasswordBtn.style.display = 'block';
        // Clear inputs
        document.getElementById('settings-old-password').value = '';
        const np = document.getElementById('settings-new-password');
        const cp = document.getElementById('settings-confirm-password');
        if (np) { np.value = ''; np.type = 'password'; }
        if (cp) { cp.value = ''; cp.type = 'password'; }
        const tnp = document.getElementById('toggle-new-pwd-btn');
        const tcp = document.getElementById('toggle-confirm-pwd-btn');
        const eyeOpenSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
        if (tnp) tnp.innerHTML = eyeOpenSvg;
        if (tcp) tcp.innerHTML = eyeOpenSvg;
      });

      const generatePwdBtn = document.getElementById('generate-pwd-btn');
      const toggleNewPwdBtn = document.getElementById('toggle-new-pwd-btn');
      const toggleConfirmPwdBtn = document.getElementById('toggle-confirm-pwd-btn');
      const newPwdInput = document.getElementById('settings-new-password');
      const confirmPwdInput = document.getElementById('settings-confirm-password');
      const eyeOpenSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
      const eyeClosedSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"></path></svg>';

      if (generatePwdBtn) {
        generatePwdBtn.addEventListener('click', () => {
          let randStr = '';
          const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
          const numbers = '0123456789';
          const all = letters + numbers;
          randStr += letters[Math.floor(Math.random() * letters.length)];
          randStr += numbers[Math.floor(Math.random() * numbers.length)];
          for(let i=0; i<10; i++) randStr += all[Math.floor(Math.random() * all.length)];
          randStr = randStr.split('').sort(() => 0.5 - Math.random()).join('');
          if (newPwdInput) {
            newPwdInput.value = randStr;
            newPwdInput.type = 'text'; // Show it to user!
            if (toggleNewPwdBtn) toggleNewPwdBtn.innerHTML = eyeClosedSvg;
            newPwdInput.dispatchEvent(new Event('input'));
          }
          if (confirmPwdInput) {
            confirmPwdInput.value = randStr;
            confirmPwdInput.type = 'text';
            if (toggleConfirmPwdBtn) toggleConfirmPwdBtn.innerHTML = eyeClosedSvg;
            confirmPwdInput.dispatchEvent(new Event('input'));
          }
        });
      }

      if (toggleNewPwdBtn) {
        toggleNewPwdBtn.addEventListener('click', () => {
          if (newPwdInput.type === 'password') {
            newPwdInput.type = 'text';
            toggleNewPwdBtn.innerHTML = eyeClosedSvg;
          } else {
            newPwdInput.type = 'password';
            toggleNewPwdBtn.innerHTML = eyeOpenSvg;
          }
        });
      }

      if (toggleConfirmPwdBtn) {
        toggleConfirmPwdBtn.addEventListener('click', () => {
          if (confirmPwdInput.type === 'password') {
            confirmPwdInput.type = 'text';
            toggleConfirmPwdBtn.innerHTML = eyeClosedSvg;
          } else {
            confirmPwdInput.type = 'password';
            toggleConfirmPwdBtn.innerHTML = eyeOpenSvg;
          }
        });
      }

      document.getElementById('save-password-btn')?.addEventListener('click', async () => {
        const oldPassword = document.getElementById('settings-old-password').value;
        const newPassword = document.getElementById('settings-new-password').value;
        const confirmPassword = document.getElementById('settings-confirm-password').value;
        if (!newPassword) return;
        if (newPassword !== confirmPassword) {
          localToast(t('auth.passwordMismatch'));
          return;
        }
        const res = await fetch('/api/user/password', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ oldPassword, newPassword })
        });
        const data = await res.json();
        if (!res.ok) {
          localToast(t(data.error));
        } else {
          localToast(t('success.passwordUpdated'), 'success');
          cancelPasswordBtn.click();
        }
      });
    }

    if (saveUsernameBtn) {
      saveUsernameBtn.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        if (!username) return;
        saveUsernameBtn.disabled = true;
        const res = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username })
        });
        const data = await res.json();
        if (!res.ok) {
          localToast(t(data.error));
          saveUsernameBtn.disabled = false;
        } else {
          user.username = username;
          const sDisp = document.getElementById('settings-username-display');
          if (sDisp) sDisp.textContent = username;
          const dropUser = document.getElementById('dropdown-username');
          if (dropUser) dropUser.textContent = username;
          localToast(t('success.usernameUpdated'), 'success');
          saveUsernameBtn.classList.remove('btn-primary');
          saveUsernameBtn.classList.add('btn-outline');
        }
      });
    }

    // Passkey Add Button
    document.getElementById('btn-add-passkey')?.addEventListener('click', () => {
      if (typeof window.handleAddPasskey === 'function') {
        window.handleAddPasskey();
      }
    });

  }
});




// Legacy user upload stubs (deprecated in favor of admin node management)
window.loadMyModels = function() {};
window.deleteModel = function() {};
window.updateUploadButtonState = function() {};

// --- Recharge & Redeem Modal Logic ---
(function() {
  const rechargeOverlay = document.getElementById('recharge-modal-overlay');
  const giftInput = document.getElementById('recharge-gift-code-input');
  const promoInput = document.getElementById('recharge-promo-code-input');
  const submitBtn = document.getElementById('recharge-submit-btn');
  const btnText = document.getElementById('recharge-btn-text');
  const errorMsg = document.getElementById('recharge-error-msg');
  const errorText = document.getElementById('recharge-error-text');
  const closeBtn = document.getElementById('close-recharge-modal-btn');

  let rechargeState = {
    method: 'gift',
    submitting: false
  };

  window.openRechargeModal = function() {
    if (!rechargeOverlay) return;
    rechargeOverlay.style.display = 'flex';
    void rechargeOverlay.offsetWidth;
    rechargeOverlay.classList.add('active');
    if (errorMsg) errorMsg.style.display = 'none';
    if (giftInput) {
      giftInput.value = '';
      giftInput.classList.remove('recharge-shake');
      setTimeout(() => giftInput.focus(), 100);
    }
  };

  window.closeRechargeModal = function() {
    if (!rechargeOverlay) return;
    rechargeOverlay.classList.remove('active');
    setTimeout(() => {
      if (!rechargeOverlay.classList.contains('active')) {
        rechargeOverlay.style.display = 'none';
      }
    }, 200);
  };

  // Explicitly bind all recharge triggers in the DOM
  function bindRechargeTriggers() {
    const billingBtn = document.getElementById('billing-topup-btn');
    if (billingBtn) {
      billingBtn.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        window.openRechargeModal();
      };
    }
    const menuBtn = document.getElementById('menu-topup-btn');
    if (menuBtn) {
      menuBtn.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const menu = document.getElementById('user-menu');
        if (menu) menu.style.display = 'none';
        window.openRechargeModal();
      };
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindRechargeTriggers);
  } else {
    bindRechargeTriggers();
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', window.closeRechargeModal);
  }

  if (rechargeOverlay) {
    rechargeOverlay.addEventListener('click', (e) => {
      if (e.target === rechargeOverlay) window.closeRechargeModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && rechargeOverlay && rechargeOverlay.style.display === 'flex') {
      window.closeRechargeModal();
    }
  });

  // Gift Code Auto-Hyphenation Formatter (XXXX-XXXX-XXXX-XXXX)
  if (giftInput) {
    giftInput.addEventListener('input', () => {
      let val = giftInput.value.toUpperCase().replace(/[^0-9A-Z]/g, '');
      val = val.replace(/O/g, '0').replace(/[IL]/g, '1');
      if (val.length > 16) val = val.slice(0, 16);
      
      const parts = [];
      for (let i = 0; i < val.length; i += 4) {
        parts.push(val.slice(i, i + 4));
      }
      giftInput.value = parts.join('-');
      if (errorMsg) errorMsg.style.display = 'none';
      giftInput.classList.remove('recharge-shake');
    });

    giftInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleRedeemSubmit();
      }
    });
  }

  function showRechargeError(keyOrMsg) {
    if (!errorMsg || !errorText) return;
    const msg = (typeof t === 'function' ? t(keyOrMsg) : null) || keyOrMsg;
    errorText.textContent = msg;
    errorMsg.style.display = 'flex';
    if (giftInput) {
      giftInput.classList.remove('recharge-shake');
      void giftInput.offsetWidth;
      giftInput.classList.add('recharge-shake');
      giftInput.focus();
    }
  }

  async function handleRedeemSubmit() {
    if (rechargeState.submitting) return;
    const rawVal = giftInput ? giftInput.value.trim() : '';
    if (!rawVal) {
      showRechargeError('error.redeem.empty');
      return;
    }

    rechargeState.submitting = true;
    if (submitBtn) submitBtn.disabled = true;
    if (btnText) btnText.textContent = typeof t === 'function' ? t('recharge.btn.redeeming') : 'Redeeming...';

    try {
      const res = await fetch('/api/billing/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: rawVal })
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showRechargeError(data.error || 'error.redeem.invalid');
        return;
      }

      // Success
      const successMsg = typeof t === 'function' 
        ? t('recharge.success', { amount: data.amount }) 
        : ('🎉 Redeemed +' + data.amount + ' ⚡!');
      
      if (typeof window.showToast === 'function') {
        window.showToast(successMsg, 'success');
      }

      // Update credit numbers across UI
      const newBal = data.newBalance;
      const el1 = document.getElementById('credits-display');
      if (el1) el1.textContent = newBal;
      const el2 = document.getElementById('dropdown-points');
      if (el2) el2.textContent = newBal;
      const el3 = document.getElementById('settings-points-display');
      if (el3) el3.textContent = newBal;

      // Refresh ledger list if it exists
      if (typeof window.loadBillingLedger === 'function') {
        window.ledgerCache = null;
        window.loadBillingLedger('all', 1);
      } else if (typeof window.loadLedger === 'function') {
        window.loadLedger('all', 1);
      }

      setTimeout(() => {
        window.closeRechargeModal();
        if (window.fetchNotifications) window.fetchNotifications();
      }, 350);

    } catch (err) {
      showRechargeError(err.message || 'Network error');
    } finally {
      rechargeState.submitting = false;
      if (submitBtn) submitBtn.disabled = false;
      if (btnText) btnText.textContent = typeof t === 'function' ? t('recharge.btn.redeem') : 'Redeem Now';
    }
  }

  if (submitBtn) {
    submitBtn.addEventListener('click', handleRedeemSubmit);
  }
})();

/* ============================================================
   NOTIFICATION CENTER CLIENT MODULE
   ============================================================ */

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function timeAgo(dateString) {
  if (!dateString) return '';
  const now = new Date();
  const date = new Date(dateString.endsWith('Z') ? dateString : dateString.replace(' ', 'T') + 'Z');
  const seconds = Math.floor((now - date) / 1000);
  const isEn = typeof getLocale === 'function' ? getLocale() === 'en' : false;

  if (seconds < 60) {
    return isEn ? 'Just now' : '刚刚';
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return isEn ? `${minutes}m ago` : `${minutes} 分钟前`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return isEn ? `${hours}h ago` : `${hours} 小时前`;
  }
  const days = Math.floor(hours / 24);
  if (days === 1) {
    return isEn ? 'Yesterday' : '昨天';
  }
  if (days < 7) {
    return isEn ? `${days}d ago` : `${days} 天前`;
  }
  return date.toISOString().split('T')[0];
}

function getNotificationIcon(n) {
  if (n.category === 'model' && (n.event_type === 'model_published' || n.event_type === 'model_approved')) {
    return {
      className: 'icon-success',
      svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>'
    };
  }
  if (n.category === 'model' && (n.event_type === 'model_rejected' || n.event_type === 'model_delisted')) {
    return {
      className: 'icon-error',
      svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
    };
  }
  if (n.event_type === 'low_balance' || n.category === 'quota') {
    return {
      className: 'icon-warn',
      svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
    };
  }
  if (n.category === 'task' && n.priority === 'urgent') {
    return {
      className: 'icon-error',
      svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
    };
  }
  if (n.category === 'billing') {
    return {
      className: 'icon-info',
      svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path></svg>'
    };
  }
  return {
    className: 'icon-info',
    svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>'
  };
}

let notifState = {
  items: [],
  unreadCount: 0,
  hasUrgentUnread: false,
  isOpen: false,
  currentFilter: 'all'
};

window.fetchNotifications = async function() {
  if (!user) return;
  try {
    const res = await fetch('/api/notifications?limit=15');
    if (!res.ok) return;
    const data = await res.json();
    notifState.items = data.items || [];
    notifState.unreadCount = data.unreadCount || 0;
    notifState.hasUrgentUnread = data.hasUrgentUnread || false;

    updateNotificationBadge();
    renderNotificationPopover();
  } catch (err) {
    console.error('fetchNotifications error:', err);
  }
};

function updateNotificationBadge() {
  const dot = document.getElementById('notif-dot');
  const btn = document.getElementById('notif-btn');
  if (!dot || !btn) return;

  if (notifState.unreadCount > 0) {
    dot.style.display = 'block';
    if (notifState.hasUrgentUnread) {
      dot.className = 'notif-dot urgent';
      btn.classList.add('shake');
      setTimeout(() => btn.classList.remove('shake'), 1300);
    } else {
      dot.className = 'notif-dot normal';
      btn.classList.remove('shake');
    }
  } else {
    dot.style.display = 'none';
    btn.classList.remove('shake');
  }
}

function renderNotificationPopover() {
  const listEl = document.getElementById('notif-popover-list');
  if (!listEl) return;
  const isEn = typeof getLocale === 'function' ? getLocale() === 'en' : false;

  if (notifState.items.length === 0) {
    listEl.innerHTML = `<div class="notif-empty">${isEn ? 'No notifications' : '暂无新消息'}</div>`;
    return;
  }

  let html = '';
  notifState.items.slice(0, 10).forEach(n => {
    const icon = getNotificationIcon(n);
    const title = (isEn ? (n.title_en || n.title_zh) : (n.title_zh || n.title_en)) || '';
    const body = (isEn ? (n.content_en || n.content_zh) : (n.content_zh || n.content_en)) || '';
    const timeStr = timeAgo(n.created_at);
    const unreadClass = n.is_read ? 'read' : `unread ${n.priority === 'urgent' ? 'urgent' : ''}`;

    html += `
      <div class="notif-item ${unreadClass}" data-notif-id="${escapeHtml(n.notification_id)}">
        <div class="notif-icon-wrap ${icon.className}">
          ${icon.svg}
        </div>
        <div class="notif-content-wrap">
          <div class="notif-head-row">
            <span class="notif-item-title">${escapeHtml(title)}</span>
            <span class="notif-item-time">${timeStr}</span>
          </div>
          <div class="notif-item-body">${escapeHtml(body)}</div>
        </div>
      </div>
    `;
  });

  listEl.innerHTML = html;
}

window.handleNotificationClick = async function(id) {
  const notif = notifState.items.find(x => x.notification_id === id);
  if (!notif) return;

  // 1. Mark as read immediately
  if (!notif.is_read) {
    notif.is_read = 1;
    notifState.unreadCount = Math.max(0, notifState.unreadCount - 1);
    updateNotificationBadge();
    renderNotificationPopover();
    fetch(`/api/notifications/${id}/read`, { method: 'POST' }).catch(() => {});
  }

  // 2. Close popover
  const popover = document.getElementById('notif-popover');
  if (popover) {
    popover.style.display = 'none';
    notifState.isOpen = false;
  }

  // 3. Deep link execution
  if (notif.action_type === 'route' && notif.action_payload) {
    try {
      const payload = JSON.parse(notif.action_payload);
      if (payload.modal === 'settings') {
        if (typeof window.openSettingsModal === 'function') {
          window.openSettingsModal(payload.tab || 'account');
        }
      } else if (payload.modal === 'recharge') {
        if (typeof window.openRechargeModal === 'function') {
          window.openRechargeModal();
        }
      }
    } catch (e) {
      console.error('Error executing notification route payload:', e);
    }
  }
};

window.markAllNotificationsRead = async function() {
  try {
    await fetch('/api/notifications/read-all', { method: 'POST' });
    notifState.items.forEach(n => n.is_read = 1);
    notifState.unreadCount = 0;
    notifState.hasUrgentUnread = false;
    updateNotificationBadge();
    renderNotificationPopover();
    if (window.loadMessagesTab) window.loadMessagesTab(notifState.currentFilter);
  } catch (err) {
    console.error('markAllNotificationsRead error:', err);
  }
};

// --- Settings Modal: Notifications Tab Controller ---
window.loadMessagesTab = async function(filter = notifState.currentFilter || 'all') {
  notifState.currentFilter = filter;
  const listEl = document.getElementById('settings-messages-list');
  if (!listEl) return;
  const isEn = typeof getLocale === 'function' ? getLocale() === 'en' : false;

  listEl.innerHTML = `<div style="text-align:center; padding:3rem; color:var(--text-secondary);">${isEn ? 'Loading notifications...' : '正在加载消息...'}</div>`;

  try {
    const res = await fetch(`/api/notifications?filter=${encodeURIComponent(filter)}&limit=50`);
    if (!res.ok) throw new Error('Failed to load messages');
    const data = await res.json();
    const items = data.items || [];

    if (items.length === 0) {
      listEl.innerHTML = `
        <div class="settings-empty-state" style="padding:3rem 1rem;">
          <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>
          <div class="settings-empty-title" style="margin-top:12px;">${isEn ? 'No notifications found' : '暂无相关消息'}</div>
        </div>`;
      return;
    }

    let html = '';
    items.forEach(n => {
      const icon = getNotificationIcon(n);
      const title = (isEn ? (n.title_en || n.title_zh) : (n.title_zh || n.title_en)) || '';
      const body = (isEn ? (n.content_en || n.content_zh) : (n.content_zh || n.content_en)) || '';
      const timeStr = timeAgo(n.created_at);
      const unreadClass = n.is_read ? 'read' : `unread ${n.priority === 'urgent' ? 'urgent' : ''}`;
      
      let badgeHtml = '';
      if (n.category === 'model') {
        badgeHtml = `<span class="settings-msg-badge" style="background:rgba(99,102,241,0.15); color:#818cf8;">${isEn ? 'Model' : '模型'}</span>`;
      } else if (n.category === 'billing' || n.category === 'quota') {
        badgeHtml = `<span class="settings-msg-badge" style="background:rgba(245,158,11,0.15); color:#fbbf24;">${isEn ? 'Billing' : '财务'}</span>`;
      } else if (n.category === 'system') {
        badgeHtml = `<span class="settings-msg-badge" style="background:rgba(16,185,129,0.15); color:#34d399;">${isEn ? 'System' : '系统'}</span>`;
      }

      let actionBtnHtml = '';
      if (n.action_type === 'route' && n.action_payload) {
        actionBtnHtml = `<button class="settings-message-action-btn" data-notif-id="${escapeHtml(n.notification_id)}">${isEn ? 'View Details ➔' : '前往查看 ➔'}</button>`;
      }

      html += `
        <div class="settings-message-row ${unreadClass}" data-notif-id="${escapeHtml(n.notification_id)}">
          <div class="notif-icon-wrap ${icon.className}">${icon.svg}</div>
          <div class="settings-msg-main">
            <div class="settings-msg-header-line">
              <span class="settings-msg-title">${escapeHtml(title)}</span>
              ${badgeHtml}
            </div>
            <div class="settings-msg-body">${escapeHtml(body)}</div>
          </div>
          <div class="settings-msg-side">
            <span class="settings-msg-time">${timeStr}</span>
            ${actionBtnHtml}
          </div>
        </div>
      `;
    });

    listEl.innerHTML = html;
  } catch (err) {
    listEl.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--error-color);">${escapeHtml(err.message || '加载消息失败')}</div>`;
  }
};

// Initialize Notification Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  const notifBtn = document.getElementById('notif-btn');
  const notifPopover = document.getElementById('notif-popover');
  const notifPopoverList = document.getElementById('notif-popover-list');
  const settingsMessagesList = document.getElementById('settings-messages-list');
  const markAllBtn = document.getElementById('notif-mark-all-btn');
  const messagesMarkAllBtn = document.getElementById('messages-mark-all-btn');
  const viewAllLink = document.getElementById('notif-view-all-link');

  if (notifPopoverList) {
    notifPopoverList.addEventListener('click', (e) => {
      const target = e.target.closest('[data-notif-id]');
      if (target && target.dataset.notifId) {
        handleNotificationClick(target.dataset.notifId);
      }
    });
  }

  if (settingsMessagesList) {
    settingsMessagesList.addEventListener('click', (e) => {
      const actionBtn = e.target.closest('.settings-message-action-btn[data-notif-id]');
      if (actionBtn && actionBtn.dataset.notifId) {
        e.stopPropagation();
        handleNotificationClick(actionBtn.dataset.notifId);
        return;
      }
      const row = e.target.closest('.settings-message-row[data-notif-id]');
      if (row && row.dataset.notifId) {
        handleNotificationClick(row.dataset.notifId);
      }
    });
  }

  if (notifBtn && notifPopover) {
    notifBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!user) {
        if (notifPopover) notifPopover.style.display = 'none';
        notifState.isOpen = false;
        window.showModal(
          t('chat.loginRequired'),
          `<p style="color:var(--text-secondary); line-height:1.6;">${t('chat.loginToUse')}</p>`,
          t('auth.goToLogin'),
          () => { window.location.href = '/login.html'; }
        );
        return;
      }
      notifState.isOpen = !notifState.isOpen;
      notifPopover.style.display = notifState.isOpen ? 'flex' : 'none';
      if (notifState.isOpen) {
        window.fetchNotifications();
      }
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('#notif-dropdown-wrapper')) {
        notifPopover.style.display = 'none';
        notifState.isOpen = false;
      }
    });
  }

  if (markAllBtn) {
    markAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      window.markAllNotificationsRead();
    });
  }

  if (messagesMarkAllBtn) {
    messagesMarkAllBtn.addEventListener('click', () => {
      window.markAllNotificationsRead();
    });
  }

  if (viewAllLink) {
    viewAllLink.addEventListener('click', (e) => {
      e.stopPropagation();
      if (notifPopover) notifPopover.style.display = 'none';
      notifState.isOpen = false;
      if (typeof window.openSettingsModal === 'function') {
        window.openSettingsModal('messages');
      }
    });
  }

  // Filter pills inside notifications panel
  document.querySelectorAll('#messages-filter-pills .messages-filter-pill, #messages-filter-pills .filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#messages-filter-pills .messages-filter-pill, #messages-filter-pills .filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      window.loadMessagesTab(pill.dataset.filter);
    });
  });

  // Initial fetch and 60-second periodic poll
  window.fetchNotifications();
  setInterval(window.fetchNotifications, 60000);

  // Handle URL error parameters (e.g. OAuth conflict redirects)
  const appUrlParams = new URLSearchParams(window.location.search);
  const appErrorParam = appUrlParams.get('error');
  if (appErrorParam) {
    const errorMsgMap = {
      oauth_already_bound: '此第三方账号已被其他用户绑定，无法重复绑定',
      oauth_conflict: '该第三方账号绑定的邮箱与当前账户不一致',
      oauth_state_invalid: '第三方授权状态失效，请重试',
      oauth_failed: '第三方授权登录失败，请重试'
    };
    const toastMsg = errorMsgMap[appErrorParam] || (typeof t === 'function' ? t(`error.${appErrorParam}`) : null) || appErrorParam;
    if (typeof localToast === 'function') {
      localToast(toastMsg, 'error');
    }
    if (window.location.hash === '#settings' && typeof window.openSettingsModal === 'function') {
      window.openSettingsModal('account');
    }
  }
});

