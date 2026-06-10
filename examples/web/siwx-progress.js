/**
 * <siwx-progress> — framework-agnostic Web Component for SIWX flow visualization.
 *
 * Usage:
 *   <siwx-progress></siwx-progress>
 *
 *   el.steps = [
 *     { id: "nonce",  label: "Fetch nonce",       state: "done" },
 *     { id: "wallet", label: "Wallet sign-in",     state: "active" },
 *     { id: "verify", label: "Server verify",      state: "pending" },
 *     { id: "token",  label: "Issue token",        state: "pending" },
 *     { id: "linked", label: "Identity linked",    state: "pending",
 *       subchecks: [{ name: "domain", ok: true, ms: 0.1 }] },
 *   ];
 *
 * States: pending | active | done | failed
 * No external dependencies.
 */
class SiwxProgress extends HTMLElement {
  static get observedAttributes() { return ['steps']; }

  constructor() {
    super();
    this._steps = [];
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        ol { list-style: none; padding: 0; margin: 0; }
        li {
          display: flex; align-items: flex-start; gap: .75rem;
          padding: .5rem 0;
          border-left: 2px solid #2d3148;
          padding-left: 1rem;
          position: relative;
          transition: border-color .2s;
        }
        li.done   { border-color: #22c55e; }
        li.active { border-color: #6366f1; }
        li.failed { border-color: #ef4444; }
        li.pending { opacity: .45; }
        .icon { font-size: 1rem; min-width: 1.2rem; text-align: center; }
        .body { flex: 1; }
        .label { font-size: .875rem; font-weight: 500; }
        .subchecks { margin-top: .35rem; }
        .sub { font-size: .7rem; color: #94a3b8; display: flex; gap: .5rem; }
        .sub.ok   { color: #4ade80; }
        .sub.fail { color: #f87171; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .spinner {
          display: inline-block;
          width: .9rem; height: .9rem;
          border: 2px solid #6366f1;
          border-top-color: transparent;
          border-radius: 50%;
          animation: spin .6s linear infinite;
        }
      </style>
      <ol id="list"></ol>
    `;
  }

  get steps() { return this._steps; }

  set steps(val) {
    this._steps = Array.isArray(val) ? val : [];
    this._render();
  }

  attributeChangedCallback(name, _old, value) {
    if (name === 'steps') {
      try { this.steps = JSON.parse(value); } catch (_) { /* ignore */ }
    }
  }

  _icon(state) {
    if (state === 'done')    return '✓';
    if (state === 'failed')  return '✗';
    if (state === 'active')  return '<span class="spinner"></span>';
    return '○';
  }

  _render() {
    const list = this.shadowRoot.getElementById('list');
    list.innerHTML = this._steps.map(s => {
      const subchecksHTML = (s.subchecks || []).map(c => `
        <div class="sub ${c.ok ? 'ok' : 'fail'}">
          ${c.ok ? '✓' : '✗'} ${c.name}
          <span style="opacity:.6">${c.ms != null ? c.ms.toFixed(2) + 'ms' : ''}</span>
        </div>`).join('');

      return `
        <li class="${s.state || 'pending'}">
          <span class="icon">${this._icon(s.state)}</span>
          <div class="body">
            <div class="label">${s.label}</div>
            ${subchecksHTML ? `<div class="subchecks">${subchecksHTML}</div>` : ''}
          </div>
        </li>`;
    }).join('');
  }
}

customElements.define('siwx-progress', SiwxProgress);
