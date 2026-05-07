import './style.css';
import {
    Toggle,
    GetProxyIP,
    UpdateProxyIP,
    IsMacOS,
    Quit,
    SubmitSudoPassword,
    HasSudoPassword,
} from '../wailsjs/go/main/App';
import { EventsOn } from '../wailsjs/runtime/runtime';

const state = {
    on: false,
    switching: false,
    isMacOS: false,
};

const $ = (id) => document.getElementById(id);
const toggleBtn = $('toggleBtn');
const toggleText = $('toggleText');
const ipRow = $('ipRow');
const ipText = $('ipText');
const ipInput = $('ipInput');
const errorEl = $('error');
const closeBtn = $('closeBtn');
const pwDialog = $('pwDialog');
const pwForm = $('pwForm');
const pwInput = $('pwInput');
const pwError = $('pwError');
const pwCancel = $('pwCancel');

function showError(msg) {
    errorEl.textContent = msg || '';
    errorEl.classList.toggle('visible', !!msg);
}

function clearError() {
    showError('');
}

async function applyState(on, { animate = false } = {}) {
    const wasOn = state.on;
    state.on = !!on;

    if (animate && wasOn !== state.on) {
        // Cross-fade text
        toggleBtn.classList.add('fading');
        await new Promise((r) => setTimeout(r, 180));
        toggleText.textContent = state.on ? 'ON' : 'OFF';
        toggleBtn.classList.remove('fading');
    } else {
        toggleText.textContent = state.on ? 'ON' : 'OFF';
    }

    toggleBtn.classList.toggle('is-on', state.on);
    ipRow.classList.toggle('locked', state.on);

    if (animate) {
        toggleBtn.classList.remove('pulse');
        // Force reflow so the animation re-triggers
        void toggleBtn.offsetWidth;
        toggleBtn.classList.add('pulse');
    }
}

function setBusy(busy) {
    state.switching = busy;
    toggleBtn.disabled = busy;
    if (busy) {
        toggleText.textContent = '...';
    }
}

async function performToggle() {
    if (state.switching) return;
    clearError();
    setBusy(true);
    try {
        await Toggle();
        await applyState(!state.on, { animate: true });
    } catch (err) {
        const msg = String(err && err.message ? err.message : err);
        if (msg === 'NEED_PASSWORD') {
            // Reset busy display before showing modal
            toggleText.textContent = state.on ? 'ON' : 'OFF';
            await askPassword();
            // After password accepted, retry toggle
            setBusy(true);
            try {
                await Toggle();
                await applyState(!state.on, { animate: true });
            } catch (err2) {
                showError(String(err2 && err2.message ? err2.message : err2));
                toggleText.textContent = state.on ? 'ON' : 'OFF';
            }
        } else {
            showError(msg);
            toggleText.textContent = state.on ? 'ON' : 'OFF';
        }
    } finally {
        setBusy(false);
    }
}

function askPassword() {
    return new Promise((resolve, reject) => {
        pwError.textContent = '';
        pwInput.value = '';
        pwDialog.showModal();
        // Focus after modal is rendered
        setTimeout(() => pwInput.focus(), 30);

        const cleanup = () => {
            pwForm.removeEventListener('submit', onSubmit);
            pwCancel.removeEventListener('click', onCancel);
            pwDialog.removeEventListener('cancel', onCancel);
        };

        const onSubmit = async (e) => {
            e.preventDefault();
            const pw = pwInput.value;
            if (!pw) {
                pwError.textContent = '请输入密码';
                return;
            }
            pwError.textContent = '验证中…';
            try {
                await SubmitSudoPassword(pw);
                cleanup();
                pwDialog.close();
                resolve();
            } catch (err) {
                const msg = String(err && err.message ? err.message : err);
                pwError.textContent = msg;
                pwInput.select();
            }
        };

        const onCancel = (e) => {
            if (e) e.preventDefault();
            cleanup();
            pwDialog.close();
            reject(new Error('已取消'));
        };

        pwForm.addEventListener('submit', onSubmit);
        pwCancel.addEventListener('click', onCancel);
        pwDialog.addEventListener('cancel', onCancel);
    });
}

function enterIPEdit() {
    if (state.on || state.switching) return;
    ipInput.value = ipText.textContent.trim();
    ipRow.classList.add('editing');
    setTimeout(() => {
        ipInput.focus();
        ipInput.select();
    }, 0);
}

function exitIPEdit(commit) {
    if (!ipRow.classList.contains('editing')) return;
    ipRow.classList.remove('editing');
    if (!commit) return;
    const newIP = ipInput.value.trim();
    if (!newIP || newIP === ipText.textContent.trim()) return;
    UpdateProxyIP(newIP)
        .then(() => {
            ipText.textContent = newIP;
            clearError();
        })
        .catch((err) => {
            showError(String(err && err.message ? err.message : err));
        });
}

// === Event wiring ===

toggleBtn.addEventListener('click', performToggle);

ipText.addEventListener('click', enterIPEdit);

ipInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        exitIPEdit(true);
    } else if (e.key === 'Escape') {
        e.preventDefault();
        exitIPEdit(false);
    }
});

ipInput.addEventListener('blur', () => exitIPEdit(true));

closeBtn.addEventListener('click', () => Quit());

document.addEventListener('keydown', (e) => {
    // Esc closes the app, but only when no modal/edit is active
    if (e.key === 'Escape' && !pwDialog.open && !ipRow.classList.contains('editing')) {
        Quit();
    }
});

// === Startup ===

(async function init() {
    try {
        const [ip, mac] = await Promise.all([GetProxyIP(), IsMacOS()]);
        ipText.textContent = ip;
        state.isMacOS = mac;
    } catch (err) {
        showError(String(err && err.message ? err.message : err));
    }
})();

// React to async residual detection from Go
EventsOn('state:residual', () => {
    applyState(true, { animate: true });
});
