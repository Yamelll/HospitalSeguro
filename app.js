(() => {
    'use strict';

    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.content : '';

    const passwordToggle = document.getElementById('toggle-password');
    if (passwordToggle) {
        passwordToggle.addEventListener('click', () => {
            const input = document.getElementById('password');
            if (!input) return;
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            passwordToggle.textContent = show ? 'Ocultar' : 'Mostrar';
            passwordToggle.setAttribute('aria-pressed', String(show));
        });
    }

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', () => {
            const submit = document.getElementById('login-submit');
            if (submit) {
                submit.disabled = true;
                submit.textContent = 'Validando…';
            }
        });
    }

    async function requestJson(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const headers = { ...(options.headers || {}) };
        if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
            headers['X-CSRF-Token'] = csrfToken;
        }
        if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
        const response = await fetch(url, { ...options, method, headers });
        let data = {};
        try { data = await response.json(); } catch (_) { /* respuesta no JSON */ }
        if (!response.ok) {
            if (response.status === 401) window.location.assign('/login');
            throw new Error(data.error || 'La solicitud no pudo completarse.');
        }
        return data;
    }

    function showError(element, message) {
        if (!element) return;
        element.textContent = message;
        element.classList.add('visible');
    }

    function clearError(element) {
        if (!element) return;
        element.textContent = '';
        element.classList.remove('visible');
    }

    function fillTable(body, records, columns, emptyMessage = 'No hay registros para mostrar.') {
        if (!body) return;
        body.replaceChildren();
        if (!records || !records.length) {
            const row = body.insertRow();
            const cell = row.insertCell();
            cell.colSpan = columns.length || 1;
            cell.className = 'empty';
            cell.textContent = emptyMessage;
            return;
        }
        for (const record of records) {
            const row = body.insertRow();
            for (const column of columns) {
                const cell = row.insertCell();
                const value = record[column.key];
                if (column.badge && value !== null && value !== undefined) {
                    const badge = document.createElement('span');
                    badge.className = 'badge';
                    badge.textContent = String(value);
                    cell.append(badge);
                } else if (column.date && value) {
                    const parsed = new Date(value);
                    cell.textContent = Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
                } else {
                    cell.textContent = value === null || value === undefined ? '—' : String(value);
                }
            }
        }
    }

    function fillDynamicTable(head, body, records) {
        if (!head || !body) return;
        head.replaceChildren();
        const headerRow = document.createElement('tr');
        const keys = records.length ? Object.keys(records[0]) : [];
        keys.forEach((key) => {
            const th = document.createElement('th');
            th.textContent = key;
            headerRow.append(th);
        });
        head.append(headerRow);
        fillTable(body, records, keys.map((key) => ({ key })));
    }

    async function loadTable({ url, bodyId, errorId, columns, headId }) {
        const error = document.getElementById(errorId);
        clearError(error);
        try {
            const data = await requestJson(url);
            if (headId) fillDynamicTable(document.getElementById(headId), document.getElementById(bodyId), data);
            else fillTable(document.getElementById(bodyId), data, columns);
        } catch (exception) {
            showError(error, exception.message);
        }
    }

    const loaders = {
        pacientes: () => loadTable({
            url: '/api/pacientes', bodyId: 'patients-body', errorId: 'patients-error',
            columns: [
                { key: 'PacienteID' }, { key: 'Identificacion' }, { key: 'Nombre' },
                { key: 'Apellidos' }, { key: 'Correo' }, { key: 'Telefono' }
            ]
        }),
        expedientes: () => loadTable({
            url: '/api/expedientes', bodyId: 'expedientes-body', errorId: 'expedientes-error',
            columns: [
                { key: 'ExpedienteID' }, { key: 'PacienteID' }, { key: 'PersonalID' },
                { key: 'Motivo' }, { key: 'Diagnostico' }, { key: 'Tratamiento' }
            ]
        }),
        personal: () => loadTable({
            url: '/api/personal', bodyId: 'personal-body', errorId: 'personal-error',
            headId: 'personal-head'
        }),
        consentimientos: () => loadTable({
            url: '/api/consentimientos', bodyId: 'consentimientos-body', errorId: 'consentimientos-error',
            headId: 'consentimientos-head'
        }),
        usuarios: () => loadTable({
            url: '/api/usuarios', bodyId: 'usuarios-body', errorId: 'usuarios-error',
            columns: [
                { key: 'UsuarioID' }, { key: 'NombreUsuario' }, { key: 'Rol' },
                { key: 'Activo', badge: true }, { key: 'FechaCreacion', date: true }
            ]
        }),
        auditoria: () => loadTable({
            url: '/api/auditoria', bodyId: 'audit-body', errorId: 'audit-error',
            columns: [
                { key: 'AuditoriaID' }, { key: 'FechaEvento', date: true },
                { key: 'UsuarioAplicacion' }, { key: 'Accion', badge: true },
                { key: 'TablaAfectada' }, { key: 'Detalle' }
            ]
        })
    };

    const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
    function activateTab(tab, load = true) {
        tabs.forEach((item) => item.setAttribute('aria-selected', String(item === tab)));
        document.querySelectorAll('[role="tabpanel"]').forEach((panel) => {
            panel.hidden = panel.id !== tab.getAttribute('aria-controls');
        });
        const key = tab.id.replace(/-tab$/, '');
        if (load && loaders[key]) loaders[key]();
    }

    tabs.forEach((tab) => tab.addEventListener('click', () => activateTab(tab)));
    tabs.forEach((tab) => {
        if (tab.getAttribute('aria-selected') === 'true') activateTab(tab);
    });

    const refreshMap = {
        'refresh-patients': 'pacientes',
        'refresh-expedientes': 'expedientes',
        'refresh-personal': 'personal',
        'refresh-consentimientos': 'consentimientos',
        'refresh-usuarios': 'usuarios',
        'refresh-audit': 'auditoria'
    };
    Object.entries(refreshMap).forEach(([buttonId, key]) => {
        const button = document.getElementById(buttonId);
        if (button && loaders[key]) button.addEventListener('click', loaders[key]);
    });

    const runSanitization = document.getElementById('run-sanitization');
    if (runSanitization) {
        runSanitization.addEventListener('click', async () => {
            const confirmation = document.getElementById('sanitization-confirmation');
            if (!confirmation || confirmation.value.trim() !== 'SANITIZAR') {
                const result = document.getElementById('sanitization-result');
                result.className = 'result error';
                result.textContent = 'Escribe SANITIZAR para confirmar la operación.';
                return;
            }
            if (!window.confirm('Esta acción puede modificar datos de pacientes. ¿Deseas continuar?')) return;
            const result = document.getElementById('sanitization-result');
            result.className = 'result';
            result.textContent = 'Ejecutando procedimiento…';
            runSanitization.disabled = true;
            try {
                const data = await requestJson('/api/anonimizar', {
                    method: 'POST',
                    body: JSON.stringify({ confirmacion: confirmation.value.trim() })
                });
                result.classList.add('success');
                result.textContent = data.mensaje;
                if (loaders.pacientes) await loaders.pacientes();
            } catch (exception) {
                result.classList.add('error');
                result.textContent = exception.message;
            } finally {
                runSanitization.disabled = false;
            }
        });
    }

    const logoutForm = document.getElementById('logout-form');
    if (logoutForm) {
        logoutForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            try {
                await fetch(logoutForm.action, {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': csrfToken }
                });
            } finally {
                window.location.assign('/login');
            }
        });
    }
})();
