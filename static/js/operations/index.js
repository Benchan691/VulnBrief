(function () {
    const pageConfig = JSON.parse(document.getElementById('page-config').textContent);
    const refreshMs = 20000;

    function showMessage(text, type) {
        const box = document.getElementById('message');
        box.className = 'alert alert-' + type;
        box.textContent = text;
        box.classList.remove('d-none');
    }

    function clearMessage() {
        document.getElementById('message').classList.add('d-none');
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function formatTime(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return escapeHtml(value);
        return escapeHtml(date.toLocaleString());
    }

    function requestJson(url) {
        return fetch(url, { headers: { Accept: 'application/json' } }).then(function (response) {
            return response.json().then(function (body) {
                if (!response.ok) {
                    throw new Error((body && body.error) || 'Request failed.');
                }
                return body;
            });
        });
    }

    function renderScheduler(scheduler) {
        const banner = document.getElementById('scheduler-banner');
        const alive = Boolean(scheduler && scheduler.alive);
        banner.className = 'alert mb-4 ' + (alive ? 'alert-success' : 'alert-warning');
        const retention = (scheduler && scheduler.retention) || {};
        const retentionResult = retention.last_result
            ? JSON.stringify(retention.last_result)
            : '—';
        banner.innerHTML =
            '<div class="d-flex flex-wrap justify-content-between gap-2">' +
            '<div><strong>Scheduler:</strong> ' + (alive ? 'Alive' : 'Stale / not running') + '</div>' +
            '<div class="small">Last tick: ' + formatTime(scheduler && scheduler.last_tick_at) + '</div>' +
            '</div>' +
            '<div class="small mt-2">' +
            'Host: ' + escapeHtml((scheduler && scheduler.hostname) || '—') +
            ' · PID: ' + escapeHtml((scheduler && scheduler.pid) != null ? scheduler.pid : '—') +
            ' · Retention last run: ' + formatTime(retention.last_run_at) +
            ' · Retention result: ' + escapeHtml(retentionResult) +
            '</div>';
    }

    function renderReports(rows) {
        const body = document.getElementById('report-rows');
        const empty = document.getElementById('reports-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const delivery = row.delivery || {};
            const schedule = row.schedule_enabled
                ? escapeHtml(row.schedule_weekday) + ' ' + escapeHtml(row.schedule_time) + ' HKT'
                : 'Off';
            const next = row.due
                ? '<span class="badge text-bg-warning">Due</span> ' + formatTime(row.next_run_at)
                : formatTime(row.next_run_at);
            const deliveryText = delivery.delivery_status
                ? escapeHtml(delivery.delivery_status) + ' / ' + escapeHtml(delivery.status || '—')
                : '—';
            const tr = document.createElement('tr');
            tr.innerHTML =
                '<td><div class="fw-semibold">' + escapeHtml(row.email) + '</div>' +
                '<div class="small text-muted">' + escapeHtml(row.team || '') + '</div>' +
                '<div class="small">' + (row.enabled ? 'Enabled' : 'Disabled') +
                ' · ' + escapeHtml(row.generation_mode || '') + '</div></td>' +
                '<td>' + schedule + '</td>' +
                '<td>' + next +
                (row.schedule_claim_owner
                    ? '<div class="small text-muted">Claim: ' + escapeHtml(row.schedule_claim_owner) + '</div>'
                    : '') +
                '</td>' +
                '<td>' + formatTime(row.last_run_at) +
                (row.last_job_id
                    ? '<div class="small text-muted">Job ' + escapeHtml(row.last_job_id) + '</div>'
                    : '') +
                (row.last_match_count != null
                    ? '<div class="small text-muted">Matches ' + escapeHtml(row.last_match_count) + '</div>'
                    : '') +
                '</td>' +
                '<td>' + deliveryText +
                (delivery.delivery_error
                    ? '<div class="small text-danger">' + escapeHtml(delivery.delivery_error) + '</div>'
                    : '') +
                '</td>' +
                '<td class="small text-danger">' + escapeHtml(row.last_error || '—') + '</td>';
            body.appendChild(tr);
        });
    }

    function renderNewsletters(rows) {
        const body = document.getElementById('newsletter-rows');
        const empty = document.getElementById('newsletters-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const tr = document.createElement('tr');
            tr.innerHTML =
                '<td><div class="fw-semibold">' + escapeHtml(row.email) + '</div>' +
                '<div class="small text-muted">' + escapeHtml(row.team || '') + '</div></td>' +
                '<td>' + (row.enabled ? 'Yes' : 'No') + '</td>' +
                '<td class="small">' + escapeHtml(row.delivery_cursor || '—') + '</td>' +
                '<td class="small">' + escapeHtml(row.cve_delivery_cutoff || '—') + '</td>' +
                '<td>' + escapeHtml(row.total_delivered) + '</td>';
            body.appendChild(tr);
        });
    }

    function renderDeliveries(rows) {
        const body = document.getElementById('delivery-rows');
        const empty = document.getElementById('deliveries-empty');
        body.innerHTML = '';
        if (!rows.length) {
            empty.classList.remove('d-none');
            return;
        }
        empty.classList.add('d-none');
        rows.forEach(function (row) {
            const tr = document.createElement('tr');
            tr.innerHTML =
                '<td class="small">' + formatTime(row.sent_at) + '</td>' +
                '<td>' + escapeHtml(row.email) + '</td>' +
                '<td class="small">' + escapeHtml(row.source_collection) + '</td>' +
                '<td>' + escapeHtml(row.title || row.selection_id || '—') + '</td>';
            body.appendChild(tr);
        });
    }

    function loadHealth() {
        return requestJson(pageConfig.healthUrl)
            .then(function (body) {
                clearMessage();
                renderScheduler(body.scheduler || {});
                renderReports(body.reports || []);
                renderNewsletters(body.newsletters || []);
                renderDeliveries(body.recent_newsletter_deliveries || []);
            })
            .catch(function (error) {
                showMessage(error.message || 'Unable to load scheduler health.', 'danger');
            });
    }

    document.getElementById('refresh-btn').addEventListener('click', loadHealth);
    loadHealth();
    setInterval(loadHealth, refreshMs);
})();
