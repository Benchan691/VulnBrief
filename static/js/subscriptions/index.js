(function () {
    const {
        subscriptionsUrl,
        previewUrl,
        reviewsUrl,
    } = JSON.parse(document.getElementById('page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('subscription-modal'));
    const newsletterCollections = new CollectionPicker('newsletter');
    const rows = document.getElementById('rows');
    const message = document.getElementById('message');
    let collections = [], subscriptions = [], editingEmail = null;
    let reportKeywords = [];
    let previewTimer = null;
    let previewAbortController = null;
    let previewRequestId = 0;

    const severityLevels = ['Critical', 'High', 'Medium', 'Low'];
    function newsletterFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-md-6">' +
        '<label for="newsletter-collections-toggle" class="form-label small">Collections</label>' +
        '<div class="dropdown w-100">' +
        '<button id="newsletter-collections-toggle" type="button" class="form-select form-select-sm dropdown-toggle subscription-collections-toggle text-start w-100" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">All collections</button>' +
        '<div id="newsletter-collections-menu" class="dropdown-menu w-100 shadow-sm p-2">' +
        '<input id="newsletter-collections-search" type="search" class="form-control form-control-sm mb-2" placeholder="Search collections..." autocomplete="off">' +
        '<div id="newsletter-collections-options" class="subscription-collections-options"></div>' +
        '<div class="dropdown-divider my-2"></div>' +
        '<div class="d-flex justify-content-between px-1">' +
        '<button type="button" class="btn btn-link btn-sm p-0 collections-action" data-action="all">Select all</button>' +
        '<button type="button" class="btn btn-link btn-sm p-0 text-muted collections-action" data-action="clear">Clear</button>' +
        '</div></div></div></div></div>';
    }

    function reportFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-12"><label class="form-label small">Severity / status</label><div class="d-flex flex-wrap gap-3">' +
        severityLevels.map(function (level) {
            return '<div class="form-check"><input id="report-status-' + level + '" class="form-check-input report-status-checkbox" type="checkbox" value="' + level + '"><label class="form-check-label small" for="report-status-' + level + '">' + level + '</label></div>';
        }).join('') +
        '</div><div class="form-text">Leave all unchecked to match all known severities.</div></div>' +
        '<div class="col-12"><label class="form-label small" for="report-keyword-input">Keywords</label><div class="input-group input-group-sm"><span class="input-group-text"><i class="bi bi-search"></i></span><input id="report-keyword-input" type="search" class="form-control" placeholder="Add keyword..." autocomplete="off"><button id="report-keyword-add" class="btn btn-outline-primary" type="button">Add</button><button id="report-keyword-clear" class="btn btn-outline-secondary" type="button">Clear</button></div><div id="report-keywords" class="d-flex flex-wrap gap-1 mt-2"></div></div>' +
        '<div class="col-md-6 d-flex align-items-end"><div class="form-check mb-2"><input id="report-include-unknown" class="form-check-input" type="checkbox"><label class="form-check-label small" for="report-include-unknown">Include unknown severity</label></div></div>' +
        timeWindowMarkup('report') +
        '</div>';
    }

    function timeWindowMarkup(prefix) {
        return '<div class="col-md-6"><label class="form-label small">Time window</label><select id="' + prefix + '-time-window" class="form-select form-select-sm"><option value="all">All time</option><option value="daily">Today</option><option value="week">Last 7 days</option><option value="custom">Custom</option></select></div>' +
        '<div id="' + prefix + '-custom-window" class="col-12 d-none"><div class="row g-2">' +
        '<div class="col-md-6"><label class="form-label small">Start</label><input id="' + prefix + '-start" type="datetime-local" class="form-control form-control-sm"></div>' +
        '<div class="col-md-6"><label class="form-label small">End</label><input id="' + prefix + '-end" type="datetime-local" class="form-control form-control-sm"></div></div></div>';
    }

    document.getElementById('newsletter-fields').innerHTML = newsletterFilterMarkup();
    document.getElementById('report-fields').innerHTML = reportFilterMarkup();

    function showMessage(text, kind) { message.textContent = text; message.className = 'alert alert-' + kind; }
    function requestJson(url, options) {
        return fetch(url, options).then(function (response) {
            const contentType = (response.headers.get('content-type') || '').toLowerCase();
            if (!contentType.includes('application/json')) {
                return response.text().then(function () {
                    throw new Error('Server returned HTML instead of JSON.');
                });
            }
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || 'Request failed.');
                return body;
            });
        });
    }
    function apiUrl(email, suffix) { return subscriptionsUrl + '/' + encodeURIComponent(email) + (suffix || ''); }
    function setReportPreview(summary, kind) {
        const box = document.getElementById('report-preview');
        const target = document.getElementById('report-preview-summary');
        box.className = 'alert border small mt-3 mb-0 alert-' + kind;
        target.textContent = summary;
    }
    function isReportEnriched() {
        return document.getElementById('report-generation-mode').value === 'enriched_weekly';
    }
    function keywordKey(value) { return String(value || '').replace(/\s+/g, '').toLowerCase(); }
    function renderReportKeywords() {
        const box = document.getElementById('report-keywords');
        box.replaceChildren();
        if (!reportKeywords.length) {
            const empty = document.createElement('div');
            empty.className = 'text-muted small';
            empty.textContent = 'No keywords selected.';
            box.append(empty);
            scheduleReportPreview();
            return;
        }
        reportKeywords.forEach(function (keyword, index) {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'btn btn-outline-secondary btn-sm';
            chip.textContent = keyword + ' x';
            chip.onclick = function () {
                reportKeywords.splice(index, 1);
                renderReportKeywords();
            };
            box.append(chip);
        });
        scheduleReportPreview();
    }
    function addReportKeyword(value) {
        const keyword = String(value || '').trim();
        if (!keyword) return;
        const key = keywordKey(keyword);
        if (!reportKeywords.some(function (item) { return keywordKey(item) === key; })) {
            reportKeywords.push(keyword);
            renderReportKeywords();
        }
        document.getElementById('report-keyword-input').value = '';
    }
    function clearReportKeywords() {
        reportKeywords = [];
        renderReportKeywords();
    }

    function toggleCustomWindow(prefix) {
        const custom = document.getElementById(prefix + '-time-window').value === 'custom';
        document.getElementById(prefix + '-custom-window').classList.toggle('d-none', !custom);
    }
    function setStatusFilters(prefix, status) {
        const selected = Array.isArray(status) ? status : (status ? [status] : []);
        if (prefix === 'report') {
            document.querySelectorAll('#report-fields .report-status-checkbox').forEach(function (input) {
                input.checked = selected.includes(input.value);
            });
            return;
        }
        document.getElementById(prefix + '-status').value = selected[0] || '';
    }
    function readStatusFilters(prefix) {
        if (prefix === 'report') {
            return Array.from(document.querySelectorAll('#report-fields .report-status-checkbox'))
                .filter(function (input) { return input.checked; })
                .map(function (input) { return input.value; });
        }
        return document.getElementById(prefix + '-status').value;
    }
    function setFilters(prefix, filters) {
        filters = filters || {};
        if (prefix === 'newsletter') {
            newsletterCollections.render(collections, filters.collections || []);
            return;
        }
        if (prefix === 'report') {
            reportKeywords = Array.isArray(filters.keywords) ? filters.keywords.slice() : [];
            renderReportKeywords();
        }
        setStatusFilters(prefix, filters.status || []);
        document.getElementById(prefix + '-include-unknown').checked = filters.include_unknown === true;
        document.getElementById(prefix + '-time-window').value = filters.time_window || 'all';
        toggleCustomWindow(prefix);
    }
    function readFilters(prefix) {
        const filters = {};
        if (prefix === 'newsletter') {
            return {collections: newsletterCollections.selectedValues()};
        } else if (isReportEnriched()) {
            filters.collections = ['cve_review'];
        }
        filters.status = readStatusFilters(prefix);
        if (prefix === 'report') filters.keywords = reportKeywords;
        filters.include_unknown = document.getElementById(prefix + '-include-unknown').checked;
        filters.time_window = document.getElementById(prefix + '-time-window').value;
        filters.start = document.getElementById(prefix + '-start').value;
        filters.end = document.getElementById(prefix + '-end').value;
        if (filters.time_window !== 'custom') { filters.start = ''; filters.end = ''; }
        return filters;
    }
    function buildReportProfilePayload() {
        return {
            report_profile: {
                enabled: document.getElementById('report-enabled').checked,
                filters: readFilters('report'),
                generation_mode: document.getElementById('report-generation-mode').value,
                report_language: document.getElementById('report-language').value,
                schedule_enabled: document.getElementById('report-schedule-enabled').checked,
                schedule_weekday: document.getElementById('report-schedule-weekday').value,
                schedule_time: document.getElementById('report-schedule-time').value
            }
        };
    }
    function refreshReportPreview() {
        if (!document.getElementById('report-enabled').checked) {
            setReportPreview('Report profile is disabled.', 'secondary');
            return;
        }
        if (previewAbortController) previewAbortController.abort();
        previewAbortController = new AbortController();
        const requestId = ++previewRequestId;
        setReportPreview('Loading preview...', 'light');
        requestJson(previewUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(buildReportProfilePayload()),
            signal: previewAbortController.signal
        }).then(function (body) {
            if (requestId !== previewRequestId) return;
            const top = body.top_cves && body.top_cves.length ? body.top_cves.join(', ') : 'No example CVEs yet';
            setReportPreview(body.count + ' matching CVE(s). Top examples: ' + top + '.', body.count ? 'info' : 'warning');
        }).catch(function (e) {
            if (e.name === 'AbortError') return;
            if (requestId !== previewRequestId) return;
            setReportPreview(e.message, 'danger');
        });
    }
    function scheduleReportPreview() {
        if (previewTimer) window.clearTimeout(previewTimer);
        previewTimer = window.setTimeout(refreshReportPreview, 400);
    }
    function openEditor(subscription) {
        editingEmail = subscription ? subscription.email : null;
        document.getElementById('modal-title').textContent = subscription ? 'Edit Subscription' : 'Add Subscription';
        document.getElementById('email').value = subscription ? subscription.email : ''; document.getElementById('email').disabled = !!subscription;
        document.getElementById('team').value = subscription ? subscription.team : '';
        const newsletter = subscription ? subscription.newsletter_profile : {enabled:false,filters:{}};
        const report = subscription ? subscription.report_profile : {enabled:true,filters:{},generation_mode:'template',report_language:'en'};
        document.getElementById('newsletter-enabled').checked = newsletter.enabled; setFilters('newsletter', newsletter.filters);
        document.getElementById('report-enabled').checked = report.enabled; setFilters('report', report.filters);
        document.getElementById('report-generation-mode').value = report.generation_mode;
        document.getElementById('report-language').value = report.report_language;
        document.getElementById('report-schedule-enabled').checked = report.schedule_enabled === true;
        document.getElementById('report-schedule-weekday').value = report.schedule_weekday || 'mon';
        document.getElementById('report-schedule-time').value = report.schedule_time || '09:00';
        refreshReportPreview();
        modal.show();
    }
    function renderRows() {
        rows.replaceChildren(); document.getElementById('empty').classList.toggle('d-none', subscriptions.length !== 0);
        subscriptions.forEach(function (item) {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td><strong></strong><div class="text-muted small"></div></td><td></td><td></td><td></td>';
            tr.children[0].querySelector('strong').textContent = item.email; tr.children[0].querySelector('div').textContent = item.team;
            tr.children[1].textContent = item.newsletter_profile.enabled ? 'Enabled · ' + (item.newsletter_profile.filters.collections.length || 'all') + ' collection(s)' : 'Disabled';
            tr.children[2].textContent = item.report_profile.enabled ? ('Enabled' + (item.report_profile.schedule_enabled ? ' · weekly ' + (item.report_profile.schedule_weekday || '') + ' ' + (item.report_profile.schedule_time || '') + ' HKT' : '')) : 'Disabled';
            const actions = document.createElement('div'); actions.className = 'd-flex flex-wrap gap-1';
            if (item.newsletter_profile.enabled) {
                actions.innerHTML += '<a class="btn btn-outline-primary btn-sm" href="/subscriptions/' + encodeURIComponent(item.email) + '/newsletter-feed">View Feed</a>';
                actions.innerHTML += '<button class="btn btn-success btn-sm send-statistic" type="button">Send Statistic</button>';
            }
            actions.innerHTML += '<button class="btn btn-outline-primary btn-sm edit" type="button">Edit</button><button class="btn btn-outline-danger btn-sm remove" type="button">Delete</button>';
            if (item.newsletter_profile.enabled) {
                actions.querySelector('.send-statistic').onclick = function () {
                    requestJson(apiUrl(item.email, '/send-statistic'), {method:'POST'})
                        .then(function(body){ showMessage(body.message || 'Newsletter statistics email sent.', 'success'); })
                        .catch(function(e){ showMessage(e.message, 'danger'); });
                };
            }
            actions.querySelector('.edit').onclick = function () { openEditor(item); };
            actions.querySelector('.remove').onclick = function () { if (confirm('Delete subscription for ' + item.email + '?')) requestJson(apiUrl(item.email), {method:'DELETE'}).then(load).catch(function(e){showMessage(e.message,'danger');}); };
            tr.children[3].append(actions); rows.append(tr);
        });
    }
    function load() { return requestJson(subscriptionsUrl).then(function(body){subscriptions=body.data;renderRows();}).catch(function(e){showMessage(e.message,'danger');}).finally(function(){document.getElementById('loading').classList.add('d-none');}); }
    newsletterCollections.wire();
    document.getElementById('report-time-window').addEventListener('change', function () { toggleCustomWindow('report'); });
    document.getElementById('report-keyword-add').addEventListener('click', function () {
        addReportKeyword(document.getElementById('report-keyword-input').value);
    });
    document.getElementById('report-keyword-input').addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            addReportKeyword(event.target.value);
        }
    });
    document.getElementById('report-keyword-clear').addEventListener('click', clearReportKeywords);
    document.getElementById('report-enabled').addEventListener('change', refreshReportPreview);
    document.getElementById('report-generation-mode').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-language').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-enabled').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-weekday').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-schedule-time').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-time-window').addEventListener('change', scheduleReportPreview);
    document.getElementById('report-start').addEventListener('input', scheduleReportPreview);
    document.getElementById('report-end').addEventListener('input', scheduleReportPreview);
    document.querySelectorAll('#report-fields .report-status-checkbox').forEach(function (input) {
        input.addEventListener('change', scheduleReportPreview);
    });
    document.getElementById('report-include-unknown').addEventListener('change', scheduleReportPreview);
    document.getElementById('add-btn').onclick = function () { openEditor(null); };
    document.getElementById('subscription-form').onsubmit = function (event) {
        event.preventDefault();
        const payload = { email:document.getElementById('email').value, team:document.getElementById('team').value,
            newsletter_profile:{enabled:document.getElementById('newsletter-enabled').checked,filters:readFilters('newsletter')},
            report_profile: buildReportProfilePayload().report_profile };
        requestJson(editingEmail ? apiUrl(editingEmail) : subscriptionsUrl, {method:editingEmail?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(function(){modal.hide();showMessage('Subscription saved.','success');return load();}).catch(function(e){showMessage(e.message,'danger');});
    };
    requestJson(reviewsUrl).then(function(body){collections=body.data.map(function(item){return item.name;});return load();}).catch(function(e){showMessage(e.message,'danger');});
})();
