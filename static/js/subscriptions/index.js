(function () {
    const {
        subscriptionsUrl,
        previewUrl,
        reviewsUrl,
        vendorProductImportUrl,
        vendorProductTemplateUrl,
    } = JSON.parse(document.getElementById('page-config').textContent);
    const modal = new bootstrap.Modal(document.getElementById('subscription-modal'));
    const newsletterCollections = new CollectionPicker('newsletter', {emptySelectionMeansAll: true});
    const rows = document.getElementById('rows');
    const message = document.getElementById('message');
    let collections = [], subscriptions = [], editingEmail = null;
    let reportVendorProductFilter = emptyVendorProductFilter();
    let reportLegacyKeywords = [];
    let reportOriginalLegacyKeywords = [];
    let reportHasLegacyKeywords = false;
    let vendorProductImportBusy = false;
    let vendorProductImportRequestId = 0;
    let previewTimer = null;
    let previewAbortController = null;
    let previewRequestId = 0;

    const severityLevels = ['Critical', 'High', 'Medium', 'Low'];
    function emptyVendorProductFilter() {
        return {
            enabled: false,
            schema_version: 1,
            include_possible_matches: false,
            rows: []
        };
    }
    function newsletterFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-md-6">' +
        '<label for="newsletter-collections-toggle" class="form-label small">' + t('Collections') + '</label>' +
        '<div class="dropdown w-100">' +
        '<button id="newsletter-collections-toggle" type="button" class="form-select form-select-sm dropdown-toggle subscription-collections-toggle text-start w-100" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">' + t('All collections') + '</button>' +
        '<div id="newsletter-collections-menu" class="dropdown-menu w-100 shadow-sm p-2">' +
        '<input id="newsletter-collections-search" type="search" class="form-control form-control-sm mb-2" placeholder="' + t('Search collections...') + '" autocomplete="off">' +
        '<div id="newsletter-collections-options" class="subscription-collections-options"></div>' +
        '<div class="dropdown-divider my-2"></div>' +
        '<div class="d-flex justify-content-between px-1">' +
        '<button type="button" class="btn btn-link btn-sm p-0 collections-action" data-action="all">' + t('Select all') + '</button>' +
        '<button type="button" class="btn btn-link btn-sm p-0 text-muted collections-action" data-action="reset">' + t('Reset to all') + '</button>' +
        '</div></div></div></div></div>';
    }

    function reportFilterMarkup() {
        return '<div class="row g-2">' +
        '<div class="col-12"><label class="form-label small">' + t('Severity / status') + '</label><div class="d-flex flex-wrap gap-3">' +
        severityLevels.map(function (level) {
            return '<div class="form-check"><input id="report-status-' + level + '" class="form-check-input report-status-checkbox" type="checkbox" value="' + level + '"><label class="form-check-label small" for="report-status-' + level + '">' + t(level) + '</label></div>';
        }).join('') +
        '</div><div class="form-text">' + t('Leave all unchecked to match all known severities.') + '</div></div>' +
        '<div class="col-12"><div id="report-vendor-product-import" class="subscription-vendor-product-import border rounded p-3">' +
        '<div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2"><label class="form-label small fw-semibold mb-0" for="report-vendor-product-file">' + t('Product inventory (CSV)') + '</label><a id="report-vendor-product-template" class="btn btn-outline-secondary btn-sm" href="#" download><i class="bi bi-download me-1"></i>' + t('Download CSV template') + '</a></div>' +
        '<input id="report-vendor-product-file" class="form-control form-control-sm" type="file" accept=".csv,text/csv" aria-describedby="report-vendor-product-help">' +
        '<div id="report-vendor-product-help" class="form-text">' + t('Choose a CSV with vendor and product rows. It is validated and loaded into this form; changes apply only after you save.') + '</div>' +
        '<div class="subscription-match-warning small mt-2"><i class="bi bi-exclamation-triangle me-1"></i>' + t('CVE vendor and product data may be incomplete. Matching can produce false positives or false negatives; review the report preview before saving.') + '</div>' +
        '<div id="report-legacy-keywords-warning" class="alert alert-warning small py-2 mt-2 mb-0 d-none" role="alert"></div>' +
        '<div id="report-vendor-product-status" class="alert small py-2 mt-2 mb-0 d-none" role="status" aria-live="polite"></div>' +
        '<div id="report-vendor-product-summary" class="small text-muted mt-2"></div>' +
        '<div id="report-vendor-product-preview" class="table-responsive subscription-vendor-product-preview mt-2 d-none"><table class="table table-sm table-bordered align-middle mb-0"><thead class="table-light"><tr><th>' + t('CSV row') + '</th><th>' + t('Vendor') + '</th><th>' + t('Product') + '</th><th>' + t('Vendor aliases') + '</th><th>' + t('Product aliases') + '</th></tr></thead><tbody id="report-vendor-product-rows"></tbody></table></div>' +
        '<div id="report-vendor-product-preview-note" class="form-text d-none"></div>' +
        '<div class="d-flex flex-wrap justify-content-between align-items-start gap-2 mt-2"><div class="form-check"><input id="report-include-possible-matches" class="form-check-input" type="checkbox" aria-describedby="report-include-possible-help"><label class="form-check-label small" for="report-include-possible-matches">' + t('Include product-only possible matches when structured vendor data is missing') + '</label><div id="report-include-possible-help" class="form-text">' + t('This may reduce false negatives but increases false-positive risk. Ambiguous products and known conflicting inventory vendors are suppressed.') + '</div></div><button id="report-vendor-product-clear" class="btn btn-outline-danger btn-sm" type="button">' + t('Clear inventory') + '</button></div>' +
        '</div></div>' +
        '<div class="col-md-6 d-flex align-items-end"><div class="form-check mb-2"><input id="report-include-unknown" class="form-check-input" type="checkbox"><label class="form-check-label small" for="report-include-unknown">' + t('Include unknown severity') + '</label></div></div>' +
        timeWindowMarkup('report') +
        '</div>';
    }

    function timeWindowMarkup(prefix) {
        return '<div class="col-md-6"><label class="form-label small">' + t('Time window') + '</label><select id="' + prefix + '-time-window" class="form-select form-select-sm"><option value="all">' + t('All time') + '</option><option value="daily">' + t('Today') + '</option><option value="week">' + t('Last 7 days') + '</option><option value="custom">' + t('Custom') + '</option></select></div>' +
        '<div id="' + prefix + '-custom-window" class="col-12 d-none"><div class="row g-2">' +
        '<div class="col-md-6"><label class="form-label small">' + t('Start') + '</label><input id="' + prefix + '-start" type="datetime-local" class="form-control form-control-sm"></div>' +
        '<div class="col-md-6"><label class="form-label small">' + t('End') + '</label><input id="' + prefix + '-end" type="datetime-local" class="form-control form-control-sm"></div></div></div>';
    }

    document.getElementById('newsletter-fields').innerHTML = newsletterFilterMarkup();
    document.getElementById('report-fields').innerHTML = reportFilterMarkup();
    document.getElementById('report-vendor-product-template').href = vendorProductTemplateUrl;

    function showMessage(text, kind) { message.textContent = text; message.className = 'alert alert-' + kind; }
    function showModalMessage(text, kind) {
        const modalMessage = document.getElementById('subscription-modal-message');
        modalMessage.textContent = text || '';
        modalMessage.className = text ? 'alert alert-' + kind : 'alert d-none';
    }
    function setSendStatisticStatus(text, kind) {
        const status = document.getElementById('newsletter-send-statistic-status');
        if (!text) {
            status.textContent = '';
            status.className = 'alert small mt-2 mb-0 d-none';
            return;
        }
        status.textContent = text;
        status.className = 'alert alert-' + kind + ' small mt-2 mb-0';
    }
    function setSendStatisticBusy(busy) {
        const button = document.getElementById('newsletter-send-statistic');
        const label = button.querySelector('.send-statistic-label');
        button.disabled = busy;
        if (busy) {
            label.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>' + t('Sending...');
        } else {
            label.textContent = t('Send Statistic');
        }
    }
    function requestJson(url, options) {
        return fetch(url, options).then(function (response) {
            const contentType = (response.headers.get('content-type') || '').toLowerCase();
            if (!contentType.includes('application/json')) {
                return response.text().then(function () {
                    throw new Error(t('Server returned HTML instead of JSON.'));
                });
            }
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || t('Request failed.'));
                return body;
            });
        });
    }
    function apiUrl(email, suffix) { return subscriptionsUrl + '/' + encodeURIComponent(email) + (suffix || ''); }
    function setReportPreview(summary, kind, examples) {
        const box = document.getElementById('report-preview');
        const target = document.getElementById('report-preview-summary');
        const exampleList = document.getElementById('report-preview-examples');
        box.className = 'alert border small mt-3 mb-0 alert-' + kind;
        target.textContent = summary;
        exampleList.replaceChildren();
        const confidenceLabels = {
            confirmed: t('Confirmed'),
            probable: t('Probable'),
            possible: t('Possible')
        };
        (Array.isArray(examples) ? examples : []).forEach(function (example) {
            const evidence = example.evidence && typeof example.evidence === 'object'
                ? example.evidence : {};
            const evidenceSummary = evidence.text || evidence.product || [
                evidence.vendor,
                evidence.product
            ].filter(Boolean).join(' / ') || evidence.source || evidence.type || '—';
            const item = document.createElement('li');
            item.textContent = t('{cve} — {confidence} vendor/product match: {vendor} / {product}. Evidence: {evidence}', {
                cve: example.cve || '—',
                confidence: confidenceLabels[example.confidence] || example.confidence || '—',
                vendor: example.matched_vendor || '—',
                product: example.matched_product || '—',
                evidence: evidence.source
                    ? evidence.source + ': ' + evidenceSummary
                    : evidenceSummary
            });
            exampleList.append(item);
        });
        exampleList.classList.toggle('d-none', exampleList.children.length === 0);
    }
    function isReportEnriched() {
        return document.getElementById('report-generation-mode').value === 'enriched_weekly';
    }
    function updateReportSearchPromptVisibility() {
        const wrap = document.getElementById('report-search-prompt-wrap');
        if (wrap) {
            wrap.classList.toggle('d-none', !isReportEnriched());
        }
    }
    function normalizeVendorProductRow(value) {
        if (!value || typeof value !== 'object') return null;
        const vendor = typeof value.vendor === 'string' ? value.vendor.trim() : '';
        const product = typeof value.product === 'string' ? value.product.trim() : '';
        if (!vendor || !product) return null;
        function aliases(items) {
            if (!Array.isArray(items)) return [];
            return items.filter(function (item) { return typeof item === 'string' && item.trim(); })
                .map(function (item) { return item.trim(); });
        }
        const normalized = {
            vendor: vendor,
            product: product,
            vendor_aliases: aliases(value.vendor_aliases),
            product_aliases: aliases(value.product_aliases)
        };
        if (Number.isInteger(value.row_number) && value.row_number >= 2) {
            normalized.row_number = value.row_number;
        }
        return normalized;
    }
    function normalizeVendorProductFilter(value) {
        value = value && typeof value === 'object' ? value : {};
        const normalizedRows = Array.isArray(value.rows) ? value.rows.map(normalizeVendorProductRow).filter(Boolean) : [];
        return {
            enabled: value.enabled === true && normalizedRows.length > 0,
            schema_version: 1,
            include_possible_matches: value.include_possible_matches === true,
            rows: normalizedRows
        };
    }
    function hasValidVendorProductInventory() {
        return reportVendorProductFilter.enabled === true && reportVendorProductFilter.rows.length > 0;
    }
    function vendorProductFilterPayload() {
        return {
            enabled: hasValidVendorProductInventory(),
            schema_version: 1,
            include_possible_matches: document.getElementById('report-include-possible-matches').checked,
            rows: reportVendorProductFilter.rows.map(function (row) {
                const payloadRow = {
                    vendor: row.vendor,
                    product: row.product,
                    vendor_aliases: row.vendor_aliases.slice(),
                    product_aliases: row.product_aliases.slice()
                };
                if (Number.isInteger(row.row_number) && row.row_number >= 2) {
                    payloadRow.row_number = row.row_number;
                }
                return payloadRow;
            })
        };
    }
    function renderLegacyKeywordWarning() {
        const warning = document.getElementById('report-legacy-keywords-warning');
        warning.classList.toggle('d-none', !reportHasLegacyKeywords);
        warning.textContent = reportHasLegacyKeywords
            ? (reportLegacyKeywords.length
                ? t('This subscription contains a legacy keyword filter. It remains unchanged unless you load a valid product CSV and save the subscription.')
                : t('A valid product inventory is ready. It will replace the legacy keyword filter when you save.'))
            : '';
    }
    function renderVendorProductInventory() {
        const preview = document.getElementById('report-vendor-product-preview');
        const previewRows = document.getElementById('report-vendor-product-rows');
        const summary = document.getElementById('report-vendor-product-summary');
        const note = document.getElementById('report-vendor-product-preview-note');
        const clearButton = document.getElementById('report-vendor-product-clear');
        const inventoryRows = reportVendorProductFilter.rows;
        const shownRows = inventoryRows.slice(0, 25);

        previewRows.replaceChildren();
        summary.textContent = inventoryRows.length
            ? t('{count} vendor/product row(s) loaded and ready to save.', {count: inventoryRows.length})
            : t('No vendor/product inventory loaded. Other report filters may match all vendors and products.');
        preview.classList.toggle('d-none', inventoryRows.length === 0);
        clearButton.disabled = vendorProductImportBusy || inventoryRows.length === 0;

        shownRows.forEach(function (row, index) {
            const tr = document.createElement('tr');
            [
                row.row_number || index + 2,
                row.vendor,
                row.product,
                row.vendor_aliases.join(', ') || '—',
                row.product_aliases.join(', ') || '—'
            ].forEach(function (value) {
                const td = document.createElement('td');
                td.textContent = value;
                tr.append(td);
            });
            previewRows.append(tr);
        });

        const truncated = inventoryRows.length > shownRows.length;
        note.classList.toggle('d-none', !truncated);
        note.textContent = truncated
            ? t('Showing the first {shown} of {count} loaded rows.', {shown: shownRows.length, count: inventoryRows.length})
            : '';
        renderLegacyKeywordWarning();
    }
    function setVendorProductImportStatus(text, kind, warnings) {
        const status = document.getElementById('report-vendor-product-status');
        status.replaceChildren();
        if (!text && (!warnings || !warnings.length)) {
            status.className = 'alert small py-2 mt-2 mb-0 d-none';
            return;
        }
        status.className = 'alert alert-' + kind + ' small py-2 mt-2 mb-0';
        if (text) {
            const messageText = document.createElement('div');
            messageText.textContent = text;
            status.append(messageText);
        }
        if (Array.isArray(warnings) && warnings.length) {
            const list = document.createElement('ul');
            list.className = 'mb-0 mt-1 ps-3';
            warnings.forEach(function (warning) {
                const item = document.createElement('li');
                item.textContent = String(warning);
                list.append(item);
            });
            status.append(list);
        }
    }
    function setVendorProductImportBusy(busy) {
        vendorProductImportBusy = busy;
        const container = document.getElementById('report-vendor-product-import');
        const input = document.getElementById('report-vendor-product-file');
        const includePossible = document.getElementById('report-include-possible-matches');
        const saveButton = document.querySelector('#subscription-form button[type="submit"]');
        container.setAttribute('aria-busy', busy ? 'true' : 'false');
        input.disabled = busy;
        includePossible.disabled = busy;
        saveButton.disabled = busy;
        renderVendorProductInventory();
    }
    function importVendorProductCsv(file) {
        if (!file || vendorProductImportBusy) return;
        const requestId = ++vendorProductImportRequestId;
        const includePossibleMatches = document.getElementById('report-include-possible-matches').checked;
        const form = new FormData();
        form.append('file', file);
        setVendorProductImportBusy(true);
        setVendorProductImportStatus(t('Validating CSV...'), 'info');
        requestJson(vendorProductImportUrl, {method: 'POST', body: form})
            .then(function (body) {
                if (requestId !== vendorProductImportRequestId) return;
                const imported = normalizeVendorProductFilter(body.vendor_product_filter);
                if (!imported.enabled || !imported.rows.length) {
                    throw new Error(t('The CSV did not contain any valid vendor/product rows.'));
                }
                imported.include_possible_matches = includePossibleMatches;
                reportVendorProductFilter = imported;
                reportLegacyKeywords = [];
                document.getElementById('report-include-possible-matches').checked = includePossibleMatches;
                renderVendorProductInventory();
                setVendorProductImportStatus(
                    t('Validated and loaded {count} vendor/product row(s). Save the subscription to apply them.', {count: imported.rows.length}),
                    body.warnings && body.warnings.length ? 'warning' : 'success',
                    body.warnings
                );
                scheduleReportPreview();
            })
            .catch(function (error) {
                if (requestId !== vendorProductImportRequestId) return;
                setVendorProductImportStatus(error.message, 'danger');
            })
            .finally(function () {
                if (requestId !== vendorProductImportRequestId) return;
                document.getElementById('report-vendor-product-file').value = '';
                setVendorProductImportBusy(false);
            });
    }
    function clearVendorProductInventory() {
        if (!window.confirm(t('Clear the product inventory? Other report filters may then match all vendors and products.'))) {
            return;
        }
        const includePossibleMatches = document.getElementById('report-include-possible-matches').checked;
        reportVendorProductFilter = emptyVendorProductFilter();
        reportVendorProductFilter.include_possible_matches = includePossibleMatches;
        reportLegacyKeywords = reportOriginalLegacyKeywords.slice();
        document.getElementById('report-vendor-product-file').value = '';
        renderVendorProductInventory();
        setVendorProductImportStatus(t('Product inventory will be cleared when you save.'), 'secondary');
        scheduleReportPreview();
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
            const legacyKeywords = Array.isArray(filters.keywords)
                ? filters.keywords.filter(function (item) { return typeof item === 'string' && item.trim(); })
                : [];
            reportVendorProductFilter = normalizeVendorProductFilter(filters.vendor_product_filter);
            reportOriginalLegacyKeywords = legacyKeywords.slice();
            reportHasLegacyKeywords = legacyKeywords.length > 0;
            reportLegacyKeywords = hasValidVendorProductInventory() ? [] : legacyKeywords.slice();
            document.getElementById('report-include-possible-matches').checked = reportVendorProductFilter.include_possible_matches;
            document.getElementById('report-vendor-product-file').value = '';
            setVendorProductImportStatus('', '');
            renderVendorProductInventory();
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
        if (prefix === 'report') {
            filters.vendor_product_filter = vendorProductFilterPayload();
            if (reportLegacyKeywords.length && !hasValidVendorProductInventory()) {
                filters.keywords = reportLegacyKeywords.slice();
            }
        }
        filters.include_unknown = document.getElementById(prefix + '-include-unknown').checked;
        filters.time_window = document.getElementById(prefix + '-time-window').value;
        filters.start = document.getElementById(prefix + '-start').value;
        filters.end = document.getElementById(prefix + '-end').value;
        if (filters.time_window !== 'custom') { filters.start = ''; filters.end = ''; }
        return filters;
    }
    function buildReportProfilePayload() {
        const payload = {
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
        if (isReportEnriched()) {
            payload.report_profile.search_prompt = (document.getElementById('report-search-prompt').value || '').trim();
        }
        return payload;
    }
    function refreshReportPreview() {
        const requestId = ++previewRequestId;
        if (previewAbortController) {
            previewAbortController.abort();
            previewAbortController = null;
        }
        if (!document.getElementById('report-enabled').checked) {
            setReportPreview(t('Report profile is disabled.'), 'secondary');
            return;
        }
        if (reportLegacyKeywords.length && !hasValidVendorProductInventory()) {
            setReportPreview(
                t('Import a vendor/product CSV to replace the legacy keyword filter and preview confidence levels.'),
                'warning'
            );
            return;
        }
        previewAbortController = new AbortController();
        setReportPreview(t('Loading preview...'), 'light');
        requestJson(previewUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(buildReportProfilePayload()),
            signal: previewAbortController.signal
        }).then(function (body) {
            if (requestId !== previewRequestId) return;
            const top = body.top_cves && body.top_cves.length ? body.top_cves.join(', ') : t('No example CVEs yet');
            const summary = body.vendor_product_filter_enabled
                ? t('{count} CVE(s) matched the inventory. Vendor/product match confidence: {confirmed} confirmed, {probable} probable, {possible} possible. Top examples: {top}.', {
                    count: body.count || 0,
                    confirmed: body.confirmed_count || 0,
                    probable: body.probable_count || 0,
                    possible: body.possible_count || 0,
                    top: top
                })
                : t('{count} matching CVE(s). Top examples: {top}.', {count: body.count || 0, top: top});
            setReportPreview(
                summary,
                body.count ? 'info' : 'warning',
                body.match_examples || []
            );
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
        vendorProductImportRequestId += 1;
        setVendorProductImportBusy(false);
        showModalMessage('', '');
        editingEmail = subscription ? subscription.email : null;
        document.getElementById('modal-title').textContent = subscription ? t('Edit Subscription') : t('Add Subscription');
        document.getElementById('email').value = subscription ? subscription.email : ''; document.getElementById('email').disabled = !!subscription;
        document.getElementById('team').value = subscription ? subscription.team : '';
        const newsletter = subscription ? subscription.newsletter_profile : {enabled:false,filters:{}};
        const report = subscription ? subscription.report_profile : {enabled:true,filters:{},generation_mode:'template',report_language:'en'};
        document.getElementById('newsletter-enabled').checked = newsletter.enabled; setFilters('newsletter', newsletter.filters);
        document.getElementById('newsletter-statistic-schedule-enabled').checked = newsletter.statistic_schedule_enabled === true;
        document.getElementById('report-enabled').checked = report.enabled; setFilters('report', report.filters);
        setVendorProductImportBusy(false);
        document.getElementById('report-generation-mode').value = report.generation_mode;
        document.getElementById('report-language').value = report.report_language;
        document.getElementById('report-search-prompt').value = report.search_prompt || '';
        document.getElementById('report-schedule-enabled').checked = report.schedule_enabled === true;
        document.getElementById('report-schedule-weekday').value = report.schedule_weekday || 'mon';
        document.getElementById('report-schedule-time').value = report.schedule_time || '09:00';
        setSendStatisticBusy(false);
        setSendStatisticStatus('', '');
        updateNewsletterSendStatisticVisibility();
        updateReportSearchPromptVisibility();
        refreshReportPreview();
        modal.show();
    }
    function updateNewsletterSendStatisticVisibility() {
        const wrap = document.getElementById('newsletter-send-statistic-wrap');
        const show = !!editingEmail && document.getElementById('newsletter-enabled').checked;
        wrap.classList.toggle('d-none', !show);
        if (!show) {
            setSendStatisticStatus('', '');
            setSendStatisticBusy(false);
        }
    }
    function renderRows() {
        rows.replaceChildren(); document.getElementById('empty').classList.toggle('d-none', subscriptions.length !== 0);
        subscriptions.forEach(function (item) {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td><strong></strong><div class="text-muted small"></div></td><td></td><td></td><td></td>';
            tr.children[0].querySelector('strong').textContent = item.email; tr.children[0].querySelector('div').textContent = item.team;
            const collectionCount = item.newsletter_profile.filters.collections.length;
            tr.children[1].textContent = item.newsletter_profile.enabled ? (collectionCount ? t('Enabled · {count} collection(s)', {count: collectionCount}) : t('Enabled · all collection(s)')) : t('Disabled');
            if (item.report_profile.enabled) {
                const reportSummary = [item.report_profile.schedule_enabled
                    ? t('Enabled · weekly {weekday} {time} HKT', {weekday: item.report_profile.schedule_weekday || '', time: item.report_profile.schedule_time || ''})
                    : t('Enabled')];
                const inventory = item.report_profile.filters.vendor_product_filter || {};
                if (inventory.enabled && Array.isArray(inventory.rows) && inventory.rows.length) {
                    reportSummary.push(t('{count} product(s)', {count: inventory.rows.length}));
                } else if (Array.isArray(item.report_profile.filters.keywords) && item.report_profile.filters.keywords.length) {
                    reportSummary.push(t('legacy keyword filter'));
                }
                tr.children[2].textContent = reportSummary.join(' · ');
            } else {
                tr.children[2].textContent = t('Disabled');
            }
            const actions = document.createElement('div'); actions.className = 'd-flex flex-wrap gap-1';
            actions.innerHTML = '<button class="btn btn-outline-primary btn-sm edit" type="button">' + t('Edit') + '</button><button class="btn btn-outline-danger btn-sm remove" type="button">' + t('Delete') + '</button>';
            actions.querySelector('.edit').onclick = function () { openEditor(item); };
            actions.querySelector('.remove').onclick = function () { if (confirm(t('Delete subscription for {email}?', {email: item.email}))) requestJson(apiUrl(item.email), {method:'DELETE'}).then(load).catch(function(e){showMessage(e.message,'danger');}); };
            tr.children[3].append(actions); rows.append(tr);
        });
    }
    function load() { return requestJson(subscriptionsUrl).then(function(body){subscriptions=body.data;renderRows();}).catch(function(e){showMessage(e.message,'danger');}).finally(function(){document.getElementById('loading').classList.add('d-none');}); }
    newsletterCollections.wire();
    document.getElementById('report-time-window').addEventListener('change', function () { toggleCustomWindow('report'); });
    document.getElementById('report-vendor-product-file').addEventListener('change', function (event) {
        importVendorProductCsv(event.target.files && event.target.files[0]);
    });
    document.getElementById('report-vendor-product-clear').addEventListener('click', clearVendorProductInventory);
    document.getElementById('report-include-possible-matches').addEventListener('change', function (event) {
        reportVendorProductFilter.include_possible_matches = event.target.checked;
        scheduleReportPreview();
    });
    document.getElementById('report-enabled').addEventListener('change', refreshReportPreview);
    document.getElementById('report-generation-mode').addEventListener('change', function () {
        updateReportSearchPromptVisibility();
        scheduleReportPreview();
    });
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
    document.getElementById('newsletter-enabled').addEventListener('change', updateNewsletterSendStatisticVisibility);
    document.getElementById('newsletter-send-statistic').addEventListener('click', function () {
        if (!editingEmail || document.getElementById('newsletter-send-statistic').disabled) return;
        setSendStatisticBusy(true);
        setSendStatisticStatus(t('Sending statistics email...'), 'info');
        requestJson(apiUrl(editingEmail, '/send-statistic'), {method: 'POST'})
            .then(function (body) {
                const text = body.message || t('Newsletter statistics email sent.');
                setSendStatisticStatus(text, 'success');
                showMessage(text, 'success');
            })
            .catch(function (e) {
                setSendStatisticStatus(e.message, 'danger');
                showMessage(e.message, 'danger');
            })
            .finally(function () {
                setSendStatisticBusy(false);
            });
    });
    document.getElementById('subscription-form').onsubmit = function (event) {
        event.preventDefault();
        if (vendorProductImportBusy) {
            showModalMessage(t('Wait for CSV validation to finish before saving.'), 'warning');
            return;
        }
        showModalMessage('', '');
        const payload = { email:document.getElementById('email').value, team:document.getElementById('team').value,
            newsletter_profile:{
                enabled:document.getElementById('newsletter-enabled').checked,
                filters:readFilters('newsletter'),
                statistic_schedule_enabled:document.getElementById('newsletter-statistic-schedule-enabled').checked
            },
            report_profile: buildReportProfilePayload().report_profile };
        requestJson(editingEmail ? apiUrl(editingEmail) : subscriptionsUrl, {method:editingEmail?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(function(){modal.hide();showMessage(t('Subscription saved.'),'success');return load();}).catch(function(e){showModalMessage(e.message,'danger');});
    };
    requestJson(reviewsUrl).then(function(body){collections=body.data.map(function(item){return item.name;});return load();}).catch(function(e){showMessage(e.message,'danger');});
})();
