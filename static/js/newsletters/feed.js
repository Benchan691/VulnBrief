(function () {
    const {email, savedFilters, queryUrl, reviewsUrl} = JSON.parse(
        document.getElementById('page-config').textContent
    );
    const rows = document.getElementById('rows');
    const message = document.getElementById('message');
    const prompt = document.getElementById('prompt');
    const loading = document.getElementById('loading');
    const empty = document.getElementById('empty');
    const resultSummary = document.getElementById('result-summary');
    const keyword = document.getElementById('feed-keyword');
    const pageSize = document.getElementById('page-size');
    const pagination = document.getElementById('pagination');
    const pageLabel = document.getElementById('page-label');
    const previousPage = document.getElementById('previous-page');
    const nextPage = document.getElementById('next-page');
    const previewModal = new bootstrap.Modal(document.getElementById('preview-modal'));
    const collectionPicker = new CollectionPicker('feed');
    let collections = [];
    let currentPage = 1;
    let totalPages = 0;

    function previewUrl(item) {
        return '/generated-newsletters/'
            + encodeURIComponent(item.source_collection) + '/'
            + encodeURIComponent(item.selection_id) + '/preview';
    }

    function filterMarkup(prefix) {
        return '<div class="row g-2">' +
        '<div class="col-md-6">' +
        '<label for="' + prefix + '-collections-toggle" class="form-label small">Collections</label>' +
        '<div class="dropdown w-100">' +
        '<button id="' + prefix + '-collections-toggle" type="button" class="form-select form-select-sm dropdown-toggle text-start w-100" data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">All collections</button>' +
        '<div id="' + prefix + '-collections-menu" class="dropdown-menu w-100 shadow-sm p-2">' +
        '<input id="' + prefix + '-collections-search" type="search" class="form-control form-control-sm mb-2" placeholder="Search collections..." autocomplete="off">' +
        '<div id="' + prefix + '-collections-options"></div>' +
        '<div class="dropdown-divider my-2"></div>' +
        '<div class="d-flex justify-content-between px-1">' +
        '<button type="button" class="btn btn-link btn-sm p-0 collections-action" data-action="all">Select all</button>' +
        '<button type="button" class="btn btn-link btn-sm p-0 text-muted collections-action" data-action="clear">Clear</button>' +
        '</div></div></div></div></div>';
    }

    document.getElementById('feed-fields').innerHTML = filterMarkup('feed');

    function showMessage(text, kind) {
        message.textContent = text;
        message.className = 'alert alert-' + kind;
    }

    function requestJson(url, options) {
        return fetch(url, options).then(function (response) {
            return response.json().then(function (body) {
                if (!response.ok) throw new Error(body.error || 'Request failed.');
                return body;
            });
        });
    }

    function setFilters(filters) {
        filters = filters || {};
        collectionPicker.render(collections, filters.collections || []);
        keyword.value = filters.keyword || '';
    }

    function readFilters() {
        const filters = {
            collections: collectionPicker.selectedValues(),
            keyword: keyword.value.trim(),
        };
        return filters;
    }

    function setViewState(state) {
        prompt.classList.toggle('d-none', state !== 'prompt');
        loading.classList.toggle('d-none', state !== 'loading');
        empty.classList.toggle('d-none', state !== 'empty');
        rows.parentElement.parentElement.classList.toggle('d-none', state === 'prompt' || state === 'loading');
        if (state !== 'results') {
            pagination.classList.add('d-none');
        }
    }

    function updatePagination(body) {
        currentPage = body.page || 1;
        totalPages = body.pages || 0;
        const hasPages = totalPages > 0 && body.count > 0;
        pagination.classList.toggle('d-none', !hasPages);
        if (!hasPages) {
            return;
        }
        pageLabel.textContent = 'Page ' + currentPage + ' of ' + totalPages;
        previousPage.disabled = currentPage <= 1;
        nextPage.disabled = currentPage >= totalPages;
    }

    function renderRows(items) {
        rows.replaceChildren();
        items.forEach(function (item) {
            const tr = document.createElement('tr');
            const url = previewUrl(item);
            tr.innerHTML = '<td></td><td></td><td></td><td></td><td><button class="btn btn-outline-primary btn-sm me-1 preview-btn" type="button">Preview</button><button class="btn btn-outline-secondary btn-sm copy-btn" type="button">Copy HTML</button></td>';
            tr.children[0].textContent = item.generated_at ? new Date(item.generated_at).toLocaleString() : '';
            tr.children[1].textContent = item.source_collection;
            tr.children[2].textContent = item.title;
            tr.children[3].textContent = item.template_key;
            tr.querySelector('.preview-btn').addEventListener('click', function () {
                document.getElementById('preview-frame').src = url;
                previewModal.show();
            });
            tr.querySelector('.copy-btn').addEventListener('click', function () {
                fetch(url).then(function (response) {
                    if (!response.ok) throw new Error('Unable to load newsletter HTML.');
                    return response.text();
                }).then(function (html) {
                    return navigator.clipboard.writeText(html);
                }).catch(function (error) {
                    showMessage(error.message, 'danger');
                });
            });
            rows.append(tr);
        });
    }

    function applyFilters(page) {
        currentPage = page || 1;
        message.className = 'alert d-none';
        setViewState('loading');
        resultSummary.classList.add('d-none');
        requestJson(queryUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                filters: readFilters(),
                page: currentPage,
                page_size: parseInt(pageSize.value, 10),
            }),
        }).then(function (body) {
            renderRows(body.data);
            if (body.count === 0) {
                setViewState('empty');
                updatePagination(body);
            } else {
                setViewState('results');
                resultSummary.textContent = body.count + ' matching newsletter' + (body.count === 1 ? '' : 's');
                resultSummary.classList.remove('d-none');
                updatePagination(body);
            }
        }).catch(function (error) {
            setViewState('prompt');
            showMessage(error.message, 'danger');
        });
    }

    collectionPicker.wire();

    document.getElementById('apply-btn').onclick = function () { applyFilters(1); };
    document.getElementById('clear-btn').onclick = function () {
        setFilters({});
        rows.replaceChildren();
        currentPage = 1;
        totalPages = 0;
        resultSummary.classList.add('d-none');
        pagination.classList.add('d-none');
        message.className = 'alert d-none';
        setViewState('prompt');
    };
    previousPage.addEventListener('click', function () {
        if (currentPage > 1) applyFilters(currentPage - 1);
    });
    nextPage.addEventListener('click', function () {
        if (currentPage < totalPages) applyFilters(currentPage + 1);
    });
    pageSize.addEventListener('change', function () {
        if (!resultSummary.classList.contains('d-none') || !empty.classList.contains('d-none')) {
            applyFilters(1);
        }
    });

    requestJson(reviewsUrl).then(function (body) {
        collections = body.data.map(function (item) { return item.name; });
        setFilters(savedFilters);
        setViewState('prompt');
    }).catch(function (error) {
        showMessage(error.message, 'danger');
    });
})();
