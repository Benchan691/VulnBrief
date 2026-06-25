import csv
import os
from functools import lru_cache


@lru_cache(maxsize=1)
def load_cpe_pairs(path):
    if not os.path.exists(path):
        return []
    with open(path, newline='', encoding='utf-8') as handle:
        return [
            {
                'vendor': (row.get('vendor') or '').strip(),
                'product': (row.get('product') or '').strip(),
            }
            for row in csv.DictReader(handle)
            if (row.get('vendor') or '').strip() and (row.get('product') or '').strip()
        ]


def search_cpe_pairs(path, query='', limit=50):
    terms = [term for term in str(query or '').lower().split() if term]
    results = []
    for pair in load_cpe_pairs(path):
        haystack = f"{pair['vendor']} {pair['product']}".lower()
        if terms and not all(term in haystack for term in terms):
            continue
        results.append({
            **pair,
            'label': f"{pair['vendor']} | {pair['product']}",
        })
        if len(results) >= limit:
            break
    return results


def search_cpe_vendors(path, query='', limit=50):
    terms = [term for term in str(query or '').lower().split() if term]
    results = []
    seen = set()
    for pair in load_cpe_pairs(path):
        vendor = pair['vendor']
        key = vendor.lower()
        if key in seen or (terms and not all(term in key for term in terms)):
            continue
        seen.add(key)
        results.append({'vendor': vendor, 'label': vendor})
        if len(results) >= limit:
            break
    return results


def search_cpe_products(path, vendor, query='', limit=50):
    vendor_key = str(vendor or '').strip().lower()
    terms = [term for term in str(query or '').lower().split() if term]
    results = []
    seen = set()
    if not vendor_key:
        return results
    for pair in load_cpe_pairs(path):
        product = pair['product']
        key = product.lower()
        if pair['vendor'].lower() != vendor_key or key in seen:
            continue
        if terms and not all(term in key for term in terms):
            continue
        seen.add(key)
        results.append({
            **pair,
            'label': f"{pair['vendor']} | {pair['product']}",
        })
        if len(results) >= limit:
            break
    return results
