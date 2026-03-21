import os

def get_dir_size(path):
    total = 0
    for root, dirs, files in os.walk(path):
        if '_sfpg_data' in dirs:
            dirs.remove('_sfpg_data')
        for f in files:
            if f in ('index.html', 'index.php'): continue
            fp = os.path.join(root, f)
            if os.path.exists(fp): total += os.path.getsize(fp)
    return total

def format_size(size):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
        if size < 1024.0: return f"{size:,.2f} {unit}".replace(',', ' ').replace('.', ',')
        size /= 1024.0
    return f"{size:,.2f} ТБ".replace(',', ' ').replace('.', ',')

def get_safe_path(base, rel):
    path = os.path.abspath(os.path.join(base, rel.lstrip('/')))
    if path.startswith(os.path.abspath(base)): return path
    return None

def get_all_items(base):
    items = []
    for root, dirs, files in os.walk(base):
        if '_sfpg_data' in dirs: dirs.remove('_sfpg_data')
        rel_root = os.path.relpath(root, base)
        if rel_root == '.': rel_root = ''
        for d in sorted(dirs):
            items.append(os.path.join(rel_root, d) + '/')
        for f in sorted(files):
            if f not in ('index.html', 'index.php'):
                items.append(os.path.join(rel_root, f))
    return items

def resolve_items_list(base, pattern, all_items):
    import fnmatch
    resolved = []
    for p in pattern.split(','):
        p = p.strip()
        if not p: continue
        try:
            idx = int(p) - 1
            if 0 <= idx < len(all_items): resolved.append(os.path.join(base, all_items[idx]))
        except ValueError:
            target = get_safe_path(base, p)
            if target and os.path.exists(target): resolved.append(target)
            else:
                matches = fnmatch.filter(all_items, p)
                for m in matches: resolved.append(os.path.join(base, m))
    return resolved

def resolve_item(base, p, all_items):
    try:
        idx = int(p) - 1
        if 0 <= idx < len(all_items): return os.path.join(base, all_items[idx])
    except ValueError: pass
    return get_safe_path(base, p)

def get_unique_path(path):
    if not os.path.exists(path): return path
    base, ext = os.path.splitext(path)
    counter = 1
    while os.path.exists(f"{base}_{counter}{ext}"): counter += 1
    return f"{base}_{counter}{ext}"

def safe_quote(path):
    import urllib.parse
    return urllib.parse.quote(path.replace('\\', '/'))

def is_php_file(filename):
    if not filename: return False
    blocked = ('.php', '.php3', '.php4', '.php5', '.php7', '.phtml')
    return filename.lower().strip().endswith(blocked)
