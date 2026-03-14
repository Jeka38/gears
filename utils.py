import os
import urllib.parse
import fnmatch
from config import MAX_DIR_DEPTH

def format_size(size):
    """Форматирует размер в человеко-читаемый вид (Б → кБ → МБ → ГБ)"""
    for unit in ['Б', 'кБ', 'МБ', 'ГБ']:
        if size < 1024:
            res = f"{size:.1f}".replace('.', ',')
            return f"{res} {unit}"
        size /= 1024
    return f"{size:.1f} ГБ".replace('.', ',')

def get_dir_size(path):
    """Подсчитывает суммарный размер всех файлов в папке (рекурсивно), исключая index.html"""
    return sum(os.path.getsize(os.path.join(d, f))
               for d, _, fs in os.walk(path) for f in fs if f != 'index.html')

def safe_quote(text):
    """Красивое кодирование URL (сохраняем кириллицу для читаемости)"""
    text = text.replace(' ', '_')
    return "".join(c if ord(c) >= 128 or c.isalnum() or c in '._-~/:?=&()'
                   else urllib.parse.quote(c) for c in text)

def get_safe_path(user_dir, path_str):
    """Безопасное получение пути внутри папки пользователя"""
    user_dir = os.path.abspath(user_dir)
    target_path = os.path.abspath(os.path.join(user_dir, path_str.strip().lstrip('/')))
    if not target_path.startswith(user_dir):
        return None
    return target_path

def get_unique_path(path):
    """Получаем уникальный путь для предотвращения перезаписи"""
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    counter = 1
    while True:
        new_path = f"{base}_{counter}{ext}"
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def resolve_item(user_dir, arg, items):
    """Разрешение аргумента как индекса или пути"""
    try:
        idx = int(arg) - 1
        if 0 <= idx < len(items):
            return get_safe_path(user_dir, items[idx])
    except ValueError:
        pass
    return get_safe_path(user_dir, arg)

def resolve_items_list(user_dir, arg, items):
    """Разрешение списка аргументов (индексы, пути, шаблоны)"""
    resolved = []
    parts = [p.strip() for p in arg.split(',') if p.strip()]
    for p in parts:
        if '*' in p or '?' in p:
            if '/' not in p:
                for itm in items:
                    name = os.path.basename(itm.rstrip('/'))
                    if fnmatch.fnmatch(name, p):
                        path = get_safe_path(user_dir, itm)
                        if path: resolved.append(path)
            else:
                matches = fnmatch.filter(items, p)
                for m in matches:
                    path = get_safe_path(user_dir, m)
                    if path: resolved.append(path)
        else:
            path = resolve_item(user_dir, p, items)
            if path: resolved.append(path)
    return list(dict.fromkeys(resolved))

def get_all_items(user_dir):
    """Получаем все элементы рекурсивно с ограничением вложенности"""
    items = []
    for root, dirs, files in os.walk(user_dir):
        rel_root = os.path.relpath(root, user_dir)
        if rel_root == ".":
            rel_root = ""

        # Ограничение вложенности: не более MAX_DIR_DEPTH уровней директорий
        if rel_root != "" and rel_root.count(os.sep) >= MAX_DIR_DEPTH:
            continue

        for d in dirs:
            path = os.path.join(rel_root, d)
            if path.count(os.sep) < MAX_DIR_DEPTH:
                items.append(path + "/")
        for f in files:
            if f == 'index.html':
                continue
            path = os.path.join(rel_root, f)
            # Файлы могут находиться в директориях уровня MAX_DIR_DEPTH
            if path.count(os.sep) <= MAX_DIR_DEPTH:
                items.append(path)
    return sorted(items)
