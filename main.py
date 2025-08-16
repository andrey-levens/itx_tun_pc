import sys
import json
import urllib.parse
import subprocess
import base64
import os
import atexit
import time
import psutil
import ctypes
import logging
import platform
import requests
import shutil
import winreg
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QSystemTrayIcon, QMenu, QAction,
    QButtonGroup, QFrame, QMessageBox, QDialog, QCheckBox, QDialogButtonBox, QToolTip
)
from PyQt5.QtCore import Qt, QEvent, pyqtSignal, QThreadPool, QRunnable, QTimer, QUrl
from PyQt5.QtGui import QCloseEvent, QIcon, QFont, QDesktopServices
from functools import lru_cache
import asyncio
import aiohttp
import aiohttp.connector
import aiofiles
import qasync

LAST_FETCH_TIME = 0
FETCH_CACHE = None
FETCH_CACHE_TIMEOUT = 300

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
DEBUG_LOGGED_FUNCTIONS = {'fetch_vless_links_async', 'run_sing_box_background', 'change_subscription'}

LOG_FONT_SIZE = 12

def log_message(message, level="INFO"):
    if level == "DEBUG" and not any(func in message for func in DEBUG_LOGGED_FUNCTIONS):
        return
    logging.log(getattr(logging, level), message)

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def apply_material_design_style(app):
    style = f"""
        QMainWindow {{
            background-color: #121212;
        }}
        QWidget {{
            background-color: #121212;
            color: #FFFFFF;
            font-family: Roboto, Arial, sans-serif;
            font-size: 15px;
        }}
        QLineEdit {{
            background-color: #1E1E1E;
            color: #FFFFFF;
            border: 1px solid #333333;
            border-radius: 8px;
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}
        QLineEdit:focus {{
            border: 2px solid #B0BEC5;
            box-shadow: 0 0 8px rgba(176, 190, 197, 0.3);
        }}
        QPushButton {{
            background-color: #333333;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 12px;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            transition: background-color 0.2s, box-shadow 0.2s;
            outline: none;
        }}
        QPushButton:hover {{
            background-color: #424242;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
        }}
        QPushButton:pressed {{
            background-color: #212121;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
        }}
        QPushButton:checked {{
            background-color: #0288D1;
            color: #FFFFFF;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            border: 1px solid #0288D1;
        }}
        QPushButton:focus {{
            outline: none;
            border: 1px solid #0288D1;
        }}
        QPushButton:disabled {{
            background-color: #212121;
            color: #757575;
            box-shadow: none;
        }}
        QComboBox {{
            background-color: #1E1E1E;
            color: #FFFFFF;
            border: 1px solid #333333;
            border-radius: 8px;
            padding: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}
        QComboBox::drop-down {{
            border: none;
            background-color: #1E1E1E;
        }}
        QComboBox::down-arrow {{
            image: none;
            width: 12px;
            height: 12px;
        }}
        QComboBox QAbstractItemView {{
            background-color: #1E1E1E;
            color: #FFFFFF;
            selection-background-color: #333333;
            border: 1px solid #333333;
            border-radius: 8px;
        }}
        QLabel {{
            color: #FFFFFF;
            font-size: 18px;
            font-weight: 400;
        }}
        QLabel#statusLabel {{
            font-size: {LOG_FONT_SIZE}px;
        }}
        QFrame[frameShape="4"] {{
            background-color: #333333;
            height: 2px;
        }}
        QMessageBox, QDialog {{
            background-color: #121212;
            color: #FFFFFF;
            font-family: Roboto, Arial, sans-serif;
            font-size: 15px;
        }}
        QMessageBox QLabel, QDialog QLabel {{
            color: #FFFFFF;
            background-color: #121212;
        }}
        QMessageBox QPushButton, QDialog QPushButton {{
            background-color: #333333;
            color: #FFFFFF;
            border: none;
            border-radius: 8px;
            padding: 10px;
            min-width: 80px;
        }}
        QMessageBox QPushButton:hover, QDialog QPushButton:hover {{
            background-color: #424242;
        }}
        QCheckBox {{
            color: #FFFFFF;
            padding: 5px;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border: 1px solid #333333;
            background-color: #1E1E1E;
            border-radius: 4px;
        }}
        QCheckBox::indicator:checked {{
            background-color: #0288D1;
            border: 1px solid #0288D1;
        }}
        QToolTip {{
            background-color: #1E1E1E;
            color: #FFFFFF;
            border: 1px solid #333333;
            border-radius: 4px;
            padding: 5px;
        }}
        QPushButton#modeButton {{
            qproperty-flat: false;
        }}
    """
    app.setStyleSheet(style)

def is_admin():
    if platform.system() != "Windows":
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    try:
        result = ctypes.windll.shell32.IsUserAnAdmin()
        return bool(result)
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка проверки прав администратора: {e}", "ERROR")
        return False

def request_admin_privileges():
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка запроса прав администратора: {e}", "ERROR")
        return False

def manage_autostart(enable):
    app_name = "ITX_VPN"
    app_path = sys.executable
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        if enable:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, f'"{app_path}"')
            log_message(f"[{get_timestamp()}] Приложение добавлено в автозагрузку", "INFO")
        else:
            try:
                winreg.DeleteValue(key, app_name)
                log_message(f"[{get_timestamp()}] Приложение удалено из автозагрузки", "INFO")
            except FileNotFoundError:
                log_message(f"[{get_timestamp()}] Приложение не было в автозагрузке", "DEBUG")
        winreg.CloseKey(key)
        return True
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка управления автозагрузкой: {e}", "ERROR")
        return False

def save_state(config_path, subscription_url, selected_country):
    state = {
        "config_path": config_path,
        "subscription_url": subscription_url,
        "selected_country": selected_country
    }
    state_file = os.path.join(get_app_data_path(), "state.json")
    try:
        with open(state_file, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        log_message(f"[{get_timestamp()}] Состояние сохранено в {state_file}", "DEBUG")
        return True
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка сохранения состояния: {e}", "ERROR")
        return False

def load_state():
    state_file = os.path.join(get_app_data_path(), "state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r', encoding='utf-8') as f:
                state = json.load(f)
            log_message(f"[{get_timestamp()}] Состояние загружено из {state_file}", "DEBUG")
            os.remove(state_file)
            return state
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка загрузки состояния: {e}", "ERROR")
            return {}
    return {}

def load_settings():
    settings_file = os.path.join(get_app_data_path(), "settings.json")
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
            return settings
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка чтения настроек: {e}", "ERROR")
    return {
        "discord_proxy_enabled": False,
        "autostart_enabled": False,
        "last_mode": "",
        "last_country": ""
    }

def save_settings(settings):
    settings_file = os.path.join(get_app_data_path(), "settings.json")
    try:
        os.makedirs(get_app_data_path(), exist_ok=True)
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        log_message(f"[{get_timestamp()}] Настройки сохранены", "DEBUG")
        return True
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка сохранения настроек: {e}", "ERROR")
        return False

def is_discord_running():
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == 'discord.exe':
                return True
        return False
    except psutil.Error as e:
        log_message(f"[{get_timestamp()}] Ошибка проверки процессов Discord: {e}", "ERROR")
        return False

def check_default_discord_path():
    default_path = os.path.expanduser(r"~\AppData\Local\Discord")
    if os.path.exists(default_path):
        for folder in os.listdir(default_path):
            if folder.startswith("app-") and os.path.exists(os.path.join(default_path, folder, "Discord.exe")):
                return os.path.join(default_path, folder)
    return None

def find_discord_folder(start_path):
    try:
        for root, dirs, files in os.walk(start_path):
            if "Discord" in dirs:
                discord_path = os.path.join(root, "Discord")
                if os.path.exists(os.path.join(discord_path, "Discord.exe")):
                    return discord_path
    except PermissionError:
        pass
    return None

def backup_discord_dll(discord_path):
    original_dll = os.path.join(discord_path, "version.dll")
    backup_dll = os.path.join(discord_path, "version.dll.bak")
    try:
        if os.path.exists(original_dll) and not os.path.exists(backup_dll):
            shutil.copy2(original_dll, backup_dll)
            log_message(f"[{get_timestamp()}] Создана резервная копия {backup_dll}", "INFO")
            return True
        return False
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка создания резервной копии: {e}", "ERROR")
        return False

def restore_discord_dll(discord_path):
    original_dll = os.path.join(discord_path, "version.dll")
    backup_dll = os.path.join(discord_path, "version.dll.bak")
    try:
        if is_discord_running():
            log_message(f"[{get_timestamp()}] Discord запущен, невозможно восстановить dll", "ERROR")
            return False, f"⚠ Закройте Discord перед отключением прокси [{get_timestamp()}]"
        if os.path.exists(backup_dll):
            if os.path.exists(original_dll):
                os.remove(original_dll)
                log_message(f"[{get_timestamp()}] Удален текущий {original_dll}", "INFO")
            shutil.move(backup_dll, original_dll)
            log_message(f"[{get_timestamp()}] Восстановлен {original_dll}", "INFO")
            return True, f"✔ Discord больше не использует прокси [{get_timestamp()}]"
        else:
            if os.path.exists(original_dll):
                os.remove(original_dll)
                log_message(f"[{get_timestamp()}] Удален {original_dll}, резервная копия отсутствует", "INFO")
            return True, f"✔ Discord больше не использует прокси [{get_timestamp()}]"
    except PermissionError:
        log_message(f"[{get_timestamp()}] Ошибка: Закройте Discord перед восстановлением dll", "ERROR")
        return False, f"⚠ Закройте Discord перед отключением прокси [{get_timestamp()}]"
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка восстановления dll: {e}", "ERROR")
        return False, f"⚠ Ошибка отключения прокси для Discord: {e} [{get_timestamp()}]"

def replace_discord_dll(discord_path):
    if is_discord_running():
        log_message(f"[{get_timestamp()}] Discord запущен, невозможно заменить dll", "ERROR")
        return False, f"⚠ Закройте Discord перед настройкой прокси [{get_timestamp()}]"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dll_path = os.path.join(script_dir, "version.dll")
    dest_path = os.path.join(discord_path, "version.dll")
    try:
        if not os.path.exists(dll_path):
            log_message(f"[{get_timestamp()}] Файл version.dll не найден в {script_dir}", "ERROR")
            return False, f"⚠ Файл version.dll не найден [{get_timestamp()}]"
        backup_discord_dll(discord_path)
        shutil.copy2(dll_path, dest_path)
        log_message(f"[{get_timestamp()}] Файл version.dll скопирован в {dest_path}", "INFO")
        return True, f"✔ Discord теперь работает через прокси [{get_timestamp()}]"
    except PermissionError:
        log_message(f"[{get_timestamp()}] Ошибка: Закройте Discord перед установкой dll", "ERROR")
        return False, f"⚠ Закройте Discord перед настройкой прокси [{get_timestamp()}]"
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка при копировании файла: {e}", "ERROR")
        return False, f"⚠ Ошибка настройки прокси для Discord: {e} [{get_timestamp()}]"

def setup_discord_proxy(enable):
    discord_path = check_default_discord_path()
    if not discord_path:
        start_path = os.path.expanduser(r"~\AppData\Local")
        discord_path = find_discord_folder(start_path)
    if not discord_path:
        log_message(f"[{get_timestamp()}] Папка Discord не найдена", "ERROR")
        return False, f"⚠ Папка Discord не найдена [{get_timestamp()}]"
    log_message(f"[{get_timestamp()}] Папка Discord найдена: {discord_path}", "INFO")
    if enable:
        return replace_discord_dll(discord_path)
    else:
        return restore_discord_dll(discord_path)

def check_windows_version():
    return platform.win32_ver()[0]

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def get_app_data_path():
    return os.path.join(os.getenv('APPDATA'), 'ITX_VPN')

@lru_cache(maxsize=1)
def load_subscription():
    subscription_dir = get_app_data_path()
    subscription_file = os.path.join(subscription_dir, "subscription.json")
    log_message(f"[{get_timestamp()}] Загрузка подписки: {subscription_file}", "DEBUG")
    try:
        if not os.path.exists(subscription_file):
            os.makedirs(subscription_dir, exist_ok=True)
            with open(subscription_file, 'w', encoding='utf-8') as f:
                json.dump({"url": ""}, f, indent=2, ensure_ascii=False)
            return ""
        with open(subscription_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        url = data.get("url", "")
        if not url:
            log_message(f"[{get_timestamp()}] Подписка пуста в {subscription_file}", "DEBUG")
        else:
            log_message(f"[{get_timestamp()}] Загружен URL подписки: {url[:10]}...", "INFO")
        return url
    except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
        log_message(f"[{get_timestamp()}] Ошибка загрузки подписки: {e}", "ERROR")
        return ""

async def save_subscription_async(url):
    subscription_dir = get_app_data_path()
    subscription_file = os.path.join(subscription_dir, "subscription.json")
    log_message(f"[{get_timestamp()}] Сохранение подписки: {url[:10]}...", "DEBUG")
    try:
        os.makedirs(subscription_dir, exist_ok=True)
        async with aiofiles.open(subscription_file, 'w', encoding='utf-8', buffering=8192) as f:
            await f.write(json.dumps({"url": url}, indent=2, ensure_ascii=False))
        log_message(f"[{get_timestamp()}] Подписка сохранена в {subscription_file}", "INFO")
        return True
    except IOError as e:
        log_message(f"[{get_timestamp()}] Ошибка сохранения подписки: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка сохранения подписки: {e}"

async def fetch_vless_links_async(subscription_url):
    global LAST_FETCH_TIME, FETCH_CACHE
    current_time = time.time()
    if FETCH_CACHE and (current_time - LAST_FETCH_TIME) < FETCH_CACHE_TIMEOUT:
        log_message(f"[{get_timestamp()}] Использование кэша подписки", "DEBUG")
        return FETCH_CACHE
    log_message(f"[{get_timestamp()}] Асинхронная загрузка подписки: {subscription_url}", "DEBUG")
    try:
        connector = aiohttp.TCPConnector(limit=50)
        async with aiohttp.ClientSession(headers={"User-Agent": "ITX-VPN/0.2"}, connector=connector,
                                         timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(subscription_url) as response:
                response.raise_for_status()
                decoded_data = base64.b64decode(await response.text()).decode('utf-8')
                links = decoded_data.strip().split('\n')
                FETCH_CACHE = links
                LAST_FETCH_TIME = current_time
                return links
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка асинхронной загрузки: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка: {e}"

@lru_cache(maxsize=32)
def load_config(config_path):
    log_message(f"[{get_timestamp()}] Загрузка конфигурации: {config_path}", "DEBUG")
    try:
        with open(resource_path(config_path), 'r', encoding='utf-8') as f:
            config = json.load(f)
        if 'outbounds' not in config:
            return f"[{get_timestamp()}] Ошибка: В конфигурации {config_path} отсутствует секция 'outbounds'"
        return config
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_message(f"[{get_timestamp()}] Ошибка загрузки конфигурации {config_path}: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка загрузки конфигурации {config_path}: {e}"

async def save_config_async(config, config_path):
    log_message(f"[{get_timestamp()}] Асинхронное сохранение конфигурации: {config_path}", "DEBUG")
    try:
        async with aiofiles.open(resource_path(config_path), 'w', encoding='utf-8', buffering=8192) as f:
            await f.write(json.dumps(config, indent=2, ensure_ascii=False))
        return True
    except IOError as e:
        log_message(f"[{get_timestamp()}] Ошибка сохранения конфигурации {config_path}: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка сохранения файла: {e}"

@lru_cache(maxsize=32)
def generate_outbounds_cached(vless_links):
    log_message(f"[{get_timestamp()}] Генерация outbounds", "DEBUG")
    configs = {}
    for link in vless_links:
        try:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username
            server = parsed.hostname
            port = int(parsed.port) if parsed.port else 443
            query = urllib.parse.parse_qs(parsed.query)
            country = urllib.parse.unquote(parsed.fragment).strip() if parsed.fragment else "Unknown"
            if " " in country:
                country = " ".join(country.split(" ")[1:])
            country = country.strip() or "Unknown"
            outbound = {
                "type": "vless",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0],
                    "utls": {
                        "enabled": True,
                        "fingerprint": query.get("fp", [""])[0]
                    },
                    "reality": {
                        "enabled": True,
                        "public_key": query.get("pbk", [""])[0],
                        "short_id": query.get("sid", [""])[0]
                    }
                }
            }
            configs[country] = outbound
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка парсинга VLESS ссылки: {e}", "ERROR")
            continue
    log_message(f"[{get_timestamp()}] Найдено {len(configs)} серверов", "DEBUG")
    return configs if configs else f"[{get_timestamp()}] Ошибка: Ссылки VLESS не найдены"

def update_config(config, selected_outbound, config_path):
    log_message(f"[{get_timestamp()}] Обновление конфигурации: {config_path}", "DEBUG")
    try:
        is_proxy_mode = 'proxy' in config_path.lower()
        outbound_to_use = selected_outbound.copy()
        target_tag = "My-VLESS" if is_proxy_mode else "proxy"
        outbound_to_use["tag"] = target_tag
        found = False
        for i, outbound in enumerate(config.get('outbounds', [])):
            if outbound.get('tag') == target_tag:
                config['outbounds'][i] = outbound_to_use
                found = True
                log_message(f"[{get_timestamp()}] Обновлен outbound с тегом '{target_tag}'", "DEBUG")
                break
        if not found:
            config['outbounds'].append(outbound_to_use)
            log_message(f"[{get_timestamp()}] Добавлен новый outbound с тегом '{target_tag}'", "DEBUG")
        server = selected_outbound.get('server', '')
        if 'route' in config and 'rules' in config['route']:
            for rule in config['route']['rules']:
                if 'domain' in rule:
                    rule['domain'] = [server]
                    log_message(f"[{get_timestamp()}] Обновлен domain в route: {server}", "DEBUG")
        return config
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка в update_config: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка обновления конфигурации: {e}"

def get_sing_box_pids():
    log_message(f"[{get_timestamp()}] Проверка процессов sing-box", "DEBUG")
    try:
        log_message(f"[{get_timestamp()}] Версия psutil: {psutil.__version__}", "DEBUG")
        return [proc.pid for proc in psutil.process_iter(['pid', 'name'])
                if proc.info['name'].lower() == 'sing-box.exe']
    except psutil.Error as e:
        log_message(f"[{get_timestamp()}] Ошибка проверки процессов sing-box: {e}", "ERROR")
        return []

def cleanup_network():
    creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*TUN*" } | Disable-NetAdapter -Confirm:$false'],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=creation_flags
        )
        log_message(
            f"[{get_timestamp()}] Результат очистки сети: {'Успех' if result.returncode == 0 else result.stderr}",
            "DEBUG")
        return f"[{get_timestamp()}] TUN-интерфейсы отключены" if result.returncode == 0 else f"[{get_timestamp()}] Ошибка: {result.stderr}"
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка очистки сети: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка очистки сети: {e}"

def cleanup_proxy():
    creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
    try:
        result = subprocess.run(
            ['reg', 'add', r'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings', '/v', 'ProxyEnable',
             '/t', 'REG_DWORD', '/d', '0', '/f'],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=creation_flags
        )
        log_message(
            f"[{get_timestamp()}] Результат сброса прокси: {'Успех' if result.returncode == 0 else result.stderr}",
            "DEBUG")
        return f"[{get_timestamp()}] Системный прокси сброшен" if result.returncode == 0 else f"[{get_timestamp()}] Ошибка: {result.stderr}"
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка сброса прокси: {e}", "ERROR")
        return f"[{get_timestamp()}] Ошибка сброса прокси: {e}"

def run_sing_box_background(config_path):
    log_message(f"[{get_timestamp()}] Запуск sing-box: {config_path}", "DEBUG")
    pids = get_sing_box_pids()
    if pids:
        return None, f"[{get_timestamp()}] sing-box уже запущен с PID: {pids}"
    try:
        os.chdir(resource_path("."))
        process = subprocess.Popen(
            [resource_path("sing-box.exe"), "run", "-c", resource_path(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(0.05)
        if process.poll() is None:
            log_message(f"[{get_timestamp()}] sing-box запущен", "DEBUG")
            return process, f"[{get_timestamp()}] Запущен sing-box с конфигурацией {config_path}"
        return None, f"[{get_timestamp()}] Ошибка запуска sing-box"
    except Exception as e:
        log_message(f"[{get_timestamp()}] Ошибка запуска sing-box: {e}", "ERROR")
        return None, f"[{get_timestamp()}] Ошибка запуска: {e}"

def terminate_sing_box(process):
    log_message(f"[{get_timestamp()}] Завершение sing-box", "DEBUG")
    status = []
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=2)
            status.append(f"[{get_timestamp()}] Процесс sing-box завершен")
        except subprocess.TimeoutExpired:
            process.kill()
            status.append(f"[{get_timestamp()}] Процесс принудительно завершен")
        except Exception as e:
            status.append(f"[{get_timestamp()}] Ошибка завершения процесса: {e}")
    for pid in get_sing_box_pids():
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=2)
            status.append(f"[{get_timestamp()}] Завершен процесс sing-box (PID: {pid})")
        except Exception as e:
            status.append(f"[{get_timestamp()}] Ошибка завершения PID {pid}: {e}")
    status.append(cleanup_network())
    return "\n".join(status) if status else f"[{get_timestamp()}] Нет процессов sing-box"

class FetchWorker(QRunnable):
    def __init__(self, url, callback, loop):
        super().__init__()
        self.url = url
        self.callback = callback
        self.loop = loop

    def run(self):
        log_message(f"[{get_timestamp()}] Запуск FetchWorker для {self.url[:10]}...", "DEBUG")
        try:
            result = asyncio.run_coroutine_threadsafe(fetch_vless_links_async(self.url), self.loop).result()
            self.callback(result)
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка в FetchWorker: {e}", "ERROR")
            self.callback(f"[{get_timestamp()}] Ошибка: {e}")
        finally:
            log_message(f"[{get_timestamp()}] FetchWorker завершён", "DEBUG")

class ConfigWorker(QRunnable):
    def __init__(self, outbounds, selected_country, config_path, callback, loop):
        super().__init__()
        self.outbounds = outbounds
        self.selected_country = selected_country
        self.config_path = config_path
        self.callback = callback
        self.loop = loop

    def run(self):
        log_message(f"[{get_timestamp()}] Запуск ConfigWorker для {self.config_path}", "DEBUG")
        try:
            config = load_config(self.config_path)
            if isinstance(config, str):
                self.callback((self.config_path, None, config))
                return
            config = update_config(config, self.outbounds[self.selected_country], self.config_path)
            if isinstance(config, str):
                self.callback((self.config_path, None, config))
                return
            result = asyncio.run_coroutine_threadsafe(save_config_async(config, self.config_path), self.loop).result()
            self.callback((self.config_path, config, result if isinstance(result, str) else None))
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка в ConfigWorker: {e}", "ERROR")
            self.callback((self.config_path, None, f"[{get_timestamp()}] Ошибка: {e}"))
        finally:
            log_message(f"[{get_timestamp()}] ConfigWorker завершён", "DEBUG")

class WelcomeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ITX TUN V0.1")
        self.setFixedSize(550, 250)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)
        welcome_label = QLabel("Добро пожаловать в ITX TUN!")
        welcome_label.setFont(QFont("Roboto", 16, QFont.Bold))
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        subscription_label = QLabel(
            "Для использования приложения необходима подписка.\n"
            "Нажмите кнопку ниже, чтобы получить подписку:"
        )
        subscription_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(subscription_label)
        self.get_subscription_button = QPushButton("Получить подписку")
        self.get_subscription_button.clicked.connect(self.open_subscription_link)
        self.get_subscription_button.setToolTip("Открыть Telegram-бот для получения подписки")
        layout.addWidget(self.get_subscription_button)
        self.subscription_input = QLineEdit(
            placeholderText="Введите ссылку на подписку",
            toolTip="Введите URL вашей VLESS-подписки"
        )
        layout.addWidget(self.subscription_input)
        button_layout = QHBoxLayout()
        self.enter_button = QPushButton("Добавить подписку")
        self.enter_button.clicked.connect(self.accept_subscription)
        self.exit_button = QPushButton("Выйти")
        self.exit_button.clicked.connect(self.close_app)
        button_layout.addWidget(self.enter_button)
        button_layout.addWidget(self.exit_button)
        layout.addLayout(button_layout)
        self.setLayout(layout)

    def open_subscription_link(self):
        QDesktopServices.openUrl(QUrl("https://t.me/itxshop_bot"))
        log_message(f"[{get_timestamp()}] Открыта ссылка на Telegram-бот", "INFO")

    def accept_subscription(self):
        if self.subscription_input.text().strip():
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, введите ссылку на подписку.")

    def close_app(self):
        self.reject()
        sys.exit(0)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.setFixedSize(400, 200)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        layout = QVBoxLayout()
        self.discord_proxy_checkbox = QCheckBox("Заставить Discord работать через прокси")
        settings = load_settings()
        self.discord_proxy_checkbox.setChecked(settings.get("discord_proxy_enabled", False))
        self.discord_proxy_checkbox.stateChanged.connect(self.on_discord_proxy_toggled)
        layout.addWidget(self.discord_proxy_checkbox)
        self.autostart_checkbox = QCheckBox("Запускать при старте системы")
        self.autostart_checkbox.setChecked(settings.get("autostart_enabled", False))
        self.autostart_checkbox.stateChanged.connect(self.on_autostart_toggled)
        layout.addWidget(self.autostart_checkbox)
        layout.addStretch()
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        self.setLayout(layout)

    def on_discord_proxy_toggled(self, state):
        enable = bool(state)
        success, message = setup_discord_proxy(enable)
        parent = self.parent()
        if parent:
            parent.update_status_signal.emit(message)
        else:
            log_message(message, "INFO")
        if success:
            settings = load_settings()
            settings["discord_proxy_enabled"] = enable
            save_settings(settings)
        else:
            self.discord_proxy_checkbox.blockSignals(True)
            self.discord_proxy_checkbox.setChecked(not enable)
            self.discord_proxy_checkbox.blockSignals(False)

    def on_autostart_toggled(self, state):
        enable = bool(state)
        success = manage_autostart(enable)
        parent = self.parent()
        if success:
            settings = load_settings()
            settings["autostart_enabled"] = enable
            save_settings(settings)
            message = f"✔ Автозапуск {'включен' if enable else 'отключен'} [{get_timestamp()}]"
        else:
            self.autostart_checkbox.blockSignals(True)
            self.autostart_checkbox.setChecked(not enable)
            self.autostart_checkbox.blockSignals(False)
            message = f"⚠ Ошибка управления автозапуском [{get_timestamp()}]"
        if parent:
            parent.update_status_signal.emit(message)
        else:
            log_message(message, "INFO")

class SingBoxGUI(QMainWindow):
    update_status_signal = pyqtSignal(str)
    update_servers_signal = pyqtSignal(object)
    subscription_updated_signal = pyqtSignal(bool, str)

    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        log_message(f"[{get_timestamp()}] Инициализация приложения", "DEBUG")
        self.setWindowTitle("ITX TUN V1.0")
        self.setFixedSize(450, 465)
        self.setWindowFlags(Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowMinimizeButtonHint)
        self.setWindowIcon(QIcon(resource_path("icon.ico")))
        self.mode_descriptions = {
            "proxy_full.json": "Весь трафик будет передаваться в VPN с помощью локального прокси.",
            "proxy_rule.json": "Часть трафика будет передаваться в VPN с помощью локального прокси. Редактировать список сервисов, которые будут работать в VPN, вы можете в файле my-ruleset.json.",
            "tun_full.json": "Весь трафик будет передаваться в VPN с помощью виртуального сетевого интерфейса (TUN). На данный момент, к сожалению, данный режим работы самый медленный в работе.",
            "tun_rule.json": "Часть трафика будет передаваться в VPN с помощью виртуального сетевого интерфейса (TUN). Редактировать список сервисов, которые будут работать в VPN, вы можете в файле my-ruleset.json. Данный режим идеально подойдет для: серфинга в интернете и идеальной работы Discord!"
        }
        self.outbounds = None
        icon_path = resource_path("icon.png")
        if not os.path.exists(icon_path):
            log_message(f"[{get_timestamp()}] Ошибка: Файл иконки {icon_path} не существует", "ERROR")
        else:
            log_message(f"[{get_timestamp()}] Иконка найдена: {icon_path}", "DEBUG")
        self.tray_icon = QSystemTrayIcon(QIcon(icon_path), self)
        self.tray_icon.setToolTip("ITX TUN V1.0")
        tray_menu = QMenu()
        tray_menu.addAction("Показать", self.show)
        tray_menu.addAction("Выход", self.close_app)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()
        log_message(f"[{get_timestamp()}] Инициализация трея завершена", "DEBUG")
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(4)
        self.sing_box_process = None
        self.current_mode = None
        self.current_mode_button = None
        self.config_modes = [
            {"file": "proxy_full.json", "description": "Proxy full", "requires_admin": False},
            {"file": "proxy_rule.json", "description": "Proxy rule", "requires_admin": False},
            {"file": "tun_full.json", "description": "TUN full", "requires_admin": True},
            {"file": "tun_rule.json", "description": "TUN rule", "requires_admin": True}
        ]
        self.available_modes = []
        self.config_cache = {}
        self.tooltip_timer = QTimer(self)
        self.tooltip_timer.setSingleShot(True)
        self.current_hovered_button = None
        self.init_ui()
        self.update_status_signal.connect(self.status_label.setText)
        self.update_servers_signal.connect(self.populate_servers)
        self.subscription_updated_signal.connect(self.on_subscription_updated)
        self.cleanup_existing_processes()
        atexit.register(self.stop_sing)

    def init_ui(self):
        log_message(f"[{get_timestamp()}] Инициализация UI", "DEBUG")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QVBoxLayout()
        self.main_layout.setSpacing(16)
        self.main_layout.setContentsMargins(24, 24, 24, 24)
        central_widget.setLayout(self.main_layout)
        self.subscription_label = QLabel("Добавьте подписку:", font=QFont("Roboto", 20))
        self.subscription_input = QLineEdit(
            placeholderText="Введите ссылку на подписку",
            toolTip="Введите URL вашей VLESS-подписки"
        )
        self.subscription_input.textChanged.connect(self.on_subscription_input_changed)
        self.change_subscription_btn = QPushButton("Добавить")
        self.change_subscription_btn.setEnabled(False)
        self.change_subscription_btn.clicked.connect(self.change_subscription)
        subscription_layout = QHBoxLayout()
        subscription_layout.addWidget(self.subscription_input)
        subscription_layout.addWidget(self.change_subscription_btn)
        self.server_label = QLabel("Локация:", font=QFont("Roboto", 20))
        self.server_combo = QComboBox(
            enabled=False,
            toolTip="Выберите локацию"
        )
        self.server_combo.currentTextChanged.connect(self.on_server_changed)
        self.server_layout = QHBoxLayout()
        self.server_layout.addWidget(self.server_label)
        self.server_layout.addWidget(self.server_combo)
        self.modes_section_layout = QVBoxLayout()
        self.modes_section_layout.setSpacing(8)
        self.top_line = QFrame()
        self.top_line.setFrameShape(QFrame.HLine)
        self.top_line.setFrameShadow(QFrame.Sunken)
        self.mode_label = QLabel("Режим работы:", font=QFont("Roboto", 20, QFont.Bold))
        self.mode_buttons_layout = QHBoxLayout()
        self.mode_button_group = QButtonGroup(self)
        self.mode_buttons = []
        for mode in self.config_modes:
            config_path = resource_path(mode['file'])
            if os.path.exists(config_path):
                self.available_modes.append(mode)
                button = QPushButton(mode['description'])
                button.setObjectName("modeButton")
                button.setCheckable(True)
                button.setProperty("config_path", mode['file'])
                button.setProperty("requires_admin", mode['requires_admin'])
                button.setMouseTracking(True)
                description = self.mode_descriptions.get(mode['file'], "Описание отсутствует")
                button.setProperty("description", description)
                button.installEventFilter(self)
                button.clicked.connect(self.on_mode_button_clicked)
                self.mode_button_group.addButton(button)
                self.mode_buttons.append(button)
                self.mode_buttons_layout.addWidget(button)
                config = load_config(config_path)
                if not isinstance(config, str):
                    self.config_cache[mode['file']] = config
                else:
                    log_message(f"[{get_timestamp()}] Некорректная конфигурация {mode['file']}: {config}", "ERROR")
            else:
                log_message(f"[{get_timestamp()}] Файл конфигурации {config_path} не найден", "ERROR")
        if not self.available_modes:
            self.mode_buttons_layout.addWidget(QLabel("Конфигурации отсутствуют"))
            log_message(f"[{get_timestamp()}] Конфигурации отсутствуют", "ERROR")
            self.status_label.setText(f"⚠ [{get_timestamp()}] Конфигурационные файлы отсутствуют")
        self.bottom_line = QFrame()
        self.bottom_line.setFrameShape(QFrame.HLine)
        self.bottom_line.setFrameShadow(QFrame.Sunken)
        self.modes_section_layout.addWidget(self.top_line)
        self.modes_section_layout.addWidget(self.mode_label)
        self.modes_section_layout.addLayout(self.mode_buttons_layout)
        self.modes_section_layout.addWidget(self.bottom_line)
        self.start_btn = QPushButton("Запустить", clicked=self.start_sing)
        self.stop_btn = QPushButton("Остановить", clicked=self.stop_sing, enabled=False)
        self.settings_btn = QPushButton("⚙", clicked=self.open_settings)
        self.settings_btn.setToolTip("Настройки")
        self.settings_btn.setFixedSize(40, 40)
        self.control_layout = QHBoxLayout()
        self.control_layout.addWidget(self.start_btn)
        self.control_layout.addWidget(self.stop_btn)
        self.control_layout.addWidget(self.settings_btn)
        self.minimize_btn = QPushButton("Свернуть", clicked=self.hide)
        self.exit_btn = QPushButton("Выход", clicked=self.close_app)
        self.system_layout = QHBoxLayout()
        self.system_layout.addWidget(self.minimize_btn)
        self.system_layout.addWidget(self.exit_btn)
        self.status_label = QLabel("Готово", alignment=Qt.AlignCenter, font=QFont("Roboto", LOG_FONT_SIZE))
        self.status_label.setObjectName("statusLabel")
        self.main_layout.addWidget(self.subscription_label)
        self.main_layout.addLayout(subscription_layout)
        self.main_layout.addLayout(self.server_layout)
        self.main_layout.addLayout(self.modes_section_layout)
        self.main_layout.addLayout(self.control_layout)
        self.main_layout.addLayout(self.system_layout)
        self.main_layout.addWidget(self.status_label)
        self.main_layout.addStretch()
        self.update_ui_visibility()

    def check_subscription_and_show_welcome(self):
        saved_url = load_subscription()
        if not saved_url:
            dialog = WelcomeDialog(self)
            if dialog.exec_():
                self.subscription_input.setText(dialog.subscription_input.text().strip())
                self.change_subscription()
            else:
                sys.exit(0)
        else:
            self.load_initial_subscription()
            self.check_autostart()
            self.show()

    def eventFilter(self, obj, event):
        if isinstance(obj, QPushButton) and obj in self.mode_buttons:
            description = obj.property("description")
            if event.type() == QEvent.HoverEnter:
                log_message(f"[{get_timestamp()}] HoverEnter на {obj.text()}", "DEBUG")
                self.current_hovered_button = obj
                self.tooltip_timer.timeout.connect(
                    lambda: QToolTip.showText(obj.mapToGlobal(obj.rect().center()), description))
                self.tooltip_timer.start(1000)
            elif event.type() == QEvent.HoverLeave:
                log_message(f"[{get_timestamp()}] HoverLeave с {obj.text()}", "DEBUG")
                self.current_hovered_button = None
                self.tooltip_timer.stop()
                QToolTip.hideText()
        return super().eventFilter(obj, event)

    def open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_():
            log_message(f"[{get_timestamp()}] Настройки сохранены", "DEBUG")
        else:
            log_message(f"[{get_timestamp()}] Настройки отменены", "DEBUG")

    def on_subscription_input_changed(self):
        text = self.subscription_input.text().strip()
        self.change_subscription_btn.setEnabled(bool(text))
        log_message(
            f"[{get_timestamp()}] Поле подписки изменено. Кнопка 'Добавить': {'активная' if text else 'неактивна'}",
            "DEBUG")

    def on_server_changed(self):
        settings = load_settings()
        settings["last_country"] = self.server_combo.currentText()
        save_settings(settings)
        log_message(f"[{get_timestamp()}] Выбран сервер: {settings['last_country']}", "DEBUG")

    def on_mode_button_clicked(self):
        if self.sing_box_process is not None:
            self.update_status_signal.emit(f"⚠ Остановите VPN перед сменой режима [{get_timestamp()}]")
            if self.current_mode_button:
                self.current_mode_button.setChecked(True)
            return
        new_button = self.sender()
        if self.current_mode_button and self.current_mode_button != new_button:
            self.current_mode_button.setChecked(False)
        self.current_mode_button = new_button
        log_message(f"[{get_timestamp()}] Выбран режим: {self.current_mode_button.text()}", "DEBUG")
        if self.current_mode_button.property("requires_admin") and not is_admin():
            self.update_status_signal.emit(
                f"⚠ Требуются права администратора для режима {self.current_mode_button.text()} [{get_timestamp()}]")
            config_path = self.current_mode_button.property("config_path")
            subscription_url = self.subscription_input.text().strip()
            selected_country = self.server_combo.currentText()
            if save_state(config_path, subscription_url, selected_country):
                request_admin_privileges()
            else:
                self.update_status_signal.emit(f"⚠ Не удалось сохранить состояние для перезапуска [{get_timestamp()}]")
            self.current_mode_button.setChecked(False)
            self.current_mode_button = None
        else:
            self.current_mode_button.setChecked(True)
            settings = load_settings()
            settings["last_mode"] = self.current_mode_button.property("config_path")
            save_settings(settings)
            self.update_ui_visibility()

    def update_ui_visibility(self):
        log_message(f"[{get_timestamp()}] Обновление видимости UI", "DEBUG")
        has_subscription = self.outbounds is not None and not isinstance(self.outbounds, str)
        self.subscription_label.setText("Добавленная ссылка:" if has_subscription else "Добавьте подписку:")
        self.change_subscription_btn.setText("Обновить" if has_subscription else "Добавить")
        self.change_subscription_btn.setEnabled(True)
        self.server_combo.setEnabled(has_subscription)
        for button in self.mode_buttons:
            button.setEnabled(self.sing_box_process is None)
            if button == self.current_mode_button:
                button.setChecked(True)
            else:
                button.setChecked(False)
        self.start_btn.setEnabled(has_subscription and self.sing_box_process is None)
        self.stop_btn.setEnabled(self.sing_box_process is not None)
        self.settings_btn.setEnabled(True)
        log_message(
            f"[{get_timestamp()}] has_subscription={has_subscription}, sing_box_process={self.sing_box_process is not None}",
            "DEBUG")

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show()
            self.raise_()
            self.activateWindow()

    def closeEvent(self, event: QCloseEvent):
        log_message(f"[{get_timestamp()}] Сворачивание в трей", "DEBUG")
        event.ignore()
        self.hide()
        self.tray_icon.showMessage("ITX TUN V1.0", "Приложение свернуто в трей", QSystemTrayIcon.Information, 1000)

    def close_app(self):
        log_message(f"[{get_timestamp()}] Выход из приложения", "DEBUG")
        self.stop_sing()
        sys.exit(0)

    def load_initial_subscription(self):
        log_message(f"[{get_timestamp()}] Загрузка начальной подписки", "DEBUG")
        try:
            state = load_state()
            saved_url = state.get("subscription_url", load_subscription())
            saved_country = state.get("selected_country", "")
            if saved_url:
                self.subscription_input.setText(saved_url)
                self.change_subscription_btn.setEnabled(True)
                self.change_subscription()
            else:
                self.status_label.setText(f"⚠ Введите ссылку на подписку [{get_timestamp()}]")
            self.outbounds = None
            saved_config_path = state.get("config_path")
            if saved_config_path:
                for button in self.mode_buttons:
                    if button.property("config_path") == saved_config_path:
                        button.setChecked(True)
                        self.current_mode_button = button
                        break
            if saved_country:
                self.server_combo.setCurrentText(saved_country)
            self.update_ui_visibility()
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка в load_initial_subscription: {e}", "ERROR")
            self.status_label.setText(f"⚠ Ошибка: {e} [{get_timestamp()}]")
            self.outbounds = None
            self.update_ui_visibility()

    def check_autostart(self):
        settings = load_settings()
        if settings.get("autostart_enabled", False) and settings.get("last_mode") and settings.get("last_country"):
            log_message(f"[{get_timestamp()}] Автозапуск включен, пытаемся запустить VPN", "DEBUG")
            for button in self.mode_buttons:
                if button.property("config_path") == settings["last_mode"]:
                    self.current_mode_button = button
                    button.setChecked(True)
                    break
            if self.current_mode_button:
                if self.current_mode_button.property("requires_admin") and not is_admin():
                    self.update_status_signal.emit(
                        f"⚠ Требуются права администратора для режима {self.current_mode_button.text()} [{get_timestamp()}]")
                    subscription_url = self.subscription_input.text().strip()
                    selected_country = settings["last_country"]
                    if save_state(settings["last_mode"], subscription_url, selected_country):
                        request_admin_privileges()
                    return
                self.server_combo.setCurrentText(settings["last_country"])
                self.start_sing()

    def change_subscription(self):
        log_message(f"[{get_timestamp()}] Смена подписки: начало", "DEBUG")
        url = self.subscription_input.text().strip()
        if not url:
            self.update_status_signal.emit(f"⚠ Ссылка не указана [{get_timestamp()}]")
            log_message(f"[{get_timestamp()}] Смена подписки: пустой URL", "DEBUG")
            self.subscription_updated_signal.emit(False, f"⚠ Ссылка не указана [{get_timestamp()}]")
            return
        async def save_and_fetch():
            try:
                result = await save_subscription_async(url)
                log_message(f"[{get_timestamp()}] Смена подписки: результат сохранения: {result}", "DEBUG")
                if result is not True:
                    self.update_status_signal.emit(f"⚠ {result}")
                    log_message(f"[{get_timestamp()}] Смена подписки: ошибка сохранения", "DEBUG")
                    self.subscription_updated_signal.emit(False, f"⚠ {result}")
                    return
                self.update_status_signal.emit(f"⏳ Загрузка серверов... [{get_timestamp()}]")
                worker = FetchWorker(url, self.on_servers_fetched, self.loop)
                self.threadpool.start(worker)
                log_message(f"[{get_timestamp()}] Смена подписки: запущен FetchWorker", "DEBUG")
            except Exception as e:
                log_message(f"[{get_timestamp()}] Ошибка в change_subscription: {e}", "ERROR")
                self.update_status_signal.emit(f"⚠ Ошибка: {e} [{get_timestamp()}]")
                self.subscription_updated_signal.emit(False, f"⚠ Ошибка: {e} [{get_timestamp()}]")
        asyncio.run_coroutine_threadsafe(save_and_fetch(), self.loop)
        self.subscription_input.clearFocus()
        self.change_subscription_btn.setFocus()
        log_message(f"[{get_timestamp()}] Смена подписки: завершение", "DEBUG")

    def on_servers_fetched(self, vless_links):
        log_message(f"[{get_timestamp()}] Обработка загруженных серверов", "DEBUG")
        if isinstance(vless_links, str):
            self.update_status_signal.emit(f"⚠ {vless_links}")
            self.outbounds = None
            self.update_servers_signal.emit(None)
            self.subscription_updated_signal.emit(False, f"⚠ {vless_links}")
            log_message(f"[{get_timestamp()}] Ошибка загрузки серверов: {vless_links}", "DEBUG")
            return
        self.outbounds = generate_outbounds_cached(tuple(vless_links))
        if isinstance(self.outbounds, str):
            self.update_status_signal.emit(f"⚠ {self.outbounds}")
            self.outbounds = None
            self.update_servers_signal.emit(None)
            self.subscription_updated_signal.emit(False, f"⚠ {self.outbounds}")
            log_message(f"[{get_timestamp()}] Ошибка генерации outbounds: {self.outbounds}", "DEBUG")
        else:
            self.update_status_signal.emit(f"✔ Серверы загружены [{get_timestamp()}]")
            log_message(f"[{get_timestamp()}] Серверы успешно загружены", "DEBUG")
            settings = load_settings()
            if settings.get("last_country") in self.outbounds:
                self.server_combo.setCurrentText(settings["last_country"])
            self.update_servers_signal.emit(self.outbounds)
            self.subscription_updated_signal.emit(True, f"✔ Подписка успешно обновлена [{get_timestamp()}]")

    def on_subscription_updated(self, success, message):
        log_message(f"[{get_timestamp()}] Результат обновления подписки: {message}", "DEBUG")
        if success:
            self.show()
        else:
            dialog = WelcomeDialog(self)
            dialog.subscription_input.setText(self.subscription_input.text().strip())
            QMessageBox.warning(dialog, "Ошибка", message)
            if dialog.exec_():
                self.subscription_input.setText(dialog.subscription_input.text().strip())
                self.change_subscription()
            else:
                sys.exit(0)

    def populate_servers(self, outbounds):
        self.server_combo.clear()
        if outbounds and not isinstance(outbounds, str):
            for country in sorted(outbounds.keys()):
                self.server_combo.addItem(country)
            self.server_combo.setEnabled(True)
        else:
            self.server_combo.setEnabled(False)
        self.update_ui_visibility()

    def start_sing(self):
        log_message(f"[{get_timestamp()}] Запуск sing-box", "DEBUG")
        if not self.outbounds or isinstance(self.outbounds, str):
            self.update_status_signal.emit(f"⚠ Нет доступных серверов [{get_timestamp()}]")
            return
        if not self.available_modes:
            self.update_status_signal.emit(f"⚠ Конфигурации отсутствуют [{get_timestamp()}]")
            return
        selected_button = self.mode_button_group.checkedButton()
        if not selected_button:
            self.update_status_signal.emit(f"⚠ Режим не выбран [{get_timestamp()}]")
            return
        self.current_mode_button = selected_button
        config_path = selected_button.property("config_path")
        requires_admin = selected_button.property("requires_admin")
        if requires_admin and not is_admin():
            self.update_status_signal.emit(
                f"⚠ Требуются права администратора для режима {selected_button.text()} [{get_timestamp()}]")
            subscription_url = self.subscription_input.text().strip()
            selected_country = self.server_combo.currentText()
            if save_state(config_path, subscription_url, selected_country):
                request_admin_privileges()
            else:
                self.update_status_signal.emit(f"⚠ Не удалось сохранить состояние для перезапуска [{get_timestamp()}]")
            return
        selected_country = self.server_combo.currentText()
        if selected_country not in self.outbounds:
            self.update_status_signal.emit(f"⚠ Локация '{selected_country}' не найдена [{get_timestamp()}]")
            return
        settings = load_settings()
        settings["last_mode"] = config_path
        settings["last_country"] = selected_country
        save_settings(settings)
        worker = ConfigWorker(self.outbounds, selected_country, config_path, self.on_config_updated, self.loop)
        self.threadpool.start(worker)
        self.update_status_signal.emit(f"⏳ Запуск sing-box... [{get_timestamp()}]")
        self.subscription_input.clearFocus()
        self.start_btn.setFocus()

    def on_config_updated(self, result):
        config_path, config, error = result
        if error:
            self.update_status_signal.emit(f"⚠ {error}")
            return
        self.config_cache[config_path] = config
        self.sing_box_process, msg = run_sing_box_background(config_path)
        self.current_mode = "proxy" if 'proxy' in config_path.lower() else 'tun'
        log_message(f"[{get_timestamp()}] Установлен режим: {self.current_mode}", "DEBUG")
        self.update_status_signal.emit(f"✔ {msg}" if self.sing_box_process else f"⚠ {msg}")
        self.start_btn.setEnabled(self.sing_box_process is None)
        self.stop_btn.setEnabled(self.sing_box_process is not None)
        self.change_subscription_btn.setEnabled(True)
        self.server_combo.setEnabled(bool(self.outbounds and not isinstance(self.outbounds, str)))
        for button in self.mode_buttons:
            button.setEnabled(self.sing_box_process is None)
            if button == self.current_mode_button:
                button.setChecked(True)
            else:
                button.setChecked(False)
        self.update_ui_visibility()

    def stop_sing(self):
        log_message(f"[{get_timestamp()}] Остановка sing-box", "DEBUG")
        try:
            status = terminate_sing_box(self.sing_box_process)
            if self.current_mode == 'proxy':
                status += "\n" + cleanup_proxy()
                log_message(f"[{get_timestamp()}] Очистка системного прокси", "DEBUG")
            self.sing_box_process = None
            self.current_mode = None
            if self.current_mode_button:
                self.current_mode_button.setChecked(False)
            self.current_mode_button = None
            self.update_status_signal.emit(f"✔ {status}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.change_subscription_btn.setEnabled(True)
            self.server_combo.setEnabled(bool(self.outbounds and not isinstance(self.outbounds, str)))
            for button in self.mode_buttons:
                button.setEnabled(True)
                button.setChecked(False)
            self.update_ui_visibility()
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка в stop_sing: {e}", "ERROR")
            self.update_status_signal.emit(f"⚠ Ошибка остановки: {e} [{get_timestamp()}]")
            self.subscription_input.clearFocus()
            self.stop_btn.setFocus()

    def cleanup_existing_processes(self):
        log_message(f"[{get_timestamp()}] Очистка процессов", "DEBUG")
        try:
            for pid in get_sing_box_pids():
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    proc.wait(timeout=2)
                    log_message(f"[{get_timestamp()}] Завершён процесс PID: {pid}", "DEBUG")
                except Exception as e:
                    log_message(f"[{get_timestamp()}] Ошибка очистки процесса PID {pid}: {e}", "ERROR")
        except Exception as e:
            log_message(f"[{get_timestamp()}] Ошибка очистки процессов: {e}", "ERROR")
            cleanup_network()
            cleanup_proxy()

def start_application(app, loop):
    saved_url = load_subscription()
    window = SingBoxGUI(loop)
    if saved_url:
        window.check_subscription_and_show_welcome()
    else:
        dialog = WelcomeDialog(window)
        if dialog.exec_():
            window.subscription_input.setText(dialog.subscription_input.text().strip())
            window.change_subscription()
        else:
            sys.exit(0)
    if check_windows_version() < "10":
        log_message(
            f"[{get_timestamp()}] Предупреждение: приложение может работать некорректно на Windows {check_windows_version()}",
            "WARNING")
        window.status_label.setText(f"⚠ [{get_timestamp()}] Требуется Windows 10 или выше")

if __name__ == "__main__":
    try:
        log_message(f"[{get_timestamp()}] Запуск приложения", "DEBUG")
        app = QApplication(sys.argv)
        loop = qasync.QEventLoop(app)
        asyncio.set_event_loop(loop)
        apply_material_design_style(app)
        start_application(app, loop)
        with loop:
            loop.run_forever()
    except Exception as e:
        log_message(f"[{get_timestamp()}] Критическая ошибка: {e}", "ERROR")