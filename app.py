import streamlit as st
import os
import json
import time
import requests
import pandas as pd
import threading
import smtplib
import logging
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import List, Dict
from playwright.sync_api import sync_playwright
import glob
import socket
import platform
import zipfile
import subprocess


# Настройка логирования
LOG_FILE = "app.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def log_message(message: str, level: str = "info"):
    tz_msk = timezone(timedelta(hours=3))
    now_str = datetime.now(timezone.utc).astimezone(tz_msk).strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"{now_str} [{level.upper()}] {message}"
    
    # Запись в файл
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")
        
    if level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)
    else:
        logging.info(message)

# Глобальный синглтон для хранения состояния парсинга (сохраняется при перезапусках Streamlit)
@st.cache_resource
def get_parser_state() -> dict:
    return {"status": "idle", "processed": 0, "total": 0, "last_error": None, "excel_file": None}

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "fgis_token": "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJGQVUgTklBIiwic3ViIjoiYW5vbnltb3VzIiwiZXhwIjoxNzg0MjE0ODcxLCJpYXQiOjE3ODQxODYwNzF9.EJ_Ucxr2DvcUodjbxYOWkL-VjBbhb7mmwXX2G2wlOezt3oK_7Co0wmkI-qyu0h7q1fmJZnGvL6EUgcKFTp-dDA",
    "cookies": {
        "_ym_d": "1773817936",
        "_ym_fa": "11080.gA0pXAktrNtlSCOcKNwVJ6vSQ2PZ2A2iVm4vNv5NbCXkelSSxUpOETYyWrYRnGTj.VTGE7TWClREEubI5u7w0L0PJVf8%2C",
        "_ym_isad": "2",
        "_ym_uid": "1773817936714719593",
        "PHPSESSID": "W2Pyq8mgYZ4xXE6r4rQtOC1I6QxdIxlb",
        "session-cookie": "18c2b3c6967397ee9641add9e59e4e02cecaf59bea6885b61fbf45cf6a5fff7ccb5761fee5e852713d65d1e42ce90ff5"
    },
    "auto_update_token": True,
    "token_update_time_msk": "02:00",
    "smtp_sender": "roskachestvo.apps@gmail.com",
    "smtp_password": "",
    "admin_email": "",
    "boss_email": "",
    "admin_report_time_msk": "09:00",
    "auto_run_parser": True,
    "email_subject_admin": "Отчет ФГИС ФСА: Работоспособность системы",
    "email_body_admin": """<h3>Отчет о работоспособности системы ФГИС ФСА</h3>
<p><b>Время проверки (МСК):</b> {time_msk}</p>
<p><b>Статус токена:</b> {token_status}</p>
<p><b>Результат проверки API ФСА:</b> {api_test_status}</p>
<p><b>Детали:</b> {details}</p>
<p><i>Система работает в штатном режиме.</i></p>""",
    "email_subject_boss": "Реестр ФГИС ФСА: Сертификаты, требующие прекращения действия",
    "email_body_boss": """<h3>Уважаемый руководитель!</h3>
<p>В ходе автоматического анализа реестра ФГИС ФСА были обнаружены сертификаты соответствия, срок действия которых уже истек, но они все еще находятся в статусе <b>"Действует"</b>.</p>
<p>Пожалуйста, переведите данные сертификаты в статус <b>"Прекращен"</b> в ручном режиме во ФГИС ФСА.</p>
<br>
{table_html}
<br>
<p><i>Отчет сформирован автоматически.</i></p>""",
    "proxy": "",
    "use_xray_proxy": False,
    "xray_config": {}
}

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_xray_proxy() -> bool:
    config = load_config()
    if not config.get("use_xray_proxy"):
        return False
        
    xray_cfg = config.get("xray_config")
    if not xray_cfg:
        log_message("Xray прокси включен, но xray_config пустой.", "warning")
        return False
        
    port = 10809
    try:
        if isinstance(xray_cfg, dict) and "inbounds" in xray_cfg:
            for inbound in xray_cfg["inbounds"]:
                if inbound.get("protocol") == "http":
                    port = inbound.get("port", port)
                    break
    except Exception as e:
        log_message(f"Не удалось распарсить порт из config: {e}", "warning")

    if is_port_in_use(port):
        log_message(f"Xray прокси уже активен на порту {port}.")
        return True

    log_message("Запуск Xray прокси для обхода геоблокировок...")
    
    sys_name = platform.system().lower()
    arch = platform.machine().lower()
    
    os_name = "linux" if sys_name == "linux" else "macos"
    if "arm" in arch or "aarch64" in arch:
        arch_suffix = "arm64-v8a"
    else:
        arch_suffix = "64"
        
    binary_name = "xray"
    if sys_name == "windows":
        binary_name = "xray.exe"
        filename = f"Xray-windows-{arch_suffix}.zip"
    else:
        filename = f"Xray-{os_name}-{arch_suffix}.zip"
        
    binary_path = os.path.abspath(binary_name)
    
    if not os.path.exists(binary_path):
        XRAY_VERSION = "26.3.27"
        url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{filename}"
        log_message(f"Скачивание бинарного файла Xray с {url}...")
        try:
            r = requests.get(url, stream=True, timeout=30)
            if r.status_code != 200:
                log_message(f"Не удалось скачать Xray: статус {r.status_code}", "error")
                return False
                
            zip_path = "xray.zip"
            with open(zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            log_message("Распаковка Xray...")
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(".")
                
            if os.path.exists(zip_path):
                os.remove(zip_path)
                
            if sys_name != "windows" and os.path.exists(binary_path):
                os.chmod(binary_path, 0o755)
        except Exception as e:
            log_message(f"Ошибка при скачивании или распаковке Xray: {e}", "error")
            return False
            
    if not os.path.exists(binary_path):
        log_message("Бинарный файл Xray не найден после скачивания.", "error")
        return False
        
    import copy
    config_file = "xray_config_run.json"
    try:
        xray_cfg_clean = copy.deepcopy(xray_cfg)
        if isinstance(xray_cfg_clean, dict) and "log" in xray_cfg_clean:
            del xray_cfg_clean["log"]
            
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(xray_cfg_clean, f, indent=2)
    except Exception as e:
        log_message(f"Не удалось сохранить конфиг Xray: {e}", "error")
        return False
        
    try:
        log_out = open("xray_run.log", "w", encoding="utf-8")
        proc = subprocess.Popen(
            [binary_path, "-config", config_file],
            stdout=log_out,
            stderr=subprocess.STDOUT,
            close_fds=True
        )
        time.sleep(3)
        
        if not is_port_in_use(port):
            log_message("Ошибка: Xray запущен, но порт не отвечает. Проверяем логи...", "error")
            if os.path.exists("xray_run.log"):
                with open("xray_run.log", "r", encoding="utf-8") as lf:
                    content = lf.read()
                    log_message(f"Логи Xray:\n{content}", "error")
            return False
            
        log_message(f"Процесс Xray успешно запущен на порту {port}.")
        return True
    except Exception as e:
        log_message(f"Не удалось запустить Xray: {e}", "error")
        return False


def load_config() -> dict:
    config = DEFAULT_CONFIG.copy()
    
    # 1. Загружаем из локального файла config.json, если он есть
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            log_message(f"Ошибка загрузки конфигурации из файла: {e}", "error")
            
    # 2. Если запущен в Streamlit Cloud, переопределяем значения через st.secrets
    try:
        for k in DEFAULT_CONFIG.keys():
            if k in st.secrets:
                val = st.secrets[k]
                # Пропускаем стандартные заглушки/плейсхолдеры, чтобы они не перебивали настройки из веб-интерфейса
                if isinstance(val, str) and ("ВАШ_" in val or "example.com" in val):
                    continue
                    
                if isinstance(DEFAULT_CONFIG[k], dict):
                    try:
                        if isinstance(val, str):
                            config[k] = json.loads(val)
                        else:
                            config[k] = dict(val)
                    except Exception as e:
                        if isinstance(val, str):
                            lines_str = [f"{i+1:03d}: {line}" for i, line in enumerate(val.split('\n'))]
                            full_lines = "\n".join(lines_str)
                            log_message(f"Ошибка разбора словаря {k} из секретов: {e}.\nСодержимое конфигурации:\n{full_lines}", "warning")
                        else:
                            log_message(f"Ошибка разбора словаря {k} из секретов: {e}. Тип: {type(val)}", "warning")
                    except Exception:
                        pass
                else:
                    config[k] = val
    except Exception:
        pass # Игнорируем ошибки, если st.secrets не инициализирован (локальный запуск)
        
    return config


def save_config(config: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log_message(f"Ошибка сохранения конфигурации: {e}", "error")

def get_msk_now() -> datetime:
    tz_msk = timezone(timedelta(hours=3))
    return datetime.now(timezone.utc).astimezone(tz_msk)

# ----------------- SMTP ОТПРАВКА -----------------

def send_email(to_email: str, subject: str, body: str, attachment_path: str = None) -> bool:
    config = load_config()
    sender = config.get("smtp_sender", "roskachestvo.apps@gmail.com")
    password = config.get("smtp_password", "")
    
    if not to_email:
        log_message(f"Пропуск отправки email: не указан адрес получателя.", "warning")
        return False
    if not sender or not password:
        log_message("Ошибка отправки почты: SMTP отправитель или пароль приложения не настроены.", "error")
        return False
        
    try:
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html', 'utf-8'))
        
        if attachment_path and os.path.exists(attachment_path):
            filename = os.path.basename(attachment_path)
            with open(attachment_path, "rb") as f:
                attach = MIMEApplication(f.read(), _subtype="xlsx")
                attach.add_header('Content-Disposition', 'attachment', filename=filename)
                msg.attach(attach)
                
        # Подключаемся к Gmail SMTP с поддержкой SSL (465) и резервным TLS (587)
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15)
            server.login(sender, password)
        except Exception as ssl_err:
            log_message(f"Подключение через SSL (порт 465) не удалось: {ssl_err}. Пробуем резервный TLS (порт 587)...", "warning")
            server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
            server.starttls()
            server.login(sender, password)
            
        server.sendmail(sender, [to_email], msg.as_string())
        server.close()
        log_message(f"Письмо успешно отправлено на {to_email} с темой '{subject}'")
        return True
    except Exception as e:
        log_message(f"Ошибка отправки письма на {to_email}: {str(e)}", "error")
        return False

# ----------------- PLAYWRIGHT ОБНОВЛЕНИЕ ТОКЕНА -----------------

def run_playwright_token_update() -> bool:
    log_message("Запуск Playwright для обновления токена...")
    url = "https://pub.fsa.gov.ru/rsds/products"
    
    config = load_config()
    proxy = config.get("proxy", "")
    if config.get("use_xray_proxy"):
        xray_port = 10809
        try:
            xray_cfg = config.get("xray_config", {})
            if isinstance(xray_cfg, dict) and "inbounds" in xray_cfg:
                for inbound in xray_cfg["inbounds"]:
                    if inbound.get("protocol") == "http":
                        xray_port = inbound.get("port", xray_port)
                        break
        except:
            pass
        proxy = f"http://127.0.0.1:{xray_port}"
        
    for attempt in range(2):
        try:
            with sync_playwright() as p:
                launch_kwargs = {"headless": True}
                if proxy:
                    launch_kwargs["proxy"] = {"server": proxy}
                browser = p.chromium.launch(**launch_kwargs)
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1280, "height": 800}
                )
                page = context.new_page()
                
                page.goto(url, wait_until="networkidle", timeout=60000)
                time.sleep(5)
                
                token = page.evaluate("() => localStorage.getItem('fgis_token')")
                
                playwright_cookies = context.cookies()
                cookies_dict = {c['name']: c['value'] for c in playwright_cookies}
                
                browser.close()
                
                if token:
                    config = load_config()
                    config["fgis_token"] = token
                    if cookies_dict:
                        for k, v in cookies_dict.items():
                            config["cookies"][k] = v
                    save_config(config)
                    log_message("Токен и куки ФГИС ФСА успешно обновлены через Playwright.")
                    return True
                else:
                    log_message("Ошибка: Playwright загрузил страницу, но 'fgis_token' в localStorage отсутствует.", "error")
                    return False
                    
        except Exception as e:
            if ("Executable doesn't exist" in str(e) or "playwright install" in str(e).lower()) and attempt == 0:
                log_message("Браузер Chromium не найден в Playwright. Запуск автоматической установки...")
                try:
                    import subprocess
                    subprocess.run(["playwright", "install", "chromium"], check=True)
                    log_message("Установка Chromium успешно завершена.")
                    continue
                except Exception as install_err:
                    log_message(f"Не удалось автоматически установить Chromium: {install_err}", "error")
                    return False
            else:
                log_message(f"Критическая ошибка автообновления токена через Playwright: {str(e)}", "error")
                return False

# ----------------- ПАРСЕР ФГИС ФСА -----------------

class FSAparser:
    def __init__(self, token: str, cookies: dict):
        self.url = "https://pub.fsa.gov.ru/api/v1/rsds/certificate/production"
        self.token = token
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "ru",
            "Authorization": f"Bearer {self.token}",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json",
            "Origin": "https://pub.fsa.gov.ru",
            "Referer": "https://pub.fsa.gov.ru/rsds/products",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        self.cookies = cookies
        self.base_payload = {
            "columns": [],
            "sort": ["-id"],
            "limit": 100,
            "offset": 0,
            "sortBy": "id",
            "sortDest": "desc",
            "numberOfAllRecords": False,
            "page": 0,
            "attestatRegNumber": None,
            "numberCertificate": None,
            "sendDate": {"startDate": None, "endDate": None},
            "certEndDate": {},
            "idLegalSubjectType": None,
            "idObjectCertType": None,
            "idCertType": None,
            "idProductOrigin": [],
            "idStatus": [],
            "idType": None,
            "idsSystemVoluntaryCertificationPublic": []
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            self.session.cookies.update(self.cookies)
            
        config = load_config()
        proxy = config.get("proxy", "")
        if config.get("use_xray_proxy"):
            xray_port = 10809
            try:
                xray_cfg = config.get("xray_config", {})
                if isinstance(xray_cfg, dict) and "inbounds" in xray_cfg:
                    for inbound in xray_cfg["inbounds"]:
                        if inbound.get("protocol") == "http":
                            xray_port = inbound.get("port", xray_port)
                            break
            except:
                pass
            proxy = f"http://127.0.0.1:{xray_port}"
            
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
            
    def test_connection(self) -> bool:
        payload = self.base_payload.copy()
        payload["limit"] = 1
        try:
            res = self.session.post(self.url, json=payload, timeout=15)
            return res.status_code == 200
        except Exception as e:
            log_message(f"Тест соединения к API ФСА завершился ошибкой: {e}", "warning")
            return False

    def parse_all(self) -> List[Dict]:
        parser_state = get_parser_state()
        all_items = []
        page = 0
        total = None
        
        parser_state["status"] = "running"
        parser_state["processed"] = 0
        parser_state["total"] = 0
        parser_state["last_error"] = None
        
        log_message("Начало парсинга сертификатов с API ФСА...")
        
        while True:
            payload = self.base_payload.copy()
            payload["page"] = page
            payload["offset"] = page
            payload["limit"] = 100
            
            try:
                response = self.session.post(self.url, json=payload, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if total is None:
                        total = data.get("total", 0)
                        parser_state["total"] = total
                        log_message(f"API ФСА: Найдено всего записей: {total}")
                    
                    items = data.get("items", [])
                    
                    if not items:
                        log_message(f"Парсинг успешно завершен. Получено {len(all_items)} записей.")
                        break
                    
                    all_items.extend(items)
                    parser_state["processed"] = len(all_items)
                    
                    if len(all_items) >= total:
                        break
                    
                    time.sleep(0.5)
                    page += 1
                else:
                    error_msg = f"Ошибка API ФСА {response.status_code}: {response.text[:150]}"
                    log_message(error_msg, "error")
                    parser_state["last_error"] = error_msg
                    break
                    
            except Exception as e:
                error_msg = f"Исключение при запросе к API ФСА: {str(e)}"
                log_message(error_msg, "error")
                parser_state["last_error"] = error_msg
                break
                
        parser_state["status"] = "completed" if not parser_state["last_error"] else "failed"
        return all_items

    def flatten_certificate(self, cert: Dict) -> Dict:
        flat = {
            "id": cert.get("id"),
            "productionId": cert.get("productionId"),
            "numberCertificate": cert.get("numberCertificate"),
            "attestatRegNumber": cert.get("attestatRegNumber"),
            "blankNumber": cert.get("blankNumber"),
            "fullNameProduct": cert.get("fullNameProduct", "").replace("\n", " ").strip() if cert.get("fullNameProduct") else "",
            "fullNameApplicant": cert.get("fullNameApplicant"),
            "innApplicant": cert.get("innApplicant"),
            "ogrnApplicant": cert.get("ogrnApplicant"),
            "applicantType": cert.get("applicantType"),
            "idLegalSubjectType": cert.get("idLegalSubjectType"),
            "idLegalFormApplicant": cert.get("idLegalFormApplicant"),
            "fullNameManufacturer": cert.get("fullNameManufacturer"),
            "innManufacturer": cert.get("innManufacturer"),
            "certSendDate": cert.get("certSendDate"),
            "certEndDate": cert.get("certEndDate"),
            "certCreateDate": cert.get("certCreateDate"),
            "inspectionControlPlanDate": cert.get("inspectionControlPlanDate"),
            "idStatus": cert.get("idStatus"),
            "idType": cert.get("idType"),
            "idCertScheme": cert.get("idCertScheme"),
            "idProductOrigin": cert.get("idProductOrigin"),
            "sdsNumber": cert.get("sdsNumber"),
            "sdsName": cert.get("sdsName"),
            "testingLabs_count": len(cert.get("testingLabs", [])) if cert.get("testingLabs") else 0,
            "protocols_count": sum(len(lab.get("protocols", [])) for lab in cert.get("testingLabs", [])) if cert.get("testingLabs") else 0,
        }
        
        labs = cert.get("testingLabs", []) or []
        lab_numbers = []
        protocol_dates = []
        
        for lab in labs:
            if lab.get("regNumberTestingLab"):
                lab_numbers.append(lab.get("regNumberTestingLab"))
            for protocol in lab.get("protocols", []) or []:
                if protocol.get("date"):
                    protocol_dates.append(protocol.get("date"))
        
        flat["testingLabs"] = ", ".join(lab_numbers)
        flat["protocolDates"] = ", ".join(protocol_dates)
        return flat

    def save_to_files(self, certificates: List[Dict]) -> str:
        if not certificates:
            return None
        
        # Сортируем сырые сертификаты по ID по убыванию, чтобы порядок на всех листах совпадал
        certificates = sorted(certificates, key=lambda x: x.get("id", 0), reverse=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_filename = f"certificates_{timestamp}.xlsx"
        json_filename = f"certificates_raw_{timestamp}.json"
        
        # Сохраняем сырой JSON
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(certificates, f, ensure_ascii=False, indent=2)
            log_message(f"Сырые данные JSON сохранены в {json_filename}")
        except Exception as e:
            log_message(f"Ошибка сохранения JSON: {e}", "error")
            
        # Форматируем и сохраняем Excel
        try:
            # 1. Полная выгрузка (Лист 1)
            flat_data = [self.flatten_certificate(c) for c in certificates]
            df = pd.DataFrame(flat_data)
            
            # 2. Для руководителя (Лист 2)
            STATUS_NAMES = {
                1: "Черновик",
                2: "Аннулирован",
                3: "Приостановлен",
                4: "Продлен",
                5: "Архивный",
                6: "Действует",
                7: "Прекращен"
            }
            
            def format_date(date_str: str) -> str:
                if not date_str:
                    return ""
                try:
                    if len(date_str) >= 10:
                        if "-" in date_str[:10]:
                            parts = date_str[:10].split("-")
                            if len(parts[0]) == 4:
                                return f"{parts[2]}.{parts[1]}.{parts[0]}"
                            return f"{parts[0]}.{parts[1]}.{parts[2]}"
                except Exception:
                    pass
                return date_str

            adapted_data = []
            for c in certificates:
                flat = self.flatten_certificate(c)
                sds_sign = c.get("sdsSign") or c.get("signSds") or c.get("systemSign") or c.get("sdsSignLabel") or ""
                reg_date = flat.get("certSendDate") or flat.get("certCreateDate") or ""
                
                row = {
                    "Статус сертификата": STATUS_NAMES.get(flat.get("idStatus"), f"Код {flat.get('idStatus')}"),
                    "Номер сертификата": flat.get("numberCertificate", ""),
                    "Дата регистрации сертификата в системе": format_date(reg_date),
                    "Дата окончания действия сертификата": format_date(flat.get("certEndDate", "")),
                    "Знак системы": sds_sign,
                    "Номер системы": flat.get("sdsNumber") or "",
                    "Наименование системы": flat.get("sdsName") or "",
                    "Общее наименование продукции": flat.get("fullNameProduct", ""),
                    "Заявитель": flat.get("fullNameApplicant", ""),
                    "ИНН Заявителя": flat.get("innApplicant", ""),
                    "Изготовитель": flat.get("fullNameManufacturer", ""),
                    "ИНН Изготовителя": flat.get("innManufacturer", ""),
                    "Номер записи в РАЛ органа по сертификации": flat.get("attestatRegNumber", "")
                }
                adapted_data.append(row)
                
            df_adapted = pd.DataFrame(adapted_data)
            
            with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Полная выгрузка', index=False)
                df_adapted.to_excel(writer, sheet_name='Для руководителя', index=False)
                
                stats = pd.DataFrame({
                    'Показатель': [
                        'Всего сертификатов',
                        'Уникальных заявителей',
                        'Уникальных производителей',
                        'Уникальных ИНН',
                        'Среднее кол-во лабораторий',
                        'Действующих (статус 6)'
                    ],
                    'Значение': [
                        len(df),
                        df['fullNameApplicant'].nunique() if 'fullNameApplicant' in df.columns else 0,
                        df['fullNameManufacturer'].nunique() if 'fullNameManufacturer' in df.columns else 0,
                        df['innApplicant'].nunique() if 'innApplicant' in df.columns else 0,
                        round(df['testingLabs_count'].mean(), 2) if 'testingLabs_count' in df.columns and len(df) > 0 else 0,
                        len(df[df['idStatus'] == 6]) if 'idStatus' in df.columns else 0
                    ]
                })
                stats.to_excel(writer, sheet_name='Статистика', index=False)
                
                for sheet in writer.sheets:
                    worksheet = writer.sheets[sheet]
                    for column in worksheet.columns:
                        max_length = 0
                        column_letter = column[0].column_letter
                        for cell in column:
                            try:
                                if len(str(cell.value)) > max_length:
                                    max_length = len(str(cell.value))
                            except:
                                pass
                        worksheet.column_dimensions[column_letter].width = min(max_length + 2, 50)
            
            log_message(f"Данные Excel успешно сохранены в {excel_filename}")
            
            # Удаляем предыдущие файлы выгрузок (все, кроме только что созданных)
            import glob
            for old_file in glob.glob("certificates_*.xlsx") + glob.glob("certificates_raw_*.json"):
                if old_file not in [excel_filename, json_filename]:
                    try:
                        os.remove(old_file)
                        log_message(f"Удален предыдущий файл выгрузки: {old_file}")
                    except Exception as ex:
                        log_message(f"Не удалось удалить старый файл {old_file}: {ex}", "warning")
                        
            return excel_filename
        except Exception as e:
            log_message(f"Ошибка сохранения Excel: {e}", "error")
            return None

# ----------------- БИЗНЕС ЛОГИКА ФОНОВЫХ ЗАДАЧ -----------------

def run_parsing_and_report_flow() -> str:
    parser_state = get_parser_state()
    config = load_config()
    parser = FSAparser(config["fgis_token"], config["cookies"])
    
    certs = parser.parse_all()
    if not certs:
        log_message("Парсинг не вернул результатов. Отправка отчета руководителю отменена.", "warning")
        parser_state["status"] = "failed"
        parser_state["last_error"] = "Парсинг не вернул результатов."
        return None
        
    excel_file = parser.save_to_files(certs)
    parser_state["excel_file"] = excel_file
    
    expired_certs = []
    tz_msk = timezone(timedelta(hours=3))
    today = datetime.now(timezone.utc).astimezone(tz_msk).date()
    
    for c in certs:
        if c.get("idStatus") == 6:
            end_date_str = c.get("certEndDate")
            if end_date_str:
                try:
                    end_date = datetime.strptime(end_date_str, "%d-%m-%Y").date()
                    if end_date < today:
                        expired_certs.append(c)
                except Exception:
                    pass
                    
    log_message(f"Анализ просрочки завершен: из {len(certs)} действующих найдено {len(expired_certs)} просроченных сертификатов.")
    
    if expired_certs:
        rows_html = ""
        for i, c in enumerate(expired_certs, 1):
            detail_url = f"https://pub.fsa.gov.ru/rsds/certificate/details/{c.get('id')}"
            rows_html += f"""
            <tr>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">{i}</td>
                <td style="border: 1px solid #ddd; padding: 8px;"><a href="{detail_url}" target="_blank">{c.get('numberCertificate', 'N/A')}</a></td>
                <td style="border: 1px solid #ddd; padding: 8px;">{c.get('fullNameApplicant', 'N/A')}</td>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: center; color: red; font-weight: bold;">{c.get('certEndDate', 'N/A')}</td>
            </tr>
            """
        
        table_html = f"""
        <table style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
            <thead>
                <tr style="background-color: #f2f2f2;">
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: center; width: 50px;">№</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: left;">Номер сертификата (ссылка)</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: left;">Заявитель</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: center; width: 150px;">Дата окончания</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
        """
        
        subject = config.get("email_subject_boss", "Реестр ФГИС ФСА: Требуется прекращение действия сертификатов")
        body = config.get("email_body_boss", "").replace("{table_html}", table_html)
        
        if config.get("boss_email"):
            send_email(config["boss_email"], subject, body, attachment_path=excel_file)
        else:
            log_message("Адрес руководителя (boss_email) не настроен. Письмо не отправлено.", "warning")
    else:
        log_message("Просроченных действующих сертификатов не обнаружено. Отправляем уведомление руководителю...")
        if config.get("boss_email"):
            subject = "Реестр ФГИС ФСА: Проверка просроченных сертификатов"
            body = """<h3>Уважаемый руководитель!</h3>
            <p>В ходе автоматического анализа реестра ФГИС ФСА действующих сертификатов с истекшим сроком действия <b>не обнаружено</b>.</p>
            <p>Полный реестр сертификатов находится во вложении.</p>
            <br>
            <p><i>Отчет сформирован автоматически.</i></p>"""
            send_email(config["boss_email"], subject, body, attachment_path=excel_file)
        else:
            log_message("Адрес руководителя (boss_email) не настроен. Письмо не отправлено.", "warning")
        
    parser_state["status"] = "completed"
    return excel_file

def auto_update_token_task():
    log_message("--- Старт фоновой задачи автообновления токена ---")
    success = run_playwright_token_update()
    
    if success:
        config = load_config()
        if config.get("auto_run_parser", True):
            log_message("Запуск автоматического парсинга после обновления токена...")
            threading.Thread(target=run_parsing_and_report_flow, daemon=True).start()
    else:
        config = load_config()
        if config.get("admin_email"):
            subject = "КРИТИЧЕСКИЙ СБОЙ: Автообновление токена ФГИС ФСА"
            body = f"""<h3>Внимание! Произошел сбой автообновления токена ФГИС ФСА.</h3>
            <p><b>Время сбоя (МСК):</b> {get_msk_now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Система не смогла автоматически обновить токен через Playwright. Пожалуйста, зайдите во вкладку разработчика на сайте ФСА, скопируйте <code>fgis_token</code> и обновите настройки вручную в веб-интерфейсе.</p>
            <p>Подробности смотрите в лог-файле <code>app.log</code>.</p>"""
            send_email(config["admin_email"], subject, body)

def send_admin_report_task():
    log_message("--- Старт фоновой задачи отправки отчета админу ---")
    config = load_config()
    
    parser = FSAparser(config["fgis_token"], config["cookies"])
    is_working = parser.test_connection()
    
    token_status = "Активен" if is_working else "Неактивен / Протух"
    api_test_status = "Успешно (API отвечает 200)" if is_working else "Ошибка авторизации / Сетевая ошибка"
    details = "Все проверки пройдены. Автообновление работает." if is_working else "Требуется ручное обновление токена или кук."
    
    subject = config.get("email_subject_admin", "Отчет ФГИС ФСА: Работоспособность системы")
    body_template = config.get("email_body_admin", "")
    
    body = body_template.format(
        time_msk=get_msk_now().strftime('%Y-%m-%d %H:%M:%S'),
        token_status=token_status,
        api_test_status=api_test_status,
        details=details
    )
    
    if config.get("admin_email"):
        send_email(config["admin_email"], subject, body)
    else:
        log_message("Адрес администратора (admin_email) не настроен. Отчет не отправлен.", "warning")

def send_notifications_from_latest_data() -> tuple:
    """
    Находит последнюю выгрузку, анализирует просроченные сертификаты,
    отправляет уведомление руководителю (boss_email) с прикрепленным файлом Excel
    и отчет администратору (admin_email).
    Возвращает (success_boss, success_admin, details_msg).
    """
    config = load_config()
    
    # 1. Поиск файлов выгрузки
    json_files = glob.glob("certificates_raw_*.json")
    if not json_files:
        return False, False, "Не найдено файлов предыдущих выгрузок. Пожалуйста, запустите выгрузку сертификатов сначала."
    
    # Сортируем по имени по убыванию (самый свежий по таймстампу)
    json_files.sort(reverse=True)
    latest_json = json_files[0]
    
    # Извлекаем таймстамп из названия
    timestamp = latest_json.replace("certificates_raw_", "").replace(".json", "")
    excel_file = f"certificates_{timestamp}.xlsx"
    if not os.path.exists(excel_file):
        excel_files = glob.glob(f"certificates_*{timestamp}*.xlsx")
        if excel_files:
            excel_file = excel_files[0]
        else:
            excel_file = None
            
    try:
        with open(latest_json, "r", encoding="utf-8") as f:
            certs = json.load(f)
    except Exception as e:
        log_message(f"Ошибка чтения JSON при ручной отправке: {e}", "error")
        return False, False, f"Ошибка чтения файла выгрузки: {str(e)}"
        
    # 2. Анализ просроченных сертификатов
    expired_certs = []
    tz_msk = timezone(timedelta(hours=3))
    today = datetime.now(timezone.utc).astimezone(tz_msk).date()
    
    for c in certs:
        if c.get("idStatus") == 6:
            end_date_str = c.get("certEndDate")
            if end_date_str:
                try:
                    end_date = datetime.strptime(end_date_str, "%d-%m-%Y").date()
                    if end_date < today:
                        expired_certs.append(c)
                except Exception:
                    pass
                    
    log_message(f"Ручная рассылка: из {len(certs)} действующих найдено {len(expired_certs)} просроченных сертификатов.")
    
    # 3. Отправка руководителю
    success_boss = False
    if expired_certs:
        rows_html = ""
        for i, c in enumerate(expired_certs, 1):
            detail_url = f"https://pub.fsa.gov.ru/rsds/certificate/details/{c.get('id')}"
            rows_html += f"""
            <tr>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">{i}</td>
                <td style="border: 1px solid #ddd; padding: 8px;"><a href="{detail_url}" target="_blank">{c.get('numberCertificate', 'N/A')}</a></td>
                <td style="border: 1px solid #ddd; padding: 8px;">{c.get('fullNameApplicant', 'N/A')}</td>
                <td style="border: 1px solid #ddd; padding: 8px; text-align: center; color: red; font-weight: bold;">{c.get('certEndDate', 'N/A')}</td>
            </tr>
            """
        
        table_html = f"""
        <table style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
            <thead>
                <tr style="background-color: #f2f2f2;">
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: center; width: 50px;">№</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: left;">Номер сертификата (ссылка)</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: left;">Заявитель</th>
                    <th style="border: 1px solid #ddd; padding: 12px; text-align: center; width: 150px;">Дата окончания</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
        """
        
        subject_boss = config.get("email_subject_boss", "Реестр ФГИС ФСА: Требуется прекращение действия сертификатов")
        body_boss = config.get("email_body_boss", "").replace("{table_html}", table_html)
        
        if config.get("boss_email"):
            attachment = excel_file if excel_file and os.path.exists(excel_file) else None
            success_boss = send_email(config["boss_email"], subject_boss, body_boss, attachment_path=attachment)
        else:
            success_boss = "no_email"
    else:
        if config.get("boss_email"):
            subject_boss = "Реестр ФГИС ФСА: Проверка просроченных сертификатов"
            body_boss = """<h3>Уважаемый руководитель!</h3>
            <p>В ходе анализа реестра ФГИС ФСА действующих сертификатов с истекшим сроком действия <b>не обнаружено</b>.</p>
            <p>Полный реестр сертификатов находится во вложении.</p>
            <br>
            <p><i>Отчет сформирован автоматически.</i></p>"""
            attachment = excel_file if excel_file and os.path.exists(excel_file) else None
            success_boss = send_email(config["boss_email"], subject_boss, body_boss, attachment_path=attachment)
        else:
            success_boss = "no_email"
        
    # 4. Отправка администратору
    success_admin = False
    parser_obj = FSAparser(config["fgis_token"], config["cookies"])
    is_working = parser_obj.test_connection()
    
    token_status = "Активен" if is_working else "Неактивен / Протух"
    api_test_status = "Успешно (API отвечает 200)" if is_working else "Ошибка авторизации / Сетевая ошибка"
    details = f"Ручной запуск отправки уведомлений. Файл последней выгрузки: {latest_json}."
    
    subject_admin = config.get("email_subject_admin", "Отчет ФГИС ФСА: Работоспособность системы")
    body_template = config.get("email_body_admin", "")
    body_admin = body_template.format(
        time_msk=get_msk_now().strftime('%Y-%m-%d %H:%M:%S'),
        token_status=token_status,
        api_test_status=api_test_status,
        details=details
    )
    
    if config.get("admin_email"):
        success_admin = send_email(config["admin_email"], subject_admin, body_admin)
    else:
        success_admin = "no_email"
        
    info_msg = f"Использован файл от {timestamp}. Найдено {len(certs)} сертификатов, {len(expired_certs)} просрочено."
    return success_boss, success_admin, info_msg

# ----------------- ГЛОБАЛЬНЫЙ ПЛАНИРОВЩИК (МСК) -----------------

def scheduler_worker():
    log_message("Фоновый поток планировщика запущен.")
    last_run_token = ""
    last_run_admin = ""
    
    while True:
        try:
            config = load_config()
            now_msk = get_msk_now()
            now_str = now_msk.strftime("%H:%M")
            today_str = now_msk.strftime("%Y-%m-%d")
            
            # 1. Проверяем автообновление токена (2:00 МСК по дефолту)
            if config.get("auto_update_token", True):
                target_token_time = config.get("token_update_time_msk", "02:00")
                if now_str == target_token_time and last_run_token != today_str:
                    last_run_token = today_str
                    log_message(f"Планировщик: Время {now_str} МСК. Запуск автообновления токена...")
                    threading.Thread(target=auto_update_token_task, daemon=True).start()
            
            # 2. Проверяем отчет админу (9:00 МСК по дефолту)
            target_admin_time = config.get("admin_report_time_msk", "09:00")
            if now_str == target_admin_time and last_run_admin != today_str:
                last_run_admin = today_str
                log_message(f"Планировщик: Время {now_str} МСК. Запуск отправки отчета админу...")
                threading.Thread(target=send_admin_report_task, daemon=True).start()
                
        except Exception as e:
            log_message(f"Ошибка в цикле планировщика: {e}", "error")
            
        time.sleep(30)

@st.cache_resource
def start_scheduler():
    log_message("Инициализация глобального планировщика в Streamlit...")
    thread = threading.Thread(target=scheduler_worker, daemon=True)
    thread.start()
    
    try:
        start_xray_proxy()
    except Exception as e:
        log_message(f"Ошибка автоматического запуска Xray прокси: {e}", "error")
        
    return True

start_scheduler()
try:
    start_xray_proxy()
except Exception as e:
    log_message(f"Ошибка запуска Xray прокси на верхнем уровне: {e}", "error")


# ----------------- WEB ИНТЕРФЕЙС STREAMLIT -----------------

st.set_page_config(
    page_title="Панель управления ФГИС ФСА",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .reportview-container {
        background: #0F172A;
    }
    h1, h2, h3 {
        color: #F8FAFC !important;
        font-family: 'Outfit', sans-serif;
    }
    .stButton>button {
        background-color: #2563EB;
        color: white;
        border-radius: 8px;
        font-weight: 600;
        border: none;
        transition: all 0.3s ease;
        padding: 0.5rem 1rem;
    }
    .stButton>button:hover {
        background-color: #1D4ED8;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
    }
    .status-active {
        color: #10B981;
        font-weight: bold;
    }
    .status-inactive {
        color: #EF4444;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.title("📊 Автоматизация импорта сертификатов ФГИС ФСА")
st.write("Система автообновления авторизации, парсинга реестра соответствия и email-оповещения.")

config = load_config()

with st.sidebar:
    st.header("⚙️ Статус Системы")
    
    parser = FSAparser(config["fgis_token"], config["cookies"])
    is_connected = parser.test_connection()
    
    if is_connected:
        st.markdown('<p class="status-active">● Токен активен и работает</p>', unsafe_allow_html=True)
    else:
        st.markdown('<p class="status-inactive">● Токен требует обновления</p>', unsafe_allow_html=True)
        
    st.write(f"**Московское время:** {get_msk_now().strftime('%H:%M:%S')}")
    st.write(f"**Токен обновляется в:** {config.get('token_update_time_msk', '02:00')} МСК")
    st.write(f"**Отчет админу в:** {config.get('admin_report_time_msk', '09:00')} МСК")
    
    st.markdown("---")
    st.write("© 2026 Роскачество. Автоматизация.")

tab_main, tab_settings, tab_logs = st.tabs(["🚀 Панель управления", "⚙️ Настройки и Шаблоны", "📋 Журнал событий (Логи)"])

# ----------------- ВКЛАДКА 1: ПАНЕЛЬ УПРАВЛЕНИЯ -----------------
with tab_main:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Выгрузка сертификатов")
        st.write("Вы можете запустить принудительный парсинг реестра ФГИС ФСА вручную. При завершении парсинга Excel-файл будет отправлен руководителю (если настроена почта), а также доступен для скачивания здесь.")
        
        parser_state = get_parser_state()
        
        # Кнопка ручного запуска
        if st.button("📥 Запустить выгрузку сертификатов"):
            parser_state["status"] = "running"
            parser_state["processed"] = 0
            parser_state["total"] = 0
            parser_state["last_error"] = None
            parser_state["excel_file"] = None
            
            thread = threading.Thread(target=run_parsing_and_report_flow, daemon=True)
            thread.start()
            st.rerun()

        # Отображение прогресса парсинга
        if parser_state["status"] == "running":
            st.info("Выгрузка запущена. Пожалуйста, подождите...")
            processed = parser_state["processed"]
            total = parser_state["total"]
            if total > 0:
                pct = min(processed / total, 1.0)
                st.progress(pct)
                st.write(f"Спарсено: {processed} из {total} сертификатов ({int(pct*100)}%)")
            else:
                st.write(f"Спарсено: {processed} сертификатов (запрос общего количества)...")
            
            # Авторефреш через 2 секунды
            time.sleep(2)
            st.rerun()
            
        elif parser_state["status"] == "completed":
            st.success(f"Парсинг успешно завершен! Спарсено {parser_state['processed']} записей.")
            excel_path = parser_state["excel_file"]
            if excel_path and os.path.exists(excel_path):
                with open(excel_path, "rb") as f:
                    st.download_button(
                        label="💾 Скачать отчет Excel",
                        data=f,
                        file_name=os.path.basename(excel_path),
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
            # Не сбрасываем в idle сразу, чтобы кнопка скачивания оставалась видна. Сбросим при следующем нажатии кнопки "Запустить"
            
        elif parser_state["status"] == "failed":
            st.error(f"Парсинг завершился ошибкой: {parser_state['last_error']}")
            
        st.markdown("---")
        st.subheader("✉️ Рассылка уведомлений")
        st.write("Отправить отчеты руководителю и администратору вручную на основе данных последней выгрузки (без повторного парсинга):")
        
        if st.button("Отправить уведомления", icon=":material/send:", type="primary", width="stretch"):
            with st.spinner("Отправка уведомлений..."):
                success_boss, success_admin, info_msg = send_notifications_from_latest_data()
                
                if success_boss == "no_email":
                    st.warning("Почта руководителя не настроена в настройках.")
                elif success_boss:
                    st.success("Уведомление руководителю успешно отправлено!")
                else:
                    st.error("Не удалось отправить уведомление руководителю. Проверьте логи.")
                    
                if success_admin == "no_email":
                    st.warning("Почта администратора не настроена в настройках.")
                elif success_admin:
                    st.success("Отчет администратору успешно отправлен!")
                else:
                    st.error("Не удалось отправить отчет администратору. Проверьте логи.")
                
                if success_boss or success_admin:
                    st.info(info_msg)
            
    with col2:
        st.subheader("Быстрый тест функций")
        st.write("Проверить автообновление токена или отправить тестовые письма прямо сейчас:")
        
        if st.button("🔑 Тест автообновления токена (Playwright)"):
            with st.spinner("Запуск Chromium и получение токена... Это может занять до 1 минуты."):
                success = run_playwright_token_update()
                if success:
                    st.success("Токен успешно обновлен! Обновите страницу для просмотра статуса.")
                    st.rerun()
                else:
                    st.error("Не удалось обновить токен. Проверьте логи.")
                    
        if st.button("✉️ Отправить тест админу"):
            with st.spinner("Отправка тестового письма..."):
                config = load_config()
                if config.get("admin_email"):
                    success = send_email(
                        config["admin_email"],
                        "ТЕСТ: " + config.get("email_subject_admin"),
                        "<h3>Это тестовое сообщение</h3><p>Система SMTP работает корректно.</p>"
                    )
                    if success:
                        st.success(f"Тестовое письмо отправлено на {config['admin_email']}")
                    else:
                        st.error("Ошибка отправки. Проверьте настройки SMTP и пароль приложения.")
                else:
                    st.warning("Сначала укажите почту админа в настройках.")

# ----------------- ВКЛАДКА 2: НАСТРОЙКИ И ШАБЛОНЫ -----------------
with tab_settings:
    st.subheader("Настройки авторизации и планировщика")
    
    col_auth1, col_auth2 = st.columns(2)
    with col_auth1:
        auto_update = st.checkbox("Включить автообновление токена (Playwright в указанное время)", value=config.get("auto_update_token", True))
        token_time = st.text_input("Время автообновления токена (МСК, HH:MM)", value=config.get("token_update_time_msk", "02:00"))
        auto_parse = st.checkbox("Автоматически парсить сертификаты после обновления токена", value=config.get("auto_run_parser", True))
        proxy_val = st.text_input("HTTP/HTTPS Прокси (например, http://ip:port или http://user:pass@ip:port)", value=config.get("proxy", ""))
        
        st.markdown("##### Встроенный Xray (VLESS Reality)")
        use_xray = st.checkbox("Использовать встроенный Xray прокси", value=config.get("use_xray_proxy", False))
        xray_json = st.text_area("Конфигурация Xray (JSON)", value=json.dumps(config.get("xray_config", {}), ensure_ascii=False, indent=2), height=150)
        
    with col_auth2:
        st.info("💡 **Как работает автообновление:** Приложение использует библиотеку Playwright для симуляции захода пользователя на страницу реестра. Сессионные куки и токен вытаскиваются из localStorage автоматически раз в сутки в указанное время МСК.")
        
    st.markdown("---")
    
    st.subheader("Ручной ввод токена (если автообновление выключено)")
    manual_token = st.text_area("Токен авторизации (Bearer fgis_token)", value=config.get("fgis_token", ""), height=100)
    
    manual_cookies = st.text_area("Куки сессии (в формате JSON)", value=json.dumps(config.get("cookies", {}), ensure_ascii=False, indent=2), height=150)
    
    st.markdown("---")
    st.subheader("Настройки отправки почты (Gmail SMTP)")
    
    col_mail1, col_mail2 = st.columns(2)
    with col_mail1:
        smtp_sender = st.text_input("Почта отправителя (Gmail)", value=config.get("smtp_sender", "roskachestvo.apps@gmail.com"))
        smtp_password = st.text_input("Пароль приложения Gmail (App Password)", value=config.get("smtp_password", ""), type="password")
        st.caption("⚠️ **Важно:** Для Gmail необходимо сгенерировать 'Пароль приложения' в настройках безопасности Google Аккаунта. Обычный пароль от почты работать не будет.")
        
    with col_mail2:
        admin_email = st.text_input("Email Администратора (для отчетов о работе)", value=config.get("admin_email", ""))
        boss_email = st.text_input("Email Руководителя (для списков просроченных сертов)", value=config.get("boss_email", ""))
        admin_time = st.text_input("Время отправки отчета админу (МСК, HH:MM)", value=config.get("admin_report_time_msk", "09:00"))
        
    st.markdown("---")
    st.subheader("Шаблоны писем (HTML поддерживается)")
    
    col_tpl1, col_tpl2 = st.columns(2)
    with col_tpl1:
        st.markdown("**Шаблон для Администратора**")
        subj_admin = st.text_input("Тема письма админу", value=config.get("email_subject_admin", ""))
        body_admin = st.text_area("Тело письма админу", value=config.get("email_body_admin", ""), height=200)
        st.caption("Доступные переменные для подстановки: `{time_msk}`, `{token_status}`, `{api_test_status}`, `{details}`")
        
    with col_tpl2:
        st.markdown("**Шаблон для Руководителя**")
        subj_boss = st.text_input("Тема письма руководителю", value=config.get("email_subject_boss", ""))
        body_boss = st.text_area("Тело письма руководителю", value=config.get("email_body_boss", ""), height=200)
        st.caption("Переменная `{table_html}` обязательна для подстановки таблицы просроченных сертификатов.")
        
    if st.button("💾 Сохранить все настройки"):
        try:
            parsed_cookies = json.loads(manual_cookies)
        except Exception as e:
            st.error(f"Ошибка в формате JSON кук: {e}")
            parsed_cookies = config.get("cookies", {})
            
        config["fgis_token"] = manual_token
        config["cookies"] = parsed_cookies
        config["auto_update_token"] = auto_update
        config["token_update_time_msk"] = token_time
        config["auto_run_parser"] = auto_parse
        config["proxy"] = proxy_val
        
        try:
            parsed_xray = json.loads(xray_json)
        except Exception as e:
            st.error(f"Ошибка в формате JSON Xray: {e}")
            parsed_xray = config.get("xray_config", {})
            
        config["use_xray_proxy"] = use_xray
        config["xray_config"] = parsed_xray
        
        config["smtp_sender"] = smtp_sender
        config["smtp_password"] = smtp_password
        config["admin_email"] = admin_email
        config["boss_email"] = boss_email
        config["admin_report_time_msk"] = admin_time
        config["email_subject_admin"] = subj_admin
        config["email_body_admin"] = body_admin
        config["email_subject_boss"] = subj_boss
        config["email_body_boss"] = body_boss
        
        save_config(config)
        
        if use_xray:
            with st.spinner("Запуск Xray прокси..."):
                start_xray_proxy()
                
        st.success("Все настройки успешно сохранены и применены!")
        st.rerun()

# ----------------- ВКЛАДКА 3: ЖУРНАЛ СОБЫТИЙ (ЛОГИ) -----------------
with tab_logs:
    st.subheader("Логи работы системы в реальном времени")
    st.write("Показаны последние 100 строк из файла `app.log`:")
    
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                last_lines = lines[-100:]
                log_content = "".join(last_lines)
                st.code(log_content, language="log")
        except Exception as e:
            st.error(f"Не удалось прочитать файл логов: {e}")
    else:
        st.info("Файл логов пуст или еще не создан.")
        
    if st.button("🧹 Очистить логи"):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write("")
            st.success("Логи успешно очищены!")
            st.rerun()
        except Exception as e:
            st.error(f"Не удалось очистить логи: {e}")
