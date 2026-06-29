#!/usr/bin/env python3
"""
UK VPN Node Scanner v2.0
Автоматический сканер публичных VLESS Reality нод.
Находит, тестирует и ранжирует лучшие ноды для обхода Content Control в UK.

Запуск:  python scanner.py
Env:     GITHUB_TOKEN  — токен GitHub для API (опционально, повышает лимит)
         XRAY_BIN      — путь к бинарнику Xray (по умолчанию ./xray)
         DEBUG          — включить debug логирование
"""

import asyncio
import re
import base64
import json
import os
import sys
import logging
import random
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timezone, timedelta
from typing import Optional

import aiohttp

# ═══════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ
# ═══════════════════════════════════════════════════════════════

# Репозитории с публичными VLESS Reality конфигурациями
REPOS = [
    "yebekhe/TelegramV2rayCollector",
    "barry-far/V2ray-Configs",
    "mahdibland/V2RayAggregator",
    "mfuu/v2ray",
    "Epodonios/v2ray-configs",
    "ebrasha/free-v2ray-public-list",
    "pog7x/vpn-configs",
]

# Доверенные SNI-домены для маскировки Reality трафика.
# UK Content Control НЕ блокирует эти домены, т.к. они являются
# критической инфраструктурой интернета.
TRUSTED_SNI_DOMAINS = [
    # Tech Giants
    "apple.com", "icloud.com", "cdn-apple.com", "swdist.apple.com",
    "images.apple.com",
    "google.com", "googleapis.com", "gstatic.com", "dl.google.com",
    "googlevideo.com",
    "microsoft.com", "azure.com", "windows.com", "live.com",
    "office.com", "windowsupdate.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    # CDN / Infrastructure
    "cloudflare.com", "cdnjs.cloudflare.com", "cloudflare-dns.com",
    "fastly.net", "akamaihd.net", "akamai.net",
    # Dev / Work
    "github.com", "githubusercontent.com", "gitlab.com",
    "zoom.us", "teams.microsoft.com",
    # Streaming & Media (non-adult)
    "twitch.tv", "vimeo.com", "spotify.com", "netflix.com",
    "disneyplus.com",
    # Search & General
    "yahoo.com", "bing.com", "duckduckgo.com",
    "mozilla.org", "firefox.com",
    "samsung.com", "sony.com",
]

TEST_URL = "https://cp.cloudflare.com/generate_204"
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=524288"  # 512 KB

HISTORY_FILE = "history.json"
STATS_FILE = "docs/stats.json"
SUBSCRIPTION_FILE = "docs/sub.txt"
PHAT_SUBSCRIPTION_FILE = "docs/phatVPN.txt"


MAX_CONCURRENCY = 20           # Параллельных тестов Xray
MAX_CANDIDATES = 500           # Макс. нод на тестирование
TOP_N = 50                     # Сколько лучших нод в подписку
HISTORY_MAX_AGE_DAYS = 14      # Очистка старых записей из истории
XRAY_STARTUP_TIMEOUT = 4.0    # Таймаут ожидания запуска Xray (сек)

XRAY_BIN = os.environ.get("XRAY_BIN", "./xray")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

log = logging.getLogger("scanner")

# ═══════════════════════════════════════════════════════════════
#  УТИЛИТЫ
# ═══════════════════════════════════════════════════════════════


def setup_logging():
    """Настройка логирования с красивым форматом."""
    level = logging.DEBUG if os.environ.get("DEBUG") else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    ))
    log.setLevel(level)
    log.addHandler(handler)


async def wait_for_port(port: int, host: str = "127.0.0.1",
                        timeout: float = XRAY_STARTUP_TIMEOUT) -> bool:
    """Ожидание готовности TCP-порта с retry (вместо sleep)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            await asyncio.sleep(0.2)
    return False


def make_api_headers() -> dict:
    """Заголовки для GitHub API с опциональным токеном."""
    headers = {
        "User-Agent": "UK-VPN-Scanner/2.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers


# ═══════════════════════════════════════════════════════════════
#  ИСТОРИЯ И СКОРИНГ
# ═══════════════════════════════════════════════════════════════


def load_history() -> dict:
    """Загрузка файла истории."""
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        log.warning(f"Не удалось загрузить историю: {e}")
        return {}


def save_history(data: dict):
    """Сохранение файла истории."""
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def cleanup_history(history: dict) -> dict:
    """Удаление хостов, не замеченных дольше HISTORY_MAX_AGE_DAYS."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_MAX_AGE_DAYS)).isoformat()
    cleaned = {}
    removed = 0
    for host, data in history.items():
        last_seen = data.get("last_seen", "")
        if last_seen and last_seen >= cutoff:
            cleaned[host] = data
        else:
            removed += 1
    if removed:
        log.info(f"🧹 Очищено {removed} устаревших хостов из истории")
    return cleaned


def compute_score(latency: int, speed_mbps: Optional[float],
                  packet_loss: float, hist_data: dict) -> float:
    """
    Комплексный рейтинг ноды:
      • Базовый балл — обратно пропорционален latency (быстрые = лучше)
      • Uptime множитель — стабильные ноды получают бонус
      • Speed бонус — быстрые ноды получают дополнительные очки (в Mbps)
      • Stability бонус — за долгую серию успешных тестов (основан на сглаженном ok)
      • Fail штраф — основан на проценте сбоев (fail rate), а не на общей сумме
      • Packet loss штраф — вычитается за потерю пакетов
    """
    base = 10000 / max(latency, 1)

    ok = hist_data.get("ok", 0.0)
    fail = hist_data.get("fail", 0.0)
    total = ok + fail
    uptime = ok / max(0.1, total)

    speed_bonus = 0.0
    if speed_mbps and speed_mbps > 0:
        # 32 Mbps дает максимальный бонус в 80 баллов
        speed_bonus = min(speed_mbps * 2.5, 80.0)

    # Взвешиваем стабильность: чем дольше нода успешно работает, тем выше ее базовый авторитет
    stability_bonus = min(ok * 3, 30)  # cap 30
    
    # Штраф за процент неудач (fail rate). Cоставляет до 50 баллов при 100% падений
    fail_rate_penalty = (fail / max(0.1, total)) * 50

    # Штраф за потерю пакетов (до 100 баллов при 100% потере пакетов)
    packet_loss_penalty = packet_loss * 100.0

    return (base * (0.3 + 0.7 * uptime)) + speed_bonus + stability_bonus - fail_rate_penalty - packet_loss_penalty


# ═══════════════════════════════════════════════════════════════
#  СКАНИРОВАНИЕ GITHUB РЕПОЗИТОРИЕВ
# ═══════════════════════════════════════════════════════════════


async def fetch_file_urls_from_repo(session: aiohttp.ClientSession,
                                    repo: str) -> list[str]:
    """Получение URL файлов с конфигурациями из репозитория GitHub."""
    api_url = f"https://api.github.com/repos/{repo}/contents/"
    headers = make_api_headers()
    urls: list[str] = []

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with session.get(api_url, headers=headers, timeout=timeout) as resp:
            if resp.status == 200:
                files = await resp.json()
                for f in files:
                    name = f.get("name", "").lower()
                    if f.get("type") == "file" and (
                        name.endswith(".txt") or name.endswith(".b64")
                        or "sub" in name or "config" in name
                        or "vless" in name or "reality" in name
                    ):
                        dl = f.get("download_url")
                        if dl:
                            urls.append(dl)
                log.debug(f"  {repo}: {len(urls)} файлов")
            elif resp.status == 403:
                log.warning(f"⚠️  Rate limit для {repo} — используйте GITHUB_TOKEN")
            elif resp.status == 404:
                log.debug(f"  {repo}: не найден (404)")
            else:
                log.warning(f"  {repo}: HTTP {resp.status}")
    except asyncio.TimeoutError:
        log.warning(f"⏱️  Таймаут: {repo}")
    except Exception as e:
        log.warning(f"  Ошибка {repo}: {e}")

    return urls


async def fetch_nodes_from_url(session: aiohttp.ClientSession,
                               url: str) -> list[str]:
    """Скачивание и декодирование конфигов из файла (plain text или base64)."""
    nodes: list[str] = []
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                return nodes
            content = await resp.text()

            # Попытка base64 декодирования если нет явных VLESS URI
            if "vless://" not in content:
                try:
                    decoded = base64.b64decode(content.strip()).decode(
                        "utf-8", errors="ignore"
                    )
                    if "vless://" in decoded:
                        content = decoded
                except Exception:
                    pass

            for line in content.splitlines():
                line = line.strip()
                if line.startswith("vless://"):
                    nodes.append(line)
    except asyncio.TimeoutError:
        log.debug(f"  Таймаут: {url}")
    except Exception as e:
        log.debug(f"  Ошибка загрузки: {e}")

    return nodes


# ═══════════════════════════════════════════════════════════════
#  ПАРСИНГ VLESS REALITY КОНФИГОВ
# ═══════════════════════════════════════════════════════════════


def parse_vless_node(raw: str) -> Optional[dict]:
    """Парсинг VLESS Reality URI в структурированный dict.

    Фильтры:
      • Только security=reality
      • Обязательный publicKey (pbk)
      • SNI из доверенного списка
    """
    try:
        parsed = urlparse(raw)
        if parsed.scheme != "vless":
            return None

        port = parsed.port or 443
        params = parse_qs(parsed.query)

        security = params.get("security", [""])[0].lower()
        if security != "reality":
            return None

        pbk = params.get("pbk", [""])[0]
        if not pbk:
            return None

        sni = params.get("sni", [""])[0].lower()
        if not sni:
            return None

        # Проверка SNI — точное совпадение или поддомен
        sni_ok = any(sni == d or sni.endswith("." + d) for d in TRUSTED_SNI_DOMAINS)
        if not sni_ok:
            return None

        flow = params.get("flow", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        sid = params.get("sid", [""])[0]
        net = params.get("type", ["tcp"])[0]
        fragment = unquote(parsed.fragment) if parsed.fragment else ""

        return {
            "raw": raw,
            "host": parsed.hostname,
            "port": port,
            "uuid": parsed.username,
            "pbk": pbk,
            "sid": sid,
            "fp": fp,
            "flow": flow,
            "sni": sni,
            "net": net,
            "name": fragment,
        }
    except Exception as e:
        log.debug(f"  Ошибка парсинга URI: {e}")
        return None


# ═══════════════════════════════════════════════════════════════
#  ОПРЕДЕЛЕНИЕ СТРАНЫ (ИЗ ИМЕНИ + GeoIP API)
# ═══════════════════════════════════════════════════════════════

# Маппинг флагов-эмодзи → ISO коды
_FLAG_MAP = {
    "🇺🇸": "US", "🇬🇧": "GB", "🇩🇪": "DE", "🇫🇷": "FR", "🇳🇱": "NL",
    "🇨🇦": "CA", "🇯🇵": "JP", "🇰🇷": "KR", "🇸🇬": "SG", "🇦🇺": "AU",
    "🇮🇪": "IE", "🇸🇪": "SE", "🇳🇴": "NO", "🇫🇮": "FI", "🇩🇰": "DK",
    "🇨🇭": "CH", "🇦🇹": "AT", "🇧🇪": "BE", "🇪🇸": "ES", "🇮🇹": "IT",
    "🇵🇱": "PL", "🇷🇺": "RU", "🇹🇷": "TR", "🇮🇳": "IN", "🇧🇷": "BR",
    "🇭🇰": "HK", "🇹🇼": "TW", "🇮🇱": "IL", "🇿🇦": "ZA", "🇲🇽": "MX",
    "🇺🇦": "UA", "🇷🇴": "RO", "🇨🇿": "CZ", "🇭🇺": "HU", "🇵🇹": "PT",
    "🇱🇺": "LU", "🇧🇬": "BG", "🇭🇷": "HR", "🇱🇹": "LT", "🇱🇻": "LV",
    "🇪🇪": "EE", "🇷🇸": "RS", "🇲🇩": "MD", "🇬🇪": "GE", "🇦🇲": "AM",
    "🇦🇿": "AZ", "🇰🇿": "KZ", "🇹🇭": "TH", "🇻🇳": "VN", "🇮🇩": "ID",
    "🇵🇭": "PH", "🇲🇾": "MY",
}

# Маппинг названий стран → ISO коды
_COUNTRY_NAMES = {
    "united states": "US", "usa": "US", "america": "US",
    "united kingdom": "GB", "uk": "GB", "england": "GB", "britain": "GB",
    "germany": "DE", "deutschland": "DE",
    "france": "FR", "netherlands": "NL", "holland": "NL",
    "canada": "CA", "japan": "JP", "korea": "KR", "singapore": "SG",
    "australia": "AU", "ireland": "IE", "sweden": "SE", "norway": "NO",
    "finland": "FI", "denmark": "DK", "switzerland": "CH", "austria": "AT",
    "belgium": "BE", "spain": "ES", "italy": "IT", "poland": "PL",
    "russia": "RU", "turkey": "TR", "turkiye": "TR",
    "india": "IN", "brazil": "BR",
    "hong kong": "HK", "taiwan": "TW", "israel": "IL",
    "czech": "CZ", "czechia": "CZ", "romania": "RO", "hungary": "HU",
    "portugal": "PT", "bulgaria": "BG", "croatia": "HR",
    "lithuania": "LT", "latvia": "LV", "estonia": "EE",
    "serbia": "RS", "moldova": "MD", "georgia": "GE",
    "ukraine": "UA", "kazakhstan": "KZ",
    "thailand": "TH", "vietnam": "VN", "indonesia": "ID",
    "philippines": "PH", "malaysia": "MY",
}


def extract_country_from_name(name: str) -> str:
    """Извлечение кода страны из имени/фрагмента ноды."""
    if not name:
        return ""

    # Флаги-эмодзи
    for emoji, code in _FLAG_MAP.items():
        if emoji in name:
            return code

    # [US], (DE), и т.д.
    m = re.search(r"[\[\(]([A-Z]{2})[\]\)]", name.upper())
    if m:
        return m.group(1)

    # Текстовые названия стран
    name_lower = name.lower()
    for cname, code in _COUNTRY_NAMES.items():
        if cname in name_lower:
            return code

    return ""


async def geoip_batch_lookup(session: aiohttp.ClientSession,
                             ips: list[str]) -> dict[str, str]:
    """Батч-геолокация IP через ip-api.com (бесплатно, до 100 за запрос)."""
    result: dict[str, str] = {}

    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        payload = [
            {"query": ip, "fields": "query,countryCode,status"}
            for ip in batch
        ]
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.post(
                "http://ip-api.com/batch", json=payload, timeout=timeout,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data:
                        if item.get("status") == "success":
                            result[item["query"]] = item.get("countryCode", "")
                elif resp.status == 429:
                    log.warning("GeoIP rate limit, ожидание 60с...")
                    await asyncio.sleep(60)
        except Exception as e:
            log.warning(f"GeoIP batch error: {e}")

        # Пауза между батчами (rate limit: 15 batch/min)
        if i + 100 < len(ips):
            await asyncio.sleep(4.5)

    return result


# ═══════════════════════════════════════════════════════════════
#  ТЕСТИРОВАНИЕ НОД ЧЕРЕЗ XRAY
# ═══════════════════════════════════════════════════════════════


def build_xray_config(node: dict, http_port: int) -> dict:
    """Генерация конфига Xray с HTTP inbound (НЕ SOCKS — для совместимости с aiohttp)."""
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": http_port,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"timeout": 10},
        }],
        "outbounds": [{
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [{
                    "address": node["host"],
                    "port": node["port"],
                    "users": [{
                        "id": node["uuid"],
                        "encryption": "none",
                        "flow": node.get("flow", ""),
                    }],
                }],
            },
            "streamSettings": {
                "network": node.get("net", "tcp"),
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "fingerprint": node.get("fp", "chrome"),
                    "serverName": node["sni"],
                    "publicKey": node["pbk"],
                    "shortId": node.get("sid", ""),
                    "spiderX": "",
                },
            },
        }],
    }


async def test_node_via_xray(sem: asyncio.Semaphore, node: dict,
                             port: int) -> dict:
    """Тестирование одной ноды: запуск Xray → HTTP запрос через прокси → замер."""
    async with sem:
        config = build_xray_config(node, port)
        config_path = f"/tmp/xray_cfg_{port}.json"
        process = None

        try:
            with open(config_path, "w") as f:
                json.dump(config, f)

            process = await asyncio.create_subprocess_exec(
                XRAY_BIN, "-config", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # Ждём пока HTTP прокси будет готов
            if not await wait_for_port(port):
                log.debug(f"  Порт {port} не поднялся для {node['host']}")
                return _fail_result(node)

            proxy_url = f"http://127.0.0.1:{port}"
            latency = None
            speed_mbps = None

            # ── Тест latency и Packet Loss (3 попытки) ──
            latencies = []
            failures = 0
            for _ in range(3):
                try:
                    timeout = aiohttp.ClientTimeout(total=3.0)
                    async with aiohttp.ClientSession() as s:
                        t0 = asyncio.get_event_loop().time()
                        async with s.get(TEST_URL, proxy=proxy_url,
                                         timeout=timeout) as resp:
                            if resp.status in (200, 204):
                                latencies.append(int(
                                    (asyncio.get_event_loop().time() - t0) * 1000
                                ))
                            else:
                                failures += 1
                except Exception:
                    failures += 1

            packet_loss = round(failures / 3.0, 2)
            if latencies:
                latency = int(sum(latencies) / len(latencies))

            # ── Тест скорости (только если ping OK и < 3с) ──
            if latency is not None and latency < 3000:
                # Динамический размер тестового файла для более реалистичного замера
                if latency < 150:
                    test_bytes = 1572864  # 1.5 MB
                elif latency < 300:
                    test_bytes = 1048576  # 1.0 MB
                else:
                    test_bytes = 524288   # 512 KB

                speed_url = f"https://speed.cloudflare.com/__down?bytes={test_bytes}"
                try:
                    timeout = aiohttp.ClientTimeout(total=12)
                    async with aiohttp.ClientSession() as s:
                        t0 = asyncio.get_event_loop().time()
                        async with s.get(speed_url, proxy=proxy_url,
                                         timeout=timeout) as resp:
                            if resp.status == 200:
                                data = await resp.read()
                                elapsed = asyncio.get_event_loop().time() - t0
                                if elapsed > 0:
                                    # Конвертируем в Mbps: (байты * 8) / (1024 * 1024 * секунды)
                                    speed_mbps = round((len(data) * 8) / (1024 * 1024 * elapsed), 1)
                except Exception:
                    pass

            if latency is not None:
                return {
                    "node": node,
                    "latency": latency,
                    "speed_mbps": speed_mbps,
                    "packet_loss": packet_loss,
                    "success": True,
                }
            return _fail_result(node)

        except Exception as e:
            log.debug(f"  Ошибка тестирования {node['host']}: {e}")
            return _fail_result(node)

        finally:
            # Гарантированная очистка процесса Xray
            if process:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                except Exception:
                    pass
            try:
                os.remove(config_path)
            except OSError:
                pass


def _fail_result(node: dict) -> dict:
    return {"node": node, "latency": None, "speed_mbps": None, "packet_loss": 1.0, "success": False}


# ═══════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ ОТЧЁТА
# ═══════════════════════════════════════════════════════════════


def print_report(scored: list[dict], ok_count: int, fail_count: int,
                 total_tested: int):
    """Красивый отчёт в консоль."""
    log.info("")
    log.info("═" * 78)
    log.info(
        f"  📈 РЕЗУЛЬТАТЫ: {ok_count} рабочих │ {fail_count} мёртвых │ "
        f"{total_tested} протестировано"
    )
    log.info("═" * 78)

    if not scored:
        log.warning("  ❌ Рабочие ноды не найдены!")
        return

    log.info(
        f"  {'#':>3} │ {'Score':>7} │ {'Ping':>6} │ "
        f"{'Speed':>9} │ {'CC':>2} │ {'Host':<32} │ SNI"
    )
    log.info("  " + "─" * 76)

    show_count = min(len(scored), 25)
    for i, n in enumerate(scored[:show_count], 1):
        speed = f"{n['speed_mbps']}Mbps" if n.get("speed_mbps") else "—"
        log.info(
            f"  {i:>3} │ {n['score']:>7.1f} │ {n['latency']:>4}ms │ "
            f"{speed:>9} │ {n['country']:>2} │ {n['host']:<32} │ {n['sni']}"
        )

    if len(scored) > show_count:
        log.info(f"  ... и ещё {len(scored) - show_count} нод")
    log.info("")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════


async def main():
    setup_logging()

    log.info("═" * 58)
    log.info("  🚀 UK VPN Node Scanner v2.0")
    log.info("  🕐 " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    log.info("═" * 58)

    # Загрузка и очистка истории
    history = load_history()
    history = cleanup_history(history)

    all_nodes_raw: list[str] = []

    async with aiohttp.ClientSession() as session:

        # ═════ Шаг 1: Сканирование репозиториев ═════
        log.info("🔍 Шаг 1/6: Сканирование GitHub репозиториев...")
        repo_tasks = [fetch_file_urls_from_repo(session, r) for r in REPOS]
        repo_results = await asyncio.gather(*repo_tasks)

        all_file_urls: list[str] = []
        for urls in repo_results:
            all_file_urls.extend(urls)
        log.info(f"   Найдено файлов подписок: {len(all_file_urls)}")

        # Загрузка нод
        dl_tasks = [fetch_nodes_from_url(session, url) for url in all_file_urls]
        dl_results = await asyncio.gather(*dl_tasks)
        for nodes in dl_results:
            all_nodes_raw.extend(nodes)

        log.info(f"   Скачано сырых конфигов: {len(all_nodes_raw)}")

        # ═════ Шаг 2: Парсинг и валидация ═════
        log.info("⚙️  Шаг 2/6: Парсинг и валидация VLESS Reality...")

        unique_raw = list(set(all_nodes_raw))
        log.info(f"   Уникальных URI: {len(unique_raw)}")

        parsed_nodes = []
        for raw in unique_raw:
            node = parse_vless_node(raw)
            if node:
                parsed_nodes.append(node)

        # Дедупликация по (host, port)
        seen: set[tuple[str, int]] = set()
        deduped: list[dict] = []
        for node in parsed_nodes:
            key = (node["host"], node["port"])
            if key not in seen:
                seen.add(key)
                deduped.append(node)

        log.info(f"   Валидных уникальных нод: {len(deduped)}")

        # ═════ Шаг 3: GeoIP ═════
        log.info("🌍 Шаг 3/6: Определение геолокации...")

        country_map: dict[str, str] = {}

        # Сначала из имени/фрагмента
        for node in deduped:
            cc = extract_country_from_name(node.get("name", ""))
            if cc:
                country_map[node["host"]] = cc

        # Остальные через API
        ips_to_lookup = [
            n["host"] for n in deduped if n["host"] not in country_map
        ]
        ips_to_lookup = list(set(ips_to_lookup))

        if ips_to_lookup:
            log.info(f"   GeoIP lookup для {len(ips_to_lookup)} IP...")
            geo = await geoip_batch_lookup(session, ips_to_lookup)
            country_map.update(geo)

        # Назначаем страну
        for node in deduped:
            node["country"] = country_map.get(node["host"], "??")

        # Статистика по странам
        country_counts: dict[str, int] = {}
        for node in deduped:
            c = node["country"]
            country_counts[c] = country_counts.get(c, 0) + 1

        top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]
        log.info(
            "   Топ стран: "
            + ", ".join(f"{c}:{n}" for c, n in top_countries)
        )

        # ═════ Шаг 4: Тестирование через Xray ═════
        # Извлекаем ранее работавшие ноды из истории, чтобы они гарантированно проверились и накопились
        known_working_nodes = []
        for host, h_data in history.items():
            if h_data.get("ok", 0) > 0 and h_data.get("node"):
                known_working_nodes.append(h_data["node"])

        known_keys = {(n["host"], n["port"]) for n in known_working_nodes}
        new_scraped_nodes = [
            n for n in deduped if (n["host"], n["port"]) not in known_keys
        ]
        
        random.shuffle(new_scraped_nodes)
        
        candidates = known_working_nodes + new_scraped_nodes
        candidates = candidates[:MAX_CANDIDATES]

        log.info(f"⚡ Шаг 4/6: Тестирование {len(candidates)} нод через Xray (из них {len(known_working_nodes)} ранее успешных)...")

        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        base_port = 25000

        test_tasks = [
            test_node_via_xray(sem, node, base_port + i)
            for i, node in enumerate(candidates)
        ]
        test_results = await asyncio.gather(*test_tasks)

        # ═════ Шаг 5: Скоринг ═════
        log.info("📊 Шаг 5/6: Расчёт рейтингов...")

        scored: list[dict] = []
        ok_count = 0
        fail_count = 0

        for res in test_results:
            node = res["node"]
            host = node["host"]

            # Инициализация для новых нод
            if host not in history:
                history[host] = {
                    "ok": 0.0,
                    "fail": 0.0,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": ""
                }
            # Поддержка обратной совместимости для старых записей
            elif "first_seen" not in history[host]:
                history[host]["first_seen"] = "2026-06-17T00:00:00.000000+00:00"

            if res["success"]:
                ok_count += 1
                # Экспоненциальное сглаживание (EMA) для ok и fail (decay = 0.9)
                history[host]["ok"] = history[host].get("ok", 0.0) * 0.9 + 1.0
                history[host]["fail"] = history[host].get("fail", 0.0) * 0.9
                history[host]["last_seen"] = datetime.now(timezone.utc).isoformat()
                history[host]["node"] = node  # Сохраняем полную конфигурацию для повторных тестов

                h_ok = history[host]["ok"]
                h_fail = history[host]["fail"]
                uptime = h_ok / max(0.1, h_ok + h_fail)

                # Вычисляем возраст ноды в днях
                first_seen_str = history[host].get("first_seen", datetime.now(timezone.utc).isoformat())
                try:
                    clean_str = first_seen_str.replace("Z", "+00:00")
                    first_seen_dt = datetime.fromisoformat(clean_str)
                    age_delta = datetime.now(timezone.utc) - first_seen_dt
                    age_days = max(0, age_delta.days)
                except Exception:
                    age_days = 0

                score = compute_score(
                    res["latency"], res.get("speed_mbps"), res.get("packet_loss", 0.0), history[host],
                )
                scored.append({
                    "score": score,
                    "latency": res["latency"],
                    "speed_mbps": res.get("speed_mbps"),
                    "packet_loss": res.get("packet_loss", 0.0),
                    "country": node.get("country", "??"),
                    "host": host,
                    "sni": node["sni"],
                    "raw": node["raw"],
                    "age_days": age_days,
                    "uptime": uptime,
                })
            else:
                fail_count += 1
                history[host]["ok"] = history[host].get("ok", 0.0) * 0.9
                history[host]["fail"] = history[host].get("fail", 0.0) * 0.9 + 1.0

        scored.sort(key=lambda x: x["score"], reverse=True)
        top = scored[:TOP_N]

        print_report(scored, ok_count, fail_count, len(candidates))

        # ═════ Шаг 6: Сохранение ═════
        log.info("💾 Шаг 6/6: Сохранение подписки и статистики...")

        os.makedirs("docs", exist_ok=True)

        if top:
            # Маппинг ISO кодов в полные названия стран
            country_names_full = {
                "US": "United States", "GB": "United Kingdom", "DE": "Germany",
                "FR": "France", "NL": "Netherlands", "CA": "Canada",
                "JP": "Japan", "KR": "South Korea", "SG": "Singapore",
                "AU": "Australia", "IE": "Ireland", "SE": "Sweden",
                "NO": "Norway", "FI": "Finland", "DK": "Denmark",
                "CH": "Switzerland", "AT": "Austria", "BE": "Belgium",
                "ES": "Spain", "IT": "Italy", "PL": "Poland",
                "RU": "Russia", "TR": "Turkey", "IN": "India",
                "BR": "Brazil", "HK": "Hong Kong", "TW": "Taiwan",
                "IL": "Israel", "ZA": "South Africa", "MX": "Mexico",
                "UA": "Ukraine", "RO": "Romania", "CZ": "Czechia",
                "HU": "Hungary", "PT": "Portugal", "LU": "Luxembourg",
                "BG": "Bulgaria", "HR": "Croatia", "LT": "Lithuania",
                "LV": "Latvia", "EE": "Estonia", "RS": "Serbia",
                "MD": "Moldova", "GE": "Georgia", "AM": "Armenia",
                "AZ": "Azerbaijan", "KZ": "Kazakhstan", "TH": "Thailand",
                "VN": "Vietnam", "ID": "Indonesia", "PH": "Philippines",
                "MY": "Malaysia",
            }
            code_to_flag = {v: k for k, v in _FLAG_MAP.items()}

            formatted_uris = []
            
            # Добавляем расширенные метаданные подписки
            formatted_uris.append("#profile-title: phatVPN")
            formatted_uris.append("#profile-update-interval: 2")
            formatted_uris.append("#support-url: https://t.me/phatBeats")
            formatted_uris.append("#profile-web-page-url: https://phatjunior.github.io/uk-vpn-scanner/")
            formatted_uris.append("#subscription-userinfo: upload=1073741824; download=5368709120; total=107374182400; expire=1798761600")

            for rank, n in enumerate(top, 1):
                cc = n.get("country", "??")
                flag = code_to_flag.get(cc, "🏳️")
                c_name = country_names_full.get(cc, "Unknown")
                
                # Порядковый номер по качеству (месту в топе)
                new_name = f"{flag} {c_name} #{rank}"
                
                raw_uri = n["raw"]
                if "#" in raw_uri:
                    base_uri = raw_uri.split("#")[0]
                else:
                    base_uri = raw_uri
                
                formatted_uris.append(f"{base_uri}#{new_name}")

            sub_content = "\n".join(formatted_uris)
            # Изменили кодировку на plain text: v2RayTun и другие клиенты часто
            # не могут прочитать #profile-title, если файл полностью в Base64.
            # Plain text VLESS-ссылки поддерживаются всеми современными клиентами.

            with open(SUBSCRIPTION_FILE, "w") as f:
                f.write(sub_content)
            with open(PHAT_SUBSCRIPTION_FILE, "w") as f:
                f.write(sub_content)
            
            # Для обратной совместимости со старыми клиентами, создадим base64 версию
            sub_b64 = base64.b64encode("\n".join(formatted_uris[5:]).encode()).decode()
            with open("docs/sub_b64.txt", "w") as f:
                f.write(sub_b64)

            log.info(f"   ✅ Подписка сохранена: {SUBSCRIPTION_FILE} и {PHAT_SUBSCRIPTION_FILE} ({len(top)} нод)")



            # Статистика для Web Dashboard
            stats = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "total_scanned": len(candidates),
                "historical_unique_scanned": len(history),  # Общее число уникальных нод в истории
                "total_working": ok_count,
                "total_dead": fail_count,
                "success_rate": round(ok_count / max(1, len(candidates)) * 100, 1),
                "top_nodes": [
                    {
                        "rank": i + 1,
                        "score": round(n["score"], 1),
                        "latency_ms": n["latency"],
                        "speed_mbps": n["speed_mbps"],
                        "packet_loss": round(n["packet_loss"] * 100, 1),
                        "country": n["country"],
                        "host": _mask_ip(n["host"]),
                        "sni": n["sni"],
                        "raw": n["raw"],
                        "age_days": n.get("age_days", 0),
                        "uptime": round(n.get("uptime", 1.0) * 100, 1),
                    }
                    for i, n in enumerate(top)
                ],
                "country_distribution": dict(
                    sorted(country_counts.items(), key=lambda x: -x[1])
                ),
                "scan_config": {
                    "repos_scanned": len(REPOS),
                    "files_found": len(all_file_urls),
                    "raw_configs": len(all_nodes_raw),
                    "unique_valid": len(deduped),
                    "max_concurrency": MAX_CONCURRENCY,
                    "top_n": TOP_N,
                },
            }

            with open(STATS_FILE, "w") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            log.info(f"   📊 Статистика: {STATS_FILE}")
        else:
            log.warning("   ❌ Рабочие ноды не найдены!")

        save_history(history)
        log.info("   📜 История обновлена")

    log.info("")
    log.info("🏁 Сканирование завершено!")


def _mask_ip(ip: str) -> str:
    """Маскирование IP для публичного отображения (приватность)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***. ***"
    return ip[:len(ip) // 2] + "***"


if __name__ == "__main__":
    asyncio.run(main())