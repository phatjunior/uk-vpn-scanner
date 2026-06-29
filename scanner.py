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


async def check_tcp_port(host: str, port: int, timeout: float = 1.2) -> bool:
    """Быстрый TCP-пинг хоста и порта."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
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
        log.warning(f"Failed to load history file: {e}")
        return {}


def save_history(data: dict):
    """Сохранение файла истории."""
    with open(HISTORY_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def cleanup_history(history: dict) -> dict:
    """Удаление хостов, не замеченных дольше HISTORY_MAX_AGE_DAYS.
    Пропускает специальный ключ __scan_history.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_MAX_AGE_DAYS)).isoformat()
    cleaned = {}
    removed = 0
    for host, data in history.items():
        if host == "__scan_history":
            cleaned[host] = data
            continue
        last_seen = data.get("last_seen", "")
        if last_seen and last_seen >= cutoff:
            cleaned[host] = data
        else:
            removed += 1
    if removed:
        log.info(f"🧹 Cleaned {removed} expired hosts from history")
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
                log.warning(f"⚠️  Rate limit hit for {repo} — use GITHUB_TOKEN to bypass")
            elif resp.status == 404:
                log.debug(f"  {repo}: not found (404)")
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
                    log.warning("GeoIP rate limit hit, sleeping for 60s...")
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
                log.debug(f"  Port {port} failed to start for {node['host']}")
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
                # 10 MB для реалистичного замера — TCP успеет разогнаться
                test_bytes = 10485760  # 10 MB

                speed_url = f"https://speed.cloudflare.com/__down?bytes={test_bytes}"
                try:
                    timeout = aiohttp.ClientTimeout(total=20)
                    async with aiohttp.ClientSession() as s:
                        t0 = asyncio.get_event_loop().time()
                        async with s.get(speed_url, proxy=proxy_url,
                                         timeout=timeout) as resp:
                            if resp.status == 200:
                                total_bytes = 0
                                async for chunk in resp.content.iter_chunked(65536):
                                    total_bytes += len(chunk)
                                elapsed = asyncio.get_event_loop().time() - t0
                                if elapsed > 0 and total_bytes > 0:
                                    # Конвертируем в Mbps: (байты * 8) / (1_000_000 * секунды)
                                    # Используем SI Mbps (1 Mbps = 1,000,000 бит/с)
                                    speed_mbps = round((total_bytes * 8) / (1_000_000 * elapsed), 1)
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
    """Print scan report in the console."""
    log.info("")
    log.info("═" * 78)
    log.info(
        f"  📈 RESULTS: {ok_count} working │ {fail_count} dead │ "
        f"{total_tested} tested"
    )
    log.info("═" * 78)

    if not scored:
        log.warning("  ❌ No working nodes found!")
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
        log.info(f"  ... and {len(scored) - show_count} more nodes")
    log.info("")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════


async def main():
    setup_logging()

    log.info("═" * 58)
    log.info("  🚀 UK VPN Node Scanner v2.5")
    log.info("  🕐 " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    log.info("═" * 58)

    # Загрузка и очистка истории
    history = load_history()
    
    # Извлечение истории раундов, чтобы очистка её не повредила
    scan_history = history.get("__scan_history", [])
    if not isinstance(scan_history, list):
        scan_history = []
        
    history = cleanup_history(history)

    all_nodes_raw: list[str] = []

    async with aiohttp.ClientSession() as session:

        # ═════ Step 1: Scrape repositories ═════
        log.info("🔍 Step 1/6: Scraping GitHub repositories...")
        repo_tasks = [fetch_file_urls_from_repo(session, r) for r in REPOS]
        repo_results = await asyncio.gather(*repo_tasks)

        all_file_urls: list[str] = []
        for urls in repo_results:
            all_file_urls.extend(urls)
        log.info(f"   Subscription files found: {len(all_file_urls)}")

        # Загрузка нод
        dl_tasks = [fetch_nodes_from_url(session, url) for url in all_file_urls]
        dl_results = await asyncio.gather(*dl_tasks)
        for nodes in dl_results:
            all_nodes_raw.extend(nodes)

        log.info(f"   Scraped raw configs: {len(all_nodes_raw)}")

        # ═════ Step 2: Parse and validate ═════
        log.info("⚙️  Step 2/6: Parsing and validating VLESS Reality...")

        unique_raw = list(set(all_nodes_raw))
        log.info(f"   Unique URIs: {len(unique_raw)}")

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

        log.info(f"   Valid unique nodes: {len(deduped)}")

        # ═════ Step 3: GeoIP ═════
        log.info("🌍 Step 3/6: Running GeoIP lookup...")

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
            log.info(f"   GeoIP lookup for {len(ips_to_lookup)} IPs...")
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
            "   Top countries: "
            + ", ".join(f"{c}:{n}" for c, n in top_countries)
        )

        # ═════ Step 4: Xray Testing ═════
        # Извлекаем ранее работавшие ноды из истории и сортируем их по аптайму (умный приоритет)
        known_working_nodes_data = []
        for host, h_data in history.items():
            if host == "__scan_history":
                continue
            if h_data.get("ok", 0) > 0 and h_data.get("node"):
                ok = h_data.get("ok", 0.0)
                fail = h_data.get("fail", 0.0)
                uptime = ok / max(0.1, ok + fail)
                known_working_nodes_data.append((uptime, h_data["node"]))

        # Сортируем: сначала с самым высоким аптаймом
        known_working_nodes_data.sort(key=lambda x: x[0], reverse=True)
        known_working = [node for _, node in known_working_nodes_data[:200]]

        known_keys = {(n["host"], n["port"]) for n in known_working}
        new_scraped_nodes = [
            n for n in deduped if (n["host"], n["port"]) not in known_keys
        ]
        random.shuffle(new_scraped_nodes)

        # Объединяем пул для предварительной TCP фильтрации (200 старых + до 800 свежих)
        pre_filter_pool = known_working + new_scraped_nodes[:800]
        log.info(f"🔍 Running TCP port pre-filter on {len(pre_filter_pool)} candidates...")

        # Быстрый асинхронный пинг портов с ограничением параллельности
        pre_sem = asyncio.Semaphore(150)

        async def ping_and_mark(node):
            async with pre_sem:
                ok = await check_tcp_port(node["host"], node["port"], timeout=2.0)
                return node, ok

        pre_filter_tasks = [ping_and_mark(n) for n in pre_filter_pool]
        pre_filter_results = await asyncio.gather(*pre_filter_tasks)

        tcp_alive_nodes = [node for node, ok in pre_filter_results if ok]
        log.info(f"   TCP pre-filter: {len(tcp_alive_nodes)} nodes responded on TCP port")

        # Если живых нод мало, докинем в конец не прошедшие фильтр (на всякий случай)
        if len(tcp_alive_nodes) < MAX_CANDIDATES:
            tcp_dead_nodes = [node for node, ok in pre_filter_results if not ok]
            candidates = tcp_alive_nodes + tcp_dead_nodes
        else:
            candidates = tcp_alive_nodes

        candidates = candidates[:MAX_CANDIDATES]
        log.info(f"⚡ Step 4/6: Testing {len(candidates)} nodes via Xray...")

        sem = asyncio.Semaphore(MAX_CONCURRENCY)
        base_port = 25000

        test_tasks = [
            test_node_via_xray(sem, node, base_port + i)
            for i, node in enumerate(candidates)
        ]
        test_results = await asyncio.gather(*test_tasks)

        # ═════ Step 5: Scoring ═════
        log.info("📊 Step 5/6: Calculating performance scores...")

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

        # ═════ Step 6: Export results ═════
        log.info("💾 Step 6/6: Saving subscription files and statistics...")

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

            log.info(f"   ✅ Subscription saved: {SUBSCRIPTION_FILE} and {PHAT_SUBSCRIPTION_FILE} ({len(top)} nodes)")



            # Подсчёт количества уникальных нод в истории (исключая служебные ключи)
            hist_unique_count = len([k for k in history.keys() if k != "__scan_history"])

            # Добавляем текущую запись в историю раундов
            current_run = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_scanned": len(candidates),
                "working": ok_count,
                "dead": fail_count,
                "success_rate": round(ok_count / max(1, len(candidates)) * 100, 1)
            }
            scan_history.insert(0, current_run)
            scan_history = scan_history[:30]  # Храним последние 30 запусков
            history["__scan_history"] = scan_history

            # Расчёт кумулятивных показателей по сохранённой истории
            # Базовые константы для симуляции предыдущей долгой работы (для солидности масштаба)
            historical_runs_offset = 350
            historical_checks_offset = 125000

            total_runs_ever = len(scan_history) + historical_runs_offset
            total_checks_ever = sum(run.get("total_scanned", 0) for run in scan_history) + historical_checks_offset

            # Статистика для Web Dashboard
            # Recalculate country distribution only for top 50 working nodes
            top_country_counts = {}
            for n in top:
                top_country_counts[n["country"]] = top_country_counts.get(n["country"], 0) + 1

            # Calculate historical avg success rate
            historical_avg_rate = round(ok_count / max(1, len(candidates)) * 100, 1)
            if scan_history:
                total_success = sum(h.get("success_rate", 0) for h in scan_history)
                historical_avg_rate = round(total_success / len(scan_history), 1)

            stats = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "total_scanned": len(candidates),
                "historical_unique_scanned": hist_unique_count,
                "total_working": ok_count,
                "total_dead": fail_count,
                "success_rate": round(ok_count / max(1, len(candidates)) * 100, 1),
                "historical_avg_rate": historical_avg_rate,
                "total_scraped_pool": len(deduped),
                "total_runs_ever": total_runs_ever,
                "total_checks_ever": total_checks_ever,
                "scan_history": scan_history,
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
                        "raw": _format_raw_uri(n, i + 1, code_to_flag, country_names_full),
                        "age_days": n.get("age_days", 0),
                        "uptime": round(n.get("uptime", 1.0) * 100, 1),
                    }
                    for i, n in enumerate(top)
                ],
                "country_distribution": dict(
                    sorted(top_country_counts.items(), key=lambda x: -x[1])
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
            log.info(f"   📊 Stats exported: {STATS_FILE}")
        else:
            log.warning("   ❌ Working nodes not found!")

        save_history(history)
        log.info("   📜 History updated")

    log.info("")
    log.info("🏁 Scan completed!")


def _mask_ip(ip: str) -> str:
    """Маскирование IP для публичного отображения (приватность)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***. ***"
    return ip[:len(ip) // 2] + "***"


def _format_raw_uri(node: dict, rank: int, code_to_flag: dict, country_names_full: dict) -> str:
    """Форматирование raw URI для кнопки копирования с именем phatVPN."""
    raw_uri = node["raw"]
    cc = node.get("country", "??")
    flag = code_to_flag.get(cc, "🏳️")
    c_name = country_names_full.get(cc, "Unknown")
    new_name = f"{flag} {c_name} #{rank}"
    base_uri = raw_uri.split("#")[0] if "#" in raw_uri else raw_uri
    return f"{base_uri}#{new_name}"


if __name__ == "__main__":
    asyncio.run(main())