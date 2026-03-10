#!/usr/bin/env python3
"""
SNI VLESS Scanner
Ищет сайты в той же подсети или ASN, подходящие для SNI VLESS проксирования.
Использование: python3 sni_scanner.py <IP> [--mode subnet|asn|both] [--threads 50] [--timeout 3]
"""

import argparse
import ipaddress
import socket
import ssl
import sys
import json
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Попытка импортировать опциональные зависимости
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass


# ──────────────────────────────────────────────
# Утилиты получения информации об IP
# ──────────────────────────────────────────────

def get_ip_info(ip: str) -> dict:
    """Получить информацию об IP через ipinfo.io (ASN, подсеть, страна)."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        if HAS_REQUESTS:
            r = requests.get(url, timeout=5)
            return r.json()
        else:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[!] Не удалось получить ipinfo для {ip}: {e}")
        return {}


def get_asn_prefixes(asn: str) -> list:
    """
    Получить список IP-префиксов для ASN через bgpview.io API.
    ASN в формате 'AS12345' или '12345'.
    """
    asn_num = asn.upper().lstrip("AS")
    url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
    prefixes = []
    try:
        if HAS_REQUESTS:
            r = requests.get(url, timeout=10)
            data = r.json()
        else:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode())

        for p in data.get("data", {}).get("ipv4_prefixes", []):
            prefixes.append(p["prefix"])
    except Exception as e:
        print(f"[!] Не удалось получить префиксы для {asn}: {e}")
    return prefixes


def subnet_from_ip(ip: str, prefix_len: int = 24) -> str:
    """Вернуть подсеть /prefix_len для заданного IP."""
    net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
    return str(net)


# ──────────────────────────────────────────────
# Проверка хоста на пригодность для SNI VLESS
# ──────────────────────────────────────────────

def check_tls_sni(ip: str, hostname: str, port: int = 443, timeout: float = 3.0) -> dict:
    """
    Проверяет TLS-рукопожатие с заданным SNI (hostname) на IP:port.
    Возвращает словарь с результатом.
    """
    result = {
        "ip": ip,
        "hostname": hostname,
        "port": port,
        "tls_ok": False,
        "cert_cn": None,
        "alpn": None,
        "tls_version": None,
        "http2": False,
        "error": None,
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                result["tls_ok"] = True
                result["tls_version"] = tls.version()
                alpn = tls.selected_alpn_protocol()
                result["alpn"] = alpn
                result["http2"] = (alpn == "h2")

                cert = tls.getpeercert()
                if cert:
                    for field in cert.get("subject", ()):
                        for k, v in field:
                            if k == "commonName":
                                result["cert_cn"] = v
    except ssl.SSLError as e:
        result["error"] = f"SSL: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    return result


def check_http_header(ip: str, hostname: str, port: int = 443, timeout: float = 3.0) -> bool:
    """Быстрая проверка: отвечает ли сервер хоть каким-то HTTP ответом."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as tls:
                req = (
                    f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n"
                    "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(req.encode())
                resp = tls.recv(512).decode(errors="ignore")
                return resp.startswith("HTTP/")
    except Exception:
        return False


def is_good_sni_candidate(result: dict) -> bool:
    """
    Эвристика: хост подходит для SNI VLESS если:
    - TLS установлен успешно
    - Поддерживает TLS 1.2 или 1.3
    - Желательно h2 (HTTP/2)
    """
    if not result["tls_ok"]:
        return False
    if result["tls_version"] not in ("TLSv1.2", "TLSv1.3"):
        return False
    return True


# ──────────────────────────────────────────────
# Обратный DNS и поиск hostname по IP
# ──────────────────────────────────────────────

def reverse_dns(ip: str) -> str | None:
    """Попытка получить hostname через обратный DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_hostname_from_cert(ip: str, port: int = 443, timeout: float = 3.0) -> str | None:
    """Получить CN/SAN из TLS-сертификата без SNI."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s) as tls:
                cert = tls.getpeercert()
                if cert:
                    # CN
                    for field in cert.get("subject", ()):
                        for k, v in field:
                            if k == "commonName":
                                return v
                    # SAN
                    for tp, val in cert.get("subjectAltName", ()):
                        if tp == "DNS":
                            return val
    except Exception:
        pass
    return None


def discover_hostnames(ip: str, timeout: float = 3.0) -> list:
    """
    Собирает возможные hostname для IP:
    1. Обратный DNS
    2. CN из сертификата (без SNI)
    """
    hosts = []
    rdns = reverse_dns(ip)
    if rdns:
        hosts.append(rdns)
    cert_cn = get_hostname_from_cert(ip, timeout=timeout)
    if cert_cn and cert_cn not in hosts:
        # CN может быть wildcard — берём как есть для проверки
        hosts.append(cert_cn)
    return hosts


# ──────────────────────────────────────────────
# Сканирование диапазона IP
# ──────────────────────────────────────────────

def scan_ip(ip: str, timeout: float, port: int = 443) -> dict | None:
    """
    Сканирует один IP:
    - Определяет hostname(s)
    - Проверяет TLS/SNI
    Возвращает dict результата или None если не подходит.
    """
    hostnames = discover_hostnames(ip, timeout=timeout)

    if not hostnames:
        # Попробуем всё равно подключиться без SNI — просто проверить порт
        result = check_tls_sni(ip, ip, port=port, timeout=timeout)
        if is_good_sni_candidate(result):
            result["hostname"] = ip
            return result
        return None

    best = None
    for host in hostnames:
        result = check_tls_sni(ip, host, port=port, timeout=timeout)
        if is_good_sni_candidate(result):
            if best is None or (result["http2"] and not best["http2"]):
                best = result
    return best


def scan_range(ips: list, timeout: float, threads: int, port: int = 443) -> list:
    """Параллельное сканирование списка IP."""
    results = []
    total = len(ips)
    done = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_ip, ip, timeout, port): ip for ip in ips}
        for fut in as_completed(futures):
            done += 1
            ip = futures[fut]
            try:
                res = fut.result()
                if res:
                    results.append(res)
                    mark = "✓ h2" if res.get("http2") else "✓"
                    print(f"  [{mark}] {ip:16s}  SNI: {res['hostname']:<40s}  {res['tls_version']}")
            except Exception as e:
                pass
            # Прогресс
            if done % 20 == 0 or done == total:
                pct = done / total * 100
                print(f"  Прогресс: {done}/{total} ({pct:.0f}%)", end="\r", flush=True)

    print()
    return results


# ──────────────────────────────────────────────
# Генерация IP-адресов из подсетей
# ──────────────────────────────────────────────

def ips_from_prefixes(prefixes: list, max_hosts: int = 2000) -> list:
    """Генерирует список IP из набора CIDR-префиксов, ограниченный max_hosts."""
    all_ips = []
    for prefix in prefixes:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            # Пропускаем слишком большие сети, берём первые хосты
            hosts = list(net.hosts())
            all_ips.extend([str(h) for h in hosts])
            if len(all_ips) >= max_hosts:
                break
        except ValueError:
            pass
    return all_ips[:max_hosts]


# ──────────────────────────────────────────────
# Вывод результатов
# ──────────────────────────────────────────────

def print_results(results: list, target_ip: str):
    print("\n" + "═" * 65)
    print(f"  Результаты сканирования для IP: {target_ip}")
    print(f"  Найдено кандидатов: {len(results)}")
    print("═" * 65)

    if not results:
        print("  Подходящих хостов не найдено.")
        return

    # Сортировка: сначала h2
    results.sort(key=lambda x: (not x.get("http2"), x.get("hostname", "")))

    print(f"\n  {'IP':<16}  {'Hostname':<38}  {'TLS':<8}  {'ALPN':<6}  {'Cert CN'}")
    print("  " + "-" * 95)
    for r in results:
        alpn = r.get("alpn") or "-"
        cn = r.get("cert_cn") or "-"
        tls = r.get("tls_version") or "-"
        h2mark = " [H2]" if r.get("http2") else ""
        print(f"  {r['ip']:<16}  {r['hostname']:<38}  {tls:<8}  {alpn:<6}  {cn}{h2mark}")

    print("\n  Лучшие кандидаты для VLESS SNI (HTTP/2):")
    h2 = [r for r in results if r.get("http2")]
    if h2:
        for r in h2[:10]:
            print(f"    → {r['hostname']}  ({r['ip']})")
    else:
        print("    Хостов с HTTP/2 не найдено. Используйте любой из списка выше.")

    print()

    # Сохранение в файл
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"sni_results_{target_ip.replace('.', '_')}_{ts}.txt"
    with open(out_file, "w") as f:
        f.write(f"# SNI VLESS кандидаты для {target_ip}\n")
        f.write(f"# Дата: {datetime.now().isoformat()}\n\n")
        for r in results:
            f.write(f"{r['ip']}\t{r['hostname']}\t{r.get('tls_version','')}\t"
                    f"{'h2' if r.get('http2') else 'h1'}\t{r.get('cert_cn','')}\n")
    print(f"  Результаты сохранены: {out_file}")


# ──────────────────────────────────────────────
# Главная функция
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Поиск SNI VLESS кандидатов в подсети или ASN"
    )
    parser.add_argument("ip", help="Целевой IP-адрес")
    parser.add_argument(
        "--mode", choices=["subnet", "asn", "both"], default="both",
        help="Режим сканирования (default: both)"
    )
    parser.add_argument("--subnet-prefix", type=int, default=24,
                        help="Длина маски подсети (default: 24, т.е. /24)")
    parser.add_argument("--threads", type=int, default=50,
                        help="Число потоков (default: 50)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Таймаут соединения в секундах (default: 3)")
    parser.add_argument("--port", type=int, default=443,
                        help="Порт TLS (default: 443)")
    parser.add_argument("--max-hosts", type=int, default=1000,
                        help="Максимум IP для сканирования из ASN (default: 1000)")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════╗")
    print("║        SNI VLESS Scanner  v1.0           ║")
    print("╚══════════════════════════════════════════╝\n")

    target = args.ip

    # Валидация IP
    try:
        ipaddress.ip_address(target)
    except ValueError:
        print(f"[!] Неверный IP: {target}")
        sys.exit(1)

    print(f"[*] Целевой IP: {target}")
    print(f"[*] Режим: {args.mode}  |  Потоки: {args.threads}  |  Таймаут: {args.timeout}s")

    # Получаем информацию об IP
    print("\n[*] Получаем информацию об IP...")
    info = get_ip_info(target)
    if info:
        org = info.get("org", "N/A")
        country = info.get("country", "N/A")
        region = info.get("region", "N/A")
        print(f"    Организация : {org}")
        print(f"    Страна      : {country} / {region}")
        if "bogon" in info:
            print("    [!] Это bogon/частный адрес")

    # Извлекаем ASN
    asn = None
    org_field = info.get("org", "")
    m = re.match(r"(AS\d+)", org_field)
    if m:
        asn = m.group(1)
        print(f"    ASN         : {asn}")

    ips_to_scan = set()

    # Режим: подсеть
    if args.mode in ("subnet", "both"):
        subnet = subnet_from_ip(target, args.subnet_prefix)
        print(f"\n[*] Подсеть /{args.subnet_prefix}: {subnet}")
        net = ipaddress.ip_network(subnet, strict=False)
        subnet_ips = [str(h) for h in net.hosts()]
        print(f"    Хостов в подсети: {len(subnet_ips)}")
        ips_to_scan.update(subnet_ips)

    # Режим: ASN
    if args.mode in ("asn", "both") and asn:
        print(f"\n[*] Получаем префиксы для {asn}...")
        prefixes = get_asn_prefixes(asn)
        if prefixes:
            print(f"    Найдено префиксов: {len(prefixes)}")
            asn_ips = ips_from_prefixes(prefixes, max_hosts=args.max_hosts)
            print(f"    IP для сканирования из ASN: {len(asn_ips)} (лимит: {args.max_hosts})")
            ips_to_scan.update(asn_ips)
        else:
            print("    [!] Не удалось получить префиксы ASN")
    elif args.mode in ("asn", "both") and not asn:
        print("\n[!] ASN не определён, пропускаем ASN-сканирование")

    ips_list = sorted(ips_to_scan, key=lambda x: ipaddress.ip_address(x))
    print(f"\n[*] Всего уникальных IP для сканирования: {len(ips_list)}")
    print("[*] Начинаем сканирование...\n")

    results = scan_range(ips_list, timeout=args.timeout,
                         threads=args.threads, port=args.port)

    print_results(results, target)


if __name__ == "__main__":
    main()
