#!/usr/bin/env python3
"""
SNI VLESS Scanner
Ищет сайты в одной подсети или ASN, подходящие для SNI VLESS проксирования.

Логика проверки каждого IP:
  1. rDNS         → получаем hostname
  2. DNS-резолвинг hostname → проверяем что домен смотрит на этот IP
  3. TLS/SNI      → версия, ALPN, CN из сертификата
  4. HTTP GET /   → статус, title, location, server

В лог пишутся ВСЕ IP с причиной отсева на каждом шаге.
В txt только успешные кандидаты: домен + IP + что за сайт.

Использование:
  python sni_scanner.py <IP> [--mode subnet|asn|both] [--threads 50] [--timeout 3]
"""

import argparse
import ipaddress
import os
import random
import re
import socket
import ssl
import sys
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

import urllib.request


# ──────────────────────────────────────────────
# Получение информации об IP / ASN
# ──────────────────────────────────────────────

def get_ip_info(ip: str) -> dict:
    url = f"https://ipinfo.io/{ip}/json"
    try:
        if HAS_REQUESTS:
            return requests.get(url, timeout=5).json()
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[!] ipinfo недоступен: {e}")
        return {}


def get_asn_prefixes(asn: str) -> list:
    asn_num = asn.upper().lstrip("AS")
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}&sourceapp=sni-scanner"
    try:
        if HAS_REQUESTS:
            data = requests.get(url, timeout=10).json()
        else:
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode())
        prefixes = []
        for p in data.get("data", {}).get("prefixes", []):
            prefix = p.get("prefix", "")
            if ":" not in prefix:
                prefixes.append(prefix)
        return prefixes
    except Exception as e:
        print(f"[!] RIPE Stat недоступен: {e}")
        return []


def ips_from_prefixes(prefixes: list, max_hosts: int) -> list:
    """
    FIX #7: перемешиваем префиксы перед обходом, чтобы не уходить
    весь лимит в первый (возможно огромный) префикс ASN.
    """
    shuffled = list(prefixes)
    random.shuffle(shuffled)
    all_ips = []
    for prefix in shuffled:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            # FIX: ленивая итерация — не загружаем весь /8 (16M IP) в память сразу
            for host in net.hosts():
                all_ips.append(str(host))
                if len(all_ips) >= max_hosts:
                    return all_ips
        except ValueError:
            pass
    return all_ips


def subnet_ips(ip: str, prefix_len: int) -> list:
    net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
    count = net.num_addresses
    if count > 10000:
        print(f"[!] Предупреждение: подсеть /{prefix_len} содержит {count - 2} хостов — сканирование займёт много времени.")
    return [str(h) for h in net.hosts()]


# ──────────────────────────────────────────────
# Шаг 1: rDNS
# ──────────────────────────────────────────────

def rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ──────────────────────────────────────────────
# Шаг 2: DNS-резолвинг — проверяем что домен смотрит на этот IP
# ──────────────────────────────────────────────

def resolve_hostname(hostname: str, dns_server: str = "8.8.8.8") -> list:
    """
    Возвращает список A-записей для hostname.

    Если dns_server начинается с "https://" — использует DoH (DNS-over-HTTPS).
    Это единственный способ обойти fake-dns (v2rayN и аналоги), который
    перехватывает все запросы на порт 53 и возвращает 198.18.x.x.

    Иначе — прямой DNS по UDP с fallback на TCP к тому же серверу.
    Системный резолвер (getaddrinfo) намеренно не используется.
    """
    import struct

    def _skip_name(data: bytes, offset: int) -> int:
        while offset < len(data):
            length = data[offset]
            if length & 0xC0 == 0xC0:
                return offset + 2
            if length == 0:
                return offset + 1
            offset += 1 + length
        return offset

    def _build_query(name: str) -> bytes:
        header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
        labels = b""
        for part in name.encode().split(b"."):
            labels += bytes([len(part)]) + part
        labels += b"\x00"
        return header + labels + struct.pack(">HH", 1, 1)

    def _parse_a_records(data: bytes) -> list:
        if len(data) < 12:
            return []
        ancount = struct.unpack(">H", data[6:8])[0]
        if ancount == 0:
            return []
        offset = 12
        qdcount = struct.unpack(">H", data[4:6])[0]
        for _ in range(qdcount):
            offset = _skip_name(data, offset)
            offset += 4
        ips = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            offset = _skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
                ips.append(".".join(str(b) for b in data[offset:offset+4]))
            offset += rdlen
        return ips

    def _warn_if_fake(ips, transport):
        if any(ip.startswith("198.18.") for ip in ips):
            import sys
            print(f"\n  [!] fake-dns / DNS-перехват ({transport}): получены {ips} для {hostname!r}", file=sys.stderr)
            print(f"      Используйте --dns https://dns.google/dns-query (DoH) чтобы обойти.", file=sys.stderr)

    # ── DoH (DNS-over-HTTPS) ───────────────────────────────────────────────
    if dns_server.startswith("https://"):
        try:
            query = _build_query(hostname)
            import base64
            dns_param = base64.urlsafe_b64encode(query).rstrip(b"=").decode()
            url = f"{dns_server}?dns={dns_param}"
            # Используем urllib чтобы не зависеть от requests
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-message",
                         "User-Agent": "sni-scanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                response = resp.read()
            ips = _parse_a_records(response)
            if ips:
                _warn_if_fake(ips, "DoH")
                return ips
        except Exception as e:
            import sys
            print(f"  [!] DoH ошибка ({dns_server}): {e}", file=sys.stderr)
        return []

    # ── UDP ────────────────────────────────────────────────────────────────
    try:
        query = _build_query(hostname)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3.0)
            sock.sendto(query, (dns_server, 53))
            response, _ = sock.recvfrom(4096)
        if len(response) >= 3 and (response[2] & 0x02):
            raise ValueError("truncated")
        ips = _parse_a_records(response)
        if ips:
            _warn_if_fake(ips, "UDP")
            return ips
    except Exception:
        pass

    # ── TCP (если UDP заблокирован или ответ обрезан) ──────────────────────
    try:
        query = _build_query(hostname)
        tcp_msg = struct.pack(">H", len(query)) + query
        with socket.create_connection((dns_server, 53), timeout=4.0) as sock:
            sock.sendall(tcp_msg)
            raw_len = sock.recv(2)
            if len(raw_len) == 2:
                msg_len = struct.unpack(">H", raw_len)[0]
                response = b""
                while len(response) < msg_len:
                    chunk = sock.recv(msg_len - len(response))
                    if not chunk:
                        break
                    response += chunk
                ips = _parse_a_records(response)
                if ips:
                    _warn_if_fake(ips, "TCP")
                    return ips
    except Exception:
        pass

    return []


# ──────────────────────────────────────────────
# Шаг 3: TLS / SNI + извлечение CN из сертификата
# ──────────────────────────────────────────────

def _cn_from_der(der: bytes) -> str | None:
    """
    Извлекает CN/SAN из DER без verify — getpeercert() пустой при CERT_NONE.

    FIX #1: структурирован так, что fallback DER-парсер выполняется
    при любом исходе попытки импорта cryptography — в том числе при
    ошибке внутри библиотеки (раньше `except Exception: return None`
    прерывал функцию до fallback).
    """
    cn_via_lib = None
    lib_available = False

    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        lib_available = True
        cert = x509.load_der_x509_certificate(der, default_backend())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san.value.get_values_for_type(x509.DNSName)
            if dns_names:
                cn_via_lib = dns_names[0]
        except Exception:
            pass
        if cn_via_lib is None:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            cn_via_lib = attrs[0].value if attrs else None
    except ImportError:
        pass
    except Exception:
        pass  # библиотека доступна но сломалась — пробуем fallback

    if cn_via_lib is not None:
        return cn_via_lib

    # Fallback: ищем OID 55 04 03 (commonName) прямо в байтах DER.
    try:
        i = 0
        while i < len(der) - 5:
            if der[i:i+3] == b'\x55\x04\x03':
                i += 4  # пропускаем тип строки
                length = der[i]; i += 1
                if length < 128 and i + length <= len(der):
                    cn = der[i:i+length].decode("utf-8", errors="replace")
                    if "." in cn or len(cn) > 3:
                        return cn
            i += 1
    except Exception:
        pass
    return None


def check_tls(ip: str, hostname: str, port: int, timeout: float) -> dict:
    r = {"ok": False, "version": None, "alpn": None, "h2": False,
         "cert_cn": None, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                r["ok"]      = True
                r["version"] = tls.version()
                r["alpn"]    = tls.selected_alpn_protocol()
                r["h2"]      = (r["alpn"] == "h2")
                der = tls.getpeercert(binary_form=True)
                if der:
                    r["cert_cn"] = _cn_from_der(der)
    except ssl.SSLError as e:
        r["error"] = f"ssl:{e}"
    except (socket.timeout, TimeoutError):
        r["error"] = "tls_timeout"
    except ConnectionRefusedError:
        r["error"] = "refused"
    except OSError as e:
        r["error"] = f"oserr:{e.errno}"
    except Exception as e:
        r["error"] = f"err:{type(e).__name__}"
    return r


# ──────────────────────────────────────────────
# Шаг 4: HTTP GET /
# ──────────────────────────────────────────────

def check_http(ip: str, hostname: str, port: int, timeout: float) -> dict:
    """
    FIX #6: увеличен лимит чтения с 8 192 до 32 768 байт,
    чтобы захватить <title> у страниц с большим <head>.
    """
    r = {"status": None, "server": "", "location": "", "title": "",
         "no_http": False, "error": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                req = (
                    f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Accept: text/html\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(req.encode())
                raw = b""
                while len(raw) < 32768:          # было 8192
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                text = raw.decode(errors="ignore")
                if not text.startswith("HTTP/"):
                    r["no_http"] = True
                    return r
                lines = text.split("\r\n")
                try:
                    r["status"] = int(lines[0].split()[1])
                except Exception:
                    pass
                for line in lines[1:]:
                    ll = line.lower()
                    if ll.startswith("server:"):
                        r["server"] = line.split(":", 1)[1].strip()
                    elif ll.startswith("location:"):
                        r["location"] = line.split(":", 1)[1].strip()
                m = re.search(r"<title[^>]*>([^<]{1,80})</title>", text, re.IGNORECASE)
                if m:
                    r["title"] = m.group(1).strip()
    except (socket.timeout, TimeoutError):
        r["error"] = "http_timeout"
    except Exception as e:
        r["error"] = f"err:{type(e).__name__}"
    return r


# ──────────────────────────────────────────────
# Полная проверка одного IP
# ──────────────────────────────────────────────

def cert_cn_no_sni(ip: str, port: int, timeout: float) -> tuple:
    """
    Подключается к IP и читает CN/SAN из сертификата без SNI.
    Используется в режиме --skip-rdns когда PTR не настроен.

    Возвращает (hostname, error_reason).
    При успехе: (hostname, None). При ошибке: (None, "причина").

    server_hostname=IP — по RFC 6066 OpenSSL не добавляет SNI
    когда hostname является IP-адресом. Работает на Win/Linux/macOS.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if der:
                    cn = _cn_from_der(der)
                    if cn:
                        return cn, None
                    return None, "der_no_cn"
                return None, "no_der"
    except ssl.SSLError as e:
        return None, f"ssl:{e.reason or e}"
    except (socket.timeout, TimeoutError):
        return None, "timeout"
    except ConnectionRefusedError:
        return None, "refused"
    except OSError as e:
        return None, f"oserr:{e.errno}"
    except Exception as e:
        return None, f"{type(e).__name__}"


def scan_ip(ip: str, port: int, timeout: float, skip_rdns: bool = False, dns_server: str = "8.8.8.8") -> dict:
    result = {
        "ip":            ip,
        "hostname":      None,
        "dns_ips":       [],
        "dns_match":     False,
        "tls_ok":        False,
        "tls_version":   None,
        "alpn":          None,
        "h2":            False,
        "cert_cn":       None,
        "http_status":   None,
        "http_server":   "",
        "http_location": "",
        "http_title":    "",
        "no_http":       False,
        "good":          False,
        "fail_step":     None,
        "fail_reason":   None,
    }

    if skip_rdns:
        # ── Режим --skip-rdns ──────────────────────────────────────────────
        # Шаг 1а: читаем CN прямо из сертификата (без PTR)
        hostname, cn_err = cert_cn_no_sni(ip, port, timeout)
        if not hostname:
            result["fail_step"]   = "rdns"
            result["fail_reason"] = f"no_cert_cn({cn_err})"
            return result
        # Убираем wildcard-префикс если есть (*.example.com → example.com)
        if hostname.startswith("*."):
            hostname = hostname[2:]
        if not hostname:
            result["fail_step"]   = "rdns"
            result["fail_reason"] = "empty_wildcard"
            return result
        result["hostname"] = hostname

        # Шаг 2а: DNS → домен из сертификата должен резолвиться на этот IP
        dns_ips = resolve_hostname(hostname, dns_server)
        result["dns_ips"] = dns_ips
        if ip not in dns_ips:
            result["fail_step"]   = "dns"
            result["fail_reason"] = f"dns_mismatch({','.join(dns_ips) if dns_ips else 'nxdomain'})"
            return result
        result["dns_match"] = True

    else:
        # ── Стандартный режим ──────────────────────────────────────────────
        # Шаг 1: rDNS
        hostname = rdns(ip)
        if not hostname:
            result["fail_step"]   = "rdns"
            result["fail_reason"] = "no_rdns"
            return result
        result["hostname"] = hostname

        # Шаг 2: DNS → должен резолвиться на этот IP
        dns_ips = resolve_hostname(hostname, dns_server)
        result["dns_ips"] = dns_ips
        if ip not in dns_ips:
            result["fail_step"]   = "dns"
            result["fail_reason"] = f"dns_mismatch({','.join(dns_ips) if dns_ips else 'nxdomain'})"
            return result
        result["dns_match"] = True

    # Шаг 3: TLS
    tls = check_tls(ip, hostname, port, timeout)
    result.update({
        "tls_ok":      tls["ok"],
        "tls_version": tls["version"],
        "alpn":        tls["alpn"],
        "h2":          tls["h2"],
        "cert_cn":     tls["cert_cn"],
    })
    if not tls["ok"]:
        result["fail_step"]   = "tls"
        result["fail_reason"] = tls["error"]
        return result
    if tls["version"] not in ("TLSv1.2", "TLSv1.3"):
        result["fail_step"]   = "tls"
        result["fail_reason"] = f"old_tls:{tls['version']}"
        return result

    # FIX #2: H2 теперь НЕ является жёстким требованием.
    # Reality работает и без h2 ALPN на стороне dest.
    # Сервера без H2 попадают в результаты, но помечаются в логе.
    # (ранее: `if not tls["h2"]: return FAIL` — убрано)

    # Проверка CN / SAN сертификата.
    # FIX #3: добавлен случай прямого поддомена (hostname = sub.example.com,
    # cert_cn = example.com) — раньше такой матч не проходил.
    cert_cn = tls["cert_cn"] or ""
    cn_base = cert_cn.lstrip("*.")
    cn_match = (
        cert_cn == hostname
        or cert_cn == f"*.{hostname.split('.', 1)[-1]}"
        or (cn_base and hostname.endswith("." + cn_base))
        or cn_base == hostname
        or (cert_cn and hostname.endswith("." + cert_cn))   # FIX #3: sub.example.com ← example.com
    )
    if not cn_match:
        result["fail_step"]   = "cert"
        result["fail_reason"] = f"cert_mismatch({cert_cn})"
        return result

    # Шаг 4: HTTP
    http = check_http(ip, hostname, port, timeout)
    result.update({
        "http_status":   http["status"],
        "http_server":   http["server"],
        "http_location": http["location"],
        "http_title":    http["title"],
        "no_http":       http["no_http"],
    })
    if http["no_http"]:
        result["fail_step"]   = "http"
        result["fail_reason"] = "no_http_response(reality?)"
        return result
    if http["error"]:
        result["fail_step"]   = "http"
        result["fail_reason"] = http["error"]
        return result
    if not http["status"]:
        result["fail_step"]   = "http"
        result["fail_reason"] = "no_status"
        return result

    result["good"] = True
    return result


# ──────────────────────────────────────────────
# Запись результатов
# ──────────────────────────────────────────────

class ResultWriter:
    """
    Атомарная инкрементальная запись через .tmp + os.replace.
    .txt — только успешные кандидаты: домен / IP / сайт
    .log — ВСЕ проверенные IP с результатом каждого шага

    FIX #4: добавлен threading.Lock для защиты от race condition
    при параллельной записи из 50+ потоков.
    """

    def __init__(self, txt_path: str, log_path: str, flush_every: int = 50):
        self.txt_path    = txt_path
        self.log_path    = log_path
        self._good: list = []
        self._log:  list = []
        self.total       = 0
        self.passed      = 0
        self._lock       = threading.Lock()
        self._flush_every = flush_every

    def add(self, r: dict):
        with self._lock:                      # FIX #4
            self.total += 1
            ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip       = r["ip"]
            hostname = r["hostname"] or ""
            status   = "PASS" if r["good"] else "FAIL"

            fields = [f"ip={ip}", f"domain={hostname if hostname else 'none'}"]

            if r["fail_step"] != "rdns":
                if r["dns_match"]:
                    fields.append("dns=OK")
                else:
                    resolved = ",".join(r["dns_ips"][:3]) if r["dns_ips"] else "nxdomain"
                    fields.append(f"dns=MISMATCH({resolved})")

            if r["fail_step"] not in ("rdns", "dns"):
                if r["tls_ok"]:
                    fields.append(f"tls={r['tls_version']}")
                    fields.append(f"h2={'yes' if r['h2'] else 'no'}")
                else:
                    fields.append(f"tls=FAIL({r['fail_reason']})")

            if r["fail_step"] not in ("rdns", "dns", "tls"):
                cert_cn = r["cert_cn"] or ""
                if r["fail_step"] == "cert":
                    fields.append(f"cert=MISMATCH({cert_cn})")
                else:
                    fields.append("cert=match")

            if r["fail_step"] not in ("rdns", "dns", "tls", "cert"):
                if r["good"]:
                    fields.append(f"http={r['http_status']}")
                    if r["http_server"]:
                        fields.append(f"server={r['http_server'][:30]}")
                    if r["http_title"]:
                        fields.append(f"title=\"{r['http_title'][:50]}\"")
                    elif r["http_location"]:
                        fields.append(f"redirect={r['http_location'][:50]}")
                else:
                    fields.append(f"http=FAIL({r['fail_reason']})")

            self._log.append(f"[{ts}] {status}  " + "  ".join(fields))

            if r["good"]:
                self.passed += 1
                site = r["http_title"] or r["http_location"] or str(r["http_status"] or "")
                h2_mark = " [H2]" if r["h2"] else ""
                self._good.append(f"{hostname:<45}  {r['ip']:<16}  {site[:60]}{h2_mark}")
                self._flush()  # сразу пишем найденный кандидат
            elif self.total % self._flush_every == 0:
                self._flush()  # периодический сброс лога

    def _flush(self):
        self._write_atomic(self.txt_path, "\n".join(self._good) + "\n" if self._good else "")
        self._write_atomic(self.log_path, "\n".join(self._log)  + "\n" if self._log  else "")

    @staticmethod
    def _write_atomic(path: str, content: str):
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, path)
        except Exception as e:
            print(f"[!] Ошибка записи {path}: {e}")

    def finalize(self):
        self._flush()
        print(
            f"\n  Проверено: {self.total}  |  Кандидатов: {self.passed}\n"
            f"  Домены : {self.txt_path}\n"
            f"  Лог    : {self.log_path}"
        )


# ──────────────────────────────────────────────
# Сканирование диапазона
# ──────────────────────────────────────────────

def scan_range(ips: list, port: int, timeout: float,
               threads: int, writer: ResultWriter, skip_rdns: bool = False, dns_server: str = "8.8.8.8") -> list:
    good  = []
    total = len(ips)
    done  = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_ip, ip, port, timeout, skip_rdns, dns_server): ip for ip in ips}
        for fut in as_completed(futures):
            done += 1
            try:
                r = fut.result()
                writer.add(r)
                if r["good"]:
                    good.append(r)
                    mark = "h2" if r["h2"] else "h1"
                    site = r["http_title"] or r["http_location"] or str(r["http_status"] or "")
                    print(f"  ✓ {r['ip']:<16}  {r['hostname']:<42}  {mark}  {site[:50]}")
            except Exception as e:
                ip = futures[fut]
                print(f"  [!] Ошибка потока для {ip}: {type(e).__name__}: {e}")
            if done % 20 == 0 or done == total:
                print(f"  [{done}/{total}]", end="\r", flush=True)

    print()
    return good


# ──────────────────────────────────────────────
# Итоговый вывод
# ──────────────────────────────────────────────

def print_results(results: list, target_ip: str):
    print("\n" + "═" * 80)
    print(f"  SNI-кандидаты для {target_ip}  —  найдено: {len(results)}")
    print("═" * 80)
    if not results:
        print("  Подходящих хостов не найдено.")
        return

    results.sort(key=lambda x: (not x["h2"], x["hostname"]))
    print(f"\n  {'IP':<16}  {'Hostname':<38}  {'TLS':<8}  {'ALPN':<6}  Сайт")
    print("  " + "─" * 100)
    for r in results:
        site = r["http_title"] or r["http_location"] or str(r["http_status"] or "")
        h2   = " [H2]" if r["h2"] else ""
        print(f"  {r['ip']:<16}  {r['hostname']:<38}  "
              f"{r['tls_version']:<8}  {(r['alpn'] or '-'):<6}  {site[:50]}{h2}")

    h2_list = [r for r in results if r["h2"]]
    if h2_list:
        print(f"\n  Лучшие (HTTP/2):")
        for r in h2_list[:10]:
            print(f"    → {r['hostname']}  ({r['ip']})")

    no_h2 = [r for r in results if not r["h2"]]
    if no_h2:
        print(f"\n  Без H2 (тоже подходят для Reality):")
        for r in no_h2[:5]:
            print(f"    → {r['hostname']}  ({r['ip']})")



# ──────────────────────────────────────────────
# Диагностика одного IP (--probe)
# ──────────────────────────────────────────────

def probe_ip(ip: str, port: int, timeout: float, skip_rdns: bool, dns_server: str = "8.8.8.8"):
    """Детальная диагностика одного IP — показывает каждый шаг с результатом."""
    print(f"\n  Диагностика: {ip}:{port}  (timeout={timeout}s)\n")

    # Шаг 1: TCP
    print("  [1] TCP-соединение...", end=" ")
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            print("OK")
    except (socket.timeout, TimeoutError):
        print("FAIL — таймаут. Порт закрыт или фаерволл.")
        return
    except ConnectionRefusedError:
        print("FAIL — соединение отклонено. Порт не слушает.")
        return
    except OSError as e:
        print(f"FAIL — {e}")
        return

    # Шаг 2: TLS без SNI (для --skip-rdns)
    if skip_rdns:
        print("  [2] TLS без SNI (читаем CN из сертификата)...", end=" ")
        cn, err = cert_cn_no_sni(ip, port, timeout)
        if cn:
            print(f"OK → CN/SAN = {cn!r}")
        else:
            print(f"FAIL — {err}")
            if err and "ssl:" in err:
                print("      Сервер требует SNI или отклоняет соединение без него.")
            elif err == "no_der":
                print("      TLS установлен, но сервер не вернул сертификат.")
            elif err == "der_no_cn":
                print("      Сертификат есть, но CN/SAN не найден (нестандартный формат).")
            elif err == "timeout":
                print("      TLS-handshake завис. Попробуйте --timeout 8.0")
            return
        hostname = cn.lstrip("*.")
        if not hostname:
            print("  FAIL — CN после strip пуст.")
            return
    else:
        print("  [2] rDNS (PTR-запрос)...", end=" ")
        hostname = rdns(ip)
        if hostname:
            print(f"OK → {hostname}")
        else:
            print("FAIL — PTR не настроен. Используйте --skip-rdns.")
            return

    # Шаг 3: DNS forward
    print(f"  [3] DNS резолвинг {hostname!r}...", end=" ")
    dns_ips = resolve_hostname(hostname, dns_server)
    if not dns_ips:
        print(f"FAIL — домен не резолвится (NXDOMAIN).")
        return
    if ip in dns_ips:
        print(f"OK → {dns_ips}")
    else:
        print(f"FAIL — домен резолвится на {dns_ips}, а не на {ip}.")
        return

    # Шаг 4: TLS с SNI
    print(f"  [4] TLS с SNI={hostname!r}...", end=" ")
    tls = check_tls(ip, hostname, port, timeout)
    if tls["ok"]:
        print(f"OK → {tls['version']}, ALPN={tls['alpn']}, H2={tls['h2']}, CN={tls['cert_cn']!r}")
    else:
        print(f"FAIL — {tls['error']}")
        return

    # Шаг 5: CN-матч
    print("  [5] Проверка CN...", end=" ")
    cert_cn = tls["cert_cn"] or ""
    cn_base = cert_cn.lstrip("*.")
    cn_match = (
        cert_cn == hostname
        or cert_cn == f"*.{hostname.split('.', 1)[-1]}"
        or (cn_base and hostname.endswith("." + cn_base))
        or cn_base == hostname
        or (cert_cn and hostname.endswith("." + cert_cn))
    )
    if cn_match:
        print(f"OK")
    else:
        print(f"FAIL — сертификат {cert_cn!r} не совпадает с {hostname!r}.")
        return

    # Шаг 6: HTTP
    print(f"  [6] HTTP GET /...", end=" ")
    http = check_http(ip, hostname, port, timeout)
    if http["no_http"]:
        print("FAIL — ответ не является HTTP (возможно Reality на этом IP).")
    elif http["error"]:
        print(f"FAIL — {http['error']}")
    elif http["status"]:
        print(f"OK → HTTP {http['status']}, server={http['server']!r}, title={http['title']!r}")
    else:
        print("FAIL — нет статуса.")
        return

    print(f"\n  ✓ {hostname} подходит для VLESS Reality!")

# ──────────────────────────────────────────────
# Точка входа
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SNI VLESS Scanner — поиск доменов для SNI в подсети/ASN"
    )
    parser.add_argument("ip",              help="Целевой IP-адрес")
    parser.add_argument("--mode",          choices=["subnet", "asn", "both"], default="both")
    parser.add_argument("--subnet-prefix", type=int,   default=24)
    parser.add_argument("--threads",       type=int,   default=50)
    parser.add_argument("--timeout",       type=float, default=3.0)
    parser.add_argument("--port",          type=int,   default=443)
    parser.add_argument("--max-hosts",     type=int,   default=1000)
    parser.add_argument("--skip-rdns",     action="store_true",
                        help="Не делать PTR-запрос: брать hostname из CN сертификата. "
                             "Используйте когда rDNS не настроен в подсети.")
    parser.add_argument("--probe",          action="store_true",
                        help="Режим диагностики одного IP: показывает каждый шаг подробно.")
    parser.add_argument("--dns",            default="8.8.8.8",
                        help="DNS для резолвинга. Примеры: 8.8.8.8, 1.1.1.1, "
                             "https://dns.google/dns-query (DoH). "
                             "DoH обходит fake-dns и перехват на порту 53.")
    args = parser.parse_args()

    if args.threads > 200:
        print(f"[!] --threads {args.threads} слишком много, ограничиваем до 200 (ulimit)")
        args.threads = 200

    print("╔══════════════════════════════════════════╗")
    print("║        SNI VLESS Scanner  v2.2           ║")
    print("╚══════════════════════════════════════════╝\n")

    target = args.ip
    try:
        ipaddress.ip_address(target)
    except ValueError:
        print(f"[!] Неверный IP: {target}")
        sys.exit(1)

    if args.probe:
        probe_ip(target, args.port, args.timeout, args.skip_rdns, args.dns)
        return

    print(f"[*] Целевой IP : {target}")
    print(f"[*] Режим      : {args.mode}  |  Потоки: {args.threads}  |  Таймаут: {args.timeout}s")
    if args.skip_rdns:
        print("[*] skip-rdns  : ВКЛ — hostname берётся из CN сертификата")
    if args.dns.startswith("https://"):
        print(f"[*] DNS-сервер : {args.dns}  [DoH]")
    else:
        print(f"[*] DNS-сервер : {args.dns}")

    info = get_ip_info(target)
    if info:
        print(f"    Организация: {info.get('org', 'N/A')}")
        print(f"    Страна     : {info.get('country', 'N/A')} / {info.get('region', 'N/A')}")

    # FIX #5: помимо поля org пробуем явное поле asn (если ipinfo вернул его),
    # и явно предупреждаем если ASN не удалось определить при --mode asn/both.
    asn = None
    asn_field = info.get("asn", "")         # ipinfo Basic plan возвращает "asn": "AS12345"
    org_field  = info.get("org", "")
    m = re.match(r"(AS\d+)", asn_field) or re.match(r"(AS\d+)", org_field)
    if m:
        asn = m.group(1)
        print(f"    ASN        : {asn}")
    elif args.mode in ("asn", "both"):
        print("[!] ASN не определён — ipinfo не вернул ASN. Используйте --mode subnet.")

    ips_to_scan: set = set()

    if args.mode in ("subnet", "both"):
        ips = subnet_ips(target, args.subnet_prefix)
        print(f"\n[*] Подсеть /{args.subnet_prefix}: {len(ips)} хостов")
        ips_to_scan.update(ips)

    if args.mode in ("asn", "both"):
        if asn:
            print(f"[*] Получаем префиксы {asn}...")
            prefixes = get_asn_prefixes(asn)
            if prefixes:
                asn_ips = ips_from_prefixes(prefixes, args.max_hosts)
                print(f"    Префиксов: {len(prefixes)}, IP: {len(asn_ips)}")
                ips_to_scan.update(asn_ips)
            else:
                print("    [!] Префиксы не получены")
        else:
            print("[!] ASN не определён, ASN-сканирование пропущено")

    ips_list = sorted(ips_to_scan, key=lambda x: ipaddress.ip_address(x))
    print(f"\n[*] Всего IP для сканирования: {len(ips_list)}")
    print("[*] Начинаем...\n")

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    base   = f"sni_results_{target.replace('.', '_')}_{ts}"
    writer = ResultWriter(txt_path=base + ".txt", log_path=base + ".log")

    results = []
    try:
        results = scan_range(
            ips_list,
            port=args.port,
            timeout=args.timeout,
            threads=args.threads,
            writer=writer,
            skip_rdns=args.skip_rdns,
            dns_server=args.dns,
        )
    except KeyboardInterrupt:
        print("\n[!] Прервано.")
    finally:
        writer.finalize()

    print_results(results, target)


if __name__ == "__main__":
    main()