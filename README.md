# SNI VLESS Scanner

Сканирует подсеть или ASN и находит домены пригодные для использования в качестве `dest` / `serverNames` в конфигурации VLESS Reality.

---

## Как это работает

VLESS Reality маскирует трафик под легитимное HTTPS-соединение к реальному сайту. Для этого нужен домен (`dest`) который:

- находится в той же подсети или ASN что и ваш сервер — трафик выглядит естественно
- реально резолвится на этот IP — домен должен смотреть именно на нужный адрес
- имеет валидный сертификат (CN совпадает с доменом)
- поддерживает TLS 1.2 / 1.3
- поддерживает HTTP/2 (ALPN `h2`) — обязательное условие для Reality

Скрипт автоматически проходит все эти проверки для каждого IP в диапазоне.

---

## Логика проверки каждого IP

```
1. rDNS        → получаем hostname по IP
2. DNS         → резолвим hostname и проверяем что он смотрит обратно на этот IP
3. TLS         → устанавливаем соединение с SNI=hostname, проверяем версию и H2
4. Cert        → CN сертификата должен совпадать с hostname (не чужой прокси)
5. HTTP        → делаем GET / и проверяем что сервер отвечает как настоящий сайт
```

Если любой шаг не прошёл — IP отсеивается с указанием причины.

---

## Установка

```bash
git clone https://github.com/HnDK0/SNI-Scanner.git
cd SNI-Scanner
```

### Требования

- Python 3.9+
- `requests` — опционально, ускоряет HTTP-запросы
- `cryptography` — опционально, точнее извлекает CN/SAN из сертификатов

```bash
pip install requests cryptography
```

---

## Использование

```bash
python sni_scanner.py <IP> [параметры]
```

### Параметры

| Параметр | По умолчанию | Описание |
|---|---|---|
| `ip` | — | Целевой IP вашего сервера |
| `--mode` | `both` | Режим: `subnet` — только подсеть, `asn` — только ASN, `both` — оба |
| `--subnet-prefix` | `24` | Маска подсети (`24` = 254 хоста, `22` = 1022 хоста) |
| `--threads` | `50` | Число параллельных потоков |
| `--timeout` | `3.0` | Таймаут соединения в секундах |
| `--port` | `443` | Порт TLS |
| `--max-hosts` | `1000` | Максимум IP из ASN |

### Примеры

```bash
# Сканировать подсеть и ASN (по умолчанию)
python sni_scanner.py 185.195.24.60

# Только ASN — больше результатов, дольше
python sni_scanner.py 185.195.24.60 --mode asn --max-hosts 3000

# Только подсеть — быстро
python sni_scanner.py 185.195.24.60 --mode subnet

# Расширенная подсеть /22
python sni_scanner.py 185.195.24.60 --mode subnet --subnet-prefix 22

# Быстрое сканирование с меньшим таймаутом
python sni_scanner.py 185.195.24.60 --threads 100 --timeout 2.0
```

---

## Результаты

После сканирования создаются два файла:

### `sni_results_<ip>_<timestamp>.txt`

Только успешные кандидаты — домен, IP, и что за сайт:

```
wheelblades.ru                                185.195.24.13    Магазин колёс
iter-lex.ru                                   185.195.24.89    ITER-LEX
bt.sintx.ru                                   185.195.24.167   >https://bt.sintx.ru/login
mrak-bre.ru                                   185.195.24.242   BRE! | !mrak
```

### `sni_results_<ip>_<timestamp>.log`

Все проверенные IP с результатом каждого шага:

```
[2026-03-10 08:00:24] PASS  ip=185.195.24.13   domain=wheelblades.ru        dns=OK  tls=TLSv1.3  h2=yes  cert=match  http=200  server=nginx/1.18.0  title="Магазин колёс"
[2026-03-10 08:00:35] FAIL  ip=185.195.24.14   domain=shikado.mooo.com      dns=OK  tls=TLSv1.3  h2=yes  cert=MISMATCH(*.telegram.org)
[2026-03-10 08:00:35] FAIL  ip=185.195.24.103  domain=msk.ru                dns=MISMATCH(178.210.74.11)
[2026-03-10 08:00:35] FAIL  ip=185.195.24.1    domain=none                  rdns=FAIL
[2026-03-10 08:00:35] FAIL  ip=185.195.24.101  domain=data.ariogate.online  dns=OK  tls=FAIL(TLSV1_ALERT_INTERNAL_ERROR)
[2026-03-10 08:00:47] FAIL  ip=185.195.24.215  domain=whm.itag-company.ru   dns=OK  tls=TLSv1.3  h2=no   cert=match  http=FAIL(err:SSLError)
```

---

## Использование результатов в Xray (VLESS Reality)

Берём любой домен из `.txt` файла и вставляем в конфиг:

```json
"realitySettings": {
  "dest": "wheelblades.ru:443",
  "serverNames": [
    "wheelblades.ru"
  ],
  "privateKey": "ваш_приватный_ключ",
  "shortIds": ["ваш_short_id"]
}
```

Перезапуск:
```bash
systemctl restart xray
```

---

## Устранение проблем

**`[!] RIPE Stat недоступен`** — проблема с сетью или API временно недоступен. Используйте `--mode subnet`.

**Мало кандидатов** — попробуйте `--subnet-prefix 22` или `--mode asn --max-hosts 3000`.

**Зависание** — уменьшите таймаут: `--timeout 1.5 --threads 100`.

**`ModuleNotFoundError`** — установите зависимости: `pip install requests cryptography`.

---

## Зависимости

| Библиотека | Тип | Назначение |
|---|---|---|
| `socket` | встроенная | TCP-соединения, rDNS, DNS-резолвинг |
| `ssl` | встроенная | TLS-рукопожатие, чтение сертификатов |
| `ipaddress` | встроенная | Работа с подсетями |
| `concurrent.futures` | встроенная | Параллельное сканирование |
| `urllib` | встроенная | HTTP-запросы (резервный вариант) |
| `requests` | опциональная | HTTP-запросы к ipinfo.io / RIPE Stat |
| `cryptography` | опциональная | Точное извлечение CN/SAN из сертификатов |

---

## Дисклеймер

Скрипт выполняет только пассивное зондирование: TCP-подключение, TLS-рукопожатие и HTTP-запрос к публично доступным серверам. Убедитесь что его использование соответствует законодательству вашей страны.