# proxy-duplicator (dup)

Дублирование трафика по **N параллельным SSH-туннелям** с дедупликацией на
принимающей стороне и бесшовным failover. Сделано для условий, где из
нестандартных протоколов стабильно проходит только **SSH/SOCKS5** (TCP),
например под фильтрацией ТСПУ: снаружи видны обычные параллельные SSH-сессии,
а потеря копии в одном туннеле не рвёт сессию — кадр приходит через другой.

```
Apps → Nekoray (SOCKS5) → dupc → N× SSH (direct-tcpip) → dupd → serjs/go-socks5-proxy → интернет  [TCP]
                                                            └→ обычный UDP с IP сервера          [UDP]
```

Один бинарник, две роли: `dup server` (dupd) и `dup client` (dupc).

## Как это работает

* Каждый поток — это сессия с порядковыми номерами (`sessionID + seq`).
* Клиент отправляет **каждый кадр сразу во все N туннелей**; на сервере
  первый пришедший экземпляр доставляется, дубликаты отбрасываются,
  а буфер переупорядочивания склеивает порядок.
* Если очередь одного туннеля переполнена — копия для него просто
  пропускается (она redundant); если туннель умер — его недописанные кадры
  автоматически переотправляются через выжившие. Кадр теряется, только если
  умерли **все** туннели; полная потеря всех туннелей > `both_dead_close_after`
  закрывает локальные соединения (Nekoray видит reset и ретраит).
* Здоровье каждого туннеля — приложение-level PING/PONG (5 с / 15 с), он же
  ловит «зависшую» очередь, которую не видит SSH keepalive. Мёртвый туннель
  переподнимается в фоне с backoff (1→30 с, jitter; при полном простоя всех
  туннелей cap 3 с). SSH keepalive (`keepalive_interval`, по умолчанию 15 с)
  — вторичный: роняет соединение только после 4 **транспортных** ошибок
  подряд (`0` = выкл.); отказ `keepalive@openssh.com` не считается.
* TCP: SOCKS5-рукопожатие с Nekoray terminated на dupc, payload идёт
  прозрачной трубой до go-socks5-proxy; half-close (FIN) пробрасывается.
* UDP: SOCKS5 UDP ASSOCIATE на dupc; датаграммы RFC1928 дублируются кадрами,
  на сервере уходят обычным UDP с IP сервера (минуя go-socks5-proxy) и
  возвращаются тем же путём.

## Важно: Nekoray TUN / system-proxy

Если Nekoray работает в режиме **TUN (весь трафик)** или system-proxy,
**обязательно исключите SSH-endpoint сервера** (`ssh.address` / host из
`ssh.addresses`, например `87.236.146.208`) из маршрутизации прокси
(direct-route / bypass / исключение из TUN).

Иначе получается петля:

```
ssh к серверу → TUN Nekoray → SOCKS5 dupc → SSH dial к серверу → TUN …
```

Симптомы: «рубится всё, даже по SSH не подключиться», массовые
`tunnel dial failed`. dupc ловит такой случай и пишет
`routing loop: tunnel endpoint reached via SOCKS5`.

## Сборка

Требуется Go ≥ 1.25. Зависимости: `golang.org/x/crypto`, `gopkg.in/yaml.v3`.

```bash
make build          # локальный бинарник ./dup
make test           # go test ./...
make race           # go test -race ./...
make dist           # dist/dup-windows-amd64.exe, dup-linux-amd64, dup-linux-arm64
```

В PowerShell без make:

```powershell
$env:CGO_ENABLED="0"
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o dist\dup-windows-amd64.exe .\cmd\dup
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o dist\dup-linux-amd64 .\cmd\dup
$env:GOOS="linux"; $env:GOARCH="arm64"
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o dist\dup-linux-arm64 .\cmd\dup
```

## Быстрый старт

### Сервер (Linux)

1. Поднимите go-socks5-proxy на `127.0.0.1:1080` (или другой адрес из
   `socks5_upstream`) и sshd.
2. Установите бинарник и конфиг:

```bash
./dup-linux-amd64 server -c server.yaml
```

Пример конфига — `configs/server.example.yaml`. Ключевые поля:

| Поле | Смысл |
|------|-------|
| `listen: "127.0.0.1:9000"` | куда sshd форвардит direct-tcpip (только loopback!) |
| `socks5_upstream` | локальный go-socks5-proxy для TCP |
| `ping_interval` / `ping_timeout` | детект зависших туннелей |

dupd принимает до 8 одновременных туннелей и не знает о числе туннелей
клиента — его настраивать не нужно.

systemd-юнит (простой):

```ini
[Unit]
Description=proxy-duplicator server
After=network.target

[Service]
ExecStart=/opt/dup/dup server -c /opt/dup/server.yaml
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

### Клиент (Windows/Linux)

```bash
dup client -c client.yaml      # Windows: dup.exe client -c client.yaml
```

Пример — `configs/client.example.yaml`. Ключевые поля:

| Поле | Смысл |
|------|-------|
| `tunnels: 2` | число параллельных туннелей (1, 2, 4, 8…); трафик ×N |
| `transport: ssh` | `ssh` или `plain` (plain — без SSH, для тестов/локальных цепочек) |
| `ssh.address` / `ssh.addresses` | один адрес либо список (туннель i → `addresses[i % len]`), удобно для нескольких IP одного сервера |
| `ssh.forward_port` | порт dupd на сервере (должен совпадать с его `listen`), по умолчанию 9000 |
| `ssh.host_key` | **закреплённый host key** (см. безопасность ниже) |
| `socks5_listen: "127.0.0.1:1080"` | сюда указываете SOCKS5-outbound в Nekoray |
| `both_dead_close_after` | сколько держать сессии при полном обрыве всех туннелей |

Порядок запуска не важен: dupc сам поднимает туннели с backoff.

### Проверка

```bash
# TCP (через dupc):
curl -x socks5h://127.0.0.1:1080 https://example.com

# UDP (для игр/VoIP используйте клиенты с SOCKS5 UDP ASSOCIATE,
# например настройки UDP в том же Nekoray/ядре)
```

Логи: `log.level: debug` в конфиге (или `--log-level debug`) — видно
`link up/down`, `seq gap skipped`, `requeued`, `replication stats`.

## Безопасность

* **Все локальные слушатели** (dupc socks5/udp-relay, dupd listen) привязаны к
  `127.0.0.1` — наружу торчит только sshd.
* **Закрепите host key** (`ssh.host_key`): строка из `ssh-keyscan <server>`.
  Без пина dupc принимает любой ключ (устойчивость к MITM, но риск
  подмены); с пином — чужой ключ отклоняется (тест `TestSSHWrongHostKey`).
* Аутентификация SSH: `password` и/или `key_file` (+ `key_passphrase`).
* Дублирование удваивает расход трафика (`tunnels: N` → ×N). Оба туннеля
  идут на **один** сервер → внешний IP и поведение egress не меняются
  (в отличие от балансировки между разными узлами).

## Ограничения

* `tunnels: 1` — режим без дублирования (просто стабильный туннель).
* Все туннели должны заканчиваться на одном dupd (дедупликация централизована);
  `ssh.addresses` даёт разнообразие маршрутов только если разные IP/порты —
  это тот же sshd.
* UDP-фрагментация (FRAG≠0) не поддерживается; датаграммы больше
  `limits.max_frame_payload` отбрасываются.
* Если кадр потерян сразу во **всех** туннелях, через `gap_skip_timeout` (3 с)
  сессия продолжает работу с пропуском (для TCP это фактически обрыв
  содержимого — приложение увидит ошибку; для UDP просто потеря датаграммы).

## Разработка

```
cmd/dup              — CLI (server|client|version)
internal/protocol    — кадровый формат (20-байтный заголовок "DPD1"), RFC1928-адреса
internal/transport   — Stream/SSH/plain, Replicator (fan-out, очереди, failover, PING)
internal/session     — таблица сессий, dedup/reorder, tombstones, idle-GC
internal/socks       — SOCKS5 на dupc и синтез рукопожатия к upstream на dupd
internal/relay       — TCP-релей (half-close, backpressure)
internal/client      — dupc: SOCKS5-листенер, UDP hub, туннель-менеджеры, janitor
internal/server      — dupd: приём туннелей, OPEN/UDP-сессии, pending-буфер
test/e2e             — сквозные тесты
```

Тесты не требуют sshd: режим `transport: plain` даёт ту же дупликацию по
обычному TCP, а SSH-слой покрывается in-process sshd (`test/e2e/sshd_test.go`).

```bash
go test -race ./...             # всё
DUP_E2E_VERBOSE=1 go test ./test/e2e/ -v   # с логами debug-уровня
```

Ключевые сценарии: целостность 10–20 MiB, kill одного туннеля посреди
передачи, kill половины из 4, полный обрыв и восстановление, UDP echo
(1–8192 B, burst, закрытие ассоциации), SSH + pinning + отказ по чужому
host key.
