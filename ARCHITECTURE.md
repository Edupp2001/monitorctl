# monitorctl — Architecture

`monitorctl` запускает недоверенный процесс в клетке с белым списком каталогов,
следит за всеми его потомками, блокирует нарушения в ядре, логирует их и
убивает дерево процессов. Это **инструмент сдерживания**, не антивирус: он
не распознаёт малварь, он не даёт ей выйти за пределы разрешённого.

Целевая платформа MVP: **Linux, kernel 6.3+** (рекомендуется Ubuntu 24.04 /
kernel 6.8+). Минимально жизнеспособная: kernel 5.15 LTS с деградацией
(без `PR_SET_MDWE`). Windows — follow-up.

## Purpose

- Ограничить запись в файловую систему белым списком каталогов.
- Опционально ограничить чтение (полный контроль FS).
- Опционально запретить сетевой доступ (исходящий / входящий / по IP-whitelist).
- Защитить от fileless-техник и эксплуатации в памяти
  (W^X, ptrace, process_vm_*, memfd_create, userfaultfd, perf_event_open).
- Понижать привилегии target'а до `nobody` (главная защита от kernel-exploit).
- Логировать нарушения (не всё подряд, только violations/warnings).
- Убивать дерево процессов атомарно (`cgroup.kill`).
- **Fail-safe**: смерть `monitorctl` не освобождает target из клетки.

## Threat model

### В защите (in scope)

- Commodity malware, ransomware, скрипты из интернета.
- Supply-chain post-install скрипты (`npm install`, `pip install`).
- Кража `~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg` — write/read (в `--scope=all`).
- Эксфильтрация через сеть (`--net=block`).
- Fileless exec через `memfd_create` + `fexecve` (`--mem=strict`).
- Инъекции через `ptrace`, `process_vm_readv/writev`, `/proc/pid/mem`
  (`--mem=strict` + `PR_SET_DUMPABLE=0`).
- RWX shellcode и JIT-spraying через `mmap`/`mprotect` (`PR_SET_MDWE`).
- Эксплуатация `userfaultfd`, `perf_event_open`, `io_uring` — частью seccomp,
  частью — kernel CVE mitigation через drop-privs.
- DoS target'а против monitorctl (flood syscalls, fork-бомба, OOM).

### Вне scope (out of scope, документировано)

- Kernel-exploit от `nobody`-target'а (сложнее на порядок, но возможен;
  митигации — `--drop-privs=yes`, `--mem=strict`, обновления ядра, sysctl
  `unprivileged_bpf_disabled=1`, `unprivileged_userns_clone=0`).
- JIT/ROP внутри легитимных движков (V8, JVM, .NET).
- Логические атаки внутри whitelist (шифрование в разрешённой папке).
- Обнаружение малвари — этого инструмент не делает в принципе.
- Защита процессов, не запущенных через `monitorctl`.

## Two layers: enforcement vs observability

- **Enforcement** (не дать сделать) — в ядре, детерминированно, 0 TOCTOU,
  низкий overhead. Linux: **Landlock LSM** + **seccomp** + **PR_SET_MDWE** +
  **eBPF cgroup hooks для сети**. Windows (roadmap): minifilter + ACG/CIG.
- **Observability** (увидеть и убить) — userspace по событиям из ядра.
  Linux: **eBPF tracepoints → ringbuf**. Windows (roadmap): FLT callbacks.

Enforcement и observability независимы:
- Landlock блокирует write → target получает `EACCES`. **Байт не записан** —
  это гарантия ядра, не зависит от userspace.
- eBPF видит `sys_enter_openat`, передаёт событие в userspace; userspace
  логирует и (в `on-violation=kill`) шлёт `cgroup.kill`.
- Даже если userspace залип — Landlock всё равно заблокирует.
- Даже если Landlock в `--guard=warn` не применён — eBPF залогирует.

## Guard modes (`--guard`)

| Guard | Enforcement | Observability | Блокирует | Логирует попытки | Overhead |
|---|---|---|---|---|---|
| `warn` | нет | eBPF | нет | да | ~1–5% |
| `shield` (default) | Landlock + seccomp + MDWE + eBPF-net | eBPF | да (EACCES) | да | ~2–8% |
| `airlock` | seccomp-user-notif + eBPF | eBPF | да | каждая попытка с путём | 10–100x |

`airlock` **не реализуется в MVP**. CLI возвращает ошибку `not yet implemented`.

## Scope (`--scope`)

- `writes` (default): write/delete/rename/exec вне whitelist → **violation**
  (block + kill). read вне whitelist → **warning** (лог, разрешено).
- `all`: read/write/delete/rename/exec вне whitelist → **violation**.

Landlock access rights:
- `writes`: `WRITE_FILE | REMOVE_FILE | REMOVE_DIR | MAKE_CHAR | MAKE_DIR |
  MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM | REFER | EXECUTE`.
  Не включает `READ_FILE`/`READ_DIR`.
- `all`: `writes | READ_FILE | READ_DIR`.

Полная маска на всех типах inode — kernel 5.19+. На 5.15 — небольшое
подмножество; документировать.

## On-violation (`--on-violation`)

- `kill` (default): `echo 1 > cgroup.kill` — атомарно убивает всё поддерево.
- `block`: только блокировка через Landlock, без kill.

## Network enforcement (`--net`)

Landlock сеть не покрывает надёжно (5.15 — совсем, 6.7+ — только TCP
bind/connect, без UDP и sendmsg). Enforcement — через **eBPF cgroup-hooks**:

- `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` (`connect4`, `connect6`) — исходящие TCP.
- `BPF_PROG_TYPE_CGROUP_SOCK` (`sock_create`, `bind4`, `bind6`) — создание
  сокетов и входящие.
- `BPF_PROG_TYPE_CGROUP_SKB` (`sendmsg4`, `sendmsg6`) — UDP.
- Трейспойнты `sys_enter_connect/sendto/sendmsg` — для логов.

| Флаг | Значение | Поведение |
|---|---|---|
| `--net=allow` (default) | без ограничений | BPF-программы не загружаются |
| `--net=block` | запрет наружу | `connect`/`sendto` → `-EACCES`, violation, kill |
| `--net=whitelist` | только из `--net-allow` | разрешены `(CIDR, port)` из списка |
| `--net-allow=CIDR:PORT,...` | для `whitelist` | IPv4/IPv6 CIDR + port |
| `--net-inbound=allow\|block` | default `allow` | слушать входящее |

**Whitelist только по IP/CIDR, не по доменам.** Резолв домена в userspace —
TOCTOU, CDN меняет IP. Документировать. Кто хочет «только github.com» — пусть
резолвит `getent hosts github.com` в скрипте перед запуском.

**BPF-link pinning обязателен**: `bpf_link_pin` в `/sys/fs/bpf/monitorctl/<uuid>/`.
Иначе после `kill -9 monitorctl` BPF-программы детачатся и сеть открывается.

## Memory hardening (`--mem`)

Landlock не видит `mmap`, `mprotect`, `memfd_create`, `ptrace`,
`process_vm_*`. Закрываем двумя механизмами.

### `--mem=allow` (default)

Ничего не делаем. Для доверенных бинарей.

### `--mem=warn`

BPF-трейспойнты на:
- `sys_enter_memfd_create`
- `sys_enter_ptrace`
- `sys_enter_process_vm_readv` / `sys_enter_process_vm_writev`
- `sys_enter_mprotect` (только если `PROT_WRITE|PROT_EXEC`)
- `sys_enter_mmap` (только если `PROT_EXEC`)
- `sys_enter_unshare` (только если `CLONE_NEWNS`)

Только логирование. Ожидаемый шум: `gdb`, JIT, некоторые языки — нормально.

### `--mem=strict`

1. **seccomp-фильтр** с `SECCOMP_RET_ERRNO(EACCES)` на:
   `ptrace`, `process_vm_readv`, `process_vm_writev`, `memfd_create`,
   `userfaultfd`, `perf_event_open`, `pidfd_getfd`, `keyctl`, `add_key`,
   `unshare(CLONE_NEWNS)`.
   `unshare(CLONE_NEWPID|CLONE_NEWNET)` — **разрешены** (контейнеры).
   Без user-notif, поэтому overhead ≈ 0.
2. **`prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_UGLY)`** (kernel 6.3+) — W^X
   в ядре. Если kernel < 6.3 — warning, только seccomp-часть.
3. **`prctl(PR_SET_DUMPABLE, 0)`** — запрет ptrace / `/proc/pid/mem` к target'у.

## Privilege drop (`--drop-privs`)

Default `yes`, если `monitorctl` запущен от root. В ребёнке перед `execve`:

- `capset(...)` — сброс всех capabilities кроме явно разрешённых (по умолчанию — 0).
- `setresgid(nogroup)` + `setresuid(nobody)`.
- `PR_SET_NO_NEW_PRIVS` (обязателен для Landlock).
- `setrlimit(RLIMIT_NPROC, 256)`, `setrlimit(RLIMIT_NOFILE, 1024)`,
  `setrlimit(RLIMIT_AS, ...)` — защита от fork-бомбы и OOM.
- `prctl(PR_SET_DUMPABLE, 0)` если `--mem=strict`.

**Это главная защита от kernel-exploit'ов** (`io_uring`, `nf_tables`, eBPF CVE).
Эксплойт без root сильно сложнее. Документировать.

## Process tree & kill: cgroup v2

При старте target создаётся `/sys/fs/cgroup/monitorctl/<uuid>/`,
PID target пишется в `cgroup.procs`. Все потомки автоматически попадают
в ту же cgroup по иерархии. Убийство — `echo 1 > cgroup.kill` —
атомарно покрывает всё поддерево, включая orphan-процессы.

- Никаких `PTRACE`, `wait4`, ручного трекинга fork/exec.
- **`pids.max = 256`** на target-cgroup — fork-бомба не проходит.
- **`memory.max`** — configurable, default 1 GiB — OOM-killer выбирает target.
- Cleanup на SIGINT/SIGTERM.

## Path resolution strategy

eBPF резолвит путь в userspace для логирования:
- `(pid, dirfd, filename_ptr)` → `/proc/<pid>/root`, `/proc/<pid>/fd/<dirfd>`,
  `/proc/<pid>/cwd` → реальный путь → сравнение с inode-whitelist.

**Известная уязвимость**: mount-namespace-трюки target'а (`unshare(CLONE_NEWNS)`
+ bind mount) могут обмануть userspace-резолвер. Landlock это **не** обманывает
(блокирует по реальному inode), но мы **молча теряем нарушение** (не логируем,
не убиваем) — fail-open для logs, fail-closed для enforcement.

**Митигации:**
1. **`pidfd_open` + `pidfd_getfd`** для резолва (kernel 5.6+, требует
   `CAP_SYS_PTRACE` на monitorctl). Атомарно, не даёт target'у подменить
   fd между чтениями. Fallback на `/proc/<pid>/fd/` если syscall недоступен.
2. **`--mem=strict`** блокирует `unshare(CLONE_NEWNS)` через seccomp —
   target не может создавать свой mount namespace.
3. Для критичных решений — трейспойнт `sys_exit_openat` и чтение
   `/proc/<pid>/fd/<fd>` по возвращённому fd.

**Hard links** (ваш п.10): если inode в whitelist — все hardlink-пути
разрешены. Совпадает с семантикой Landlock по `(dev, ino)`.

## Fail-safe: смерть monitorctl

Если `monitorctl` убит (OOM, `kill -9`, паника), что остаётся:

| Механизм | Persists | Notes |
|---|---|---|
| Landlock ruleset | ✅ навсегда | Irreversible, per-process |
| seccomp filter | ✅ | Per-process |
| `PR_SET_MDWE` | ✅ | Per-process |
| `--drop-privs` (uid/caps) | ✅ | Irreversible |
| Network eBPF | ⚠️ **только если запинен** | `bpf_link_pin` обязателен |
| cgroup target | ✅ | Пока процесс в ней |
| `cgroup.kill`-триггер | ❌ | Триггер умер вместе с monitorctl |
| Логи | ❌ | Очевидно |

**Стратегия:**
- **Enforcement:** fail-closed. Target остаётся заперт по FS/mem всегда.
- **Kill:** fail-closed через `cgroup.kill` при выходе monitorctl.
  `--on-exit=kill|leave` (default `kill`). В `defer` и обработчиках сигналов —
  `echo 1 > cgroup.kill`.
- **Network BPF:** `bpf_link_pin` в bpffs — переживает смерть процесса.
  Cleanup при штатном завершении.
- **Restart:** systemd `Restart=always`, `RestartSec=1s` (рекомендация в README).
- **OOM protection:** `oom_score_adj = -1000` на monitorctl в начале `main`.

**Итог:** после смерти monitorctl target либо мёртв (`--on-exit=kill`),
либо остаётся заперт по FS/mem/net без логирования и kill-триггера
(`--on-exit=leave`). **Escape невозможен в обоих случаях.**

## Hardening против атак target'а на monitorctl

Target работает от `nobody`, monitorctl — от root. Прямые атаки (kill, ptrace,
`/proc/pid/mem`) заблокированы ядром (UID separation, Yama `ptrace_scope=1`,
`PR_SET_DUMPABLE=0`). Косвенные атаки и защиты:

### DoS через flood syscalls

- **Rate-limit в BPF** для `openat O_RDONLY` (warning-события) — map
  `warn_rate`: не более 100 событий/сек на cgroup_id. Избыток — drop в BPF.
- **`pids.max = 256`** на target-cgroup — fork-бомба не проходит.
- **`memory.max`** на target-cgroup — OOM-killer выбирает target, не monitorctl.
- **`oom_score_adj = -1000`** на monitorctl — ядро убивает кого угодно, кроме
  монитора.
- **`RLIMIT_NPROC/NOFILE/AS`** через `setrlimit` в pre-exec.
- **Переполнение ringbuf**: политика `fail-closed` — при переполнении
  violation-событий `cgroup.kill`. Flood = самоубийство target'а.

### Poison path resolution

См. раздел **Path resolution strategy**.

### Control-сокет

- Unix-сокет `/run/monitorctl.sock`, `chmod 0600 root:root`.
- **`SO_PEERCRED`** на accept — только UID 0. Иначе reject.
- **Никаких TCP-портов** в MVP.

### Whitelist-файл

- Читается **до** fork+exec, после fd закрыт.
- При `reload`: проверка `stat(wl.toml).Mtime` + inode против сохранённых
  при старте. Изменение — reject с warning (TOCTOU-защита).
- Файл принадлежит `root:root`, права `0644`.

### Kernel-exploit

Не решается в userspace. Митигации: `--drop-privs=yes` (по умолчанию),
`--mem=strict` (io_uring, userfaultfd, perf_event_open в seccomp),
обновление ядра, sysctl `kernel.unprivileged_bpf_disabled=1`,
`kernel.unprivileged_userns_clone=0`. Документировать в README.

## Container support

Работает «из коробки» при запуске:
- **Изнутри контейнера** (если в нём есть `CAP_BPF`, `CAP_SYS_ADMIN`,
  `CAP_SYS_PTRACE`) — рекомендуется.
- **С хоста** с `--pid=host --cgroupns=host` — поддерживается.

Фильтр в BPF по `cgroup_id` не требует изменений. Landlock per-process,
независимо от namespace.

## Known limitations

- `--guard=warn` не видит `io_uring` (нет syscall на open) и `mmap`.
  Для enforcement — `shield`.
- `--mem=strict` требует kernel 6.3+ для `PR_SET_MDWE`. Ниже — только seccomp.
- Landlock полный набор прав — kernel 5.19+. На 5.15 — subset.
- `airlock` — roadmap. Требует libseccomp + cgo.
- Whitelist `--net-allow` только по IP/CIDR, не по доменам (TOCTOU).
- Mount-namespace-трюки target'а могут обмануть logging-резолвер (`--mem=strict`
  блокирует `CLONE_NEWNS`).
- JIT/ROP внутри легитимных движков — не покрывается.
- Kernel-exploit от `nobody` — только drop-privs + обновления.
- Windows — follow-up.

## Diagram

```
    monitorctl (Go, root, отдельная cgroup monitorctl-daemon/, oom_score_adj=-1000)
    │
    ├─ 1. читает whitelist.toml → []Inode{dev,ino} (stat)
    ├─ 2. создаёт cgroup /monitorctl/<uuid>/  (pids.max, memory.max)
    ├─ 3. загружает eBPF, пишет cgroup_id в map, пиннит links в bpffs
    ├─ 4. fork
    │     └─ в ребёнке (до execve):
    │         - capset(0), setresuid(nobody), PR_SET_NO_NEW_PRIVS  [--drop-privs]
    │         - setrlimit(NPROC/NOFILE/AS)
    │         - seccomp_install(mem_strict)                        [--mem=strict]
    │         - prctl(PR_SET_MDWE), prctl(PR_SET_DUMPABLE,0)       [--mem=strict]
    │         - landlock_restrict_self(ruleset)                    [--guard=shield]
    │         - execve(target)
    ├─ 5. кладёт PID ребёнка в cgroup.procs
    │
    ├─ goroutine A: ringbuf reader
    │     └─ violation → slog.JSON + cgroup.kill (если on-violation=kill)
    │
    ├─ goroutine B: unix-socket /run/monitorctl.sock (0600, SO_PEERCRED=root)
    │     └─ status / reload-whitelist / stop
    │
    └─ defer + signal handler:
          └─ cgroup.kill (если --on-exit=kill) + cleanup bpffs
```

## Repository structure

```
monitorctl/
├── go.mod
├── Makefile
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   └── PLAN.md
├── cmd/monitorctl/main.go
├── internal/
│   ├── config/          # TOML, валидация
│   ├── policy/          # whitelist, inode, resolve paths
│   ├── logger/          # slog JSON
│   ├── cli/             # cobra
│   ├── control/         # unix-socket, SO_PEERCRED
│   └── linux/
│       ├── cgroup/      # create/kill, pids.max, memory.max
│       ├── landlock/    # ruleset, restrict_self
│       ├── seccomp/     # mem-strict filter
│       ├── prctl/       # MDWE, DUMPABLE, NO_NEW_PRIVS
│       ├── privs/       # capset, setresuid
│       ├── ebpf/        # load, pin, ringbuf reader
│       │   └── bpf/
│       │       ├── fs.bpf.c      # openat/openat2/unlinkat/renameat2/execve
│       │       ├── net.bpf.c     # connect4/6, sendmsg4/6, sock_create, bind4/6
│       │       ├── mem.bpf.c     # memfd/ptrace/mmap/mprotect/unshare (warn)
│       │       └── *.o           # embedded
│       └── supervisor/  # fork/exec, pre-exec pipeline
├── tests/
│   ├── unit/
│   └── probes/          # attack simulation (см. PLAN.md Фаза 5.5)
├── examples/
│   ├── wl-test.toml
│   └── sandbox.toml
└── scripts/
    └── build-bpf.sh
```

## Go dependencies

- `github.com/cilium/ebpf` — загрузка BPF, ringbuf, pinning.
- `golang.org/x/sys/unix` — syscalls (Landlock, seccomp, prctl).
- `github.com/BurntSushi/toml`
- `github.com/spf13/cobra`
- `log/slog` (std)

BPF-программы — **C**, компилируются `clang -target bpf`, встраиваются через
`//go:embed` или `bpf2go`. C++ не используется.

## Config format (`whitelist.toml`)

```toml
# Пути, которые target может читать и писать.
allow = [
  "/tmp/workdir",
  "/var/lib/myapp/data",
]

# Пути, которые можно только читать (при --scope=writes:
# write в них → violation; при --scope=all — как allow).
allow_read = [
  "/usr/share/myapp",
  "/etc/myapp.conf",
]
```

Все пути `stat()`-ятся при старте. Несуществующие пути — warning, не fatal
(target может создать каталог сам).

## Log format (slog JSON, только violations и lifecycle)

```json
{
  "time": "2025-10-23T12:00:00Z",
  "level": "WARN",
  "msg": "violation",
  "guard": "shield",
  "scope": "writes",
  "category": "fs",
  "action": "kill",
  "syscall": "openat",
  "path": "/etc/passwd",
  "ino": 12345,
  "dev": 64769,
  "pid": 12345,
  "tgid": 12345,
  "comm": "evil.sh",
  "cgroup": "/monitorctl/abc-123",
  "rule": "outside_whitelist"
}
```

`category` ∈ `fs | net | mem | proc`. `action` ∈ `warn | block | kill`.

## Flags summary

```
--guard=warn|shield|airlock            default: shield      (airlock not in MVP)
--scope=writes|all                     default: writes
--on-violation=kill|block              default: kill
--on-exit=kill|leave                   default: kill

--net=allow|block|whitelist            default: allow
--net-allow=CIDR:PORT,...              (для whitelist)
--net-inbound=allow|block              default: allow

--mem=allow|warn|strict                default: allow
--drop-privs=yes|no                    default: yes (если root)

--whitelist=PATH                       required
--log-file=PATH                        default: stdout (JSON slog)
```

## Roadmap (post-MVP)

1. `--guard=airlock` — seccomp-user-notif + libseccomp, ~1 неделя.
2. Windows backend: minifilter (C/WDK) + Go-сервис, `testsigning`,
   EV-подпись — для продакшена, ~3–4 месяца.
3. Динамический whitelist — Landlock не умеет, нужен перезапуск target.
4. Prometheus-метрики.
5. systemd unit, .deb/.rpm.