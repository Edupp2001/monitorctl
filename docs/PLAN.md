# monitorctl — Project Plan

## Зафиксированные решения

- **Язык:** Go (userspace), C (eBPF-программы). C++ и Rust **не используются**.
- **MVP-платформа:** Linux, kernel 6.3+ (рекомендуется 6.8+). Минимум — 5.15
  с деградацией (без `PR_SET_MDWE`).
- **Windows:** follow-up, архитектурно заложен, не в MVP.
- **Enforcement:** Landlock + seccomp + PR_SET_MDWE + eBPF cgroup-hooks (net).
- **Дерево процессов:** cgroup v2 + `cgroup.kill`, `pids.max=256`, `memory.max`.
- **Whitelist:** статический TOML, по `(dev, ino)`. Hard links разрешены,
  если inode в whitelist.
- **`exec` вне whitelist** = нарушение, режется.
- **Логи:** `slog` JSON, только violations + lifecycle, stdout по умолчанию,
  `--log-file` опционально.
- **GUI:** нет.
- **Контейнеры:** поддержка «из коробки» при правильном запуске.
- **Nesting monitorctl поверх monitorctl:** не поддерживается в MVP (документировать).
- **Windows-подпись:** `testsigning` + self-signed, open-source dev-режим.

## Timeline overview

| Фаза | Что | Дни | Итого |
|---|---|---|---|
| 0 | Скелет проекта | 0.5–1 | 1 |
| 1 | Landlock | 2–3 | 4 |
| 2 | cgroup + kill + limits | 1.5–2 | 6 |
| 3 | eBPF FS observability | 3–5 | 11 |
| 3.5 | Net + Mem + privs + hardening | 3–4 | 15 |
| 4 | Control API + reload + BPF pinning | 1–1.5 | 16 |
| 5 | Тесты + attack probes | 2–3 | 19 |
| 6 | Документация и релиз | 1 | 20 |

**MVP: ~3 недели** одного разработчика.

## Фаза 0. Скелет (0.5–1 день)

- `go mod init github.com/<user>/monitorctl`.
- Структура каталогов из ARCHITECTURE.md.
- `cmd/monitorctl/main.go` на cobra, все флаги из ARCHITECTURE.md.
  Валидация: `--guard=airlock` → ошибка «not yet implemented»;
  `--net=whitelist` без `--net-allow` → ошибка.
- `internal/config` — парсинг TOML, валидация, `stat()` всех путей.
- `internal/logger` — `slog` с `JSONHandler`.
- `Makefile`: `build`, `test`, `lint`, `build-bpf`.
- CI: `go build`, `go vet`, `golangci-lint`.

**Артефакт:** `monitorctl --help` работает, конфиг парсится, флаги валидируются.

## Фаза 1. Landlock (2–3 дня)

- `internal/linux/landlock`: обёртка `landlock_create_ruleset`,
  `landlock_add_rule`, `landlock_restrict_self` через `x/sys/unix`.
  Функция `RestrictToWhitelist(inodes []Inode, scope Scope) error`.
- `internal/policy`: `stat()` путей → `[]Inode{dev, ino}`. Проверка
  существования путей (warning при отсутствии).
- `internal/linux/supervisor`: fork/exec target с применением Landlock
  в ребёнке **до** `execve`. `prctl(PR_SET_NO_NEW_PRIVS, 1)` обязателен.
- Unit-тест Landlock (нужен root, скипать в `-short`): запись вне whitelist
  → `EPERM`.

**Артефакт:** `--guard=shield --scope=writes --whitelist=wl.toml -- ./target`
блокирует записи вне whitelist.

## Фаза 2. cgroup + kill + limits (1.5–2 дня)

- `internal/linux/cgroup`:
  - Создание `/sys/fs/cgroup/monitorctl/<uuid>/`.
  - Запись PID в `procs`.
  - **`pids.max = 256`**, **`memory.max = 1 GiB`** (configurable).
  - Kill через `cgroup.kill`.
  - Cleanup на SIGINT/SIGTERM.
- **`--on-exit=kill|leave`** (default `kill`): в `defer` + signal handler —
  `cgroup.kill` для target-cgroup.
- **`oom_score_adj = -1000`** на самом monitorctl, выставляется в начале `main`.
- **`setrlimit(NPROC/NOFILE/AS)`** на target в pre-exec.
- Тест: target форкает детей, при kill — все умирают (включая orphan).

**Артефакт:** корректное убийство дерева, ограничения работают.

## Фаза 3. eBPF FS observability (3–5 дней)

- `internal/linux/ebpf/bpf/fs.bpf.c`:
  - Трейспойнты `sys_enter_openat`, `sys_enter_openat2`, `sys_enter_open`,
    `sys_enter_unlinkat`, `sys_enter_renameat2`, `sys_enter_execve`.
  - Фильтр по `cgroup_id` через map `target_cgroups`.
  - Ringbuf: `(cgroup_id, pid, tgid, comm, syscall, dirfd, filename_ptr, flags)`.
- `scripts/build-bpf.sh`: `clang -target bpf -O2 -g -c` + `bpf2go generate`.
- `internal/linux/ebpf/reader.go`: goroutine-читалка ringbuf.
- `internal/policy/resolve.go`: резолв пути из `(pid, dirfd, filename_ptr)`:
  - **`pidfd_open` + `pidfd_getfd`** (fallback на `/proc/<pid>/fd/`).
  - Сравнение с inode-whitelist.
- Обработка: `O_WRONLY|O_RDWR|O_CREAT` → write-violation при `scope=writes`;
  `O_RDONLY` → read-warning (rate-limited).
- **Переполнение ringbuf**: `fail-closed` для violation-событий → `cgroup.kill`.

**Артефакт:** полный `--guard=shield --scope=writes` работает.

## Фаза 3.5. Net + Mem + privs + hardening (3–4 дня)

### Net

- `internal/linux/ebpf/bpf/net.bpf.c`:
  - `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`: `connect4`, `connect6`.
  - `BPF_PROG_TYPE_CGROUP_SOCK`: `sock_create`, `bind4`, `bind6`.
  - `BPF_PROG_TYPE_CGROUP_SKB`: `sendmsg4`, `sendmsg6`.
- Парсинг `--net-allow` (CIDR + port) в Go, загрузка в map.
- **`bpf_link_pin`** в `/sys/fs/bpf/monitorctl/<uuid>/` — links переживают
  смерть процесса. Cleanup при штатном завершении.

### Mem

- `internal/linux/ebpf/bpf/mem.bpf.c`: трейспойнты для `warn`-режима.
- `internal/linux/seccomp/seccomp.go`: сборка seccomp-фильтра на
  `ptrace, process_vm_readv, process_vm_writev, memfd_create, userfaultfd,
  perf_event_open, pidfd_getfd, keyctl, add_key, unshare(CLONE_NEWNS)`.
  `CLONE_NEWPID|CLONE_NEWNET` — разрешены.
- `internal/linux/prctl`: `PR_SET_MDWE` (детект kernel ≥ 6.3 через `uname`),
  `PR_SET_DUMPABLE=0`.

### Privs

- `internal/linux/privs`: `capset(0)`, `setresgid(nogroup)`, `setresuid(nobody)`,
  `PR_SET_NO_NEW_PRIVS`, `setrlimit`.

### Rate-limit

- Map `warn_rate` в `fs.bpf.c`: не более 100 warning-событий/сек на cgroup_id.
- Избыток — drop в BPF, без нагрузки на ringbuf.

### Тесты (см. Фаза 5.5)

**Артефакт:** работают `--net=block|whitelist`, `--mem=strict`, `--drop-privs=yes`.

## Фаза 4. Control API + reload + BPF pinning (1–1.5 дня)

- `internal/control`: unix-socket `/run/monitorctl.sock`.
  - `chmod 0600 root:root`.
  - **`SO_PEERCRED`** на accept — только UID 0. Иначе reject.
  - **Никаких TCP.**
  - Команды: `status`, `reload-whitelist`, `stop`.
- `status` — JSON: target PID, cgroup, uptime, счётчики events/violations/kills.
- `reload-whitelist`: проверка `mtime` + inode whitelist-файла против
  сохранённых при старте. Изменение — reject с warning. Применяется
  только к новым target'ам (Landlock не умеет менять ruleset на лету).
- `internal/control` также в defer: `cgroup.kill` (если `--on-exit=kill`) +
  cleanup bpffs.

## Фаза 5. Тесты (2–3 дня, параллельно с 1–4)

### Unit

- `internal/policy`: табличные тесты резолва путей (AT_FDCWD, dirfd, `..`,
  symlinks, `/proc/self/fd`, hard links).
- `internal/config`: парсинг и валидация TOML.
- `internal/linux/landlock` (root, `-short` skip): запись вне whitelist → `EPERM`.
- `internal/linux/cgroup`: create/kill/cleanup.
- `internal/linux/seccomp`: проверка, что `ptrace` даёт `EPERM`.

### Integration (`tests/probes/`)

Прогоняются через `run-all.sh` и `monitorctl run`. См. Фаза 5.5.

### Load

- `fio` / `fsstress` внутри target, замер overhead vs. baseline.
  Целевой бюджет: **<10% на FS-heavy**.

## Фаза 5.5. Attack probes (часть Фазы 5)

`tests/probes/` — набор **безопасных имитаций** техник MITRE ATT&CK.
Каждый probe печатает `PROBE=<name> EXPECT=<allow|block> RESULT=<allowed|blocked>`.

```
tests/probes/
├── run-all.sh
├── fs/
│   ├── write-outside.sh       # write вне whitelist → blocked
│   ├── write-inside.sh        # positive control → allowed
│   ├── read-outside.sh        # read /etc/passwd → allowed (scope=writes) / blocked (scope=all)
│   ├── symlink-escape.sh      # symlink из whitelist в /etc → blocked
│   ├── dirfd-dotdot.sh        # openat(dirfd, "../etc/passwd") → blocked
│   ├── proc-fd-self.sh        # чтение через /proc/self/fd → blocked в scope=all
│   ├── rename-outside.sh      # mv из /etc → blocked
│   ├── unlink-outside.sh      # rm /etc/* → blocked
│   └── exec-outside.sh        # exec /bin/ls вне whitelist → blocked
├── proc/
│   ├── fork-write.sh          # write из ребёнка → blocked (Landlock наследуется)
│   ├── orphan-write.sh        # parent exit, child write → blocked (cgroup)
│   └── daemonize-write.sh     # double-fork+setsid → blocked
├── net/
│   ├── connect-block.sh       # connect 192.0.2.1:443 → blocked errno=EPERM (--net=block)
│   ├── connect-whitelist.sh   # connect 127.0.0.1:9999 → allowed (--net=whitelist --net-allow=127.0.0.1:9999)
│   └── udp-sendto.sh          # sendto 192.0.2.1:53 → blocked
└── mem/
    ├── memfd-exec.py          # memfd_create + fexecve → blocked (--mem=strict)
    ├── ptrace-inject.c        # ptrace(ATTACH, child) → blocked
    ├── mprotect-rwx.c         # mmap RW → mprotect RWX → blocked (kernel ≥6.3)
    ├── process-vm-readv.c     # process_vm_readv(child) → blocked
    └── unshare-mount.c        # unshare(CLONE_NEWNS) → blocked (--mem=strict)
```

Требования к probes:
- Безопасны: не трогают реальные секреты (только `/etc/passwd` — публичный,
  `/etc/hostname` — read-only, TEST-NET-1 `192.0.2.1` — RFC 5737).
- Только **пытаются** сделать операцию, логируют результат.
- README: «запускать только внутри monitorctl, желательно в VM».

`run-all.sh` прогоняет через `monitorctl run --guard=shield --scope=writes
--mem=strict --net=block --whitelist=examples/wl-test.toml` и выдаёт PASS/FAIL.

`Makefile` собирает `.c` probes через `gcc -O2 -o ...`, готовит окружение.

CI: privileged-контейнер с kernel ≥ 6.3, все probes PASS.

## Фаза 6. Документация и релиз (1 день)

- `README.md`: установка, примеры, ограничения, troubleshooting,
  рекомендации по sysctl (`ptrace_scope=3`, `unprivileged_bpf_disabled=1`,
  `unprivileged_userns_clone=0`), systemd-юнит с `Restart=always`.
- `examples/`:
  - `wl-test.toml` — для probes.
  - `sandbox.toml` — типичный пресет «недоверенный файл из интернета».
- Дисклеймер в README:
  > `monitorctl is a sandbox and containment tool, not an antivirus.`
- Git tag `v0.1.0`.
- Статический бинарь (`CGO_ENABLED=0` — если bpf2go позволяет; иначе
  `.deb`/`.rpm` в roadmap).

## Risk matrix

| Риск | Митигация |
|---|---|
| kernel < 5.15 без Landlock | detect, фолбэк на `warn`, warning |
| kernel < 6.3 без `PR_SET_MDWE` | `--mem=strict` работает в seccomp-части, warning |
| ringbuf переполнение | фильтр по cgroup_id в BPF; `fail-closed` (kill) |
| target flood `openat O_RDONLY` | rate-limit в BPF (100/sec) |
| target fork-бомба | `pids.max=256`, `RLIMIT_NPROC` |
| target OOM | `memory.max` на target-cgroup, `oom_score_adj=-1000` на monitorctl |
| mount-namespace-трюки target'а | `--mem=strict` блокирует `unshare(CLONE_NEWNS)`; `pidfd_getfd` для резолва |
| kernel-exploit от `nobody` | `--drop-privs=yes`, `--mem=strict`, обновления ядра, sysctl |
| смерть monitorctl (kill -9) | `--on-exit=kill` по умолчанию, BPF pinning, systemd `Restart=always` |
| bpf2go требует clang | проверка в CI, инструкция в README |
| CGO для seccomp | минимальный cgo-шим, документировать |

## Post-MVP roadmap

1. `--guard=airlock` (seccomp-user-notif + libseccomp) — 1 неделя.
2. Windows backend (minifilter C/WDK + Go-сервис) — 3–4 месяца.
3. Динамический whitelist с перезапуском target.
4. Prometheus-метрики.
5. systemd unit, .deb/.rpm, AppImage.
6. Nesting monitorctl поверх monitorctl (cgroup v2 delegation).