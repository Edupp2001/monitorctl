// Command monitorctl runs an untrusted process in a kernel-enforced sandbox.
//
// monitorctl is a sandbox and containment tool, not an antivirus.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Edupp2001/monitorctl/internal/linux/ebpf"
	"github.com/spf13/cobra"

	"github.com/Edupp2001/monitorctl/internal/config"
	"github.com/Edupp2001/monitorctl/internal/linux/cgroup"
	"github.com/Edupp2001/monitorctl/internal/linux/supervisor"
	"github.com/Edupp2001/monitorctl/internal/logger"
	"github.com/Edupp2001/monitorctl/internal/policy"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "v0.0.0-dev"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == supervisor.InternalChildArg {
		supervisor.RunChild(os.Args[2:])
		return
	}
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the root cobra command.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "monitorctl",
		Short: "Run an untrusted process in a kernel-enforced sandbox",
		Long: `monitorctl is a sandbox and containment tool, not an antivirus.

It restricts a target process (and every descendant) to a whitelist of
directories, blocks network and memory-hardening violations in the kernel,
logs every violation and kills the process tree atomically via cgroup v2.`,
		Version:      version,
		SilenceUsage: true,
	}
	root.AddCommand(newRunCmd())
	return root
}

type runOptions struct {
	guard       string
	scope       string
	onViolation string
	onExit      string
	net         string
	netAllow    string
	netInbound  string
	mem         string
	dropPrivs   string
	whitelist   string
	logFile     string
}

func newRunCmd() *cobra.Command {
	o := runOptions{}
	cmd := &cobra.Command{
		Use:   "run --whitelist=PATH [flags] -- command [args...]",
		Short: "Start a sandboxed target process",
		Long: `Start a sandboxed target process.

Example:

    monitorctl run --whitelist=wl.toml -- /bin/ls -la`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRunOptions(&o); err != nil {
				return err
			}
			if len(args) == 0 {
				return errors.New("target command is required (use '--' before it)")
			}
			return run(cmd.Context(), &o, args)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.guard, "guard", "shield", "guard mode: warn|shield|airlock")
	f.StringVar(&o.scope, "scope", "all", "scope: all|exec|write (denies read/write/exec outside whitelist)")
	f.StringVar(&o.onViolation, "on-violation", "kill", "on violation: kill|block")
	f.StringVar(&o.onExit, "on-exit", "kill", "on monitorctl exit: kill|leave")
	f.StringVar(&o.net, "net", "allow", "network: allow|block|whitelist")
	f.StringVar(&o.netAllow, "net-allow", "", "comma-separated CIDR:PORT entries (for --net=whitelist)")
	f.StringVar(&o.netInbound, "net-inbound", "allow", "inbound network: allow|block")
	f.StringVar(&o.mem, "mem", "allow", "memory hardening: allow|warn|strict")
	f.StringVar(&o.dropPrivs, "drop-privs", "yes", "drop privileges: yes|no")
	f.StringVar(&o.whitelist, "whitelist", "", "path to whitelist TOML file (required)")
	f.StringVar(&o.logFile, "log-file", "", "path to log file (default: stdout)")

	return cmd
}

func validateRunOptions(o *runOptions) error {
	if err := validateEnum("guard", o.guard, "warn", "shield", "airlock"); err != nil {
		return err
	}
	if o.guard == "airlock" {
		return errors.New("--guard=airlock is not yet implemented; use warn or shield")
	}
	if err := validateEnum("scope", o.scope, "all", "exec", "write"); err != nil {
		return err
	}
	if err := validateEnum("on-violation", o.onViolation, "kill", "block"); err != nil {
		return err
	}
	if err := validateEnum("on-exit", o.onExit, "kill", "leave"); err != nil {
		return err
	}
	if err := validateEnum("net", o.net, "allow", "block", "whitelist"); err != nil {
		return err
	}
	if err := validateEnum("net-inbound", o.netInbound, "allow", "block"); err != nil {
		return err
	}
	if err := validateEnum("mem", o.mem, "allow", "warn", "strict"); err != nil {
		return err
	}
	if err := validateEnum("drop-privs", o.dropPrivs, "yes", "no"); err != nil {
		return err
	}
	if o.net == "whitelist" && o.netAllow == "" {
		return errors.New("--net=whitelist requires --net-allow=CIDR:PORT")
	}
	if o.net != "whitelist" && o.netAllow != "" {
		return fmt.Errorf("--net-allow is only valid with --net=whitelist (got --net=%s)", o.net)
	}
	if o.dropPrivs == "yes" && os.Geteuid() != 0 {
		return errors.New("--drop-privs=yes requires root; run as root or pass --drop-privs=no")
	}
	if o.whitelist == "" {
		return errors.New("--whitelist=PATH is required")
	}
	return nil
}

func validateEnum(flag, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("invalid --%s value %q: must be one of %s",
		flag, value, strings.Join(allowed, "|"))
}

func run(ctx context.Context, o *runOptions, target []string) error {
	log, closeLog, err := logger.New(o.logFile)
	if err != nil {
		return err
	}
	defer closeLog()

	cfg, err := config.Load(o.whitelist)
	if err != nil {
		return err
	}
	for _, w := range cfg.EnsurePaths() {
		log.Warn("whitelist", "detail", w)
	}
	for _, w := range cfg.ValidatePaths() {
		log.Warn("whitelist", "detail", w)
	}

	if o.guard == "warn" {
		log.Warn("guard=warn: no enforcement applied; --scope/--net/--mem have no effect")
	}

	if err := cgroup.OOMScoreAdj(-1000); err != nil {
		log.Warn("oom_score_adj=-1000 failed (need root/CAP_SYS_RESOURCE)", "error", err.Error())
	}

	grp, err := cgroup.Create()
	if err != nil {
		return fmt.Errorf("create cgroup: %w", err)
	}

	pwl := policy.Whitelist{
		AllowRead:  cfg.AllowRead,
		AllowWrite: cfg.AllowWrite,
		AllowAll:   cfg.AllowAll,
	}
	scope, err := policy.ParseScope(o.scope)
	if err != nil {
		_ = grp.Close(true)
		return err
	}

	var killTriggered atomic.Bool
	killHandler := func(reason string) {
		if killTriggered.CompareAndSwap(false, true) {
			log.Info("killing cgroup", "reason", reason)
			if err := grp.Kill(); err != nil {
				log.Warn("cgroup.kill", "error", err.Error())
			}
		}
	}

	onViolation := func(v ebpf.Violation) {
		lg := log.Warn
		if v.Action == "warn" {
			lg = log.Info
		}
		lg("violation",
			"scope", string(v.Scope),
			"category", v.Category,
			"action", v.Action,
			"syscall", v.Syscall,
			"access", v.AccessType,
			"path", v.Path,
			"pid", v.Pid,
			"tid", v.Tid,
			"comm", v.Comm,
			"rule", v.Rule)
		if v.Action == "kill" && o.onViolation == "kill" {
			killHandler("violation")
		}
	}

	loader, ebpfErr := ebpf.Load(&ebpf.Config{
		CgroupPath:  grp.Path,
		Scope:       scope,
		Whitelist:   pwl,
		Log:         log,
		OnViolation: onViolation,
		OnOverflow: func(dropped uint64) {
			log.Error("ringbuf overflow: fail-closed kill", "dropped", dropped)
			killHandler("overflow")
		},
	})
	if ebpfErr != nil {
		log.Warn("eBPF unavailable, continuing without observability", "error", ebpfErr.Error())
	} else {
		defer func() {
			if err := loader.Close(); err != nil {
				log.Warn("close eBPF loader", "error", err.Error())
			}
		}()
		if loader != nil {
			if err := loader.Warmup(500 * time.Millisecond); err != nil {
				log.Warn("eBPF warmup failed; observability may miss events", "error", err.Error())
			} else {
				log.Info("eBPF warmup OK (tracepoint active)")
			}
		}
	}

	log.Info("monitorctl starting",
		"version", version,
		"guard", o.guard,
		"scope", o.scope,
		"on_violation", o.onViolation,
		"on_exit", o.onExit,
		"cgroup", grp.Path,
		"ebpf", ebpfErr == nil,
		"target", target[0],
		"allow_read", len(pwl.AllowRead),
		"allow_write", len(pwl.AllowWrite),
		"allow_all", len(pwl.AllowAll))

	cmd, err := supervisor.Run(ctx, &supervisor.Config{
		Guard:      o.guard,
		Scope:      o.scope,
		Whitelist:  pwl,
		CgroupPath: grp.Path,
		OnCgroupReady: func(actualCgid uint64, pid uint32) error {
			if loader == nil {
				return nil
			}
			if actualCgid != loader.Cgid() {
				log.Warn("cgid mismatch", "stat_cgid", loader.Cgid(), "actual_cgid", actualCgid)
			}
			return loader.UpdateCgid(actualCgid, pid)
		},
	}, target)
	if err != nil {
		_ = grp.Kill()
		_ = grp.Close(true)
		return err
	}

	// Verify the child actually landed in the target cgroup. clone3(CLONE_INTO_CGROUP)
	// can silently fall back to plain clone() on older kernels or when Setpgid
	// interferes; the child then stays in monitorctl's cgroup and BPF's
	// target_cgroups lookup misses every event.
	procsPath := filepath.Join(grp.Path, "cgroup.procs")
	if data, err := os.ReadFile(procsPath); err == nil {
		procs := strings.TrimSpace(string(data))
		log.Info("target started", "pid", cmd.Process.Pid, "cgroup", grp.Path, "cgroup_procs", procs)
		if procs == "" {
			log.Warn("target NOT in target cgroup: eBPF filter will miss all events; " +
				"check kernel >= 5.7 and clone3(CLONE_INTO_CGROUP) support")
			// Fallback: explicitly move the child into the cgroup. There is a
			// small race window (child may have already done a few syscalls) but
			// it's better than losing all observability.
			if err := os.WriteFile(procsPath, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0o644); err != nil {
				log.Warn("fallback cgroup.procs write failed", "error", err.Error())
			} else {
				log.Info("fallback: moved child into target cgroup explicitly")
			}
		}
	} else {
		log.Info("target started", "pid", cmd.Process.Pid, "cgroup", grp.Path)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	var exitErr error
	select {
	case sig := <-sigCh:
		log.Info("received signal", "signal", sig.String())
		if o.onExit == "kill" {
			killHandler("signal")
			select {
			case exitErr = <-exitCh:
			case <-time.After(5 * time.Second):
				log.Warn("target did not exit within 5s after cgroup.kill")
			}
		}
	case exitErr = <-exitCh:
		if killTriggered.Load() {
			log.Info("target killed by monitorctl (violation)")
		} else {
			log.Info("target exited", "status", statusString(exitErr))
		}
		if loader != nil {
			loader.Drain(500 * time.Millisecond)
			if o.onViolation == "block" {
				seen := loader.DumpSeen()
				log.Info("eBPF seen (all tracepoint hits)", "count", len(seen))
				for pid, cgid := range seen {
					log.Info("seen", "pid", pid, "cgid", cgid)
				}
			}
			if st, err := loader.Stats(); err == nil {
				log.Info("eBPF stats",
					"emitted", st.EventsEmitted,
					"processed", loader.Processed(),
					"warnings_dropped", st.WarningsDropped,
					"violations_dropped", st.ViolationsDropped)
			} else {
				log.Warn("eBPF stats unavailable", "error", err.Error())
			}
		}
		if o.onExit == "kill" {
			killHandler("normal-exit")
		}
	}

	if o.onExit == "kill" {
		if err := grp.Close(true); err != nil {
			log.Warn("cgroup cleanup", "error", err.Error())
		}
	} else {
		if err := grp.Close(false); err != nil {
			log.Warn("cgroup left in place (--on-exit=leave)",
				"cgroup", grp.Path, "error", err.Error())
		}
	}

	return exitErr
}

func statusString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
