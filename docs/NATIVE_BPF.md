# Native BPF lifecycle and exact audit-key contracts

The supervised Linux session uses numeric fork/exec/exit observations and exact audit-key bindings. This is
process attribution and event correlation; it does not prove FD/path/network semantics or produce an
action-audit receipt. Production action-audit/whole-tree flags remain false and
readiness remains unknown. See [evaluation gates](AGENT_EVALUATION.md).

## Qualified installation

`native_bpf_object.py` accepts only Linux ARM64 kernel `6.8.0-147-generic`, the
qualified running BTF, the frozen C source, and a prebuilt object:

| Artifact | Path | SHA-256 |
|---|---|---|
| Object | `/opt/harness-native/bpf/lifecycle-audit-6.8.0-147.o` | `4250238f7bf0a40c4e9655a68532a95465d04e1ec4adbefb9aa0d8705deddd85` |
| BTF | `/sys/kernel/btf/vmlinux` | `ff35ff5afb91dfb3a1cb6db29a417a39f4f598c9ebfba75186592d4a58a1d277` |
| libbpf 1.3.0 | `/usr/lib/aarch64-linux-gnu/libbpf.so.1.3.0` | `bbd39c9b5a29fd87a828a66ec097e25301dfb5af2694788a4de385570b22e1bc` |

The object and source are bounded regular single-link files under root-controlled
directories. Reads reject symlinks, writable ancestry, changed metadata or hashes.
Runtime does not compile or download code. `bpf_object__open_mem()` uses the bytes
that passed verification. The two audit-library slots and one exact libbpf slot
retain their descriptors to avoid dlopen pathname aliases.

Exactly four `observe_fork/exec/exit/audit` programs and two maps are accepted: a16MiB
ring and a one-element counter array with4byte keys/24byte values. The actual
`tp_btf` hooks have TRACING programs and RAW_TRACEPOINT links on this kernel;
`fexit/audit_log_start` has a TRACING program and TRACING link.
Object type/ID reads precede release of owned descriptors; failed identity reads
keep the object for recovery. A kernel/BTF/object change requires qualification
and new pins rather than silently accepting a compatible-looking installation.

## Admission and task instances

Audit obtains the actor lock before BPF attaches; BPF attaches before guardian
startup. Admission waits drain both streams. `kernel_cgroup_ids()` reads full
kernfs handles for the validated parent and actor leaf under one bound invocation;
inode numbers are not substitutes.

Before G, `GenerationLedger` requires the bound guardian exec and its actor fork
in the parent cgroup. Binding converts nanosecond start times to the measured
`SC_CLK_TCK` values. The trusted launcher may move from parent to leaf before G;
the initial actor exec anchors candidate execution in that leaf. Audit bindings
verify the initial handoff never reverses. After that, descendants must have a live known parent, matching generation and thread
group, and the same actor leaf. Unknown transitions fail the observation.

The ledger retains at most4096 task instances, active identities and retired
history. Instances use local tokens. Linux `de_thread()` may retire the leader,
absorb a surviving thread and copy the leader PID/start_boottime into its exec.
Only an explicit exec old-TID relation to that live thread and retired group
leader permits this alias. Generic resurrection and a later old-thread exit are
rejected. A leader exit alone does not imply group death. All observed tasks and
the guardian must end; cgroup emptiness is checked separately by the supervisor.

Atomic sequence numbers can differ from reservation order across CPUs. Transport
checks the complete sequence set and attempted/emitted/dropped counters. Task
attribution uses delivery order and per-task time, without sorting global times.
Cancellation still validates in-flight forks/execs while draining teardown, but
aborted finalization never produces an accepted observation.

## Exact audit-key correlation

The same ring and counter sequence carry80byte lifecycle and104byte audit binding
records. The pinned Ubuntu BTF uses `audit_buffer.stamp`, not the upstream v6.8
`audit_context.serial/ctime` layout. The fexit hook reads the returned buffer's
seconds/milliseconds/serial, validates the buffer/context relation and syscall
stamp agreement, and emits only numeric task identity and syscall outcome fields.
Null return, invalid stamp/context, unsupported ABI or loss fails observation.
SECCOMP emits exact task/key identity without inventing syscall result fields.

Before G, at most4096 numeric prefix records belong to the validated guardian and
launcher. Lifecycle anchors are checked before resolving that trusted prefix.
Later audit bindings resolve the active TID/TGID/start/cgroup token immediately
at BPF delivery, so delayed audit netlink delivery cannot revive a retired TID.
The bounded join accepts either transport order using exact AuditKey/type, checks
syscall identity and available outcome, and rejects duplicates, role mismatches
or missing counterparts. The root observer's own CONFIG_CHANGE syscall is
metadata, checked against its PID and root identity; it is not an actor action.

Final join evidence follows final audit decoding and process cleanup. Its numeric
digest describes this run's join completion order, not a reproducible ordering
across runs. The capture's independent event HMAC binds decoded fields; protected
receipts must bind both projections to the same execution. Joined PATH/SOCKADDR
values remain ephemeral and must not be retained or logged by future action
consumers. Exact-key correlation alone does not prove FD/path/socket semantics.

## Selector and recovery ownership

The single owner thread drains the ring through the fixed BPF selector token.
Each active drain consumes at most64 records so audit netlink can catch up with
BPF bindings. Withheld admission drains every bounded prefix batch before
resolving lifecycle anchors. Complete admission/final BPF drains pump a bounded
audit batch between BPF batches as well. libbpf1.3 updates its consumer position before a negative callback
return; only the internally marked quota EAGAIN is treated as a yield. An
unmarked EAGAIN or any latched callback error still fails. After detach, final
drain consumes every remaining batch before checking stable counters.
BPF and audit events do not count toward stdout/stderr budgets or keep the RPC
transport open after EOF. Callback exceptions are latched inside the C boundary;
subsequent records drain without converting the failed stream to success.

Cleanup stops actor tasks and guardian first, detaches BPF links, drains final
counters/records, unregisters the BPF descriptor, then frees the ring/object.
Owned program/link/map IDs must disappear within a bounded wait; only ENOENT
proves absence. libbpf frees a link pointer even on destroy error, so recovery
rechecks retained numeric IDs and never retries a freed pointer. Partial startup
does not finalize a ring that was never successfully installed.

If BPF ownership remains unproven, audit keeps its original flock/listener/rule
for recovery. After BPF closes, audit restoration and process resource cleanup
are attempted even when observation parsing failed. The original errors and
in-memory `audit_recovery` owner survive; recovery cannot accept a failed trial.

Primary ABI references: [libbpf1.3 declarations](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.h),
[link destruction](https://github.com/libbpf/libbpf/blob/v1.3.0/src/libbpf.c),
[Linux de_thread](https://github.com/torvalds/linux/blob/v6.8/fs/exec.c),
[ring ordering](https://docs.kernel.org/bpf/ringbuf.html).
