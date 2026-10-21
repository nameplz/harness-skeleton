// SPDX-License-Identifier: GPL-2.0-only
// Numeric qualification observer. UID filtering alone is not actor attribution.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct lifecycle_event {
    __u64 sequence, timestamp_ns, cgroup_id, current_cgroup_id, start_ns, related_start_ns;
    __u32 kind, tid, tgid, related_tid, related_tgid, old_tid, cpu, reserved;
};

_Static_assert(sizeof(struct lifecycle_event) == 80, "lifecycle wire ABI");

struct lifecycle_counts { __u64 attempted, emitted, dropped; };

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lifecycle_counts);
} counters SEC(".maps");

static __always_inline int emit(__u32 kind, struct task_struct *task,
                                struct task_struct *related, __u32 old_tid)
{
    if ((__u32)bpf_get_current_uid_gid() != 2000)
        return 0;
    __u32 zero = 0;
    struct lifecycle_counts *counts = bpf_map_lookup_elem(&counters, &zero);
    if (!counts)
        return 0;
    __u64 sequence = __sync_fetch_and_add(&counts->attempted, 1) + 1;
    struct lifecycle_event *event = NULL;
    if (sequence <= 131072)
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        __sync_fetch_and_add(&counts->dropped, 1);
        return 0;
    }
    *event = (struct lifecycle_event){0};
    event->sequence = sequence;
    event->timestamp_ns = bpf_ktime_get_boot_ns();
    event->cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
    event->current_cgroup_id = bpf_get_current_cgroup_id();
    event->start_ns = BPF_CORE_READ(task, start_boottime);
    event->kind = kind;
    event->tid = BPF_CORE_READ(task, pid);
    event->tgid = BPF_CORE_READ(task, tgid);
    event->old_tid = old_tid;
    event->cpu = bpf_get_smp_processor_id();
    if (related) {
        event->related_start_ns = BPF_CORE_READ(related, start_boottime);
        event->related_tid = BPF_CORE_READ(related, pid);
        event->related_tgid = BPF_CORE_READ(related, tgid);
    }
    bpf_ringbuf_submit(event, 0);
    __sync_fetch_and_add(&counts->emitted, 1);
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(observe_fork, struct task_struct *parent, struct task_struct *child)
{
    return emit(1, child, parent, 0);
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(observe_exec, struct task_struct *task, int old_pid, struct linux_binprm *bprm)
{
    return emit(2, task, NULL, old_pid);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(observe_exit, struct task_struct *task)
{
    return emit(3, task, NULL, 0);
}

char LICENSE[] SEC("license") = "GPL";
