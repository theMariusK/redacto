//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATTERN_LEN 16
#define MAX_PATTERNS    8
#define BUF_SIZE        4096
#define BUF_MASK        (BUF_SIZE - 1)

struct pattern_entry {
	char original[MAX_PATTERN_LEN];
	char replacement[MAX_PATTERN_LEN];
	__u32 len;
	__u32 active;
};

struct read_info {
	__u64 buf_ptr;
	__u64 count;
	__s64 fd;
};

struct scratch_data {
	char data[BUF_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} target_pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PATTERNS);
	__type(key, __u32);
	__type(value, struct pattern_entry);
} patterns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} pattern_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct read_info);
} active_reads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch_data);
} scratch_buf SEC(".maps");

static __always_inline int is_target(void)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&target_pid_map, &pid) != NULL;
}

/* Context for byte-comparison callback */
struct cmp_ctx {
	__u32 pos;       /* base position in scratch */
	__u32 pat_idx;
	__u32 byte_idx;  /* which byte we're comparing */
	__u32 mismatch;  /* set to 1 on first mismatch */
	__u32 direction; /* 0=compare original, 1=compare replacement */
};

static int cmp_callback(__u32 idx, struct cmp_ctx *ctx)
{
	if (ctx->mismatch)
		return 1; /* already failed, stop */

	__u32 zero = 0;
	__u32 j = ctx->byte_idx;
	ctx->byte_idx = j + 1;

	struct scratch_data *scratch = bpf_map_lookup_elem(&scratch_buf, &zero);
	if (!scratch)
		return 1;

	struct pattern_entry *pat = bpf_map_lookup_elem(&patterns, &ctx->pat_idx);
	if (!pat)
		return 1;

	char expected;
	if (ctx->direction == 0)
		expected = pat->original[j & (MAX_PATTERN_LEN - 1)];
	else
		expected = pat->replacement[j & (MAX_PATTERN_LEN - 1)];

	if (scratch->data[(ctx->pos + j) & BUF_MASK] != expected)
		ctx->mismatch = 1;

	return 0;
}

/* Context for byte-write callback */
struct write_ctx {
	__u64 buf_ptr;
	__u32 pos;
	__u32 pat_idx;
	__u32 byte_idx;
	__u32 direction; /* 0=write replacement, 1=write original */
};

static int write_callback(__u32 idx, struct write_ctx *ctx)
{
	__u32 zero = 0;
	__u32 j = ctx->byte_idx;
	ctx->byte_idx = j + 1;

	struct scratch_data *scratch = bpf_map_lookup_elem(&scratch_buf, &zero);
	if (!scratch)
		return 1;

	struct pattern_entry *pat = bpf_map_lookup_elem(&patterns, &ctx->pat_idx);
	if (!pat)
		return 1;

	char c;
	if (ctx->direction == 0)
		c = pat->replacement[j & (MAX_PATTERN_LEN - 1)];
	else
		c = pat->original[j & (MAX_PATTERN_LEN - 1)];

	/* Write one byte to userspace */
	bpf_probe_write_user((void *)(ctx->buf_ptr + (__u64)(ctx->pos + j)),
			     &c, 1);

	/* Update scratch */
	scratch->data[(ctx->pos + j) & BUF_MASK] = c;

	return 0;
}

/* Context for outer scan loop */
struct scan_ctx {
	__u64 buf_ptr;
	__u32 data_len;
	__u32 pat_idx;
	__u32 pos;
	__u32 direction; /* 0=redact, 1=rehydrate */
};

static int scan_callback(__u32 idx, struct scan_ctx *ctx)
{
	__u32 zero = 0;
	__u32 pos = ctx->pos;
	ctx->pos = pos + 1;

	struct pattern_entry *pat = bpf_map_lookup_elem(&patterns, &ctx->pat_idx);
	if (!pat || !pat->active)
		return 1;

	__u32 pat_len = pat->len;
	if (pat_len == 0 || pat_len > MAX_PATTERN_LEN)
		return 1;

	if (pos + pat_len > ctx->data_len)
		return 1;

	/* Compare pat_len bytes using bpf_loop */
	struct cmp_ctx cctx = {
		.pos       = pos,
		.pat_idx   = ctx->pat_idx,
		.byte_idx  = 0,
		.mismatch  = 0,
		.direction = ctx->direction, /* 0=check original, 1=check replacement */
	};
	bpf_loop(pat_len, cmp_callback, &cctx, 0);

	if (cctx.mismatch)
		return 0; /* no match, continue scanning */

	/* Match found — write pat_len bytes */
	struct write_ctx wctx = {
		.buf_ptr   = ctx->buf_ptr,
		.pos       = pos,
		.pat_idx   = ctx->pat_idx,
		.byte_idx  = 0,
		.direction = ctx->direction, /* 0=write replacement, 1=write original */
	};
	bpf_loop(pat_len, write_callback, &wctx, 0);

	/* Skip past match */
	ctx->pos = pos + pat_len;
	return 0;
}

static __noinline int do_scan_and_replace(__u64 buf_ptr, __u64 count,
					  int direction)
{
	__u32 zero = 0;

	struct scratch_data *scratch = bpf_map_lookup_elem(&scratch_buf, &zero);
	if (!scratch)
		return 0;

	__u32 *cnt = bpf_map_lookup_elem(&pattern_count, &zero);
	if (!cnt)
		return 0;

	__u32 num_patterns = *cnt;
	if (num_patterns > MAX_PATTERNS)
		num_patterns = MAX_PATTERNS;

	__u32 data_len = count;
	if (data_len > BUF_SIZE)
		data_len = BUF_SIZE;
	if (data_len == 0)
		return 0;

	long ret = bpf_probe_read_user(scratch->data, data_len, (void *)buf_ptr);
	if (ret < 0)
		return 0;

	for (__u32 i = 0; i < MAX_PATTERNS; i++) {
		if (i >= num_patterns)
			break;

		struct scan_ctx ctx = {
			.buf_ptr   = buf_ptr,
			.data_len  = data_len,
			.pat_idx   = i,
			.pos       = 0,
			.direction = direction,
		};

		bpf_loop(data_len, scan_callback, &ctx, 0);
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	if (!is_target())
		return 0;

	__u64 tid = bpf_get_current_pid_tgid();
	struct read_info info = {
		.buf_ptr = ctx->args[1],
		.count   = ctx->args[2],
		.fd      = ctx->args[0],
	};
	bpf_map_update_elem(&active_reads, &tid, &info, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct read_info *info = bpf_map_lookup_elem(&active_reads, &tid);
	if (!info)
		return 0;

	__s64 ret = ctx->ret;
	__u64 buf_ptr = info->buf_ptr;
	bpf_map_delete_elem(&active_reads, &tid);

	if (ret <= 0)
		return 0;

	do_scan_and_replace(buf_ptr, (__u64)ret, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	if (!is_target())
		return 0;

	__s64 fd = ctx->args[0];
	if (fd <= 2)
		return 0;

	do_scan_and_replace(ctx->args[1], ctx->args[2], 1);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 parent_pid = BPF_CORE_READ(parent, tgid);
	if (!bpf_map_lookup_elem(&target_pid_map, &parent_pid))
		return 0;

	__u32 child_pid = BPF_CORE_READ(child, tgid);
	__u8 val = 1;
	bpf_map_update_elem(&target_pid_map, &child_pid, &val, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *task)
{
	__u32 pid = BPF_CORE_READ(task, tgid);
	bpf_map_delete_elem(&target_pid_map, &pid);
	return 0;
}

struct pattern_entry *unused_pattern_entry __attribute__((unused));

char _license[] SEC("license") = "GPL";
