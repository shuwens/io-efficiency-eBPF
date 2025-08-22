// Clean Working I/O Categorizer - eBPF Program
// File: clean_working_categorizer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 64
#define MAX_ENTRIES 10240

// Primary I/O Categories (from research)
#define IO_PRIMARY_UNKNOWN 0
#define IO_PRIMARY_DATA 1           // Object storage, key-value data
#define IO_PRIMARY_METADATA 2       // .minio.sys, xl.meta, indexes
#define IO_PRIMARY_CONSISTENCY 3    // WAL, Raft logs, transactions
#define IO_PRIMARY_RELIABILITY 4    // Replication, erasure coding
#define IO_PRIMARY_FILESYSTEM 5     // Journal, allocation metadata
#define IO_PRIMARY_TEMPORARY 6      // Multipart uploads, staging
#define IO_PRIMARY_ADMINISTRATIVE 7 // Config, logs, monitoring

// Context types for amplification analysis
#define CONTEXT_SYSCALL 0
#define CONTEXT_VFS_READ 1
#define CONTEXT_VFS_WRITE 2
#define CONTEXT_BLOCK_WRITE 3

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_WRITE 5

struct clean_io_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 event_type;
  u32 primary_category;
  u32 context_type;
  u64 size;
  u64 latency_start;
  u32 cpu_id;
  s32 retval;
  char comm[MAX_COMM_LEN];
  char path_sample[MAX_PATH_LEN];
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 512 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u64);
} start_times SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);
  __type(value, char[MAX_PATH_LEN]);
} recent_paths SEC(".maps");

// Storage system detection
static __always_inline bool is_target_storage_process(const char *comm) {
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if ((comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
         comm[i + 3] == 'i') ||
        (comm[i] == 'c' && comm[i + 1] == 'e' && comm[i + 2] == 'p' &&
         comm[i + 3] == 'h') ||
        (comm[i] == 'e' && comm[i + 1] == 't' && comm[i + 2] == 'c' &&
         comm[i + 3] == 'd') ||
        (comm[i] == 'p' && comm[i + 1] == 'o' && comm[i + 2] == 's' &&
         comm[i + 3] == 't') ||
        (comm[i] == 'g' && comm[i + 1] == 'l' && comm[i + 2] == 'u' &&
         comm[i + 3] == 's'))
      return true;
  }

  // Test binaries
  if (comm[0] == 'd' && comm[1] == 'd')
    return true;

  return false;
}

// Research-based I/O categorization
static __always_inline u32 categorize_io_by_path(const char *path) {
  if (!path || path[0] == '\0')
    return IO_PRIMARY_UNKNOWN;

  // MinIO system metadata: .minio.sys/
  if (path[0] == '.' && path[1] == 'm' && path[2] == 'i' && path[3] == 'n' &&
      path[4] == 'i' && path[5] == 'o' && path[6] == '.' && path[7] == 's' &&
      path[8] == 'y' && path[9] == 's') {
    return IO_PRIMARY_METADATA;
  }

  // MinIO object metadata: xl.meta files
  for (int i = 0; i < 60; i++) {
    if (path[i] == 'x' && path[i + 1] == 'l' && path[i + 2] == '.' &&
        path[i + 3] == 'm' && path[i + 4] == 'e' && path[i + 5] == 't' &&
        path[i + 6] == 'a') {
      return IO_PRIMARY_METADATA;
    }
  }

  // Consistency operations: WAL, Raft, transaction logs
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'w' && path[i + 1] == 'a' && path[i + 2] == 'l') ||
        (path[i] == 'W' && path[i + 1] == 'A' && path[i + 2] == 'L') ||
        (path[i] == 'r' && path[i + 1] == 'a' && path[i + 2] == 'f' &&
         path[i + 3] == 't') ||
        (path[i] == 't' && path[i + 1] == 'r' && path[i + 2] == 'a' &&
         path[i + 3] == 'n' && path[i + 4] == 's')) {
      return IO_PRIMARY_CONSISTENCY;
    }
  }

  // Filesystem operations: journal files
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'j' && path[i + 1] == 'o' && path[i + 2] == 'u' &&
         path[i + 3] == 'r') ||
        (path[i] == 'j' && path[i + 1] == 'b' && path[i + 2] == 'd')) {
      return IO_PRIMARY_FILESYSTEM;
    }
  }

  // Administrative operations: config, logs
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'c' && path[i + 1] == 'o' && path[i + 2] == 'n' &&
         path[i + 3] == 'f') ||
        (path[i] == '.' && path[i + 1] == 'l' && path[i + 2] == 'o' &&
         path[i + 3] == 'g') ||
        (path[i] == 'a' && path[i + 1] == 'c' && path[i + 2] == 'c' &&
         path[i + 3] == 'e' && path[i + 4] == 's') ||
        (path[i] == 'e' && path[i + 1] == 'r' && path[i + 2] == 'r' &&
         path[i + 3] == 'o' && path[i + 4] == 'r')) {
      return IO_PRIMARY_ADMINISTRATIVE;
    }
  }

  // Reliability operations: erasure coding, healing
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'h' && path[i + 1] == 'e' && path[i + 2] == 'a' &&
         path[i + 3] == 'l') ||
        (path[i] == 'r' && path[i + 1] == 'e' && path[i + 2] == 'p' &&
         path[i + 3] == 'l' && path[i + 4] == 'i' && path[i + 5] == 'c')) {
      return IO_PRIMARY_RELIABILITY;
    }
  }

  // Check for storage data context BEFORE temp patterns
  bool has_storage_data_context = false;
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'd' && path[i + 1] == 'a' && path[i + 2] == 't' &&
         path[i + 3] == 'a') ||
        (path[i] == 'o' && path[i + 1] == 'b' && path[i + 2] == 'j' &&
         path[i + 3] == 'e' && path[i + 4] == 'c' && path[i + 5] == 't') ||
        (path[i] == 'b' && path[i + 1] == 'u' && path[i + 2] == 'c' &&
         path[i + 3] == 'k' && path[i + 4] == 'e' && path[i + 5] == 't') ||
        (path[i] == 'm' && path[i + 1] == 'i' && path[i + 2] == 'n' &&
         path[i + 3] == 'i' && path[i + 4] == 'o')) {
      has_storage_data_context = true;
      break;
    }
  }

  if (has_storage_data_context) {
    return IO_PRIMARY_DATA;
  }

  // Temporary operations: multipart, staging files
  for (int i = 0; i < 60; i++) {
    if ((path[i] == '.' && path[i + 1] == 't' && path[i + 2] == 'm' &&
         path[i + 3] == 'p') ||
        (path[i] == '.' && path[i + 1] == 'p' && path[i + 2] == 'a' &&
         path[i + 3] == 'r' && path[i + 4] == 't') ||
        (path[i] == 'm' && path[i + 1] == 'u' && path[i + 2] == 'l' &&
         path[i + 3] == 't' && path[i + 4] == 'i' && path[i + 5] == 'p' &&
         path[i + 6] == 'a' && path[i + 7] == 'r' && path[i + 8] == 't')) {
      return IO_PRIMARY_TEMPORARY;
    }
  }

  // Generic /tmp/ check (only if not storage data)
  for (int i = 0; i < 60; i++) {
    if (path[i] == '/' && path[i + 1] == 't' && path[i + 2] == 'm' &&
        path[i + 3] == 'p' && path[i + 4] == '/') {
      return IO_PRIMARY_TEMPORARY;
    }
  }

  // If it has path structure, default to data
  for (int i = 0; i < 60; i++) {
    if (path[i] == '/' && path[i + 1] != '.' && path[i + 1] != '\0') {
      return IO_PRIMARY_DATA;
    }
  }

  return IO_PRIMARY_UNKNOWN;
}

// Path tracking for categorization
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  char *filename_ptr = (char *)ctx->args[1];
  char path_sample[MAX_PATH_LEN] = {};

  bpf_probe_read_user_str(path_sample, sizeof(path_sample), filename_ptr);
  bpf_map_update_elem(&recent_paths, &pid_tgid, path_sample, BPF_ANY);

  return 0;
}

// Syscall read tracing
SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  if (ctx->ret <= 0)
    return 0;

  u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  u64 latency = timestamp - *start_time;

  struct clean_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct clean_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get recent path for categorization
  char *recent_path = bpf_map_lookup_elem(&recent_paths, &pid_tgid);
  char path_sample[MAX_PATH_LEN] = {};
  if (recent_path) {
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
      path_sample[i] = recent_path[i];
      if (recent_path[i] == '\0')
        break;
    }
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_READ;
  event->primary_category = categorize_io_by_path(path_sample);
  event->context_type = CONTEXT_SYSCALL;
  event->size = ctx->ret;
  event->latency_start = latency;
  event->cpu_id = bpf_get_smp_processor_id();
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  // Copy path
  for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
    event->path_sample[i] = path_sample[i];
    if (path_sample[i] == '\0')
      break;
  }
  event->path_sample[MAX_PATH_LEN - 1] = '\0';

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// Syscall write tracing
SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &pid_tgid, &timestamp, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  if (ctx->ret <= 0)
    return 0;

  u64 *start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
  if (!start_time)
    return 0;

  u64 timestamp = bpf_ktime_get_ns();
  u64 latency = timestamp - *start_time;

  struct clean_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct clean_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get recent path for categorization
  char *recent_path = bpf_map_lookup_elem(&recent_paths, &pid_tgid);
  char path_sample[MAX_PATH_LEN] = {};
  if (recent_path) {
    for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
      path_sample[i] = recent_path[i];
      if (recent_path[i] == '\0')
        break;
    }
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_WRITE;
  event->primary_category = categorize_io_by_path(path_sample);
  event->context_type = CONTEXT_SYSCALL;
  event->size = ctx->ret;
  event->latency_start = latency;
  event->cpu_id = bpf_get_smp_processor_id();
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  // Copy path
  for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
    event->path_sample[i] = path_sample[i];
    if (path_sample[i] == '\0')
      break;
  }
  event->path_sample[MAX_PATH_LEN - 1] = '\0';

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// VFS layer tracing (amplification measurement)
SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct clean_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct clean_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_READ;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Can't determine from VFS layer
  event->context_type = CONTEXT_VFS_READ;
  event->size = 0;
  event->latency_start = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct clean_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct clean_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_WRITE;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Can't determine from VFS layer
  event->context_type = CONTEXT_VFS_WRITE;
  event->size = 0;
  event->latency_start = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// Block layer tracing (final amplification measurement)
SEC("kprobe/submit_bio")
int trace_submit_bio(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct clean_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct clean_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_BLOCK_WRITE;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Can't determine from block layer
  event->context_type = CONTEXT_BLOCK_WRITE;
  event->size = 0; // Will be filled if we can read bio safely
  event->latency_start = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
