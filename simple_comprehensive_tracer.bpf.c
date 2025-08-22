// Simple Comprehensive I/O Tracer - Working implementation
// File: simple_comprehensive_tracer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 128 // Reduced for eBPF constraints
#define MAX_ENTRIES 10240

// Primary I/O Categories (7 main categories from research)
#define IO_PRIMARY_UNKNOWN 0
#define IO_PRIMARY_DATA 1           // User-facing data operations
#define IO_PRIMARY_METADATA 2       // System/object metadata
#define IO_PRIMARY_CONSISTENCY 3    // WAL, Raft logs, transactions
#define IO_PRIMARY_RELIABILITY 4    // Replication, erasure coding, healing
#define IO_PRIMARY_FILESYSTEM 5     // Journal, allocation metadata
#define IO_PRIMARY_TEMPORARY 6      // Staging, multipart, cleanup
#define IO_PRIMARY_ADMINISTRATIVE 7 // Config, logs, monitoring

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_WRITE 5

struct simple_comprehensive_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 event_type;
  u32 primary_category;
  u64 size;
  u64 latency_start;
  s32 retval;
  char comm[MAX_COMM_LEN];
  char path_sample[64]; // Sample of path for analysis
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

// Simplified fd tracking for path correlation
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u64);        // pid_tgid
  __type(value, char[64]); // Simplified path sample
} recent_paths SEC(".maps");

// Helper function to detect storage system processes
static __always_inline bool is_target_storage_process(const char *comm) {
  // MinIO
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
        comm[i + 3] == 'i')
      return true;
  }

  // Ceph
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'c' && comm[i + 1] == 'e' && comm[i + 2] == 'p' &&
        comm[i + 3] == 'h')
      return true;
  }

  // etcd
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'e' && comm[i + 1] == 't' && comm[i + 2] == 'c' &&
        comm[i + 3] == 'd')
      return true;
  }

  // PostgreSQL
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'p' && comm[i + 1] == 'o' && comm[i + 2] == 's' &&
        comm[i + 3] == 't')
      return true;
  }

  // GlusterFS
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'g' && comm[i + 1] == 'l' && comm[i + 2] == 'u' &&
        comm[i + 3] == 's')
      return true;
  }

  // Test binaries
  if (comm[0] == 'd' && comm[1] == 'd')
    return true;

  return false;
}

// Research-based categorization function
static __always_inline u32 categorize_io_by_path(const char *path) {
  if (!path || path[0] == '\0')
    return IO_PRIMARY_UNKNOWN;

  // MinIO .minio.sys/ metadata (HIGHEST PRIORITY)
  if (path[0] == '.' && path[1] == 'm' && path[2] == 'i' && path[3] == 'n' &&
      path[4] == 'i' && path[5] == 'o' && path[6] == '.' && path[7] == 's' &&
      path[8] == 'y' && path[9] == 's') {
    return IO_PRIMARY_METADATA;
  }

  // xl.meta files (MinIO object metadata)
  for (int i = 0; i < 60; i++) {
    if (path[i] == 'x' && path[i + 1] == 'l' && path[i + 2] == '.' &&
        path[i + 3] == 'm' && path[i + 4] == 'e' && path[i + 5] == 't' &&
        path[i + 6] == 'a') {
      return IO_PRIMARY_METADATA;
    }
  }

  // WAL and transaction logs
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'w' && path[i + 1] == 'a' && path[i + 2] == 'l') ||
        (path[i] == 'W' && path[i + 1] == 'A' && path[i + 2] == 'L') ||
        (path[i] == 'r' && path[i + 1] == 'a' && path[i + 2] == 'f' &&
         path[i + 3] == 't')) {
      return IO_PRIMARY_CONSISTENCY;
    }
  }

  // Filesystem journal
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'j' && path[i + 1] == 'o' && path[i + 2] == 'u' &&
         path[i + 3] == 'r' && path[i + 4] == 'n' && path[i + 5] == 'a' &&
         path[i + 6] == 'l') ||
        (path[i] == 'j' && path[i + 1] == 'b' && path[i + 2] == 'd')) {
      return IO_PRIMARY_FILESYSTEM;
    }
  }

  // Configuration and log files (BEFORE tmp check)
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'c' && path[i + 1] == 'o' && path[i + 2] == 'n' &&
         path[i + 3] == 'f' && path[i + 4] == 'i' && path[i + 5] == 'g') ||
        (path[i] == '.' && path[i + 1] == 'l' && path[i + 2] == 'o' &&
         path[i + 3] == 'g') ||
        (path[i] == 'a' && path[i + 1] == 'c' && path[i + 2] == 'c' &&
         path[i + 3] == 'e' && path[i + 4] == 's' && path[i + 5] == 's') ||
        (path[i] == 'e' && path[i + 1] == 'r' && path[i + 2] == 'r' &&
         path[i + 3] == 'o' && path[i + 4] == 'r')) {
      return IO_PRIMARY_ADMINISTRATIVE;
    }
  }

  // Erasure coding and healing (reliability)
  for (int i = 0; i < 60; i++) {
    if ((path[i] == 'x' && path[i + 1] == 'l' && path[i + 2] == '.') ||
        (path[i] == 'h' && path[i + 1] == 'e' && path[i + 2] == 'a' &&
         path[i + 3] == 'l') ||
        (path[i] == 'r' && path[i + 1] == 'e' && path[i + 2] == 'p' &&
         path[i + 3] == 'l' && path[i + 4] == 'i' && path[i + 5] == 'c')) {
      return IO_PRIMARY_RELIABILITY;
    }
  }

  // Look for storage data patterns BEFORE generic /tmp/ check
  bool is_storage_data = false;
  for (int i = 0; i < 60; i++) {
    // Look for "data", "object", "bucket" in path
    if ((path[i] == 'd' && path[i + 1] == 'a' && path[i + 2] == 't' &&
         path[i + 3] == 'a') ||
        (path[i] == 'o' && path[i + 1] == 'b' && path[i + 2] == 'j' &&
         path[i + 3] == 'e' && path[i + 4] == 'c' && path[i + 5] == 't') ||
        (path[i] == 'b' && path[i + 1] == 'u' && path[i + 2] == 'c' &&
         path[i + 3] == 'k' && path[i + 4] == 'e' && path[i + 5] == 't') ||
        (path[i] == 'm' && path[i + 1] == 'i' && path[i + 2] == 'n' &&
         path[i + 3] == 'i' && path[i + 4] == 'o')) {
      is_storage_data = true;
      break;
    }
  }

  if (is_storage_data) {
    return IO_PRIMARY_DATA;
  }

  // Now check for temporary files (AFTER storage data check)
  for (int i = 0; i < 60; i++) {
    // Generic /tmp/ that's not storage data
    if (path[i] == '/' && path[i + 1] == 't' && path[i + 2] == 'm' &&
        path[i + 3] == 'p') {
      // If it's a simple temp file
      bool looks_like_temp = true;
      for (int j = i + 4; j < 60 && path[j] != '\0'; j++) {
        if (path[j] == 'd' && path[j + 1] == 'a' && path[j + 2] == 't' &&
            path[j + 3] == 'a') {
          looks_like_temp = false; // It's actually data in /tmp
          break;
        }
      }
      if (looks_like_temp) {
        return IO_PRIMARY_TEMPORARY;
      }
    }

    // .tmp files, .part files
    if ((path[i] == '.' && path[i + 1] == 't' && path[i + 2] == 'm' &&
         path[i + 3] == 'p') ||
        (path[i] == '.' && path[i + 1] == 'p' && path[i + 2] == 'a' &&
         path[i + 3] == 'r' && path[i + 4] == 't')) {
      return IO_PRIMARY_TEMPORARY;
    }

    // Multipart uploads
    if (path[i] == 'm' && path[i + 1] == 'u' && path[i + 2] == 'l' &&
        path[i + 3] == 't' && path[i + 4] == 'i' && path[i + 5] == 'p' &&
        path[i + 6] == 'a' && path[i + 7] == 'r' && path[i + 8] == 't') {
      return IO_PRIMARY_TEMPORARY;
    }
  }

  // If it has path structure and doesn't match above, likely data
  bool has_path_structure = false;
  for (int i = 0; i < 60; i++) {
    if (path[i] == '/' && path[i + 1] != '.' && path[i + 1] != '\0') {
      has_path_structure = true;
      break;
    }
  }

  if (has_path_structure) {
    return IO_PRIMARY_DATA;
  }

  return IO_PRIMARY_UNKNOWN;
}

// Simplified openat tracking
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  // Get filename (simplified)
  char *filename_ptr = (char *)ctx->args[1];
  char path_sample[64] = {};

  // Read first 60 characters of path for categorization
  bpf_probe_read_user_str(path_sample, sizeof(path_sample), filename_ptr);

  // Store recent path for this process
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

  struct simple_comprehensive_event *event = bpf_ringbuf_reserve(
      &events, sizeof(struct simple_comprehensive_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get recent path for categorization
  char *recent_path = bpf_map_lookup_elem(&recent_paths, &pid_tgid);
  char path_sample[64] = {};
  if (recent_path) {
    bpf_probe_read_kernel_str(path_sample, sizeof(path_sample), recent_path);
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_READ;
  event->primary_category = categorize_io_by_path(path_sample);
  event->size = ctx->ret;
  event->latency_start = latency;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  // Copy path sample for analysis
  for (int i = 0; i < 63 && i < sizeof(path_sample); i++) {
    event->path_sample[i] = path_sample[i];
    if (path_sample[i] == '\0')
      break;
  }
  event->path_sample[63] = '\0';

  // Initialize context info for syscall operations
  event->context_info[0] = 'S';
  event->context_info[1] = 'Y';
  event->context_info[2] = 'S';
  event->context_info[3] = '_';
  event->context_info[4] = 'R';
  event->context_info[5] = 'D';
  event->context_info[6] = '\0';
  event->offset = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->stack_depth = 0;

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

  struct simple_comprehensive_event *event = bpf_ringbuf_reserve(
      &events, sizeof(struct simple_comprehensive_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get recent path for categorization
  char *recent_path = bpf_map_lookup_elem(&recent_paths, &pid_tgid);
  char path_sample[64] = {};
  if (recent_path) {
    bpf_probe_read_kernel_str(path_sample, sizeof(path_sample), recent_path);
  }

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_WRITE;
  event->primary_category = categorize_io_by_path(path_sample);
  event->size = ctx->ret;
  event->latency_start = latency;
  event->retval = ctx->ret;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  // Copy path sample
  for (int i = 0; i < 63 && i < sizeof(path_sample); i++) {
    event->path_sample[i] = path_sample[i];
    if (path_sample[i] == '\0')
      break;
  }
  event->path_sample[63] = '\0';

  // Initialize context info for syscall write operations
  event->context_info[0] = 'S';
  event->context_info[1] = 'Y';
  event->context_info[2] = 'S';
  event->context_info[3] = '_';
  event->context_info[4] = 'W';
  event->context_info[5] = 'R';
  event->context_info[6] = '\0';
  event->offset = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->stack_depth = 0;

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// Enhanced VFS tracing with more context
SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct simple_comprehensive_event *event = bpf_ringbuf_reserve(
      &events, sizeof(struct simple_comprehensive_event), 0);
  if (!event)
    return 0;

  // Try to get file information from VFS context
  struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
  char context_info[32] = {};

  // Try to read some file info (simplified)
  if (filp) {
    u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &filp->f_flags);

    // Create context information
    if (f_flags & 0x1) { // O_WRONLY
      context_info[0] = 'W';
      context_info[1] = 'O';
      context_info[2] = '\0';
    } else if (f_flags & 0x2) { // O_RDWR
      context_info[0] = 'R';
      context_info[1] = 'W';
      context_info[2] = '\0';
    } else {
      context_info[0] = 'R';
      context_info[1] = 'O';
      context_info[2] = '\0';
    }

    // Add sync flags
    if (f_flags & 0x101000) { // O_SYNC | O_DSYNC
      context_info[2] = '_';
      context_info[3] = 'S';
      context_info[4] = 'Y';
      context_info[5] = 'N';
      context_info[6] = 'C';
      context_info[7] = '\0';
    }
  } else {
    context_info[0] = 'N';
    context_info[1] = 'O';
    context_info[2] = '_';
    context_info[3] = 'F';
    context_info[4] = 'I';
    context_info[5] = 'L';
    context_info[6] = 'E';
    context_info[7] = '\0';
  }

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_READ;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // VFS level can't determine purpose
  event->size = 0;
  event->offset = 0;
  event->latency_start = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->stack_depth = 0;
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  // Copy context info
  for (int i = 0; i < 31 && context_info[i] != '\0'; i++) {
    event->context_info[i] = context_info[i];
  }
  event->context_info[31] = '\0';

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

  struct simple_comprehensive_event *event = bpf_ringbuf_reserve(
      &events, sizeof(struct simple_comprehensive_event), 0);
  if (!event)
    return 0;

  // Get file context
  struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
  char context_info[32] = {};

  if (filp) {
    u32 f_flags = 0;
    bpf_probe_read_kernel(&f_flags, sizeof(f_flags), &filp->f_flags);

    context_info[0] = 'W';
    context_info[1] = 'R';
    context_info[2] = '_';

    if (f_flags & 0x101000) { // O_SYNC | O_DSYNC
      context_info[3] = 'S';
      context_info[4] = 'Y';
      context_info[5] = 'N';
      context_info[6] = 'C';
      context_info[7] = '\0';
    } else if (f_flags & 0x1000) { // O_APPEND
      context_info[3] = 'A';
      context_info[4] = 'P';
      context_info[5] = 'P';
      context_info[6] = 'E';
      context_info[7] = 'N';
      context_info[8] = 'D';
      context_info[9] = '\0';
    } else {
      context_info[3] = 'N';
      context_info[4] = 'O';
      context_info[5] = 'R';
      context_info[6] = 'M';
      context_info[7] = '\0';
    }
  } else {
    context_info[0] = 'N';
    context_info[1] = 'O';
    context_info[2] = '_';
    context_info[3] = 'F';
    context_info[4] = 'I';
    context_info[5] = 'L';
    context_info[6] = 'E';
    context_info[7] = '\0';
  }

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_WRITE;
  event->primary_category = IO_PRIMARY_UNKNOWN;
  event->size = 0;
  event->offset = 0;
  event->latency_start = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->stack_depth = 0;
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  // Copy context info
  for (int i = 0; i < 31 && context_info[i] != '\0'; i++) {
    event->context_info[i] = context_info[i];
  }
  event->context_info[31] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// Enhanced block layer tracing with device and size information
SEC("kprobe/submit_bio")
int trace_submit_bio(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct simple_comprehensive_event *event = bpf_ringbuf_reserve(
      &events, sizeof(struct simple_comprehensive_event), 0);
  if (!event)
    return 0;

  // Get bio information for context
  struct bio *bio = (struct bio *)PT_REGS_PARM1(ctx);
  char context_info[32] = {};
  u32 bio_size = 0;
  u64 bio_sector = 0;

  if (bio) {
    // Try to read bio fields safely
    bpf_probe_read_kernel(&bio_size, sizeof(bio_size), &bio->bi_iter.bi_size);
    bpf_probe_read_kernel(&bio_sector, sizeof(bio_sector),
                          &bio->bi_iter.bi_sector);

    // Create context: "BLK_<size>K_<sector>"
    context_info[0] = 'B';
    context_info[1] = 'L';
    context_info[2] = 'K';
    context_info[3] = '_';

    // Add size in KB
    u32 size_kb = bio_size / 1024;
    if (size_kb < 10) {
      context_info[4] = '0' + size_kb;
      context_info[5] = 'K';
      context_info[6] = '\0';
    } else if (size_kb < 100) {
      context_info[4] = '0' + (size_kb / 10);
      context_info[5] = '0' + (size_kb % 10);
      context_info[6] = 'K';
      context_info[7] = '\0';
    } else {
      context_info[4] = 'L';
      context_info[5] = 'A';
      context_info[6] = 'R';
      context_info[7] = 'G';
      context_info[8] = 'E';
      context_info[9] = '\0';
    }
  } else {
    context_info[0] = 'N';
    context_info[1] = 'O';
    context_info[2] = '_';
    context_info[3] = 'B';
    context_info[4] = 'I';
    context_info[5] = 'O';
    context_info[6] = '\0';
  }

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_BLOCK_WRITE;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Block level can't determine purpose
  event->size = bio_size;
  event->offset = bio_sector * 512;
  event->latency_start = 0;
  event->dev_major = 0; // We'll add device info later if needed
  event->dev_minor = 0;
  event->cpu_id = bpf_get_smp_processor_id();
  event->stack_depth = 0;
  event->retval = 0;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->path_sample[0] = '\0';

  // Copy context info
  for (int i = 0; i < 31 && context_info[i] != '\0'; i++) {
    event->context_info[i] = context_info[i];
  }
  event->context_info[31] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
