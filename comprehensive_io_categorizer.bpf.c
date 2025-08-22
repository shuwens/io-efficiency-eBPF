// Comprehensive Storage I/O Categorizer - Research-grade eBPF implementation
// File: comprehensive_io_categorizer.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256
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

// Secondary Categories - Data Operations
#define IO_DATA_OBJECTS 10          // Primary object storage
#define IO_DATA_PARTS 11            // Multipart upload parts
#define IO_DATA_BULK_TRANSFER 12    // ETL, migrations
#define IO_DATA_KEY_VALUE 13        // Small high-frequency operations
#define IO_DATA_DATABASE_RECORDS 14 // ACID transaction data

// Secondary Categories - Metadata Operations
#define IO_METADATA_SYSTEM 20   // Inode, allocation tables
#define IO_METADATA_OBJECT 21   // xl.meta, object attributes
#define IO_METADATA_BUCKET 22   // Bucket policies, lifecycle
#define IO_METADATA_INDEXING 23 // B-trees, hash tables
#define IO_METADATA_CATALOG 24  // Schema, lineage

// Secondary Categories - Consistency Operations
#define IO_CONSISTENCY_WAL 30         // Write-ahead logs
#define IO_CONSISTENCY_RAFT 31        // Raft consensus logs
#define IO_CONSISTENCY_TRANSACTION 32 // Transaction logs
#define IO_CONSISTENCY_COMMIT 33      // Commit protocols
#define IO_CONSISTENCY_CHECKPOINT 34  // Database checkpoints

// Secondary Categories - Reliability Operations
#define IO_RELIABILITY_REPLICATION 40 // Data replication
#define IO_RELIABILITY_ERASURE 41     // Erasure coding
#define IO_RELIABILITY_HEALING 42     // Data healing/reconstruction
#define IO_RELIABILITY_INTEGRITY 43   // Checksums, verification
#define IO_RELIABILITY_BACKUP 44      // Backup operations

// Secondary Categories - Filesystem Operations
#define IO_FILESYSTEM_JOURNAL_EXT4 50 // ext4 jbd2 journal
#define IO_FILESYSTEM_JOURNAL_XFS 51  // XFS delayed logging
#define IO_FILESYSTEM_ALLOCATION 52   // Block allocation metadata
#define IO_FILESYSTEM_INODE 53        // Inode table operations
#define IO_FILESYSTEM_EXTENT 54       // Extent tree operations

// Secondary Categories - Temporary Operations
#define IO_TEMPORARY_UPLOAD 60  // Multipart upload staging
#define IO_TEMPORARY_SYSTEM 61  // /tmp directory files
#define IO_TEMPORARY_CLEANUP 62 // Garbage collection
#define IO_TEMPORARY_CACHE 63   // Cache files
#define IO_TEMPORARY_WORKING 64 // Working directories

// Secondary Categories - Administrative Operations
#define IO_ADMIN_CONFIG 70       // Configuration files
#define IO_ADMIN_CERTIFICATES 71 // SSL/TLS certificates
#define IO_ADMIN_LOGS_ACCESS 72  // Access logs
#define IO_ADMIN_LOGS_ERROR 73   // Error logs
#define IO_ADMIN_LOGS_AUDIT 74   // Audit logs
#define IO_ADMIN_MONITORING 75   // Metrics, health checks
#define IO_ADMIN_LOCK_FILES 76   // Concurrency control

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_READ 5
#define EVENT_TYPE_BLOCK_WRITE 6

struct comprehensive_io_event {
  u64 timestamp;
  u32 pid;
  u32 tid;
  u32 event_type;
  u32 primary_category;
  u32 secondary_category;
  u64 size;
  u64 offset;
  u64 latency_start;
  u32 dev_major;
  u32 dev_minor;
  s32 retval;
  s32 fd;
  char comm[MAX_COMM_LEN];
  char filename[MAX_PATH_LEN];
};

// Maps
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024); // Large buffer for detailed tracing
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64);
  __type(value, u64);
} start_times SEC(".maps");

// Enhanced FD to path mapping
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u64); // (pid_tgid << 32) | fd
  __type(value, char[MAX_PATH_LEN]);
} fd_to_path SEC(".maps");

// Helper function to detect storage system processes
static __always_inline bool is_target_storage_process(const char *comm) {
  // MinIO processes
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'm' && comm[i + 1] == 'i' && comm[i + 2] == 'n' &&
        comm[i + 3] == 'i')
      return true;
  }

  // Ceph processes (ceph-osd, ceph-mon, ceph-mgr, etc.)
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'c' && comm[i + 1] == 'e' && comm[i + 2] == 'p' &&
        comm[i + 3] == 'h')
      return true;
  }

  // etcd processes
  for (int i = 0; i < MAX_COMM_LEN - 4; i++) {
    if (comm[i] == 'e' && comm[i + 1] == 't' && comm[i + 2] == 'c' &&
        comm[i + 3] == 'd')
      return true;
  }

  // PostgreSQL processes
  for (int i = 0; i < MAX_COMM_LEN - 8; i++) {
    if (comm[i] == 'p' && comm[i + 1] == 'o' && comm[i + 2] == 's' &&
        comm[i + 3] == 't' && comm[i + 4] == 'g' && comm[i + 5] == 'r' &&
        comm[i + 6] == 'e' && comm[i + 7] == 's')
      return true;
  }

  // GlusterFS processes
  for (int i = 0; i < MAX_COMM_LEN - 7; i++) {
    if (comm[i] == 'g' && comm[i + 1] == 'l' && comm[i + 2] == 'u' &&
        comm[i + 3] == 's' && comm[i + 4] == 't' && comm[i + 5] == 'e' &&
        comm[i + 6] == 'r')
      return true;
  }

  // Test binaries (for development)
  if (comm[0] == 'd' && comm[1] == 'd' && (comm[2] == '\0' || comm[2] == '_'))
    return true;

  return false;
}

// Advanced categorization function based on comprehensive research
static __always_inline void
categorize_io_comprehensive(const char *path, u32 *primary, u32 *secondary) {
  *primary = IO_PRIMARY_UNKNOWN;
  *secondary = 0;

  if (!path || path[0] == '\0') {
    *primary = IO_PRIMARY_UNKNOWN;
    return;
  }

  // ========================= MinIO-Specific Patterns =========================

  // .minio.sys/ directory - System metadata with subcategories
  if (path[0] == '.' && path[1] == 'm' && path[2] == 'i' && path[3] == 'n' &&
      path[4] == 'i' && path[5] == 'o' && path[6] == '.' && path[7] == 's' &&
      path[8] == 'y' && path[9] == 's' && path[10] == '/') {

    *primary = IO_PRIMARY_METADATA;

    // Check specific subdirectories
    if (path[11] == 'b' && path[12] == 'u' && path[13] == 'c' &&
        path[14] == 'k' && path[15] == 'e' && path[16] == 't' &&
        path[17] == 's') {
      *secondary = IO_METADATA_BUCKET;
    } else if (path[11] == 'c' && path[12] == 'o' && path[13] == 'n' &&
               path[14] == 'f' && path[15] == 'i' && path[16] == 'g') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CONFIG;
    } else if (path[11] == 'm' && path[12] == 'u' && path[13] == 'l' &&
               path[14] == 't' && path[15] == 'i' && path[16] == 'p' &&
               path[17] == 'a' && path[18] == 'r' && path[19] == 't') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_UPLOAD;
    } else if (path[11] == 't' && path[12] == 'm' && path[13] == 'p') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_CLEANUP;
    } else if (path[11] == 'h' && path[12] == 'e' && path[13] == 'a' &&
               path[14] == 'l') {
      *primary = IO_PRIMARY_RELIABILITY;
      *secondary = IO_RELIABILITY_HEALING;
    } else {
      *secondary = IO_METADATA_SYSTEM;
    }
    return;
  }

  // xl.meta files - Object metadata (MinIO erasure coding metadata)
  for (int i = 0; i < MAX_PATH_LEN - 7; i++) {
    if (path[i] == 'x' && path[i + 1] == 'l' && path[i + 2] == '.' &&
        path[i + 3] == 'm' && path[i + 4] == 'e' && path[i + 5] == 't' &&
        path[i + 6] == 'a') {
      *primary = IO_PRIMARY_METADATA;
      *secondary = IO_METADATA_OBJECT;
      return;
    }
  }

  // ========================= Consistency & Reliability
  // =========================

  // Write-ahead logs (PostgreSQL, etcd)
  for (int i = 0; i < MAX_PATH_LEN - 3; i++) {
    if ((path[i] == 'w' && path[i + 1] == 'a' && path[i + 2] == 'l') ||
        (path[i] == 'W' && path[i + 1] == 'A' && path[i + 2] == 'L')) {
      *primary = IO_PRIMARY_CONSISTENCY;
      *secondary = IO_CONSISTENCY_WAL;
      return;
    }
  }

  // Raft logs (etcd)
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if (path[i] == 'r' && path[i + 1] == 'a' && path[i + 2] == 'f' &&
        path[i + 3] == 't') {
      *primary = IO_PRIMARY_CONSISTENCY;
      *secondary = IO_CONSISTENCY_RAFT;
      return;
    }
    if (path[i] == '.' && path[i + 1] == 'l' && path[i + 2] == 'o' &&
        path[i + 3] == 'g') {
      *primary = IO_PRIMARY_CONSISTENCY;
      *secondary = IO_CONSISTENCY_RAFT;
      return;
    }
  }

  // Transaction logs
  for (int i = 0; i < MAX_PATH_LEN - 5; i++) {
    if (path[i] == 't' && path[i + 1] == 'r' && path[i + 2] == 'a' &&
        path[i + 3] == 'n' && path[i + 4] == 's') {
      *primary = IO_PRIMARY_CONSISTENCY;
      *secondary = IO_CONSISTENCY_TRANSACTION;
      return;
    }
  }

  // ========================= Filesystem Layer =========================

  // ext4 journal (jbd2)
  for (int i = 0; i < MAX_PATH_LEN - 7; i++) {
    if ((path[i] == 'j' && path[i + 1] == 'o' && path[i + 2] == 'u' &&
         path[i + 3] == 'r' && path[i + 4] == 'n' && path[i + 5] == 'a' &&
         path[i + 6] == 'l') ||
        (path[i] == 'j' && path[i + 1] == 'b' && path[i + 2] == 'd' &&
         path[i + 3] == '2')) {
      *primary = IO_PRIMARY_FILESYSTEM;
      *secondary = IO_FILESYSTEM_JOURNAL_EXT4;
      return;
    }
  }

  // XFS journal
  for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
    if (path[i] == 'x' && path[i + 1] == 'f' && path[i + 2] == 's' &&
        path[i + 3] == 'l' && path[i + 4] == 'o' && path[i + 5] == 'g') {
      *primary = IO_PRIMARY_FILESYSTEM;
      *secondary = IO_FILESYSTEM_JOURNAL_XFS;
      return;
    }
  }

  // ========================= Temporary Operations =========================

  // MinIO multipart uploads - very specific patterns
  for (int i = 0; i < MAX_PATH_LEN - 8; i++) {
    if (path[i] == 'm' && path[i + 1] == 'u' && path[i + 2] == 'l' &&
        path[i + 3] == 't' && path[i + 4] == 'i' && path[i + 5] == 'p' &&
        path[i + 6] == 'a' && path[i + 7] == 'r' && path[i + 8] == 't') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_UPLOAD;
      return;
    }
  }

  // Temporary files - comprehensive patterns
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    // /tmp/ paths
    if (path[i] == '/' && path[i + 1] == 't' && path[i + 2] == 'm' &&
        path[i + 3] == 'p' && path[i + 4] == '/') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_SYSTEM;
      return;
    }
    // .tmp files
    if (path[i] == '.' && path[i + 1] == 't' && path[i + 2] == 'm' &&
        path[i + 3] == 'p') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_UPLOAD;
      return;
    }
    // .part files (partial uploads)
    if (path[i] == '.' && path[i + 1] == 'p' && path[i + 2] == 'a' &&
        path[i + 3] == 'r' && path[i + 4] == 't') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_UPLOAD;
      return;
    }
  }

  // ========================= Administrative Operations
  // =========================

  // Configuration files
  for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
    if (path[i] == 'c' && path[i + 1] == 'o' && path[i + 2] == 'n' &&
        path[i + 3] == 'f' && path[i + 4] == 'i' && path[i + 5] == 'g') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CONFIG;
      return;
    }
    if (path[i] == '.' && path[i + 1] == 'e' && path[i + 2] == 'n' &&
        path[i + 3] == 'v') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CONFIG;
      return;
    }
    if (path[i] == '.' && path[i + 1] == 'y' && path[i + 2] == 'a' &&
        path[i + 3] == 'm' && path[i + 4] == 'l') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CONFIG;
      return;
    }
    if (path[i] == '.' && path[i + 1] == 'j' && path[i + 2] == 's' &&
        path[i + 3] == 'o' && path[i + 4] == 'n') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CONFIG;
      return;
    }
  }

  // Certificate files
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if ((path[i] == '.' && path[i + 1] == 'c' && path[i + 2] == 'r' &&
         path[i + 3] == 't') ||
        (path[i] == '.' && path[i + 1] == 'p' && path[i + 2] == 'e' &&
         path[i + 3] == 'm') ||
        (path[i] == '.' && path[i + 1] == 'k' && path[i + 2] == 'e' &&
         path[i + 3] == 'y')) {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_CERTIFICATES;
      return;
    }
  }

  // Log files - detailed breakdown
  for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
    if (path[i] == 'a' && path[i + 1] == 'c' && path[i + 2] == 'c' &&
        path[i + 3] == 'e' && path[i + 4] == 's' && path[i + 5] == 's') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_LOGS_ACCESS;
      return;
    }
    if (path[i] == 'e' && path[i + 1] == 'r' && path[i + 2] == 'r' &&
        path[i + 3] == 'o' && path[i + 4] == 'r') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_LOGS_ERROR;
      return;
    }
    if (path[i] == 'a' && path[i + 1] == 'u' && path[i + 2] == 'd' &&
        path[i + 3] == 'i' && path[i + 4] == 't') {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_LOGS_AUDIT;
      return;
    }
  }

  // Lock files
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if ((path[i] == '.' && path[i + 1] == 'l' && path[i + 2] == 'o' &&
         path[i + 3] == 'c' && path[i + 4] == 'k') ||
        (path[i] == 'l' && path[i + 1] == 'o' && path[i + 2] == 'c' &&
         path[i + 3] == 'k')) {
      *primary = IO_PRIMARY_ADMINISTRATIVE;
      *secondary = IO_ADMIN_LOCK_FILES;
      return;
    }
  }

  // ========================= Reliability Operations =========================

  // Erasure coding patterns
  for (int i = 0; i < MAX_PATH_LEN - 2; i++) {
    if (path[i] == 'x' && path[i + 1] == 'l' && path[i + 2] == '.') {
      *primary = IO_PRIMARY_RELIABILITY;
      *secondary = IO_RELIABILITY_ERASURE;
      return;
    }
  }

  // Data healing patterns
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if (path[i] == 'h' && path[i + 1] == 'e' && path[i + 2] == 'a' &&
        path[i + 3] == 'l') {
      *primary = IO_PRIMARY_RELIABILITY;
      *secondary = IO_RELIABILITY_HEALING;
      return;
    }
  }

  // Replication patterns
  for (int i = 0; i < MAX_PATH_LEN - 7; i++) {
    if (path[i] == 'r' && path[i + 1] == 'e' && path[i + 2] == 'p' &&
        path[i + 3] == 'l' && path[i + 4] == 'i' && path[i + 5] == 'c' &&
        path[i + 6] == 'a') {
      *primary = IO_PRIMARY_RELIABILITY;
      *secondary = IO_RELIABILITY_REPLICATION;
      return;
    }
  }

  // ========================= Database-Specific Patterns
  // =========================

  // PostgreSQL WAL
  for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
    if (path[i] == 'p' && path[i + 1] == 'g' && path[i + 2] == '_' &&
        path[i + 3] == 'w' && path[i + 4] == 'a' && path[i + 5] == 'l') {
      *primary = IO_PRIMARY_CONSISTENCY;
      *secondary = IO_CONSISTENCY_WAL;
      return;
    }
  }

  // ========================= Cache and Performance =========================

  // Cache files
  for (int i = 0; i < MAX_PATH_LEN - 5; i++) {
    if (path[i] == 'c' && path[i + 1] == 'a' && path[i + 2] == 'c' &&
        path[i + 3] == 'h' && path[i + 4] == 'e') {
      *primary = IO_PRIMARY_TEMPORARY;
      *secondary = IO_TEMPORARY_CACHE;
      return;
    }
  }

  // ========================= Data Classification Heuristics
  // =========================

  // Look for data directory patterns
  bool in_data_path = false;
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if (path[i] == 'd' && path[i + 1] == 'a' && path[i + 2] == 't' &&
        path[i + 3] == 'a') {
      in_data_path = true;
      break;
    }
    // MinIO disk mount patterns (/disk1/, /disk2/, etc.)
    if (path[i] == '/' && path[i + 1] == 'd' && path[i + 2] == 'i' &&
        path[i + 3] == 's' && path[i + 4] == 'k') {
      in_data_path = true;
      break;
    }
  }

  // Check for object storage patterns
  bool has_bucket_pattern = false;
  for (int i = 0; i < MAX_PATH_LEN - 1; i++) {
    // Multiple slashes suggest bucket/object hierarchy
    if (path[i] == '/' && path[i + 1] != '.' && path[i + 1] != '\0') {
      int slash_count = 0;
      for (int j = i; j < MAX_PATH_LEN && path[j] != '\0'; j++) {
        if (path[j] == '/')
          slash_count++;
      }
      if (slash_count >= 2) {
        has_bucket_pattern = true;
        break;
      }
    }
  }

  // Check for common object extensions or patterns
  bool looks_like_object = false;
  for (int i = 0; i < MAX_PATH_LEN - 4; i++) {
    if (path[i] == '.' &&
        ((path[i + 1] == 'd' && path[i + 2] == 'a' && path[i + 3] == 't') ||
         (path[i + 1] == 'b' && path[i + 2] == 'i' && path[i + 3] == 'n') ||
         (path[i + 1] == 'o' && path[i + 2] == 'b' && path[i + 3] == 'j') ||
         (path[i + 1] == 'j' && path[i + 2] == 'p' && path[i + 3] == 'g') ||
         (path[i + 1] == 'p' && path[i + 2] == 'n' && path[i + 3] == 'g') ||
         (path[i + 1] == 'p' && path[i + 2] == 'd' && path[i + 3] == 'f'))) {
      looks_like_object = true;
      break;
    }
  }

  // Classify data operations
  if (in_data_path || has_bucket_pattern || looks_like_object) {
    *primary = IO_PRIMARY_DATA;
    if (has_bucket_pattern) {
      *secondary = IO_DATA_OBJECTS;
    } else {
      *secondary = IO_DATA_KEY_VALUE; // Smaller data operations
    }
    return;
  }

  // ========================= Fallback Classification =========================

  // If we reach here, it's likely unknown - important for investigation
  *primary = IO_PRIMARY_UNKNOWN;
  *secondary = 0;
}

// Track file opens to maintain fd->path mapping
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  // Get filename from syscall arguments (second argument for openat)
  const char __user *filename = (const char __user *)ctx->args[1];
  char path[MAX_PATH_LEN] = {};

  bpf_probe_read_user_str(path, sizeof(path), filename);

  // Store temporarily with pid_tgid as key
  bpf_map_update_elem(&fd_to_path, &pid_tgid, path, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  if (ctx->ret < 0) {
    // Failed open, clean up
    bpf_map_delete_elem(&fd_to_path, &pid_tgid);
    return 0;
  }

  // Get the stored path
  char *stored_path = bpf_map_lookup_elem(&fd_to_path, &pid_tgid);
  if (!stored_path) {
    return 0;
  }

  // Create new key: (pid_tgid << 32) | fd
  u64 fd_key = (pid_tgid << 32) | (u64)ctx->ret;
  bpf_map_update_elem(&fd_to_path, &fd_key, stored_path, BPF_ANY);

  // Clean up temporary entry
  bpf_map_delete_elem(&fd_to_path, &pid_tgid);

  return 0;
}

// Comprehensive syscall read tracing
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

  struct comprehensive_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct comprehensive_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get filename from fd mapping
  u64 fd_key = (pid_tgid << 32) |
               (u64)0; // We don't have direct access to fd in sys_exit
  char *stored_path = bpf_map_lookup_elem(&fd_to_path, &fd_key);

  char filename[MAX_PATH_LEN] = {};
  if (stored_path) {
    bpf_probe_read_kernel_str(filename, sizeof(filename), stored_path);
  }

  // Comprehensive categorization
  u32 primary_cat, secondary_cat;
  categorize_io_comprehensive(filename, &primary_cat, &secondary_cat);

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_READ;
  event->primary_category = primary_cat;
  event->secondary_category = secondary_cat;
  event->size = ctx->ret;
  event->offset = 0;
  event->latency_start = latency;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->retval = ctx->ret;
  event->fd = 0; // FD not available in sys_exit context
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// Comprehensive syscall write tracing
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

  struct comprehensive_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct comprehensive_io_event), 0);
  if (!event) {
    bpf_map_delete_elem(&start_times, &pid_tgid);
    return 0;
  }

  // Get filename from fd mapping
  u64 fd_key = (pid_tgid << 32) |
               (u64)0; // We don't have direct access to fd in sys_exit
  char *stored_path = bpf_map_lookup_elem(&fd_to_path, &fd_key);

  char filename[MAX_PATH_LEN] = {};
  if (stored_path) {
    bpf_probe_read_kernel_str(filename, sizeof(filename), stored_path);
  }

  // Comprehensive categorization
  u32 primary_cat, secondary_cat;
  categorize_io_comprehensive(filename, &primary_cat, &secondary_cat);

  event->timestamp = timestamp;
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_SYSCALL_WRITE;
  event->primary_category = primary_cat;
  event->secondary_category = secondary_cat;
  event->size = ctx->ret;
  event->offset = 0;
  event->latency_start = latency;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->retval = ctx->ret;
  event->fd = 0; // FD not available in sys_exit context
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), filename);

  bpf_ringbuf_submit(event, 0);
  bpf_map_delete_elem(&start_times, &pid_tgid);

  return 0;
}

// VFS layer tracing for amplification measurement
SEC("kprobe/vfs_read")
int trace_vfs_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct comprehensive_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct comprehensive_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_READ;
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Can't determine from VFS level
  event->secondary_category = 0;
  event->size = 0;
  event->offset = 0;
  event->latency_start = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->retval = 0;
  event->fd = -1;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->filename[0] = '\0';

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

  struct comprehensive_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct comprehensive_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_VFS_WRITE;
  event->primary_category = IO_PRIMARY_UNKNOWN;
  event->secondary_category = 0;
  event->size = 0;
  event->offset = 0;
  event->latency_start = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->retval = 0;
  event->fd = -1;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->filename[0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

// Block layer tracing for complete amplification picture
SEC("kprobe/submit_bio")
int trace_submit_bio(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  char comm[MAX_COMM_LEN];
  bpf_get_current_comm(comm, sizeof(comm));

  if (!is_target_storage_process(comm))
    return 0;

  struct comprehensive_io_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct comprehensive_io_event), 0);
  if (!event)
    return 0;

  event->timestamp = bpf_ktime_get_ns();
  event->pid = pid;
  event->tid = tid;
  event->event_type = EVENT_TYPE_BLOCK_WRITE; // Simplified for now
  event->primary_category =
      IO_PRIMARY_UNKNOWN; // Block layer can't determine purpose
  event->secondary_category = 0;
  event->size = 0; // Will be approximated
  event->offset = 0;
  event->latency_start = 0;
  event->dev_major = 0;
  event->dev_minor = 0;
  event->retval = 0;
  event->fd = -1;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  event->filename[0] = '\0';

  bpf_ringbuf_submit(event, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
