// Comprehensive Storage I/O Categorizer - Research-grade userspace program
// File: comprehensive_io_categorizer.c

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

// Include the auto-generated skeleton
#include "comprehensive_io_categorizer.skel.h"

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256

// Primary categories
#define IO_PRIMARY_UNKNOWN 0
#define IO_PRIMARY_DATA 1
#define IO_PRIMARY_METADATA 2
#define IO_PRIMARY_CONSISTENCY 3
#define IO_PRIMARY_RELIABILITY 4
#define IO_PRIMARY_FILESYSTEM 5
#define IO_PRIMARY_TEMPORARY 6
#define IO_PRIMARY_ADMINISTRATIVE 7

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_READ 5
#define EVENT_TYPE_BLOCK_WRITE 6

struct comprehensive_io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 primary_category;
  __u32 secondary_category;
  __u64 size;
  __u64 offset;
  __u64 latency_start;
  __u32 dev_major;
  __u32 dev_minor;
  __s32 retval;
  __s32 fd;
  char comm[MAX_COMM_LEN];
  char filename[MAX_PATH_LEN];
};

// Comprehensive statistics per category
struct comprehensive_io_stats {
  __u64 syscall_reads;
  __u64 syscall_writes;
  __u64 vfs_reads;
  __u64 vfs_writes;
  __u64 block_reads;
  __u64 block_writes;
  __u64 total_read_bytes;
  __u64 total_write_bytes;
  __u64 total_read_latency;
  __u64 total_write_latency;
  __u64 operation_count;
  const char *name;
  const char *description;
};

// Primary category statistics
static struct comprehensive_io_stats primary_stats[8] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN",
     "Unclassified I/O operations requiring investigation"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "DATA",
     "User-facing data operations (objects, records, key-values)"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "METADATA",
     "System and object metadata operations"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "CONSISTENCY",
     "WAL, Raft logs, transaction coordination"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "RELIABILITY",
     "Replication, erasure coding, healing operations"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "FILESYSTEM",
     "Journal, allocation metadata, inode operations"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "TEMPORARY",
     "Staging files, multipart uploads, cleanup"},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "ADMINISTRATIVE",
     "Configuration, logging, monitoring"}};

// Secondary category lookup table
static const char *get_secondary_category_name(u32 secondary) {
  switch (secondary) {
  // Data subcategories
  case 10:
    return "DATA_OBJECTS";
  case 11:
    return "DATA_PARTS";
  case 12:
    return "DATA_BULK_TRANSFER";
  case 13:
    return "DATA_KEY_VALUE";
  case 14:
    return "DATA_DATABASE_RECORDS";

  // Metadata subcategories
  case 20:
    return "METADATA_SYSTEM";
  case 21:
    return "METADATA_OBJECT";
  case 22:
    return "METADATA_BUCKET";
  case 23:
    return "METADATA_INDEXING";
  case 24:
    return "METADATA_CATALOG";

  // Consistency subcategories
  case 30:
    return "CONSISTENCY_WAL";
  case 31:
    return "CONSISTENCY_RAFT";
  case 32:
    return "CONSISTENCY_TRANSACTION";
  case 33:
    return "CONSISTENCY_COMMIT";
  case 34:
    return "CONSISTENCY_CHECKPOINT";

  // Reliability subcategories
  case 40:
    return "RELIABILITY_REPLICATION";
  case 41:
    return "RELIABILITY_ERASURE";
  case 42:
    return "RELIABILITY_HEALING";
  case 43:
    return "RELIABILITY_INTEGRITY";
  case 44:
    return "RELIABILITY_BACKUP";

  // Filesystem subcategories
  case 50:
    return "FILESYSTEM_JOURNAL_EXT4";
  case 51:
    return "FILESYSTEM_JOURNAL_XFS";
  case 52:
    return "FILESYSTEM_ALLOCATION";
  case 53:
    return "FILESYSTEM_INODE";
  case 54:
    return "FILESYSTEM_EXTENT";

  // Temporary subcategories
  case 60:
    return "TEMPORARY_UPLOAD";
  case 61:
    return "TEMPORARY_SYSTEM";
  case 62:
    return "TEMPORARY_CLEANUP";
  case 63:
    return "TEMPORARY_CACHE";
  case 64:
    return "TEMPORARY_WORKING";

  // Administrative subcategories
  case 70:
    return "ADMIN_CONFIG";
  case 71:
    return "ADMIN_CERTIFICATES";
  case 72:
    return "ADMIN_LOGS_ACCESS";
  case 73:
    return "ADMIN_LOGS_ERROR";
  case 74:
    return "ADMIN_LOGS_AUDIT";
  case 75:
    return "ADMIN_MONITORING";
  case 76:
    return "ADMIN_LOCK_FILES";

  default:
    return "UNKNOWN_SECONDARY";
  }
}

static struct env {
  bool verbose;
  bool json_output;
  bool show_filenames;
  bool investigate_mode;
  bool show_secondary;
  bool realtime;
  int duration;
  int min_size;
  const char *output_file;
  const char *focus_category; // Focus on specific category
} env = {
    .verbose = false,
    .json_output = false,
    .show_filenames = false,
    .investigate_mode = false,
    .show_secondary = false,
    .realtime = true,
    .duration = 0,
    .min_size = 0,
    .output_file = NULL,
    .focus_category = NULL,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"json", 'j', NULL, 0, "Output in JSON format"},
    {"filenames", 'f', NULL, 0, "Show filenames in real-time output"},
    {"investigate", 'i', NULL, 0,
     "Investigation mode: detailed analysis of unknown I/O"},
    {"secondary", 's', NULL, 0, "Show secondary categories in analysis"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {"quiet", 'q', NULL, 0, "Disable real-time output, only show summary"},
    {"min-size", 'm', "SIZE", 0, "Minimum I/O size to track (bytes)"},
    {"focus", 'F', "CATEGORY", 0,
     "Focus on specific category (DATA, METADATA, etc.)"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
  switch (key) {
  case 'v':
    env.verbose = true;
    break;
  case 'j':
    env.json_output = true;
    break;
  case 'f':
    env.show_filenames = true;
    break;
  case 'i':
    env.investigate_mode = true;
    env.show_filenames = true;
    break;
  case 's':
    env.show_secondary = true;
    break;
  case 'd':
    env.duration = atoi(arg);
    break;
  case 'o':
    env.output_file = arg;
    break;
  case 'q':
    env.realtime = false;
    break;
  case 'm':
    env.min_size = atoi(arg);
    break;
  case 'F':
    env.focus_category = arg;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "Comprehensive I/O categorization for storage systems (MinIO, Ceph, "
           "etcd, PostgreSQL, GlusterFS)",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;
static int total_events = 0;
static int unknown_events = 0;

static void sig_handler(int sig) { exiting = true; }

const char *get_event_type_name(int type) {
  switch (type) {
  case EVENT_TYPE_SYSCALL_READ:
    return "SYSCALL_READ";
  case EVENT_TYPE_SYSCALL_WRITE:
    return "SYSCALL_WRITE";
  case EVENT_TYPE_VFS_READ:
    return "VFS_READ";
  case EVENT_TYPE_VFS_WRITE:
    return "VFS_WRITE";
  case EVENT_TYPE_BLOCK_READ:
    return "BLOCK_READ";
  case EVENT_TYPE_BLOCK_WRITE:
    return "BLOCK_WRITE";
  default:
    return "UNKNOWN";
  }
}

static void update_stats(const struct comprehensive_io_event *e) {
  if (e->primary_category >= 8)
    return;

  struct comprehensive_io_stats *s = &primary_stats[e->primary_category];

  switch (e->event_type) {
  case EVENT_TYPE_SYSCALL_READ:
    s->syscall_reads++;
    s->total_read_bytes += e->size;
    s->total_read_latency += e->latency_start;
    s->operation_count++;
    break;
  case EVENT_TYPE_SYSCALL_WRITE:
    s->syscall_writes++;
    s->total_write_bytes += e->size;
    s->total_write_latency += e->latency_start;
    s->operation_count++;
    break;
  case EVENT_TYPE_VFS_READ:
    s->vfs_reads++;
    break;
  case EVENT_TYPE_VFS_WRITE:
    s->vfs_writes++;
    break;
  case EVENT_TYPE_BLOCK_READ:
    s->block_reads++;
    break;
  case EVENT_TYPE_BLOCK_WRITE:
    s->block_writes++;
    break;
  }

  total_events++;
  if (e->primary_category == IO_PRIMARY_UNKNOWN) {
    unknown_events++;
  }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct comprehensive_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Filter by focus category if specified
  if (env.focus_category) {
    bool matches = false;
    if (strcmp(env.focus_category, "DATA") == 0 &&
        e->primary_category == IO_PRIMARY_DATA)
      matches = true;
    else if (strcmp(env.focus_category, "METADATA") == 0 &&
             e->primary_category == IO_PRIMARY_METADATA)
      matches = true;
    else if (strcmp(env.focus_category, "CONSISTENCY") == 0 &&
             e->primary_category == IO_PRIMARY_CONSISTENCY)
      matches = true;
    else if (strcmp(env.focus_category, "RELIABILITY") == 0 &&
             e->primary_category == IO_PRIMARY_RELIABILITY)
      matches = true;
    else if (strcmp(env.focus_category, "FILESYSTEM") == 0 &&
             e->primary_category == IO_PRIMARY_FILESYSTEM)
      matches = true;
    else if (strcmp(env.focus_category, "TEMPORARY") == 0 &&
             e->primary_category == IO_PRIMARY_TEMPORARY)
      matches = true;
    else if (strcmp(env.focus_category, "ADMIN") == 0 &&
             e->primary_category == IO_PRIMARY_ADMINISTRATIVE)
      matches = true;
    else if (strcmp(env.focus_category, "UNKNOWN") == 0 &&
             e->primary_category == IO_PRIMARY_UNKNOWN)
      matches = true;

    if (!matches) {
      update_stats(e);
      return 0;
    }
  }

  // Filter small I/O if requested
  if (env.min_size > 0 &&
      (e->event_type == EVENT_TYPE_SYSCALL_READ ||
       e->event_type == EVENT_TYPE_SYSCALL_WRITE) &&
      (int)e->size < env.min_size) {
    update_stats(e);
    return 0;
  }

  // Investigation mode for unknown I/O
  if (env.investigate_mode && e->primary_category == IO_PRIMARY_UNKNOWN &&
      (e->event_type == EVENT_TYPE_SYSCALL_READ ||
       e->event_type == EVENT_TYPE_SYSCALL_WRITE)) {
    fprintf(stderr, "\n🔍 INVESTIGATING UNKNOWN I/O #%d:\n",
            unknown_events + 1);
    fprintf(stderr, "   Process: %s (PID: %u, TID: %u)\n", e->comm, e->pid,
            e->tid);
    fprintf(stderr, "   Operation: %s (%llu bytes)\n",
            get_event_type_name(e->event_type), e->size);
    fprintf(stderr, "   File: '%s'\n",
            e->filename[0] ? e->filename : "<no filename captured>");
    fprintf(stderr, "   FD: %d\n", e->fd);

    // Provide categorization hints
    if (e->filename[0]) {
      fprintf(stderr, "   Analysis hints:\n");
      if (strstr(e->filename, "/"))
        fprintf(stderr, "     - Contains path separators (likely data file)\n");
      if (strstr(e->filename, "."))
        fprintf(stderr, "     - Has file extension\n");
      if (strstr(e->filename, "tmp"))
        fprintf(stderr, "     - Contains 'tmp' (temporary file)\n");
      if (strstr(e->filename, "log"))
        fprintf(stderr, "     - Contains 'log' (logging operation)\n");
      if (strstr(e->filename, "meta"))
        fprintf(stderr, "     - Contains 'meta' (metadata operation)\n");
    }
    fprintf(stderr, "   → Consider updating categorization rules\n\n");
  }

  update_stats(e);

  if (!env.realtime)
    return 0;

  // Convert timestamp to readable format
  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (env.json_output) {
    fprintf(output_fp,
            "{\"timestamp\":\"%s.%09llu\","
            "\"pid\":%u,\"tid\":%u,\"comm\":\"%s\","
            "\"event_type\":\"%s\","
            "\"primary_category\":\"%s\","
            "\"secondary_category\":\"%s\","
            "\"size\":%llu,\"offset\":%llu,\"fd\":%d,"
            "\"filename\":\"%s\","
            "\"latency_us\":%.2f,\"retval\":%d}\n",
            ts, e->timestamp % 1000000000, e->pid, e->tid, e->comm,
            get_event_type_name(e->event_type),
            primary_stats[e->primary_category].name,
            get_secondary_category_name(e->secondary_category), e->size,
            e->offset, e->fd, e->filename[0] ? e->filename : "",
            e->latency_start / 1000.0, e->retval);
  } else {
    if (env.show_secondary) {
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-16s %-8u %-8llu %-50s\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              primary_stats[e->primary_category].name,
              get_secondary_category_name(e->secondary_category), e->pid,
              e->size,
              env.show_filenames ? (e->filename[0] ? e->filename : "<no_file>")
                                 : "");
    } else {
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-8u %-8llu %-4d %8.2f\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              primary_stats[e->primary_category].name, e->pid, e->size, e->fd,
              e->latency_start / 1000.0);
    }
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  if (env.show_secondary) {
    fprintf(output_fp, "%-17s %-15s %-12s %-16s %-8s %-8s %s\n", "TIME",
            "EVENT_TYPE", "PRIMARY", "SECONDARY", "PID", "SIZE",
            env.show_filenames ? "FILENAME" : "");
  } else {
    fprintf(output_fp, "%-17s %-15s %-12s %-8s %-8s %-4s %8s\n", "TIME",
            "EVENT_TYPE", "PRIMARY", "PID", "SIZE", "FD", "LAT(us)");
  }
  fprintf(output_fp, "%s\n",
          "===================================================================="
          "============");
}

static void print_comprehensive_summary() {
  if (env.json_output) {
    fprintf(output_fp, "{\"comprehensive_analysis\":{\n");
    fprintf(output_fp, "  \"summary\":{\n");
    fprintf(output_fp, "    \"total_events\":%d,\n", total_events);
    fprintf(output_fp, "    \"unknown_events\":%d,\n", unknown_events);
    fprintf(output_fp, "    \"classification_rate\":%.2f\n",
            total_events > 0
                ? (double)(total_events - unknown_events) / total_events * 100
                : 0);
    fprintf(output_fp, "  },\n");

    fprintf(output_fp, "  \"categories\":{\n");
    for (int i = 0; i < 8; i++) {
      struct comprehensive_io_stats *s = &primary_stats[i];
      if (s->operation_count == 0)
        continue;

      double read_amp =
          s->syscall_reads > 0
              ? (double)(s->vfs_reads + s->block_reads) / s->syscall_reads
              : 0;
      double write_amp =
          s->syscall_writes > 0
              ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
              : 0;

      fprintf(output_fp, "    \"%s\":{\n", s->name);
      fprintf(output_fp,
              "      \"syscall_reads\":%llu,\"syscall_writes\":%llu,\n",
              s->syscall_reads, s->syscall_writes);
      fprintf(output_fp, "      \"vfs_reads\":%llu,\"vfs_writes\":%llu,\n",
              s->vfs_reads, s->vfs_writes);
      fprintf(output_fp, "      \"block_reads\":%llu,\"block_writes\":%llu,\n",
              s->block_reads, s->block_writes);
      fprintf(
          output_fp,
          "      \"read_amplification\":%.2f,\"write_amplification\":%.2f,\n",
          read_amp, write_amp);
      fprintf(output_fp,
              "      \"total_read_mb\":%.2f,\"total_write_mb\":%.2f,\n",
              s->total_read_bytes / 1024.0 / 1024.0,
              s->total_write_bytes / 1024.0 / 1024.0);
      fprintf(output_fp,
              "      \"operation_count\":%llu,\"description\":\"%s\"\n",
              s->operation_count, s->description);
      fprintf(output_fp, "    }%s\n", i < 7 ? "," : "");
    }
    fprintf(output_fp, "  }\n");
    fprintf(output_fp, "}}\n");
  } else {
    fprintf(output_fp, "\n=== COMPREHENSIVE STORAGE I/O ANALYSIS ===\n");
    fprintf(output_fp, "Classification: %d/%d events (%.1f%% classified)\n",
            total_events - unknown_events, total_events,
            total_events > 0
                ? (double)(total_events - unknown_events) / total_events * 100
                : 0);

    fprintf(output_fp, "\n=== PRIMARY CATEGORY BREAKDOWN ===\n");
    fprintf(output_fp, "%-14s %7s %7s %7s %7s %7s %7s %8s %8s %8s %8s %10s\n",
            "CATEGORY", "SYS_R", "SYS_W", "VFS_R", "VFS_W", "BLK_R", "BLK_W",
            "R_AMP", "W_AMP", "READ_MB", "WRITE_MB", "OPERATIONS");
    fprintf(output_fp, "======================================================="
                       "=========================\n");

    __u64 total_syscall_r = 0, total_syscall_w = 0;
    __u64 total_vfs_r = 0, total_vfs_w = 0;
    __u64 total_block_r = 0, total_block_w = 0;
    __u64 total_read_bytes = 0, total_write_bytes = 0;
    __u64 total_operations = 0;

    for (int i = 0; i < 8; i++) {
      struct comprehensive_io_stats *s = &primary_stats[i];
      if (s->operation_count == 0)
        continue;

      double read_amp =
          s->syscall_reads > 0
              ? (double)(s->vfs_reads + s->block_reads) / s->syscall_reads
              : 0;
      double write_amp =
          s->syscall_writes > 0
              ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
              : 0;

      fprintf(output_fp,
              "%-14s %7llu %7llu %7llu %7llu %7llu %7llu %8.2f %8.2f %8.2f "
              "%8.2f %10llu\n",
              s->name, s->syscall_reads, s->syscall_writes, s->vfs_reads,
              s->vfs_writes, s->block_reads, s->block_writes, read_amp,
              write_amp, s->total_read_bytes / 1024.0 / 1024.0,
              s->total_write_bytes / 1024.0 / 1024.0, s->operation_count);

      total_syscall_r += s->syscall_reads;
      total_syscall_w += s->syscall_writes;
      total_vfs_r += s->vfs_reads;
      total_vfs_w += s->vfs_writes;
      total_block_r += s->block_reads;
      total_block_w += s->block_writes;
      total_read_bytes += s->total_read_bytes;
      total_write_bytes += s->total_write_bytes;
      total_operations += s->operation_count;
    }

    if (total_operations > 0) {
      double total_read_amp =
          total_syscall_r > 0
              ? (double)(total_vfs_r + total_block_r) / total_syscall_r
              : 0;
      double total_write_amp =
          total_syscall_w > 0
              ? (double)(total_vfs_w + total_block_w) / total_syscall_w
              : 0;

      fprintf(output_fp, "-----------------------------------------------------"
                         "---------------------------\n");
      fprintf(output_fp,
              "%-14s %7llu %7llu %7llu %7llu %7llu %7llu %8.2f %8.2f %8.2f "
              "%8.2f %10llu\n",
              "TOTAL", total_syscall_r, total_syscall_w, total_vfs_r,
              total_vfs_w, total_block_r, total_block_w, total_read_amp,
              total_write_amp, total_read_bytes / 1024.0 / 1024.0,
              total_write_bytes / 1024.0 / 1024.0, total_operations);
    }

    fprintf(output_fp, "\n=== EFFICIENCY INSIGHTS ===\n");

    // Data efficiency analysis
    struct comprehensive_io_stats *data_stats = &primary_stats[IO_PRIMARY_DATA];
    if (data_stats->operation_count > 0) {
      double data_read_amp =
          data_stats->syscall_reads > 0
              ? (double)(data_stats->vfs_reads + data_stats->block_reads) /
                    data_stats->syscall_reads
              : 0;
      double data_write_amp =
          data_stats->syscall_writes > 0
              ? (double)(data_stats->vfs_writes + data_stats->block_writes) /
                    data_stats->syscall_writes
              : 0;

      fprintf(output_fp,
              "📊 DATA Operations: %.2fx read, %.2fx write amplification\n",
              data_read_amp, data_write_amp);
      fprintf(output_fp,
              "   %.1f%% of total I/O operations (core storage workload)\n",
              (double)data_stats->operation_count / total_operations * 100);
    }

    // Metadata overhead analysis
    struct comprehensive_io_stats *meta_stats =
        &primary_stats[IO_PRIMARY_METADATA];
    if (meta_stats->operation_count > 0) {
      fprintf(output_fp,
              "🗂️  METADATA Overhead: %.1f%% of operations, %.1f%% of bytes\n",
              (double)meta_stats->operation_count / total_operations * 100,
              (double)(meta_stats->total_read_bytes +
                       meta_stats->total_write_bytes) /
                  (total_read_bytes + total_write_bytes) * 100);
    }

    // Filesystem overhead analysis
    struct comprehensive_io_stats *fs_stats =
        &primary_stats[IO_PRIMARY_FILESYSTEM];
    if (fs_stats->operation_count > 0) {
      double fs_write_amp =
          fs_stats->syscall_writes > 0
              ? (double)(fs_stats->vfs_writes + fs_stats->block_writes) /
                    fs_stats->syscall_writes
              : 0;
      fprintf(
          output_fp,
          "💿 FILESYSTEM Overhead: %.2fx write amplification from journaling\n",
          fs_write_amp);
      fprintf(output_fp, "   %.1f%% of total operations (system overhead)\n",
              (double)fs_stats->operation_count / total_operations * 100);
    }

    // Consistency overhead analysis
    struct comprehensive_io_stats *consistency_stats =
        &primary_stats[IO_PRIMARY_CONSISTENCY];
    if (consistency_stats->operation_count > 0) {
      fprintf(output_fp,
              "🔒 CONSISTENCY Overhead: %.1f%% of operations (WAL, Raft, "
              "transactions)\n",
              (double)consistency_stats->operation_count / total_operations *
                  100);
    }

    // Unknown I/O investigation
    if (unknown_events > 0) {
      fprintf(output_fp,
              "❓ UNKNOWN I/O: %d events (%.1f%%) - use -i flag for "
              "investigation\n",
              unknown_events, (double)unknown_events / total_events * 100);
    }

    fprintf(output_fp, "\n=== CATEGORY DESCRIPTIONS ===\n");
    for (int i = 1; i < 8; i++) { // Skip UNKNOWN for descriptions
      struct comprehensive_io_stats *s = &primary_stats[i];
      if (s->operation_count > 0) {
        fprintf(output_fp, "• %s: %s\n", s->name, s->description);
      }
    }

    if (env.investigate_mode) {
      fprintf(output_fp, "\n=== INVESTIGATION RECOMMENDATIONS ===\n");
      fprintf(
          output_fp,
          "• High UNKNOWN percentage suggests missing categorization rules\n");
      fprintf(output_fp,
              "• Check filename patterns in investigation output above\n");
      fprintf(
          output_fp,
          "• Consider adding new secondary categories for common patterns\n");
      fprintf(output_fp, "• Filesystem overhead may indicate suboptimal "
                         "storage configuration\n");
    }

    fprintf(output_fp, "\n=== RESEARCH VALUE ===\n");
    fprintf(output_fp,
            "• Use DATA amplification for storage efficiency comparison\n");
    fprintf(output_fp,
            "• METADATA overhead indicates system design efficiency\n");
    fprintf(output_fp,
            "• FILESYSTEM amplification shows infrastructure impact\n");
    fprintf(output_fp,
            "• CONSISTENCY overhead reveals distributed coordination costs\n");
  }
}

static int bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main(int argc, char **argv) {
  struct ring_buffer *rb = NULL;
  struct comprehensive_io_categorizer_bpf *skel;
  int err;

  err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
  if (err)
    return err;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  if (env.output_file) {
    output_fp = fopen(env.output_file, "w");
    if (!output_fp) {
      fprintf(stderr, "Failed to open output file %s: %s\n", env.output_file,
              strerror(errno));
      return 1;
    }
  } else {
    output_fp = stdout;
  }

  if (bump_memlock_rlimit()) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    return 1;
  }

  skel = comprehensive_io_categorizer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = comprehensive_io_categorizer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = comprehensive_io_categorizer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose) {
    fprintf(stderr, "Comprehensive Storage I/O Categorizer started!\n");
    fprintf(stderr, "Tracing: MinIO, Ceph, etcd, PostgreSQL, GlusterFS\n");
    if (env.focus_category)
      fprintf(stderr, "Focus: %s category\n", env.focus_category);
    if (env.investigate_mode)
      fprintf(stderr, "Investigation mode: ON (will analyze unknown I/O)\n");
    fprintf(stderr, "\n");
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                        NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  print_header();

  time_t start_time = time(NULL);
  while (!exiting) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }

    if (env.duration > 0 && (time(NULL) - start_time) >= env.duration) {
      if (env.verbose)
        fprintf(stderr, "Tracing completed after %d seconds\n", env.duration);
      break;
    }
  }

  print_comprehensive_summary();

cleanup:
  ring_buffer__free(rb);
  comprehensive_io_categorizer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
