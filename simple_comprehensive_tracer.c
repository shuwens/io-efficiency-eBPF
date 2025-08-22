// Simple Comprehensive I/O Tracer - Userspace program
// File: simple_comprehensive_tracer.c

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "simple_comprehensive_tracer.skel.h"

#define MAX_COMM_LEN 16

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
#define EVENT_TYPE_BLOCK_WRITE 5

struct simple_comprehensive_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 primary_category;
  __u64 size;
  __u64 offset;
  __u64 latency_start;
  __u32 dev_major;
  __u32 dev_minor;
  __u32 cpu_id;
  __u32 stack_depth;
  __s32 retval;
  char comm[MAX_COMM_LEN];
  char path_sample[64];
  char context_info[32];
};

struct category_stats {
  __u64 syscall_reads;
  __u64 syscall_writes;
  __u64 vfs_reads;
  __u64 vfs_writes;
  __u64 block_writes;
  __u64 total_read_bytes;
  __u64 total_write_bytes;
  __u64 operation_count;
  const char *name;
  const char *description;
};

static struct category_stats stats[8] = {
    {0, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN",
     "Unclassified I/O requiring investigation"},
    {0, 0, 0, 0, 0, 0, 0, 0, "DATA",
     "Primary object/record storage operations"},
    {0, 0, 0, 0, 0, 0, 0, 0, "METADATA",
     "System and object metadata (.minio.sys, xl.meta)"},
    {0, 0, 0, 0, 0, 0, 0, 0, "CONSISTENCY",
     "WAL, Raft logs, transaction coordination"},
    {0, 0, 0, 0, 0, 0, 0, 0, "RELIABILITY",
     "Replication, erasure coding, healing"},
    {0, 0, 0, 0, 0, 0, 0, 0, "FILESYSTEM",
     "Journal, allocation metadata, inode ops"},
    {0, 0, 0, 0, 0, 0, 0, 0, "TEMPORARY",
     "Multipart uploads, staging, cleanup"},
    {0, 0, 0, 0, 0, 0, 0, 0, "ADMIN", "Configuration, logging, monitoring"}};

static struct env {
  bool verbose;
  bool json_output;
  bool investigate_mode;
  bool show_amplification_correlation;
  bool realtime;
  int duration;
  int min_size;
  const char *output_file;
} env = {
    .verbose = false,
    .json_output = false,
    .investigate_mode = false,
    .show_amplification_correlation = false,
    .realtime = true,
    .duration = 0,
    .min_size = 0,
    .output_file = NULL,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"json", 'j', NULL, 0, "Output in JSON format"},
    {"investigate", 'i', NULL, 0,
     "Investigation mode: analyze unknown I/O patterns"},
    {"correlate", 'c', NULL, 0, "Show amplification correlation analysis"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {"quiet", 'q', NULL, 0, "Disable real-time output, only show summary"},
    {"min-size", 'm', "SIZE", 0, "Minimum I/O size to track (bytes)"},
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
  case 'i':
    env.investigate_mode = true;
    break;
  case 'c':
    env.show_amplification_correlation = true;
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
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = "Research-grade I/O categorization for storage systems based on "
           "comprehensive analysis",
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
  case EVENT_TYPE_BLOCK_WRITE:
    return "BLOCK_WRITE";
  default:
    return "UNKNOWN";
  }
}

static void update_stats(const struct simple_comprehensive_event *e) {
  if (e->primary_category >= 8)
    return;

  struct category_stats *s = &stats[e->primary_category];

  switch (e->event_type) {
  case EVENT_TYPE_SYSCALL_READ:
    s->syscall_reads++;
    s->total_read_bytes += e->size;
    s->operation_count++;
    break;
  case EVENT_TYPE_SYSCALL_WRITE:
    s->syscall_writes++;
    s->total_write_bytes += e->size;
    s->operation_count++;
    break;
  case EVENT_TYPE_VFS_READ:
    s->vfs_reads++;
    break;
  case EVENT_TYPE_VFS_WRITE:
    s->vfs_writes++;
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
  const struct simple_comprehensive_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Enhanced investigation mode with context analysis
  if (env.investigate_mode && e->primary_category == IO_PRIMARY_UNKNOWN &&
      (e->event_type == EVENT_TYPE_SYSCALL_READ ||
       e->event_type == EVENT_TYPE_SYSCALL_WRITE ||
       e->event_type == EVENT_TYPE_VFS_READ ||
       e->event_type == EVENT_TYPE_VFS_WRITE ||
       e->event_type == EVENT_TYPE_BLOCK_WRITE)) {

    fprintf(stderr, "\n🔍 INVESTIGATING UNKNOWN I/O #%d:\n",
            unknown_events + 1);
    fprintf(stderr, "   Process: %s (PID %u, TID %u, CPU %u)\n", e->comm,
            e->pid, e->tid, e->cpu_id);
    fprintf(stderr, "   Operation: %s", get_event_type_name(e->event_type));

    if (e->size > 0) {
      fprintf(stderr, " (%llu bytes", e->size);
      if (e->offset > 0)
        fprintf(stderr, ", offset %llu", e->offset);
      fprintf(stderr, ")");
    }
    fprintf(stderr, "\n");

    if (e->path_sample[0]) {
      fprintf(stderr, "   File: '%s'\n", e->path_sample);
    } else {
      fprintf(stderr, "   File: <no path available>\n");
    }

    if (e->context_info[0]) {
      fprintf(stderr, "   Context: %s\n", e->context_info);
    }

    // Enhanced analysis hints
    if (e->event_type == EVENT_TYPE_VFS_READ ||
        e->event_type == EVENT_TYPE_VFS_WRITE) {
      fprintf(stderr, "   Analysis: VFS operation (amplification layer)\n");
      fprintf(stderr, "   → Likely corresponds to recent syscall operation\n");
      fprintf(stderr, "   → Check temporal correlation with syscall events\n");
    } else if (e->event_type == EVENT_TYPE_BLOCK_WRITE) {
      fprintf(stderr, "   Analysis: Block operation (device layer)\n");
      fprintf(stderr, "   → Final I/O to storage device\n");
      fprintf(stderr, "   → Shows actual amplification impact\n");
      if (e->size > 0) {
        fprintf(stderr, "   → Block size: %llu bytes, sector: %llu\n", e->size,
                e->offset / 512);
      }
    } else if (e->path_sample[0]) {
      fprintf(stderr, "   Analysis: Syscall with path available\n");
      fprintf(stderr, "   Patterns: ");
      if (strstr(e->path_sample, "/"))
        fprintf(stderr, "[PATH] ");
      if (strstr(e->path_sample, "."))
        fprintf(stderr, "[EXT] ");
      if (strstr(e->path_sample, "tmp"))
        fprintf(stderr, "[TMP] ");
      if (strstr(e->path_sample, "log"))
        fprintf(stderr, "[LOG] ");
      if (strstr(e->path_sample, "meta"))
        fprintf(stderr, "[META] ");
      if (strstr(e->path_sample, "data"))
        fprintf(stderr, "[DATA] ");
      if (strstr(e->path_sample, "config"))
        fprintf(stderr, "[CONFIG] ");
      if (strstr(e->path_sample, "journal"))
        fprintf(stderr, "[JOURNAL] ");
      fprintf(stderr, "\n");
      fprintf(stderr, "   → Consider adding pattern to categorization logic\n");
    }

    fprintf(stderr, "\n");
  }

  update_stats(e);

  if (!env.realtime)
    return 0;

  // Filter small I/O for display
  if (env.min_size > 0 &&
      (e->event_type == EVENT_TYPE_SYSCALL_READ ||
       e->event_type == EVENT_TYPE_SYSCALL_WRITE) &&
      (int)e->size < env.min_size) {
    return 0;
  }

  t = e->timestamp / 1000000000;
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  if (env.json_output) {
    fprintf(
        output_fp,
        "{\"timestamp\":\"%s.%09llu\",\"pid\":%u,\"tid\":%u,\"comm\":\"%s\","
        "\"event_type\":\"%s\",\"category\":\"%s\",\"size\":%llu,\"offset\":%"
        "llu,"
        "\"cpu_id\":%u,\"path_sample\":\"%s\",\"context_info\":\"%s\","
        "\"latency_us\":%.2f,\"retval\":%d}\n",
        ts, e->timestamp % 1000000000, e->pid, e->tid, e->comm,
        get_event_type_name(e->event_type), stats[e->primary_category].name,
        e->size, e->offset, e->cpu_id, e->path_sample, e->context_info,
        e->latency_start / 1000.0, e->retval);
  } else {
    if (e->path_sample[0]) {
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-8u %-8llu %8.2f %-30s\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0, e->path_sample);
    } else {
      // Enhanced display for no_path operations
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-8u %-8llu %8.2f [%s] CPU%u\n",
              ts, (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0,
              e->context_info[0] ? e->context_info : "NO_CONTEXT", e->cpu_id);
    }
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  fprintf(output_fp, "%-17s %-15s %-12s %-8s %-8s %8s %-35s\n", "TIME",
          "EVENT_TYPE", "CATEGORY", "PID", "SIZE", "LAT(us)",
          "PATH_OR_CONTEXT");
  fprintf(output_fp, "%s\n",
          "===================================================================="
          "============");
}

static void print_summary() {
  fprintf(output_fp, "\n=== RESEARCH-GRADE STORAGE I/O ANALYSIS ===\n");
  fprintf(output_fp, "Total Events: %d (%.1f%% classified)\n", total_events,
          total_events > 0
              ? (double)(total_events - unknown_events) / total_events * 100
              : 0);

  fprintf(output_fp, "\n%-14s %8s %8s %8s %8s %8s %8s %8s %8s %8s %10s\n",
          "CATEGORY", "SYS_R", "SYS_W", "VFS_R", "VFS_W", "BLK_W", "R_AMP",
          "W_AMP", "READ_MB", "WRITE_MB", "OPS");
  fprintf(output_fp, "========================================================="
                     "=======================\n");

  __u64 total_syscall_r = 0, total_syscall_w = 0;
  __u64 total_vfs_r = 0, total_vfs_w = 0, total_block_w = 0;
  __u64 total_read_bytes = 0, total_write_bytes = 0, total_ops = 0;

  for (int i = 0; i < 8; i++) {
    struct category_stats *s = &stats[i];
    if (s->operation_count == 0)
      continue;

    double read_amp =
        s->syscall_reads > 0 ? (double)s->vfs_reads / s->syscall_reads : 0;
    double write_amp =
        s->syscall_writes > 0
            ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
            : 0;

    fprintf(
        output_fp,
        "%-14s %8llu %8llu %8llu %8llu %8llu %8.2f %8.2f %8.2f %8.2f %10llu\n",
        s->name, s->syscall_reads, s->syscall_writes, s->vfs_reads,
        s->vfs_writes, s->block_writes, read_amp, write_amp,
        s->total_read_bytes / 1024.0 / 1024.0,
        s->total_write_bytes / 1024.0 / 1024.0, s->operation_count);

    total_syscall_r += s->syscall_reads;
    total_syscall_w += s->syscall_writes;
    total_vfs_r += s->vfs_reads;
    total_vfs_w += s->vfs_writes;
    total_block_w += s->block_writes;
    total_read_bytes += s->total_read_bytes;
    total_write_bytes += s->total_write_bytes;
    total_ops += s->operation_count;
  }

  if (total_ops > 0) {
    double total_read_amp =
        total_syscall_r > 0 ? (double)total_vfs_r / total_syscall_r : 0;
    double total_write_amp =
        total_syscall_w > 0
            ? (double)(total_vfs_w + total_block_w) / total_syscall_w
            : 0;

    fprintf(output_fp, "-------------------------------------------------------"
                       "-------------------------\n");
    fprintf(
        output_fp,
        "%-14s %8llu %8llu %8llu %8llu %8llu %8.2f %8.2f %8.2f %8.2f %10llu\n",
        "TOTAL", total_syscall_r, total_syscall_w, total_vfs_r, total_vfs_w,
        total_block_w, total_read_amp, total_write_amp,
        total_read_bytes / 1024.0 / 1024.0, total_write_bytes / 1024.0 / 1024.0,
        total_ops);
  }

  fprintf(output_fp, "\n=== KEY RESEARCH INSIGHTS ===\n");
  if (stats[IO_PRIMARY_DATA].operation_count > 0) {
    double data_efficiency =
        (double)stats[IO_PRIMARY_DATA].operation_count / total_ops * 100;
    fprintf(
        output_fp,
        "📊 DATA efficiency: %.1f%% of operations are core storage workload\n",
        data_efficiency);
  }

  if (stats[IO_PRIMARY_METADATA].operation_count > 0) {
    double meta_overhead =
        (double)stats[IO_PRIMARY_METADATA].operation_count / total_ops * 100;
    fprintf(output_fp, "🗂️  METADATA overhead: %.1f%% of operations\n",
            meta_overhead);
  }

  if (stats[IO_PRIMARY_FILESYSTEM].operation_count > 0) {
    double fs_overhead =
        (double)stats[IO_PRIMARY_FILESYSTEM].operation_count / total_ops * 100;
    fprintf(output_fp, "💿 FILESYSTEM overhead: %.1f%% (journaling impact)\n",
            fs_overhead);
  }

  if (unknown_events > 0) {
    fprintf(output_fp, "❓ UNKNOWN: %d events (%.1f%%) - analyzing below:\n",
            unknown_events, (double)unknown_events / total_events * 100);

    fprintf(output_fp, "\n=== UNKNOWN I/O BREAKDOWN ===\n");
    fprintf(output_fp, "• VFS operations: These are amplification layers "
                       "without file context\n");
    fprintf(output_fp, "• Block operations: Final device I/O operations\n");
    fprintf(
        output_fp,
        "• Use context_info field to understand operation characteristics\n");
    fprintf(output_fp, "• Temporal correlation with syscall operations reveals "
                       "amplification\n");
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
  struct simple_comprehensive_tracer_bpf *skel;
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

  skel = simple_comprehensive_tracer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = simple_comprehensive_tracer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = simple_comprehensive_tracer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose) {
    fprintf(stderr, "Research-grade Storage I/O Categorizer started!\n");
    fprintf(stderr, "Categories: DATA, METADATA, CONSISTENCY, RELIABILITY, "
                    "FILESYSTEM, TEMPORARY, ADMIN\n");
    if (env.investigate_mode)
      fprintf(stderr,
              "Investigation mode: Will analyze unknown I/O patterns\n");
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

  print_summary();

cleanup:
  ring_buffer__free(rb);
  simple_comprehensive_tracer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
