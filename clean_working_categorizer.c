// Clean Working I/O Categorizer - Userspace Program
// File: clean_working_categorizer.c

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "clean_working_categorizer.skel.h"

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 64

// Primary categories
#define IO_PRIMARY_UNKNOWN 0
#define IO_PRIMARY_DATA 1
#define IO_PRIMARY_METADATA 2
#define IO_PRIMARY_CONSISTENCY 3
#define IO_PRIMARY_RELIABILITY 4
#define IO_PRIMARY_FILESYSTEM 5
#define IO_PRIMARY_TEMPORARY 6
#define IO_PRIMARY_ADMINISTRATIVE 7

// Context types
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
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 primary_category;
  __u32 context_type;
  __u64 size;
  __u64 latency_start;
  __u32 cpu_id;
  __s32 retval;
  char comm[MAX_COMM_LEN];
  char path_sample[MAX_PATH_LEN];
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
     "VFS/Block amplification layers (expected)"},
    {0, 0, 0, 0, 0, 0, 0, 0, "DATA", "Object/record storage operations"},
    {0, 0, 0, 0, 0, 0, 0, 0, "METADATA",
     "System metadata (.minio.sys, xl.meta)"},
    {0, 0, 0, 0, 0, 0, 0, 0, "CONSISTENCY", "WAL, Raft logs, transactions"},
    {0, 0, 0, 0, 0, 0, 0, 0, "RELIABILITY",
     "Replication, erasure coding, healing"},
    {0, 0, 0, 0, 0, 0, 0, 0, "FILESYSTEM", "Journal, allocation metadata"},
    {0, 0, 0, 0, 0, 0, 0, 0, "TEMPORARY", "Multipart uploads, staging"},
    {0, 0, 0, 0, 0, 0, 0, 0, "ADMIN", "Configuration, logging"}};

// Forward declarations
const char *get_context_name(__u32 context_type);
const char *get_event_type_name(int type);

static struct env {
  bool verbose;
  bool json_output;
  bool investigate_mode;
  bool realtime;
  int duration;
  int min_size;
  const char *output_file;
} env = {
    .verbose = false,
    .json_output = false,
    .investigate_mode = false,
    .realtime = true,
    .duration = 0,
    .min_size = 0,
    .output_file = NULL,
};

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"json", 'j', NULL, 0, "Output in JSON format"},
    {"investigate", 'i', NULL, 0,
     "Investigation mode: analyze amplification patterns"},
    {"duration", 'd', "DURATION", 0, "Trace for specified duration (seconds)"},
    {"output", 'o', "FILE", 0, "Output to file instead of stdout"},
    {"quiet", 'q', NULL, 0, "Disable real-time output, only show summary"},
    {"min-size", 'm', "SIZE", 0, "Minimum I/O size to show (bytes)"},
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
    .doc = "Working I/O categorizer with amplification analysis for storage "
           "systems research",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;
static int total_events = 0;
static int vfs_events = 0;
static int block_events = 0;
static int syscall_events = 0;

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

const char *get_context_name(__u32 context_type) {
  switch (context_type) {
  case CONTEXT_SYSCALL:
    return "SYSCALL_WITH_PATH";
  case CONTEXT_VFS_READ:
    return "VFS_READ_AMPLIFICATION";
  case CONTEXT_VFS_WRITE:
    return "VFS_WRITE_AMPLIFICATION";
  case CONTEXT_BLOCK_WRITE:
    return "BLOCK_WRITE_AMPLIFICATION";
  default:
    return "UNKNOWN_CONTEXT";
  }
}

static void update_stats(const struct clean_io_event *e) {
  if (e->primary_category >= 8)
    return;

  struct category_stats *s = &stats[e->primary_category];

  switch (e->event_type) {
  case EVENT_TYPE_SYSCALL_READ:
    s->syscall_reads++;
    s->total_read_bytes += e->size;
    s->operation_count++;
    syscall_events++;
    break;
  case EVENT_TYPE_SYSCALL_WRITE:
    s->syscall_writes++;
    s->total_write_bytes += e->size;
    s->operation_count++;
    syscall_events++;
    break;
  case EVENT_TYPE_VFS_READ:
    s->vfs_reads++;
    vfs_events++;
    break;
  case EVENT_TYPE_VFS_WRITE:
    s->vfs_writes++;
    vfs_events++;
    break;
  case EVENT_TYPE_BLOCK_WRITE:
    s->block_writes++;
    block_events++;
    break;
  }

  total_events++;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct clean_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Enhanced investigation for understanding amplification
  if (env.investigate_mode) {
    if (e->primary_category == IO_PRIMARY_UNKNOWN) {
      fprintf(stderr, "\n🔍 AMPLIFICATION LAYER #%d:\n", total_events + 1);
      fprintf(stderr, "   Process: %s (PID %u, CPU %u)\n", e->comm, e->pid,
              e->cpu_id);
      fprintf(stderr, "   Layer: %s\n", get_event_type_name(e->event_type));
      fprintf(stderr, "   Context: %s\n", get_context_name(e->context_type));

      if (e->event_type == EVENT_TYPE_VFS_READ ||
          e->event_type == EVENT_TYPE_VFS_WRITE) {
        fprintf(stderr,
                "   → This VFS operation was triggered by a recent syscall\n");
        fprintf(stderr, "   → Contributes to I/O amplification measurement\n");
      } else if (e->event_type == EVENT_TYPE_BLOCK_WRITE) {
        fprintf(stderr, "   → Final block device I/O operation\n");
        fprintf(stderr, "   → Shows actual storage device impact\n");
      }
    } else if (e->path_sample[0]) {
      fprintf(stderr, "\n📁 FILE OPERATION #%d:\n", total_events + 1);
      fprintf(stderr, "   Category: %s\n", stats[e->primary_category].name);
      fprintf(stderr, "   File: %s\n", e->path_sample);
      fprintf(stderr, "   Operation: %s (%llu bytes)\n",
              get_event_type_name(e->event_type), e->size);

      // Provide insights based on category
      switch (e->primary_category) {
      case IO_PRIMARY_DATA:
        fprintf(stderr, "   → Core storage workload (primary data)\n");
        break;
      case IO_PRIMARY_METADATA:
        fprintf(stderr, "   → Storage system metadata overhead\n");
        break;
      case IO_PRIMARY_ADMINISTRATIVE:
        fprintf(stderr, "   → Administrative overhead (config/logs)\n");
        break;
      case IO_PRIMARY_TEMPORARY:
        fprintf(stderr, "   → Temporary staging operation\n");
        break;
      }
    }
    fprintf(stderr, "\n");
  }

  update_stats(e);

  if (!env.realtime)
    return 0;

  // Filter small syscall I/O for display
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
    fprintf(output_fp,
            "{\"timestamp\":\"%s.%09llu\",\"pid\":%u,\"comm\":\"%s\","
            "\"event_type\":\"%s\",\"category\":\"%s\",\"context\":\"%s\","
            "\"size\":%llu,\"cpu_id\":%u,\"path_sample\":\"%s\","
            "\"latency_us\":%.2f,\"retval\":%d}\n",
            ts, e->timestamp % 1000000000, e->pid, e->comm,
            get_event_type_name(e->event_type), stats[e->primary_category].name,
            get_context_name(e->context_type), e->size, e->cpu_id,
            e->path_sample, e->latency_start / 1000.0, e->retval);
  } else {
    if (e->path_sample[0]) {
      fprintf(output_fp, "%s.%03llu %-15s %-10s %-8u %-8llu %8.2f %s\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0, e->path_sample);
    } else {
      fprintf(output_fp, "%s.%03llu %-15s %-10s %-8u %-8llu %8.2f [%s]\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0, get_context_name(e->context_type));
    }
  }

  fflush(output_fp);
  return 0;
}

static void print_header() {
  if (env.json_output || !env.realtime)
    return;

  fprintf(output_fp, "%-17s %-15s %-10s %-8s %-8s %8s %-40s\n", "TIME",
          "EVENT_TYPE", "CATEGORY", "PID", "SIZE", "LAT(us)",
          "PATH_OR_CONTEXT");
  fprintf(output_fp, "%s\n",
          "===================================================================="
          "============");
}

static void print_summary() {
  fprintf(output_fp, "\n=== STORAGE I/O AMPLIFICATION ANALYSIS ===\n");
  fprintf(output_fp, "Events: %d total (Syscall: %d, VFS: %d, Block: %d)\n",
          total_events, syscall_events, vfs_events, block_events);

  if (syscall_events > 0) {
    double vfs_amplification = (double)vfs_events / syscall_events;
    double block_amplification = (double)block_events / syscall_events;
    double total_amplification =
        (double)(vfs_events + block_events) / syscall_events;

    fprintf(output_fp, "\n=== AMPLIFICATION METRICS ===\n");
    fprintf(output_fp,
            "🔄 VFS Amplification: %.2fx (%d VFS ops / %d syscalls)\n",
            vfs_amplification, vfs_events, syscall_events);
    fprintf(output_fp,
            "💿 Block Amplification: %.2fx (%d block ops / %d syscalls)\n",
            block_amplification, block_events, syscall_events);
    fprintf(output_fp,
            "📊 Total I/O Amplification: %.2fx (complete storage stack)\n",
            total_amplification);
  }

  fprintf(output_fp, "\n=== CATEGORIZED OPERATIONS ===\n");
  fprintf(output_fp, "%-12s %6s %6s %6s %6s %6s %6s %6s %8s %8s %8s\n",
          "CATEGORY", "SYS_R", "SYS_W", "VFS_R", "VFS_W", "BLK_W", "R_AMP",
          "W_AMP", "READ_MB", "WRITE_MB", "OPS");
  fprintf(output_fp, "========================================================="
                     "=======================\n");

  __u64 total_ops = 0;
  for (int i = 0; i < 8; i++) {
    struct category_stats *s = &stats[i];
    if (s->operation_count == 0 && s->vfs_reads == 0 && s->vfs_writes == 0 &&
        s->block_writes == 0)
      continue;

    double read_amp =
        s->syscall_reads > 0 ? (double)s->vfs_reads / s->syscall_reads : 0;
    double write_amp =
        s->syscall_writes > 0
            ? (double)(s->vfs_writes + s->block_writes) / s->syscall_writes
            : 0;

    __u64 total_category_ops =
        s->operation_count + s->vfs_reads + s->vfs_writes + s->block_writes;

    fprintf(
        output_fp,
        "%-12s %6llu %6llu %6llu %6llu %6llu %6.2f %6.2f %8.2f %8.2f %8llu\n",
        s->name, s->syscall_reads, s->syscall_writes, s->vfs_reads,
        s->vfs_writes, s->block_writes, read_amp, write_amp,
        s->total_read_bytes / 1024.0 / 1024.0,
        s->total_write_bytes / 1024.0 / 1024.0, total_category_ops);

    total_ops += total_category_ops;
  }

  fprintf(output_fp, "\n=== KEY INSIGHTS FOR FAST 2026 RESEARCH ===\n");
  fprintf(output_fp,
          "• SYSCALL operations: Application-level I/O with file context\n");
  fprintf(
      output_fp,
      "• VFS operations: Kernel VFS layer amplification (expected UNKNOWN)\n");
  fprintf(output_fp, "• BLOCK operations: Final device I/O amplification "
                     "(expected UNKNOWN)\n");
  fprintf(
      output_fp,
      "• UNKNOWN category: Mostly amplification layers without file context\n");
  fprintf(output_fp,
          "• Total amplification = (VFS + Block) / Syscall operations\n");

  if (stats[IO_PRIMARY_DATA].operation_count > 0) {
    double data_percentage =
        (double)stats[IO_PRIMARY_DATA].operation_count / total_ops * 100;
    fprintf(output_fp, "\n🎯 DATA Operations: %.1f%% of total I/O\n",
            data_percentage);

    if (stats[IO_PRIMARY_DATA].syscall_writes > 0) {
      double data_write_amp = (double)(stats[IO_PRIMARY_DATA].vfs_writes +
                                       stats[IO_PRIMARY_DATA].block_writes) /
                              stats[IO_PRIMARY_DATA].syscall_writes;
      fprintf(output_fp, "   Data write amplification: %.2fx\n",
              data_write_amp);
    }
  }

  if (stats[IO_PRIMARY_METADATA].operation_count > 0) {
    double meta_percentage =
        (double)stats[IO_PRIMARY_METADATA].operation_count / total_ops * 100;
    fprintf(output_fp, "🗂️  METADATA Overhead: %.1f%% of operations\n",
            meta_percentage);
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
  struct clean_working_categorizer_bpf *skel;
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

  skel = clean_working_categorizer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = clean_working_categorizer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = clean_working_categorizer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose) {
    fprintf(stderr, "🔬 Research-Grade I/O Categorizer started!\n");
    fprintf(stderr, "📊 Measuring: Syscall → VFS → Block amplification\n");
    fprintf(stderr, "📁 Categories: DATA, METADATA, CONSISTENCY, RELIABILITY, "
                    "FILESYSTEM, TEMPORARY, ADMIN\n");
    if (env.investigate_mode)
      fprintf(
          stderr,
          "🔍 Investigation mode: Detailed amplification analysis enabled\n");
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
  clean_working_categorizer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
