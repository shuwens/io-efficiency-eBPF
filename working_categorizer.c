// Working I/O Categorizer - Enhanced userspace program
// File: working_categorizer.c

#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "working_categorizer.skel.h"

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
#define CONTEXT_VFS_READ 1
#define CONTEXT_VFS_WRITE 2
#define CONTEXT_BLOCK_READ 3
#define CONTEXT_BLOCK_WRITE 4
#define CONTEXT_SYNC 5
#define CONTEXT_LARGE_IO 6

// Event types
#define EVENT_TYPE_SYSCALL_READ 1
#define EVENT_TYPE_SYSCALL_WRITE 2
#define EVENT_TYPE_VFS_READ 3
#define EVENT_TYPE_VFS_WRITE 4
#define EVENT_TYPE_BLOCK_WRITE 5

struct working_io_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 event_type;
  __u32 primary_category;
  __u32 context_type;
  __u64 size;
  __u64 offset;
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
     "Unclassified - VFS/block amplification layers"},
    {0, 0, 0, 0, 0, 0, 0, 0, "DATA",
     "Object storage, key-value data, database records"},
    {0, 0, 0, 0, 0, 0, 0, 0, "METADATA",
     "System metadata (.minio.sys, xl.meta, indexes)"},
    {0, 0, 0, 0, 0, 0, 0, 0, "CONSISTENCY",
     "WAL, Raft logs, transaction coordination"},
    {0, 0, 0, 0, 0, 0, 0, 0, "RELIABILITY",
     "Replication, erasure coding, data healing"},
    {0, 0, 0, 0, 0, 0, 0, 0, "FILESYSTEM",
     "Journal, allocation metadata, inode ops"},
    {0, 0, 0, 0, 0, 0, 0, 0, "TEMPORARY",
     "Multipart uploads, staging, cleanup"},
    {0, 0, 0, 0, 0, 0, 0, 0, "ADMIN", "Configuration, logging, monitoring"}};

const char *get_context_name(__u32 context_type) {
  switch (context_type) {
  case CONTEXT_VFS_READ:
    return "VFS_READ_AMP";
  case CONTEXT_VFS_WRITE:
    return "VFS_WRITE_AMP";
  case CONTEXT_BLOCK_READ:
    return "BLOCK_READ_AMP";
  case CONTEXT_BLOCK_WRITE:
    return "BLOCK_WRITE_AMP";
  case CONTEXT_SYNC:
    return "SYNC_OPERATION";
  case CONTEXT_LARGE_IO:
    return "LARGE_IO";
  default:
    return "SYSCALL_WITH_PATH";
  }
}

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
     "Investigation mode: analyze all I/O patterns"},
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
    .doc = "Enhanced I/O categorization with amplification context analysis",
};

static volatile bool exiting = false;
static FILE *output_fp = NULL;
static int total_events = 0;
static int vfs_events = 0;
static int block_events = 0;
static int syscall_events = 0;

// Forward declaration
const char *get_context_name(__u32 context_type);
const char *get_event_type_name(int type);

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

static void update_stats(const struct working_io_event *e) {
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
  const struct working_io_event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  // Enhanced investigation for ALL unknown operations
  if (env.investigate_mode && e->primary_category == IO_PRIMARY_UNKNOWN) {
    fprintf(stderr, "\n🔍 ANALYZING I/O #%d:\n", total_events + 1);
    fprintf(stderr, "   Process: %s (PID %u, CPU %u)\n", e->comm, e->pid,
            e->cpu_id);
    fprintf(stderr, "   Layer: %s", get_event_type_name(e->event_type));

    if (e->event_type == EVENT_TYPE_SYSCALL_READ ||
        e->event_type == EVENT_TYPE_SYSCALL_WRITE) {
      fprintf(stderr, " → Application layer (has file context)");
    } else if (e->event_type == EVENT_TYPE_VFS_READ ||
               e->event_type == EVENT_TYPE_VFS_WRITE) {
      fprintf(stderr, " → VFS amplification layer");
    } else if (e->event_type == EVENT_TYPE_BLOCK_WRITE) {
      fprintf(stderr, " → Block device layer (final I/O)");
    }
    fprintf(stderr, "\n");

    if (e->size > 0) {
      fprintf(stderr, "   Size: %llu bytes", e->size);
      if (e->offset > 0)
        fprintf(stderr, " (offset %llu)", e->offset);
      fprintf(stderr, "\n");
    }

    if (e->path_sample[0]) {
      fprintf(stderr, "   File: '%s'\n", e->path_sample);
      fprintf(stderr, "   Context: %s\n", get_context_name(e->context_type));
    } else {
      fprintf(stderr, "   File: <no path> - %s\n",
              get_context_name(e->context_type));
      if (e->event_type == EVENT_TYPE_VFS_READ ||
          e->event_type == EVENT_TYPE_VFS_WRITE) {
        fprintf(stderr, "   → This is AMPLIFICATION: VFS operation triggered "
                        "by recent syscall\n");
      } else if (e->event_type == EVENT_TYPE_BLOCK_WRITE) {
        fprintf(stderr,
                "   → This is AMPLIFICATION: Block I/O from VFS operations\n");
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
            "\"size\":%llu,\"offset\":%llu,\"cpu_id\":%u,"
            "\"path_sample\":\"%s\",\"latency_us\":%.2f}\n",
            ts, e->timestamp % 1000000000, e->pid, e->comm,
            get_event_type_name(e->event_type), stats[e->primary_category].name,
            get_context_name(e->context_type), e->size, e->offset, e->cpu_id,
            e->path_sample, e->latency_start / 1000.0);
  } else {
    if (e->path_sample[0]) {
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-8u %-8llu %8.2f %s\n", ts,
              (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0, e->path_sample);
    } else {
      fprintf(output_fp, "%s.%03llu %-15s %-12s %-8u %-8llu %8.2f [%s] CPU%u\n",
              ts, (e->timestamp % 1000000000) / 1000000,
              get_event_type_name(e->event_type),
              stats[e->primary_category].name, e->pid, e->size,
              e->latency_start / 1000.0, get_context_name(e->context_type),
              e->cpu_id);
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
  fprintf(output_fp,
          "\n=== ENHANCED I/O ANALYSIS WITH AMPLIFICATION CONTEXT ===\n");
  fprintf(output_fp, "Total Events: %d (Syscall: %d, VFS: %d, Block: %d)\n",
          total_events, syscall_events, vfs_events, block_events);

  if (syscall_events > 0) {
    double vfs_amplification = (double)vfs_events / syscall_events;
    double block_amplification = (double)block_events / syscall_events;
    double total_amplification =
        (double)(vfs_events + block_events) / syscall_events;

    fprintf(output_fp, "\n=== AMPLIFICATION ANALYSIS ===\n");
    fprintf(output_fp, "VFS Amplification: %.2fx (%d VFS ops / %d syscalls)\n",
            vfs_amplification, vfs_events, syscall_events);
    fprintf(output_fp,
            "Block Amplification: %.2fx (%d block ops / %d syscalls)\n",
            block_amplification, block_events, syscall_events);
    fprintf(output_fp, "Total Amplification: %.2fx (complete storage stack)\n",
            total_amplification);
  }

  fprintf(output_fp, "\n%-14s %8s %8s %8s %8s %8s %8s %8s %8s %8s %10s\n",
          "CATEGORY", "SYS_R", "SYS_W", "VFS_R", "VFS_W", "BLK_W", "R_AMP",
          "W_AMP", "READ_MB", "WRITE_MB", "OPS");
  fprintf(output_fp, "========================================================="
                     "=======================\n");

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
  }

  fprintf(output_fp, "\n=== AMPLIFICATION INSIGHTS ===\n");
  fprintf(output_fp,
          "• UNKNOWN events are mostly VFS/block amplification layers\n");
  fprintf(output_fp, "• Each syscall triggers multiple VFS operations (read "
                     "caching, write buffering)\n");
  fprintf(
      output_fp,
      "• Block operations show final device I/O (journaling, allocation)\n");
  fprintf(output_fp,
          "• Use investigation mode (-i) to see detailed breakdown\n");

  if (stats[IO_PRIMARY_DATA].operation_count > 0) {
    fprintf(output_fp, "\n=== DATA OPERATIONS EFFICIENCY ===\n");
    struct category_stats *data = &stats[IO_PRIMARY_DATA];
    if (data->syscall_writes > 0) {
      double data_write_amp = (double)(data->vfs_writes + data->block_writes) /
                              data->syscall_writes;
      fprintf(output_fp, "Data write amplification: %.2fx\n", data_write_amp);
    }
    if (data->syscall_reads > 0) {
      double data_read_amp = (double)data->vfs_reads / data->syscall_reads;
      fprintf(output_fp, "Data read amplification: %.2fx\n", data_read_amp);
    }
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
  struct working_categorizer_bpf *skel;
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

  skel = working_categorizer_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = working_categorizer_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = working_categorizer_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  if (env.verbose) {
    fprintf(stderr,
            "Enhanced I/O Categorizer with Amplification Analysis started!\n");
    fprintf(stderr,
            "Tracking: Syscall→VFS→Block amplification with file context\n");
    if (env.investigate_mode)
      fprintf(stderr, "Investigation mode: Will analyze ALL I/O layers\n");
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
  working_categorizer_bpf__destroy(skel);

  if (output_fp != stdout)
    fclose(output_fp);

  return err < 0 ? -err : 0;
}
