// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0)
// Copyright 2024 BOANLab @ DKU

//go:build ignore

/*************/
/* Headers   */
/*************/
#ifndef __TARGET_ARCH_x86
    #define __TARGET_ARCH_x86 1
#endif

#include "vmlinux.h"
#include "libbpf/src/bpf_core_read.h"
#include "libbpf/src/bpf_helpers.h"
#include "libbpf/src/bpf_tracing.h"
#include <errno.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/****************************/
/* Syscall ID Enumeration   */
/****************************/
enum syscall_id {
    // File Operations
    SYS_OPEN = 1,
    SYS_OPENAT = 2,
    SYS_CLOSE = 3,
    SYS_UNLINK = 4,
    SYS_UNLINKAT = 5,
    SYS_CHOWN = 6,
    SYS_FCHOWNAT = 7,
    SYS_MOUNT = 8,
    SYS_UMOUNT = 9,
    SYS_READ = 10,
    SYS_WRITE = 11,
    SYS_PREAD64 = 12,
    SYS_PWRITE64 = 13,
    SYS_LSEEK = 14,
    SYS_STAT = 15,
    SYS_FSTAT = 16,
    SYS_LSTAT = 17,
    SYS_FCNTL = 18,
    SYS_FSYNC = 19,
    SYS_FDATASYNC = 20,
    SYS_SYNC = 21,

    // Network Operations
    SYS_SOCKET = 22,
    SYS_CONNECT = 23,
    SYS_ACCEPT = 24,
    SYS_BIND = 25,
    SYS_LISTEN = 26,

    // Process Management
    SYS_EXECVE = 27,
    SYS_EXECVEAT = 28,
    SYS_CLONE = 29,
    SYS_FORK = 30,
    SYS_VFORK = 31,
    SYS_EXIT = 32,
    SYS_EXIT_GROUP = 33,
    SYS_WAIT4 = 34,
    SYS_WAITID = 35,

    // File Descriptor Operations
    SYS_DUP = 36,
    SYS_DUP2 = 37,
    SYS_DUP3 = 38,

    // Memory Management
    SYS_MMAP = 39,
    SYS_MUNMAP = 40,
    SYS_MPROTECT = 41,
    SYS_MADVISE = 42,
    SYS_BRK = 43,

    // Signals
    SYS_SIGNAL = 44,
    SYS_KILL = 45,
    SYS_TGKILL = 46,
    SYS_TKILL = 47,

    // Timers
    SYS_TIMER_CREATE = 48,
    SYS_TIMER_SETTIME = 49,
    SYS_TIMER_GETTIME = 50,
    SYS_TIMER_GETOVERRUN = 51,
    SYS_TIMER_DELETE = 52,

    // User and Group Management
    SYS_SETUID = 53,
    SYS_SETGID = 54,
    SYS_GETUID = 55,
    SYS_GETEUID = 56,
    SYS_GETGID = 57,
    SYS_GETEGID = 58,

    // System Information
    SYS_GETPID = 59,
    SYS_GETPPID = 60,
    SYS_UNAME = 61,
    SYS_GETRLIMIT = 62,
    SYS_SETRLIMIT = 63,
    SYS_GETRUSAGE = 64,
};

/***********************************/
/* Syscall Category Enumeration    */
/***********************************/
// Used in default_context.event_type to classify events for Go-side dispatching.
enum syscall_category {
    FILE_OPERATION = 0,
    NETWORK_OPERATION,
    PROCESS_MANAGEMENT,
    FILE_DESCRIPTOR,
    MEMORY_MANAGEMENT,
    SIGNALS,
    TIMERS,
    USER_AND_GROUP_MANAGEMENT,
    SYSTEM_INFORMATION,
};

/****************************/
/* Buffer Size Constants    */
/****************************/
#define TASK_COMM_LEN 16
#define DIR_NAME_LEN 4096
#define FILE_NAME_LEN 256
#define EXE_PATH_LEN 256
#define SYSTEM_NAME_LEN 80
#define KERNEL_VERSION_LEN 80
#define MAX_LOOP_DIRNAME 25
#define MAX_STRING_SIZE 4096

// Network and filesystem constants
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

/*****************************/
/* Event Context Structures  */
/*****************************/

// container_key uniquely identifies a container using its Linux namespace IDs.
// This is used as the key in the container_map BPF hash map.
typedef struct container_key {
  u32 pid_ns;
  u32 mnt_ns;
} container_key;

// default_context is the base event header shared by all syscall categories.
// Every event starts with this structure, followed by category-specific fields.
// NOTE: The C compiler inserts 4 bytes of padding between event_type and ret_value
// due to s64's 8-byte alignment requirement. The Go EventHeader struct must account for this.
typedef struct default_context {
    u64 ts;

    struct container_key ck;

    u32 host_ppid;
    u32 host_pid;

    u32 ppid;
    u32 pid;
    u32 uid;

    u32 syscall_id;
    u32 event_type;
    s64 ret_value;
    char comm[TASK_COMM_LEN];
} default_context;

// file_opration_context extends default_context with file path information.
typedef struct file_opration_context {
    struct default_context basic;

    char dirname[DIR_NAME_LEN];
    char filename[FILE_NAME_LEN];
} file_opration_context;

// network_opration_context extends default_context with destination IP and port.
typedef struct network_opration_context {
    struct default_context basic;

    u32 dest_ipv4;
    u16 dest_port;
} network_opration_context;

// process_management_context extends default_context with executable path.
typedef struct process_management_context {
    struct default_context basic;

    char exe_path[EXE_PATH_LEN];
    char dirname[DIR_NAME_LEN];
    // argv
    // ENV
} process_management_context;

// file_descriptor_context extends default_context with old/new file descriptors.
typedef struct file_descriptor_context {
    struct default_context basic;

    char exe_path[EXE_PATH_LEN];
    u32 old_fd;
    u32 new_fd;
} file_descriptor_context;

// memory_management_context extends default_context with memory operation size.
typedef struct memory_management_context {
    struct default_context basic;

    // start-address
    // finish-address
    // flag
    u64 size;
} memory_management_context;

// signals_context extends default_context with signal number and target/sender PIDs.
typedef struct signals_context {
    struct default_context basic;

    u32 signum;
    u32 sender_pid;
    u32 target_pid;
} signals_context;

// timers_context extends default_context for timer-related syscalls.
typedef struct timers_context {
    struct default_context basic;

    // ID
    // Interval
    // Expiration
} timers_context;

// user_and_group_management_context extends default_context for uid/gid syscalls.
typedef struct user_and_group_management_context {
    struct default_context basic;
} user_and_group_management_context;

// system_information_context extends default_context with uname fields.
typedef struct system_information_context {
    struct default_context basic;

    char systemname[SYSTEM_NAME_LEN];
    char kernelversion[KERNEL_VERSION_LEN];
} system_information_context;

// Unused variable declarations to ensure bpf2go generates Go type definitions
// for these structs. Without these, bpf2go only generates types that appear in maps.
const struct container_key *unused1 __attribute__((unused));
const struct default_context *unused2 __attribute__((unused));
const struct file_opration_context *unused3 __attribute__((unused));
const struct network_opration_context *unused4 __attribute__((unused));
const struct process_management_context *unused5 __attribute__((unused));
const struct file_descriptor_context *unused6 __attribute__((unused));
const struct memory_management_context *unused7 __attribute__((unused));
const struct signals_context *unused8 __attribute__((unused));
const struct timers_context *unused9 __attribute__((unused));
const struct user_and_group_management_context *unused10 __attribute__((unused));
const struct system_information_context *unused11 __attribute__((unused));

/***********************/
/* BPF Map Definitions */
/***********************/

// container_map: Hash map for container filtering.
// Key: container_key (PID ns + MNT ns), Value: u16 (1 = monitored).
// Go userspace populates this map when containers are discovered.
// eBPF programs check this map to skip events from non-monitored namespaces.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct container_key);
    __type(value, u16);
    __uint(max_entries, 65535);
} container_map SEC(".maps");

// kprobe_map: Ring buffer for kprobe (syscall entry) events.
// Size: 16 MB. Events are submitted from kprobe handlers and read by Go userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} kprobe_map SEC(".maps");

// kretprobe_map: Ring buffer for kretprobe (syscall exit) events.
// Size: 16 MB. Events include syscall return values via PT_REGS_RC(ctx).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} kretprobe_map SEC(".maps");

/*****************************/
/* Common Helper Functions   */
/*****************************/

// READ_KERN: Safely reads a kernel memory value using BPF CO-RE.
// Initializes the destination to zero, then reads from the source pointer.
#define READ_KERN(ptr)                                     \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })

// is_container checks if the given namespace IDs belong to a monitored container
// by looking up the container_map. Returns 1 if found, 0 otherwise.
static __always_inline u8 is_container(u32 pid_id, u32 mnt_id) {
     struct container_key container_key = {
        .pid_ns = pid_id,
        .mnt_ns = mnt_id,
    };
    u16 *value;

    value = bpf_map_lookup_elem(&container_map, &container_key);
    return value != NULL;
}

/************************************/
/* Default Context Parsing          */
/************************************/

// default_parsing populates the common event header (default_context) with:
//   - Timestamp, PID/MNT namespace IDs
//   - Host and container-level PID/PPID
//   - UID, syscall ID, event type, process command name
// Returns NULL if the event is from a non-monitored namespace (container filter).
static __always_inline default_context * default_parsing(enum syscall_id syscall_id, enum syscall_category event_type, default_context *event, struct pt_regs *ctx) {
    event->ts = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = READ_KERN(task->nsproxy);
    struct pid_namespace *pidns = READ_KERN(ns->pid_ns_for_children);
    event->ck.pid_ns = READ_KERN(pidns->ns.inum);

    struct mnt_namespace *mntns = READ_KERN(ns->mnt_ns);
    event->ck.mnt_ns = READ_KERN(mntns->ns.inum);

    if (!is_container(event->ck.pid_ns, event->ck.mnt_ns)) {
        return NULL;
    }

    struct task_struct *parent = READ_KERN(task->parent);

    event->host_ppid = READ_KERN(parent->pid);
    event->host_pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *real_parent = READ_KERN(task->real_parent);
    struct pid *pid = READ_KERN(real_parent->thread_pid);
    unsigned int level = READ_KERN(pid->level);
    event->ppid = READ_KERN(pid->numbers[level].nr);

    struct task_struct *group_leader = READ_KERN(task->group_leader);
    pid = READ_KERN(group_leader->thread_pid);
    level = READ_KERN(pid->level);
    event->pid = READ_KERN(pid->numbers[level].nr);

    event->uid = bpf_get_current_uid_gid();
    event->syscall_id = syscall_id;
    event->event_type = event_type;
    event->ret_value = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    return event;
}

/************************************/
/* File Path Resolution             */
/************************************/

// real_mount converts a vfsmount pointer to its parent mount structure.
static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

// bufs_t: Per-CPU buffer for safe string operations in eBPF programs.
// Used during directory path construction to avoid stack overflow.
typedef struct buffers
{
    u8 buf[32768];
} bufs_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, bufs_t);
    __uint(max_entries, 4);
} bufs SEC(".maps");


#define CWD_BUF_TYPE 3

// get_buffer retrieves a per-CPU buffer for string construction.
static __always_inline bufs_t *get_buffer(int buf_type) {
    return bpf_map_lookup_elem(&bufs, &buf_type);
}

// get_full_path resolves the full filesystem path by walking the dentry tree
// from the given path up to the root. Handles mount point traversal.
// The result is written to dest as a null-terminated string.
static __always_inline int get_full_path(struct path *path, char *dest) {
    if (path == NULL) {
        return 1;
    }

    char slash = '/';
    char null = '\0';
    int offset = MAX_STRING_SIZE;

    struct dentry *dentry = path->dentry;
    struct vfsmount *vfsmnt = path->mnt;

    struct mount *mnt = real_mount(vfsmnt);

    struct dentry *parent;
    struct dentry *mnt_root;
    struct mount *m;
    struct qstr d_name;

    bufs_t *string_p = get_buffer(CWD_BUF_TYPE);
    if (string_p == NULL) {
        return 1;
    }

#pragma unroll
    for (int i = 0; i < MAX_LOOP_DIRNAME; i++) {
        bpf_probe_read(&parent, sizeof(struct dentry *), &dentry->d_parent);
        bpf_probe_read(&mnt_root, sizeof(struct dentry *), &vfsmnt->mnt_root);

        if (dentry == mnt_root) {
            bpf_probe_read(&m, sizeof(struct mount *), &mnt->mnt_parent);
            if (mnt != m) {
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt->mnt_mountpoint);
                bpf_probe_read(&mnt, sizeof(struct mount *), &mnt->mnt_parent);
                vfsmnt = &mnt->mnt;
                continue;
            }
            break;
        }

        if (dentry == parent) {
            break;
        }

        // get d_name
        bpf_probe_read(&d_name, sizeof(struct qstr), &dentry->d_name);
        offset -= (d_name.len + 1);
        if (offset < 0) {
            break;
        }

        int sz = bpf_probe_read_str(&(string_p->buf[(offset) & (MAX_STRING_SIZE - 1)]), (d_name.len + 1) & (MAX_STRING_SIZE - 1), d_name.name);
        if (sz > 1) {
            bpf_probe_read(&(string_p->buf[(offset + d_name.len) & (MAX_STRING_SIZE - 1)]), 1, &slash);
        }
        else {
            offset += (d_name.len + 1);
        }

        dentry = parent;
    }

    if (offset == MAX_STRING_SIZE) {
        return 1;
    }

    bpf_probe_read(&(string_p->buf[MAX_STRING_SIZE - 1]), 1, &null);
    offset--;

    bpf_probe_read(&(string_p->buf[offset & (MAX_STRING_SIZE - 1)]), 1, &slash);

    bpf_probe_read(dest, offset & (MAX_STRING_SIZE - 1), &string_p->buf[offset & (MAX_STRING_SIZE - 1)]);

    return 0;
}

/************************************/
/* File Operation Parsing           */
/************************************/

// get_filename_using_pathname reads a user-space pathname string into dest.
static __always_inline int get_filename_using_pathname(char *pathname, char *dest, size_t dest_len) {
    if (!pathname || dest_len == 0) {
        return 1;
    }

    bpf_probe_read_user_str(dest, dest_len, pathname);
    return 0;
}

// get_dirname_using_dirfd resolves the directory path from a dirfd.
// Handles AT_FDCWD (current working directory) and explicit directory FDs.
static __always_inline int get_dirname_using_dirfd(int dirfd, char *dest, size_t dest_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *fs = READ_KERN(task->fs);
    struct path fs_path;

    if (dirfd == AT_FDCWD) {
        fs_path = READ_KERN(fs->pwd);
    } else if (dirfd >= 0) {
        struct files_struct *files = (struct files_struct *)READ_KERN(task->files);
        struct fdtable *fdt = (struct fdtable *)READ_KERN(files->fdt);
        struct file **fd_array = (struct file **)READ_KERN(fdt->fd);
        struct file *f = READ_KERN(fd_array[dirfd]);

        if (!f) {
            return 1;
        }

        fs_path = READ_KERN(f->f_path);
    } else {
        return 1;
    }

    if (get_full_path(&fs_path, dest)) {
        return 1;
    }

    return 0;
}

// get_filename_using_fd resolves the file name from an open file descriptor
// by walking the kernel's file -> dentry -> d_name chain.
static __always_inline int get_filename_using_fd(int fd, char *dest, size_t dest_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = READ_KERN(task->files);
    struct fdtable *fdt = READ_KERN(files->fdt);
    struct file **fd_array = READ_KERN(fdt->fd);

    if (fd >= 0) {
        struct file *f = READ_KERN(fd_array[fd]);
        if (f) {
            struct path f_path = READ_KERN(f->f_path);
            struct dentry *dentry = READ_KERN(f_path.dentry);
            struct qstr d_name = READ_KERN(dentry->d_name);

            bpf_probe_read_kernel(dest, dest_len, d_name.name);
        }
    }

    return 0;
}

// parsing_file_operation_kprobe extracts file operation context from syscall entry.
// Parses pathname/fd/dirfd based on the specific syscall to populate dirname/filename.
static __always_inline int parsing_file_operation_kprobe(enum syscall_id syscall_id, file_opration_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, FILE_OPERATION, &event->basic, ctx)) {
        return 0;
    }

    char *pathname = NULL;
    int dirfd = 0;
    int fd = 0;

    switch (syscall_id) {
        case SYS_OPEN:
            pathname = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_OPENAT:
            dirfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            pathname = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_dirname_using_dirfd(dirfd, event->dirname, sizeof(event->dirname)) ||
                get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_CLOSE:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_UNLINK:
            pathname = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_UNLINKAT:
            dirfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            pathname = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_dirname_using_dirfd(dirfd, event->dirname, sizeof(event->dirname)) ||
                get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_CHOWN:
            pathname = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_FCHOWNAT:
            dirfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            pathname = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_dirname_using_dirfd(dirfd, event->dirname, sizeof(event->dirname)) ||
                get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_READ:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_WRITE:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_PREAD64:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_PWRITE64:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_LSEEK:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_STAT:
            pathname = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_FSTAT:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_LSTAT:
            pathname = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_pathname(pathname, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_FCNTL:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_FSYNC:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_FDATASYNC:
            fd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_filename_using_fd(fd, event->filename, sizeof(event->filename))) {
                return 0;
            }
            break;

        case SYS_SYNC:
            break;

        default:
            break;
    }

    return 1;
}

// parsing_file_operation_kretprobe captures the syscall return value at exit.
static __always_inline int parsing_file_operation_kretprobe(enum syscall_id syscall_id, file_opration_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, FILE_OPERATION, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Network Operation Parsing        */
/************************************/

// get_destport_using_addr extracts the destination port from a sockaddr_in structure.
// Only processes AF_INET (IPv4) addresses; returns 1 for non-IPv4.
static __always_inline int get_destport_using_addr(char *addr, network_opration_context *event) {
    struct sockaddr* sa = (struct sockaddr *)addr;
    struct sockaddr_in* poop = (struct sockaddr_in*) addr;

    sa_family_t family;
    bpf_probe_read(&family, sizeof(family), &poop->sin_family);
    if (family != AF_INET) {
        return 1;
    }

    uint16_t port;
    bpf_probe_read(&port, sizeof(port), &poop->sin_port);

    event->dest_port = port;

    return 0;
}

// get_destip_using_addr extracts the destination IPv4 address from a sockaddr_in.
static __always_inline int get_destip_using_addr(char *addr, network_opration_context *event) {
    struct sockaddr* sa = (struct sockaddr *)addr;
    struct sockaddr_in* poop = (struct sockaddr_in*) addr;

    sa_family_t family;
    bpf_probe_read(&family, sizeof(family), &poop->sin_family);
    if (family != AF_INET) {
        return 1;
    }

    uint32_t in_addr;
    bpf_probe_read(&in_addr, sizeof(in_addr), &poop->sin_addr);

    event->dest_ipv4 = in_addr;

    return 0;
}

// parsing_network_operation_kprobe extracts network operation context at syscall entry.
// Parses destination IP/port from sockaddr for connect, accept, and bind.
static __always_inline int parsing_network_operation_kprobe(enum syscall_id syscall_id, network_opration_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, NETWORK_OPERATION, &event->basic, ctx)) {
        return 0;
    }

    char *addr = NULL;

    switch (syscall_id) {
        case SYS_SOCKET:
            break;

        case SYS_CONNECT:
            addr = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_destport_using_addr(addr, event)) {
                return 0;
            }
            if (get_destip_using_addr(addr, event)) {
                return 0;
            }
            break;

        case SYS_ACCEPT:
            addr = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_destport_using_addr(addr, event)) {
                return 0;
            }
            if (get_destip_using_addr(addr, event)) {
                return 0;
            }
            break;

        case SYS_BIND:
            addr = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_destport_using_addr(addr, event)) {
                return 0;
            }
            if (get_destip_using_addr(addr, event)) {
                return 0;
            }
            break;

        case SYS_LISTEN:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_network_operation_kretprobe(enum syscall_id syscall_id, network_opration_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, NETWORK_OPERATION, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Process Management Parsing       */
/************************************/
static __always_inline int get_exepath_using_filename(char *filename, char *dest, size_t dest_len) {
    if (!filename || dest_len == 0) {
        return 1;
    }

    bpf_probe_read_user_str(dest, dest_len, filename);
    return 0;
}

static __always_inline int get_exepath_using_pathname(char *pathname, char *dest, size_t dest_len) {
    if (!pathname || dest_len == 0) {
        return 1;
    }

    bpf_probe_read_user_str(dest, dest_len, pathname);
    return 0;
}

static __always_inline int parsing_process_management_kprobe(enum syscall_id syscall_id, process_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, PROCESS_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }

    char *filename = NULL;
    int dirfd = 0;
    char *pathname= NULL;

    switch (syscall_id) {
        case SYS_EXECVE:
            filename = (char *)READ_KERN(PT_REGS_PARM1(ctx));
            if (get_exepath_using_filename(filename, event->exe_path, sizeof(event->exe_path))) {
                return 0;
            }
            break;
        case SYS_EXECVEAT:
            dirfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            pathname = (char *)READ_KERN(PT_REGS_PARM2(ctx));
            if (get_dirname_using_dirfd(dirfd, event->dirname, sizeof(event->dirname)) ||
                get_exepath_using_pathname(pathname, event->exe_path, sizeof(event->exe_path))) {
                return 0;
            }
            break;
        case SYS_CLONE:
            break;
        case SYS_FORK:
            break;
        case SYS_VFORK:
            break;
        case SYS_EXIT:
            break;
        case SYS_EXIT_GROUP:
            break;
        case SYS_WAIT4:
            break;
        case SYS_WAITID:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_process_management_kretprobe(enum syscall_id syscall_id, process_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, PROCESS_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* File Descriptor Parsing          */
/************************************/
static __always_inline int get_fd_using_oldfd_or_newfd(u32 fd, u32* destfd) {
    *destfd = fd;
    return 0;
}


static __always_inline int parsing_file_descriptor_kprobe(enum syscall_id syscall_id, file_descriptor_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, FILE_DESCRIPTOR, &event->basic, ctx)) {
        return 0;
    }

    u32 oldfd =0;
    u32 newfd = 0;

    switch (syscall_id) {
        case SYS_DUP:
            oldfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            get_fd_using_oldfd_or_newfd(oldfd, &event->old_fd);
            break;
        case SYS_DUP2:
            oldfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            newfd = (int)READ_KERN(PT_REGS_PARM2(ctx));
            get_fd_using_oldfd_or_newfd(oldfd, &event->old_fd);
            get_fd_using_oldfd_or_newfd(newfd, &event->new_fd);
            break;
        case SYS_DUP3:
            oldfd = (int)READ_KERN(PT_REGS_PARM1(ctx));
            newfd = (int)READ_KERN(PT_REGS_PARM2(ctx));
            get_fd_using_oldfd_or_newfd(oldfd, &event->old_fd);
            get_fd_using_oldfd_or_newfd(newfd, &event->new_fd);
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_file_descriptor_kretprobe(enum syscall_id syscall_id, file_descriptor_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, FILE_DESCRIPTOR, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Memory Management Parsing        */
/************************************/
static __always_inline int parsing_memory_management_kprobe(enum syscall_id syscall_id, memory_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, MEMORY_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }

    switch (syscall_id) {
        case SYS_MMAP:
            // SYS_MMAP: (void *addr, size_t length, int prot, int flags, int fd, off_t offset)
            event->size = (u64)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        case SYS_MUNMAP:
            // SYS_MUNMAP: (void *addr, size_t length)
            event->size = (u64)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        case SYS_MPROTECT:
            // SYS_MPROTECT: (void *addr, size_t len, int prot)
            event->size = (u64)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        case SYS_MADVISE:
            // SYS_MADVISE: (void *addr, size_t length, int advice)
            event->size = (u64)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        case SYS_BRK:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_memory_management_kretprobe(enum syscall_id syscall_id, memory_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, MEMORY_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Signals Parsing                  */
/************************************/
static __always_inline int parsing_signals_kprobe(enum syscall_id syscall_id, signals_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, SIGNALS, &event->basic, ctx)) {
        return 0;
    }

    event->sender_pid = event->basic.pid;

    switch (syscall_id) {
        case SYS_SIGNAL:
            // SYS_SIGNAL: (int signum, sighandler_t handler)
            event->signum = (u32)READ_KERN(PT_REGS_PARM1(ctx));
            break;
        case SYS_KILL:
            // SYS_KILL: (pid_t pid, int sig)
            event->target_pid = (u32)READ_KERN(PT_REGS_PARM1(ctx));
            event->signum = (u32)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        case SYS_TGKILL:
            // SYS_TGKILL: (int tgid, int tid, int sig)
            event->target_pid = (u32)READ_KERN(PT_REGS_PARM2(ctx));
            event->signum = (u32)READ_KERN(PT_REGS_PARM3(ctx));
            break;
        case SYS_TKILL:
            // SYS_TKILL: (int tid, int sig)
            event->target_pid = (u32)READ_KERN(PT_REGS_PARM1(ctx));
            event->signum = (u32)READ_KERN(PT_REGS_PARM2(ctx));
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_signals_kretprobe(enum syscall_id syscall_id, signals_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, SIGNALS, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Timers Parsing                   */
/************************************/
static __always_inline int parsing_timers_kprobe(enum syscall_id syscall_id, timers_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, TIMERS, &event->basic, ctx)) {
        return 0;
    }

    switch (syscall_id) {
        case SYS_TIMER_CREATE:
            break;
        case SYS_TIMER_SETTIME:
            break;
        case SYS_TIMER_GETTIME:
            break;
        case SYS_TIMER_GETOVERRUN:
            break;
        case SYS_TIMER_DELETE:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_timers_kretprobe(enum syscall_id syscall_id, timers_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, TIMERS, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* User & Group Management Parsing  */
/************************************/
static __always_inline int parsing_user_and_group_management_kprobe(enum syscall_id syscall_id, user_and_group_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, USER_AND_GROUP_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }

    switch (syscall_id) {
        case SYS_SETUID:
            break;
        case SYS_SETGID:
            break;
        case SYS_GETUID:
            break;
        case SYS_GETEUID:
            break;
        case SYS_GETGID:
            break;
        case SYS_GETEGID:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_user_and_group_management_kretprobe(enum syscall_id syscall_id, user_and_group_management_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, USER_AND_GROUP_MANAGEMENT, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* System Information Parsing       */
/************************************/
static __always_inline int parsing_system_information_kprobe(enum syscall_id syscall_id, system_information_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, SYSTEM_INFORMATION, &event->basic, ctx)) {
        return 0;
    }

    switch (syscall_id) {
        case SYS_GETPID:
            break;
        case SYS_GETPPID:
            break;
        case SYS_UNAME:
            break;
        case SYS_GETRLIMIT:
            break;
        case SYS_SETRLIMIT:
            break;
        case SYS_GETRUSAGE:
            break;
        default:
            break;
    }

    return 1;
}

static __always_inline int parsing_system_information_kretprobe(enum syscall_id syscall_id, system_information_context *event, struct pt_regs *ctx) {
    if (!default_parsing(syscall_id, SYSTEM_INFORMATION, &event->basic, ctx)) {
        return 0;
    }
    event->basic.ret_value = (s64)PT_REGS_RC(ctx);
    return 1;
}

/************************************/
/* Kprobe/Kretprobe Dispatch        */
/************************************/

// handle_kprobe is the central dispatcher for all kprobe (syscall entry) hooks.
// It reserves ring buffer space based on the syscall category, parses the context,
// and submits the event. If parsing fails (e.g., non-container namespace), the
// reserved space is discarded.
static __always_inline int handle_kprobe(struct pt_regs *ctx2, enum syscall_id syscall_id, enum syscall_category syscall_type) {
    void *event;
    struct pt_regs *ctx = (struct pt_regs *)PT_REGS_PARM1(ctx2);

    switch (syscall_type) {
        case FILE_OPERATION:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(file_opration_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_file_operation_kprobe(syscall_id, (file_opration_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case NETWORK_OPERATION:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(network_opration_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_network_operation_kprobe(syscall_id, (network_opration_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case PROCESS_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(process_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_process_management_kprobe(syscall_id, (process_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case FILE_DESCRIPTOR:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(file_descriptor_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_file_descriptor_kprobe(syscall_id, (file_descriptor_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case MEMORY_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(memory_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_memory_management_kprobe(syscall_id, (memory_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case SIGNALS:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(signals_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_signals_kprobe(syscall_id, (signals_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case TIMERS:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(timers_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_timers_kprobe(syscall_id, (timers_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case USER_AND_GROUP_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(user_and_group_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_user_and_group_management_kprobe(syscall_id, (user_and_group_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case SYSTEM_INFORMATION:
            event = bpf_ringbuf_reserve(&kprobe_map, sizeof(system_information_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_system_information_kprobe(syscall_id, (system_information_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        default:
            return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// DEFINE_KPROBE: Macro to generate kprobe SEC programs.
// Each generated function calls handle_kprobe with the appropriate syscall ID and category.
#define DEFINE_KPROBE(probe_name, syscall_id, syscall_type)              \
    SEC("kprobe/"#probe_name)                                         \
    int kprobe_##probe_name(struct pt_regs *ctx) {                    \
        return handle_kprobe(ctx, syscall_id, syscall_type);             \
    }

// handle_kretprobe is the central dispatcher for all kretprobe (syscall exit) hooks.
// Similar to handle_kprobe, but uses kretprobe_map and captures return values
// via PT_REGS_RC(ctx) in each category's kretprobe parser.
static __always_inline int handle_kretprobe(struct pt_regs *ctx, enum syscall_id syscall_id, enum syscall_category syscall_type) {
    void *event;

    switch (syscall_type) {
        case FILE_OPERATION:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(file_opration_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_file_operation_kretprobe(syscall_id, (file_opration_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case NETWORK_OPERATION:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(network_opration_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_network_operation_kretprobe(syscall_id, (network_opration_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case PROCESS_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(process_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_process_management_kretprobe(syscall_id, (process_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case FILE_DESCRIPTOR:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(file_descriptor_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_file_descriptor_kretprobe(syscall_id, (file_descriptor_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case MEMORY_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(memory_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_memory_management_kretprobe(syscall_id, (memory_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case SIGNALS:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(signals_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_signals_kretprobe(syscall_id, (signals_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case TIMERS:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(timers_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_timers_kretprobe(syscall_id, (timers_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case USER_AND_GROUP_MANAGEMENT:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(user_and_group_management_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_user_and_group_management_kretprobe(syscall_id, (user_and_group_management_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        case SYSTEM_INFORMATION:
            event = bpf_ringbuf_reserve(&kretprobe_map, sizeof(system_information_context), 0);
            if (!event) {
                return 0;
            }
            if (!parsing_system_information_kretprobe(syscall_id, (system_information_context *)event, ctx)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }
            break;
        default:
            return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// DEFINE_KRETPROBE: Macro to generate kretprobe SEC programs.
// Each generated function calls handle_kretprobe with the appropriate syscall ID and category.
#define DEFINE_KRETPROBE(probe_name, syscall_id, syscall_type)           \
    SEC("kretprobe/"#probe_name)                                      \
    int kretprobe_##probe_name(struct pt_regs *ctx) {                 \
        return handle_kretprobe(ctx, syscall_id, syscall_type);          \
    }

/****************************************/
/* Kprobe Program Definitions (Entry)   */
/****************************************/
// File Operations (21 syscalls)
DEFINE_KPROBE(__x64_sys_open, SYS_OPEN, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_openat, SYS_OPENAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_close, SYS_CLOSE, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_unlink, SYS_UNLINK, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_unlinkat, SYS_UNLINKAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_chown, SYS_CHOWN, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_fchownat, SYS_FCHOWNAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_mount, SYS_MOUNT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_umount, SYS_UMOUNT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_read, SYS_READ, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_write, SYS_WRITE, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_pread64, SYS_PREAD64, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_pwrite64, SYS_PWRITE64, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_lseek, SYS_LSEEK, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_stat, SYS_STAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_fstat, SYS_FSTAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_lstat, SYS_LSTAT, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_fcntl, SYS_FCNTL, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_fsync, SYS_FSYNC, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_fdatasync, SYS_FDATASYNC, FILE_OPERATION)
DEFINE_KPROBE(__x64_sys_sync, SYS_SYNC, FILE_OPERATION)

// Network Operations (5 syscalls)
DEFINE_KPROBE(__x64_sys_socket, SYS_SOCKET, NETWORK_OPERATION)
DEFINE_KPROBE(__x64_sys_connect, SYS_CONNECT, NETWORK_OPERATION)
DEFINE_KPROBE(__x64_sys_accept, SYS_ACCEPT, NETWORK_OPERATION)
DEFINE_KPROBE(__x64_sys_bind, SYS_BIND, NETWORK_OPERATION)
DEFINE_KPROBE(__x64_sys_listen, SYS_LISTEN, NETWORK_OPERATION)

// Process Management (9 syscalls)
DEFINE_KPROBE(__x64_sys_execve, SYS_EXECVE, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_execveat, SYS_EXECVEAT, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_clone, SYS_CLONE, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_fork, SYS_FORK, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_vfork, SYS_VFORK, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_exit, SYS_EXIT, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_exit_group, SYS_EXIT_GROUP, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_wait4, SYS_WAIT4, PROCESS_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_waitid, SYS_WAITID, PROCESS_MANAGEMENT)

// File Descriptor Operations (3 syscalls)
DEFINE_KPROBE(__x64_sys_dup, SYS_DUP, FILE_DESCRIPTOR)
DEFINE_KPROBE(__x64_sys_dup2, SYS_DUP2, FILE_DESCRIPTOR)
DEFINE_KPROBE(__x64_sys_dup3, SYS_DUP3, FILE_DESCRIPTOR)

// Memory Management (5 syscalls)
DEFINE_KPROBE(__x64_sys_mmap, SYS_MMAP, MEMORY_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_munmap, SYS_MUNMAP, MEMORY_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_mprotect, SYS_MPROTECT, MEMORY_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_madvise, SYS_MADVISE, MEMORY_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_brk, SYS_BRK, MEMORY_MANAGEMENT)

// Signals (4 syscalls)
DEFINE_KPROBE(__x64_sys_signal, SYS_SIGNAL, SIGNALS)
DEFINE_KPROBE(__x64_sys_kill, SYS_KILL, SIGNALS)
DEFINE_KPROBE(__x64_sys_tgkill, SYS_TGKILL, SIGNALS)
DEFINE_KPROBE(__x64_sys_tkill, SYS_TKILL, SIGNALS)

// Timers (5 syscalls)
DEFINE_KPROBE(__x64_sys_timer_create, SYS_TIMER_CREATE, TIMERS)
DEFINE_KPROBE(__x64_sys_timer_settime, SYS_TIMER_SETTIME, TIMERS)
DEFINE_KPROBE(__x64_sys_timer_gettime, SYS_TIMER_GETTIME, TIMERS)
DEFINE_KPROBE(__x64_sys_timer_getoverrun, SYS_TIMER_GETOVERRUN, TIMERS)
DEFINE_KPROBE(__x64_sys_timer_delete, SYS_TIMER_DELETE, TIMERS)

// User & Group Management (6 syscalls)
DEFINE_KPROBE(__x64_sys_setuid, SYS_SETUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_setgid, SYS_SETGID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_getuid, SYS_GETUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_geteuid, SYS_GETEUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_getgid, SYS_GETGID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KPROBE(__x64_sys_getegid, SYS_GETEGID, USER_AND_GROUP_MANAGEMENT)

// System Information (6 syscalls)
DEFINE_KPROBE(__x64_sys_getpid, SYS_GETPID, SYSTEM_INFORMATION)
DEFINE_KPROBE(__x64_sys_getppid, SYS_GETPPID, SYSTEM_INFORMATION)
DEFINE_KPROBE(__x64_sys_uname, SYS_UNAME, SYSTEM_INFORMATION)
DEFINE_KPROBE(__x64_sys_getrlimit, SYS_GETRLIMIT, SYSTEM_INFORMATION)
DEFINE_KPROBE(__x64_sys_setrlimit, SYS_SETRLIMIT, SYSTEM_INFORMATION)
DEFINE_KPROBE(__x64_sys_getrusage, SYS_GETRUSAGE, SYSTEM_INFORMATION)

/****************************************/
/* Kretprobe Program Definitions (Exit) */
/****************************************/
// File Operations
DEFINE_KRETPROBE(__x64_sys_open, SYS_OPEN, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_openat, SYS_OPENAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_close, SYS_CLOSE, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_unlink, SYS_UNLINK, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_unlinkat, SYS_UNLINKAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_chown, SYS_CHOWN, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_fchownat, SYS_FCHOWNAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_mount, SYS_MOUNT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_umount, SYS_UMOUNT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_read, SYS_READ, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_write, SYS_WRITE, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_pread64, SYS_PREAD64, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_pwrite64, SYS_PWRITE64, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_lseek, SYS_LSEEK, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_stat, SYS_STAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_fstat, SYS_FSTAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_lstat, SYS_LSTAT, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_fcntl, SYS_FCNTL, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_fsync, SYS_FSYNC, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_fdatasync, SYS_FDATASYNC, FILE_OPERATION)
DEFINE_KRETPROBE(__x64_sys_sync, SYS_SYNC, FILE_OPERATION)

DEFINE_KRETPROBE(__x64_sys_socket, SYS_SOCKET, NETWORK_OPERATION)
DEFINE_KRETPROBE(__x64_sys_connect, SYS_CONNECT, NETWORK_OPERATION)
DEFINE_KRETPROBE(__x64_sys_accept, SYS_ACCEPT, NETWORK_OPERATION)
DEFINE_KRETPROBE(__x64_sys_bind, SYS_BIND, NETWORK_OPERATION)
DEFINE_KRETPROBE(__x64_sys_listen, SYS_LISTEN, NETWORK_OPERATION)

DEFINE_KRETPROBE(__x64_sys_execve, SYS_EXECVE, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_execveat, SYS_EXECVEAT, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_clone, SYS_CLONE, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_fork, SYS_FORK, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_vfork, SYS_VFORK, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_exit, SYS_EXIT, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_exit_group, SYS_EXIT_GROUP, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_wait4, SYS_WAIT4, PROCESS_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_waitid, SYS_WAITID, PROCESS_MANAGEMENT)

DEFINE_KRETPROBE(__x64_sys_dup, SYS_DUP, FILE_DESCRIPTOR)
DEFINE_KRETPROBE(__x64_sys_dup2, SYS_DUP2, FILE_DESCRIPTOR)
DEFINE_KRETPROBE(__x64_sys_dup3, SYS_DUP3, FILE_DESCRIPTOR)

DEFINE_KRETPROBE(__x64_sys_mmap, SYS_MMAP, MEMORY_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_munmap, SYS_MUNMAP, MEMORY_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_mprotect, SYS_MPROTECT, MEMORY_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_madvise, SYS_MADVISE, MEMORY_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_brk, SYS_BRK, MEMORY_MANAGEMENT)

DEFINE_KRETPROBE(__x64_sys_signal, SYS_SIGNAL, SIGNALS)
DEFINE_KRETPROBE(__x64_sys_kill, SYS_KILL, SIGNALS)
DEFINE_KRETPROBE(__x64_sys_tgkill, SYS_TGKILL, SIGNALS)
DEFINE_KRETPROBE(__x64_sys_tkill, SYS_TKILL, SIGNALS)

DEFINE_KRETPROBE(__x64_sys_timer_create, SYS_TIMER_CREATE, TIMERS)
DEFINE_KRETPROBE(__x64_sys_timer_settime, SYS_TIMER_SETTIME, TIMERS)
DEFINE_KRETPROBE(__x64_sys_timer_gettime, SYS_TIMER_GETTIME, TIMERS)
DEFINE_KRETPROBE(__x64_sys_timer_getoverrun, SYS_TIMER_GETOVERRUN, TIMERS)
DEFINE_KRETPROBE(__x64_sys_timer_delete, SYS_TIMER_DELETE, TIMERS)

DEFINE_KRETPROBE(__x64_sys_setuid, SYS_SETUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_setgid, SYS_SETGID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_getuid, SYS_GETUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_geteuid, SYS_GETEUID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_getgid, SYS_GETGID, USER_AND_GROUP_MANAGEMENT)
DEFINE_KRETPROBE(__x64_sys_getegid, SYS_GETEGID, USER_AND_GROUP_MANAGEMENT)

DEFINE_KRETPROBE(__x64_sys_getpid, SYS_GETPID, SYSTEM_INFORMATION)
DEFINE_KRETPROBE(__x64_sys_getppid, SYS_GETPPID, SYSTEM_INFORMATION)
DEFINE_KRETPROBE(__x64_sys_uname, SYS_UNAME, SYSTEM_INFORMATION)
DEFINE_KRETPROBE(__x64_sys_getrlimit, SYS_GETRLIMIT, SYSTEM_INFORMATION)
DEFINE_KRETPROBE(__x64_sys_setrlimit, SYS_SETRLIMIT, SYSTEM_INFORMATION)
DEFINE_KRETPROBE(__x64_sys_getrusage, SYS_GETRUSAGE, SYSTEM_INFORMATION)
