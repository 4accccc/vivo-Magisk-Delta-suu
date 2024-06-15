#include <unistd.h>
#include <string>
#include <cinttypes>
#include <android/log.h>

#include <base.hpp>
#include <core.hpp>

#include "deny.hpp"

using namespace std;

extern "C" {

struct logger_entry {
    uint16_t len;      /* length of the payload */
    uint16_t hdr_size; /* sizeof(struct logger_entry) */
    int32_t pid;       /* generating process's pid */
    uint32_t tid;      /* generating process's tid */
    uint32_t sec;      /* seconds since Epoch */
    uint32_t nsec;     /* nanoseconds */
    uint32_t lid;      /* log id of the payload, bottom 4 bits currently */
    uint32_t uid;      /* generating process's uid */
};

#define LOGGER_ENTRY_MAX_LEN (5 * 1024)
struct log_msg {
    union [[gnu::aligned(4)]] {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry entry;
    };
};

typedef struct AndroidLogEntry_t {
    time_t tv_sec;
    long tv_nsec;
    android_LogPriority priority;
    int32_t uid;
    int32_t pid;
    int32_t tid;
    const char *tag;
    size_t tagLen;
    size_t messageLen;
    const char *message;
} AndroidLogEntry;

[[gnu::weak]] struct logger_list *android_logger_list_alloc(int mode, unsigned int tail, pid_t pid);
[[gnu::weak]] void android_logger_list_free(struct logger_list *list);
[[gnu::weak]] int android_logger_list_read(struct logger_list *list, struct log_msg *log_msg);
[[gnu::weak]] struct logger *android_logger_open(struct logger_list *list, log_id_t id);
[[gnu::weak]] int android_log_processLogBuffer(struct logger_entry *buf, AndroidLogEntry *entry);

typedef struct [[gnu::packed]] {
    int32_t tag;    // Little Endian Order
} android_event_header_t;

typedef struct [[gnu::packed]] {
    int8_t type;    // EVENT_TYPE_INT
    int32_t data;   // Little Endian Order
} android_event_int_t;

typedef struct [[gnu::packed]] {
    int8_t type;    // EVENT_TYPE_STRING;
    int32_t length; // Little Endian Order
    char data[];
} android_event_string_t;

typedef struct [[gnu::packed]] {
    int8_t type;    // EVENT_TYPE_LIST
    int8_t element_count;
} android_event_list_t;

// 30014 am_proc_start (User|1|5),(PID|1|5),(UID|1|5),(Process Name|3),(Type|3),(Component|3)
typedef struct [[gnu::packed]] {
    android_event_header_t tag;
    android_event_list_t list;
    android_event_int_t user;
    android_event_int_t pid;
    android_event_int_t uid;
    android_event_string_t process_name;
//  android_event_string_t type;
//  android_event_string_t component;
} android_event_am_proc_start;

// 3040 boot_progress_ams_ready (time|2|3)

}

// zygote pid -> mnt ns
static map<int, struct stat> zygote_map;
bool logcat_exit;

static int read_ns(const int pid, struct stat *st) {
    char path[32];
    sprintf(path, "/proc/%d/ns/mnt", pid);
    return stat(path, st);
}

static int parse_ppid(int pid) {
    char path[32];
    int ppid;
    sprintf(path, "/proc/%d/stat", pid);
    auto stat = open_file(path, "re");
    if (!stat) return -1;
    // PID COMM STATE PPID .....
    fscanf(stat.get(), "%*d %*s %*c %d", &ppid);
    return ppid;
}

static void check_zygote() {
    zygote_map.clear();
    auto proc = open("/proc", O_RDONLY | O_CLOEXEC);
    auto proc_dir = xopen_dir(proc);
    if (!proc_dir) return;
    dirent *entry;
    int pid;
    struct stat st{};
    while ((entry = readdir(proc_dir.get()))) {
        pid = parse_int(entry->d_name);
        if (pid <= 0) continue;
        if (fstatat(proc, entry->d_name, &st, 0)) continue;
        if (st.st_uid != 0) continue;
        if (proc_context_match(pid, "u:r:zygote:s0") && parse_ppid(pid) == 1) {
            if (read_ns(pid, &st) == 0) {
                LOGI("logcat: zygote PID=[%d]\n", pid);
                zygote_map[pid] = st;
                if (fork_dont_care() == 0) {
                    revert_unmount(pid);
                    _exit(0);
                }
            }
        }
    }
}

static void handle_proc(int pid) {
    if (fork_dont_care() == 0) {
        int ppid = parse_ppid(pid);
        auto it = zygote_map.find(ppid);
        if (it == zygote_map.end()) {
            LOGW("logcat: skip PID=[%d] PPID=[%d]\n", pid, ppid);
            _exit(0);
        }

        char path[16];
        struct stat st{};
        sprintf(path, "/proc/%d", pid);
        while (read_ns(pid, &st) == 0 && it->second.st_ino == st.st_ino) {
            if (stat(path, &st) == 0 && st.st_uid == 0) {
                usleep(10 * 1000);
            } else {
                LOGW("logcat: skip PID=[%d] UID=[%d]\n", pid, st.st_uid);
                _exit(0);
            }
        }

        do_mount_magisk(pid);
        _exit(0);
    }
}

static void process_events_buffer(struct logger_entry *buf) {
    if (buf->uid != 1000) return;
    auto *event_data = reinterpret_cast<const unsigned char *>(buf) + buf->hdr_size;
    auto *event_header = reinterpret_cast<const android_event_header_t *>(event_data);

    if (event_header->tag == 30014) {
        auto *am_proc_start = reinterpret_cast<const android_event_am_proc_start *>(event_data);
        auto proc = string_view(am_proc_start->process_name.data,
                                am_proc_start->process_name.length);
        if (is_deny_target(am_proc_start->uid.data, proc)) {
            LOGI("logcat: [%.*s] PID=[%d] UID=[%d]\n",
                 am_proc_start->process_name.length, am_proc_start->process_name.data,
                 am_proc_start->pid.data, am_proc_start->uid.data);
            handle_proc(am_proc_start->pid.data);
        }
        return;
    }

    if (event_header->tag == 3040) {
        LOGD("logcat: soft reboot\n");
        check_zygote();
    }
}

[[noreturn]] void run() {
    while (true) {
        const unique_ptr<logger_list, decltype(&android_logger_list_free)> logger_list{
            android_logger_list_alloc(0, 1, 0), &android_logger_list_free};
        for (log_id id: {LOG_ID_MAIN, LOG_ID_EVENTS}) {
            auto *logger = android_logger_open(logger_list.get(), id);
            if (logger == nullptr) continue;
        }

        struct log_msg msg{};
        while (true) {
            if (logcat_exit) {
                break;
            }

            if (android_logger_list_read(logger_list.get(), &msg) <= 0) {
                break;
            }

            if (msg.entry.lid == LOG_ID_EVENTS) process_events_buffer(&msg.entry);
        }

        if (logcat_exit) {
            break;
        }

        sleep(1);
    }

    LOGD("logcat: terminate\n");
    pthread_exit(nullptr);
}

void *logcat(void *) {
    check_zygote();
    run();
}
