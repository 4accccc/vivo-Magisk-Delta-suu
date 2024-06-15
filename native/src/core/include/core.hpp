#pragma once

#include <pthread.h>
#include <poll.h>
#include <string>
#include <limits>
#include <atomic>
#include <functional>

#include "socket.hpp"
#include "../core-rs.hpp"

#define AID_ROOT   0
#define AID_SHELL  2000
#define AID_APP_START 10000
#define AID_APP_END 19999
#define AID_USER_OFFSET 100000

#define to_app_id(uid)  (uid % AID_USER_OFFSET)
#define to_user_id(uid) (uid / AID_USER_OFFSET)

// Return codes for daemon
enum class RespondCode : int {
    ERROR = -1,
    OK = 0,
    ROOT_REQUIRED,
    ACCESS_DENIED,
    END
};

struct module_info {
    std::string name;
    int z32 = -1;
#if defined(__LP64__)
    int z64 = -1;
#endif
};

extern bool zygisk_enabled;
extern bool sulist_enabled;
extern std::vector<module_info> *module_list;
extern std::string native_bridge;

extern int magisktmpfs_fd;

int connect_daemon(int req, bool create = false);
std::string find_preinit_device();
void unlock_blocks();

// Poll control
using poll_callback = void(*)(pollfd*);
void register_poll(const pollfd *pfd, poll_callback callback);
void unregister_poll(int fd, bool auto_close);
void clear_poll();

// Thread pool
void exec_task(std::function<void()> &&task);

// Daemon handlers
void boot_stage_handler(int client, int code);
void denylist_handler(int client, const sock_cred *cred);
void su_daemon_handler(int client, const sock_cred *cred);

// Package
extern std::atomic<ino_t> pkg_xml_ino;
void preserve_stub_apk();
void check_pkg_refresh();
std::vector<bool> get_app_no_list();
// Call check_pkg_refresh() before calling get_manager(...)
// to make sure the package state is invalidated!
int get_manager(int user_id = 0, std::string *pkg = nullptr, bool install = false);
void prune_su_access();

// Module stuffs
void handle_modules();
void load_modules();
void disable_modules();
void remove_modules();
void exec_module_scripts(const char *stage);

// Scripting
void exec_script(const char *script);
void exec_common_scripts(const char *stage);
void exec_module_scripts(const char *stage, const std::vector<std::string_view> &modules);
void install_apk(const char *apk);
void uninstall_pkg(const char *pkg);
void clear_pkg(const char *pkg, int user_id);
[[noreturn]] void install_module(const char *file);

// Denylist
extern std::atomic_flag skip_pkg_rescan;
extern std::atomic<bool> denylist_enforced;
int denylist_cli(int argc, char **argv);
void initialize_denylist();
bool is_deny_target(int uid, std::string_view process, int max_len = 1024);
void crawl_procfs(const std::function<bool(int)> &fn);

// Revert
void revert_unmount(int pid = -1);

// SuList
void do_mount_magisk(int pid);
void update_sulist_config(bool enable);
