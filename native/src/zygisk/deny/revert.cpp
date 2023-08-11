#include <set>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#include <magisk.hpp>
#include <daemon.hpp>
#include <base.hpp>
#include <selinux.hpp>

#include "deny.hpp"

#include <link.h>

using namespace std;

static void lazy_unmount(const char* mountpoint) {
    if (umount2(mountpoint, MNT_DETACH) != -1)
        LOGD("hide_daemon: Unmounted (%s)\n", mountpoint);
}

void mount_mirrors();

void root_mount(int pid) {
    if (switch_mnt_ns(pid))
        return;

    LOGD("su_policy: handling PID=[%d]\n", pid);

    xmount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);

    if (MAGISKTMP == "/sbin") {
        if (is_rootfs()) {
            tmpfs_mount("magisk", "/sbin");
            setfilecon("/sbin", "u:object_r:rootfs:s0");
            recreate_sbin_v2("/root", false);
        } else {
            mount_sbin();
        }
    } else {
        mkdir(MAGISKTMP.data(),0755);
        tmpfs_mount("magisk", MAGISKTMP.data());
    }

    for (auto file : {"magisk32", "magisk64", "magisk", "magiskpolicy"}) {
        auto src = "/proc/1/root"s + MAGISKTMP + "/"s + file;
        auto dest = MAGISKTMP + "/"s + file;
        if (access(src.data(),F_OK) == 0){
            cp_afc(src.data(), dest.data());
        }
    }
    
    for (int i = 0; applet_names[i]; ++i) {
        string dest = MAGISKTMP + "/" + applet_names[i];
        xsymlink("./magisk", dest.data());
    }
    string dest = MAGISKTMP + "/supolicy";
    xsymlink("./magiskpolicy", dest.data());

    chdir(MAGISKTMP.data());

    xmkdir(INTLROOT, 0755);
    xmkdir(MIRRDIR, 0);
    xmkdir(BLOCKDIR, 0);
    xmkdir(WORKERDIR, 0);

    // in case some apps need to access to some internal files
    string bb_dir = "/proc/1/root/" + MAGISKTMP + "/" BBPATH;
    xsymlink(bb_dir.data(), BBPATH);

    string src = "/proc/1/root/" + MAGISKTMP + "/" INTLROOT "/config";
    cp_afc(src.data(), INTLROOT "/config");

    mount_mirrors();

    chdir("/");

    su_mount();
}

void su_daemon(int pid) {
    if (fork_dont_care() == 0) {
        root_mount(pid);
        // Send resume signal
        kill(pid, SIGCONT);
        _exit(0);
    }
}

void revert_daemon(int pid, int client) {
    if (fork_dont_care() == 0) {
        revert_unmount(pid);
        if (client >= 0) {
            write_int(client, DenyResponse::OK);
        } else if (client == -1) {
            // send resume signal
            kill(pid, SIGCONT);
        }
        _exit(0);
    }
}

void revert_unmount(int pid) {
    if (pid > 0) {
        if (switch_mnt_ns(pid))
            return;
        LOGD("magiskhide: handling PID=[%d]\n", pid);
    }
    set<string> targets;

    // Unmount dummy skeletons and MAGISKTMP
    // since mirror nodes are always mounted under skeleton, we don't have to specifically unmount
    for (auto &info: parse_mount_info("self")) {
        if (info.source == "magisk" || info.source == "worker" || // magisktmp tmpfs
            info.root.starts_with("/adb/modules")) { // bind mount from data partition
            targets.insert(info.target);
        }
    }

    auto last_target = *targets.cbegin() + '/';
    for (auto iter = next(targets.cbegin()); iter != targets.cend();) {
        if (iter->starts_with(last_target)) {
            iter = targets.erase(iter);
        } else {
            last_target = *iter++ + '/';
        }
    }

    for (auto &s : targets)
        lazy_unmount(s.data());

    // Unmount early-mount.d files
    for (auto &info: parse_mount_info("self")) {
        if (info.root == "early-mount.d") { // bind mount from early-mount
            lazy_unmount(info.target.data());
        }
    }
}

