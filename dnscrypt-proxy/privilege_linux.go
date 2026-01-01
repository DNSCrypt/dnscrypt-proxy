package main

import (
    "os"
    "os/user"
    "strconv"

    "github.com/jedisct1/dlog"
    "golang.org/x/sys/unix"
)

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
    if os.Geteuid() != 0 {
        dlog.Fatal("Root privileges are required in order to switch to a different user. Maybe try again with 'sudo'")
    }

    // Optimization: Resolve UID/GID early to avoid string processing overhead
    uid, gid := 0, 0
    userInfo, err := user.Lookup(userStr)

    if err == nil {
        // Fast path: User found in system DB
        u, _ := strconv.Atoi(userInfo.Uid)
        g, _ := strconv.Atoi(userInfo.Gid)
        uid, gid = u, g
    } else {
        // Fallback: Treat string as numeric ID directly
        val, err2 := strconv.Atoi(userStr)
        if err2 != nil || val <= 0 {
            dlog.Fatalf(
                "Unable to retrieve information about user [%s]: [%s] - Remove the user_name directive from the configuration file in order to avoid identity switch",
                userStr,
                err,
            )
        }
        uid, gid = val, val
        dlog.Warnf(
            "Unable to retrieve information about user [%s]: [%s] - Switching to user id [%v] with the same group id. You should fix the user_name directive in the configuration file if possible",
            userStr,
            err,
            uid,
        )
    }

    // Optimization: Use os.Executable instead of LookPath to avoid PATH traversal
    path, err := os.Executable()
    if err != nil {
        dlog.Fatalf("Unable to get executable path: [%s]", err)
    }

    if err := ServiceManagerReadyNotify(); err != nil {
        dlog.Fatal(err)
    }

    // Optimization: Pre-allocate slice capacity to prevent resize allocations
    args := make([]string, 0, len(os.Args)+1)
    args = append(args, os.Args...)
    args = append(args, "-child")

    dlog.Notice("Dropping privileges")

    // Optimization: Use unix package helpers instead of RawSyscall for safety and simplicity
    // These calls have negligible overhead compared to the process switch cost
    if err := unix.Setgroups([]int{}); err != nil {
        dlog.Fatalf("Unable to drop additional groups: [%s]", err)
    }
    if err := unix.Setgid(gid); err != nil {
        dlog.Fatalf("Unable to drop group privileges: [%s]", err)
    }
    if err := unix.Setuid(uid); err != nil {
        dlog.Fatalf("Unable to drop user privileges: [%s]", err)
    }

    // Optimization: Streamlined file descriptor handling
    baseFd := int(InheritedDescriptorsBase)
    for i, fd := range fds {
        srcFd := int(fd.Fd())
        dstFd := baseFd + i

        if srcFd >= baseFd {
            dlog.Fatal("Duplicated file descriptors are above base")
        }

        // unix.Dup2 handles closing dstFd atomically if it's already open
        if err := unix.Dup2(srcFd, dstFd); err != nil {
            dlog.Fatalf("Unable to clone file descriptor: [%s]", err)
        }

        // Ensure the source descriptor closes on exec, keeping only the destination open
        if _, err := unix.FcntlInt(uintptr(srcFd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
             dlog.Fatalf("Unable to set the close on exec flag: [%s]", err)
        }
    }

    // Final Exec replaces the process image
    err = unix.Exec(path, args, os.Environ())
    dlog.Fatalf("Unable to reexecute [%s]: [%s]", path, err)
    os.Exit(1)
}
