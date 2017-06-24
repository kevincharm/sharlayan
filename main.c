#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <errno.h>
#include <signal.h>

#define APP_ERR_CHECK(n, r) do { \
    if (n == -1) { \
        printf("ERROR: %s\n", r); \
    } \
} while (0);

#define KERN_ERR_CHECK(n, r) do { \
    if (n != KERN_SUCCESS) { \
        printf("ERROR: (Kernel) %s: %s\n", r, mach_error_string(n)); \
    } \
} while (0);

/**
 *  modified from https://gist.github.com/benphelps/7106366
 *  @returns mem addr offset of chatlog
 */
int get_chatlog_offset(mach_port_t task) {
    int ptr;

    static uint16_t MEM_PATTERN_CHATLOG[] = {0xe8, 0xffff, 0xffff, 0xffff, 0xffff, 0x85, 0xc0,
        0x74, 0x0e, 0x48, 0x8b, 0x0d, 0xffff, 0xffff, 0xffff, 0xffff, 0x33, 0xd2, 0xe8, 0xffff,
        0xffff, 0xffff, 0xffff,0x48, 0x8b, 0x0d};
    int sigsize = sizeof(MEM_PATTERN_CHATLOG)/sizeof(MEM_PATTERN_CHATLOG[0]);

    int size = 0xffff3000; // size of memory to scan

    unsigned int buffer_size = 0x100000;
    int bytes_read = 0;
    uint32_t sz;
    while (bytes_read <= size) {
        uint8_t buffer[buffer_size];
        unsigned int address = bytes_read;
        pointer_t buffer_pointer;
        vm_read(task, address, buffer_size, &buffer_pointer, &sz);
        memcpy(buffer, (const void *)buffer_pointer, sz);
        unsigned int bufpos = 0;
        while (bufpos <= buffer_size) {
            unsigned int sigstart = bufpos;
            unsigned int sigpos = 0;
            // parse bytes
            while (buffer[sigstart+sigpos] == (MEM_PATTERN_CHATLOG[sigpos] & 0xff)
                || buffer[sigstart+sigpos] == 0xffff) {
                sigpos++;
                if (sigpos == sigsize) {
                    return (int) bytes_read + bufpos;
                }

            }
            bufpos++;
        }
        bytes_read+=buffer_size;
    }

    return ptr;
}

/**
 *  @returns pid of ffxiv process if found, -1 if not found
 */
int get_ffxiv_pid() {
    int pid = -1;
    char linebuf[256];

    FILE *fp = popen("ps -A | grep 'ffxiv.exe'", "r");
    if (fp == NULL)
        printf("ERROR: Could not find FFXIV process!\n");

    if (fgets(linebuf, 256, fp) != NULL) {
        char *remain;
        pid = strtol(linebuf, &remain, 10);
    }

    pclose(fp);

    return pid;
}

int main() {
    kern_return_t kret;

    int pid_ffxiv = get_ffxiv_pid();
    APP_ERR_CHECK(pid_ffxiv, "get_ffxiv_pid");

    mach_port_t task;
    kret = task_for_pid(mach_task_self(), pid_ffxiv, &task);
    KERN_ERR_CHECK(kret, "task_for_pid");

    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kret = task_threads(task, &thread_list, &thread_count);
    KERN_ERR_CHECK(kret, "task_threads");

    x86_thread_state32_t state;
    mach_msg_type_number_t state_count = x86_THREAD_STATE32_COUNT;
    kret = thread_get_state(thread_list[0], x86_THREAD_STATE32,
        (thread_state_t)&state, &state_count);
    KERN_ERR_CHECK(kret, "thread_get_state");

    int chatlog_addr = get_chatlog_offset(task);

    printf("FFXIV (%d) is running %d threads.\n", pid_ffxiv, thread_count);
    printf("  -> CHATLOG at %d\n", chatlog_addr);

    return 0;
}
