#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
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
 *  apparently the chatlog base address is at 0x0107E3F0 (pre-SB?)
 *  chat pointer is then + 52
 *  @returns mem addr offset of chatlog
 */
#define MEMSCAN_BUFFER_SIZE         (0x1000000)
#define MEMSCAN_PATTERN_WILDCARD    '*'
int get_chatlog_offset(mach_port_t task) {
    kern_return_t kret;
    static unsigned char MEM_PATTERN_CHATLOG[] = "\xe8****\x85\xc0\x74\x0e\x48\x8b\x0d****\x33\xd2\xe8****\x48\x8b\x0d";
    int sigsize = strlen(MEM_PATTERN_CHATLOG);

    unsigned int size = 0xffff3000; // size of memory to scan

    const unsigned int buf_offset = 0; // TODO: specify vm offset
    const unsigned int buf_rewind = 0;
    int bytes_read = 0+buf_offset;
    uint32_t sz;
    printf("Getting chatlog memory offset...\n");
    while (bytes_read <= size) {
        static uint8_t buffer[MEMSCAN_BUFFER_SIZE];
        unsigned int address = bytes_read;
        pointer_t buf_ptr;

        kret = vm_read(task, address, MEMSCAN_BUFFER_SIZE, &buf_ptr, &sz);
        if (kret == 2) {
            bytes_read+=MEMSCAN_BUFFER_SIZE;
            continue;
        } else if (kret != KERN_SUCCESS) {
            KERN_ERR_CHECK(kret, "vm_read");
            return -1;
        }

        memset(buffer, 0, MEMSCAN_BUFFER_SIZE);
        memcpy(buffer, (const void *)buf_ptr, MEMSCAN_BUFFER_SIZE);
        vm_deallocate(task, buf_ptr, sz);
        unsigned int bufpos = 0;
        while (bufpos <= MEMSCAN_BUFFER_SIZE) {
            unsigned int sigstart = bufpos;
            unsigned int sigpos = 0;
            while (buffer[sigstart+sigpos] == MEM_PATTERN_CHATLOG[sigpos] ||
                MEM_PATTERN_CHATLOG[sigpos] == MEMSCAN_PATTERN_WILDCARD) {
                sigpos++;
                if (sigpos >= sigsize) {
                    printf("Found: ");
                    for (int i=0; i<sigsize; i++) printf("0x%x ", buffer[bufpos+i]);
                    printf("\n");
                    return (int)(bytes_read+bufpos-buf_rewind);
                }
            }

            printf("\33[2K\r\x1B[33;1mSearching...\x1B[0m");
            bufpos++;
        }
        bytes_read+=MEMSCAN_BUFFER_SIZE;
    }

    return -1;
}

#define CHATLOG_POINTER         (0x2CA90E58) // incorrect for stormblood
#define CHATLOG_READ_SIZE       (0x01000000)
void dump_memory_from_offset(mach_port_t task, uint64_t offset) {
    static uint8_t buffer[CHATLOG_READ_SIZE];
    uint32_t sz;
    pointer_t buf_ptr;
    kern_return_t kret = vm_read(task, offset, CHATLOG_READ_SIZE, &buf_ptr, &sz);
    KERN_ERR_CHECK(kret, "vm_read");

    printf("Finished vm_read.\n", buf_ptr);
    memset(buffer, 0, CHATLOG_READ_SIZE);
    memcpy(buffer, (const void *)buf_ptr, CHATLOG_READ_SIZE);
    vm_deallocate(task, buf_ptr, sz);

    // for (int i=0; i<sz; i++) printf("%c", (char)buffer[i]);
    // Write to file
    FILE *fp;
    fp = fopen("./memdump.hex", "wb");
    if (fp)
        fwrite(buffer, sizeof(uint8_t), sz, fp);

    fclose(fp);
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

/**
 *  Get base offset of vm due to ASLR
 */
int get_base_offset(mach_port_t task) {
    kern_return_t kret;

    // TODO: Get base address of process (due to address-slide caused by ASLR)
    vm_map_offset_t vmoffset;
    vm_map_size_t vmsize;
    uint32_t nesting_depth = 0;
    struct vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount = 16;

    kret = mach_vm_region_recurse(task, &vmoffset, &vmsize, &nesting_depth,
        (vm_region_recurse_info_t)&vbr, &vbrcount);
    KERN_ERR_CHECK(kret, "mach_vm_region_recurse");
    printf("vm offset is: 0x%0llx\n", (int)vmoffset);
    return (int)vmoffset;
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

    get_base_offset(task);
    // unsigned int chatlog_addr = get_chatlog_offset(task);
    // unsigned int chatlog_addr = 0x368071cul;

    printf("\nFFXIV (%d) is running %d threads.\n", pid_ffxiv, thread_count);
    // printf("  -> CHATLOG at 0x%x\n", chatlog_addr);

    // dump_memory_from_offset(task, chatlog_addr);

    return 0;
}
