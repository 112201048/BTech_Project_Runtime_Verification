#include <qemu-plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_ADDRS 128

static unsigned long addrs[MAX_ADDRS];
static int addr_count = 0;

static char watchfile[256];

static time_t last_check_time = 0;
static time_t last_file_mtime = 0;
static bool initialized = false;

/* --------------------------------------------- */
/* Load watchlist file                          */
/* --------------------------------------------- */
static bool load_watchlist(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return false;

    /* If file unchanged, skip reload */
    if (st.st_mtime == last_file_mtime && initialized)
        return true;

    FILE *f = fopen(path, "r");
    if (!f)
        return false;

    addr_count = 0;
    char line[128];

    while (fgets(line, sizeof(line), f)) {
        if (addr_count >= MAX_ADDRS)
            break;

        addrs[addr_count++] = strtoul(line, NULL, 16);
    }

    fclose(f);

    last_file_mtime = st.st_mtime;
    initialized = true;

    printf("[PLUGIN] Loaded %d addresses from watchlist\n", addr_count);
    fflush(stdout);

    return true;
}

/* --------------------------------------------- */
/* Check if address is in watchlist             */
/* --------------------------------------------- */
static bool is_watched(unsigned long addr)
{
    for (int i = 0; i < addr_count; i++) {
        if (addrs[i] == addr)
            return true;
    }
    return false;
}

/* --------------------------------------------- */
/* Memory callback                              */
/* --------------------------------------------- */
static void mem_cb(unsigned int cpu_index,
                   qemu_plugin_meminfo_t meminfo,
                   uint64_t addr,
                   void *userdata)
{
    if (!qemu_plugin_mem_is_store(meminfo))
        return;

    /* Periodically check for watchlist updates */
    time_t now = time(NULL);
    if (now - last_check_time >= 2) {
        last_check_time = now;
        load_watchlist(watchfile);
    }

    if (!initialized)
        return;

    if (is_watched(addr)) {
        printf("[PLUGIN] Variable at 0x%lx changed!\n", addr);
        fflush(stdout);
    }
}

/* --------------------------------------------- */
/* Attach mem callback to every instruction     */
/* --------------------------------------------- */
static void tb_trans_cb(qemu_plugin_id_t id,
                        struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn =
            qemu_plugin_tb_get_insn(tb, i);

        qemu_plugin_register_vcpu_mem_cb(
            insn,
            mem_cb,
            QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW,
            NULL
        );
    }
}

/* --------------------------------------------- */
/* Plugin install                               */
/* --------------------------------------------- */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(
        qemu_plugin_id_t id,
        const qemu_info_t *info,
        int argc, char **argv)
{
    if (argc < 1) {
        printf("Usage: -plugin rv_watch.so,arg=<watchlist>\n");
        return -1;
    }

    /* Remove "=on" suffix automatically added by QEMU */
    size_t len = strlen(argv[0]);
    size_t new_len = (len > 3) ? (len - 3) : len;

    strncpy(watchfile, argv[0], new_len);
    watchfile[new_len] = '\0';

    printf("[PLUGIN] Watching file: %s\n", watchfile);
    fflush(stdout);

    /* Try initial load */
    load_watchlist(watchfile);

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);

    return 0;
}
