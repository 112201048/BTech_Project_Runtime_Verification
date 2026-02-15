#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>

#define MAX_VARS 32

/* ---------- ELF PARSING (STATIC OFFSETS) ---------- */

unsigned long find_symbol_offset(const char *program, const char *symbol) {
    FILE *f = fopen(program, "rb");
    if (!f) {
        perror("elf open");
        exit(1);
    }

    /* For 32-bit ARM binaries */
    Elf32_Ehdr ehdr;
    fread(&ehdr, sizeof(ehdr), 1, f);

    fseek(f, ehdr.e_shoff, SEEK_SET);

    Elf32_Shdr shdr;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        fread(&shdr, sizeof(shdr), 1, f);

        if (shdr.sh_type == SHT_SYMTAB) {
            long symtab_pos = shdr.sh_offset;
            long symcount = shdr.sh_size / shdr.sh_entsize;

            Elf32_Shdr strhdr;
            fseek(f, ehdr.e_shoff + shdr.sh_link * sizeof(shdr), SEEK_SET);
            fread(&strhdr, sizeof(strhdr), 1, f);

            char *strtab = malloc(strhdr.sh_size);
            fseek(f, strhdr.sh_offset, SEEK_SET);
            fread(strtab, strhdr.sh_size, 1, f);

            fseek(f, symtab_pos, SEEK_SET);

            for (int j = 0; j < symcount; j++) {
                Elf32_Sym sym;
                fread(&sym, sizeof(sym), 1, f);

                char *name = &strtab[sym.st_name];

                if (strcmp(name, symbol) == 0) {
                    unsigned long offset = sym.st_value;
                    free(strtab);
                    fclose(f);
                    return offset;
                }
            }

            free(strtab);
        }
    }

    fclose(f);
    return 0;
}

/* ---------- RUNTIME BASE ADDRESS EXTRACTION ---------- */

// unsigned long get_base_address_of_pid(pid_t pid, const char *program) {
//     char path[64];
//     snprintf(path, sizeof(path), "/proc/%d/maps", pid);

//     FILE *f = fopen(path, "r");
//     if (!f) {
//         perror("maps open");
//         exit(1);
//     }

//     char line[256];
//     unsigned long base = 0;

//     while (fgets(line, sizeof(line), f)) {
//         if (strstr(line, program)) {
//             sscanf(line, "%lx-", &base);
//             break;
//         }
//     }

//     fclose(f);
//     return base;
// }

/* ---------- WRITE WATCHLIST ---------- */

void write_watchlist(unsigned long *addrs, int count) {
    FILE *f = fopen("/home/sid/shared/watchlist.txt", "w");
    if (!f) {
        perror("watchlist open");
        exit(1);
    }

    for (int i = 0; i < count; i++) {
        fprintf(f, "0x%lx\n", addrs[i]);
    }

    fclose(f);

    printf("[LAUNCHER] watchlist created with %d addresses\n", count);
}

/* ---------- MAIN LAUNCHER LOGIC ---------- */

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <program> <varlist>\n", argv[0]);
        return 1;
    }

    char *program = argv[1];
    char *varlist = argv[2];

    FILE *vf = fopen(varlist, "r");
    if (!vf) {
        perror("varlist open");
        return 1;
    }

    char vars[MAX_VARS][128];
    int varcount = 0;

    while (fgets(vars[varcount], 128, vf)) {
        vars[varcount][strcspn(vars[varcount], "\n")] = 0;
        varcount++;
    }
    fclose(vf);

    printf("[LAUNCHER] Tracking %d variables\n", varcount);

    unsigned long offsets[MAX_VARS];
    unsigned long addresses[MAX_VARS];

    /* STEP 1 – get static offsets */
    for (int i = 0; i < varcount; i++) {
        offsets[i] = find_symbol_offset(program, vars[i]);

        if (offsets[i] == 0) {
            printf("[ERROR] Symbol %s not found\n", vars[i]);
            return 1;
        }

        printf("[LAUNCHER] %s static offset = 0x%lx\n", vars[i], offsets[i]);
    }

    /* STEP 2 – fork and exec under ptrace */
    pid_t pid = fork();

    if (pid == 0) {
        /* CHILD: traced process */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(program, program, NULL);

        perror("exec failed");
        exit(1);
    }

    /* PARENT: controller */
    int status;
    waitpid(pid, &status, 0);   /* wait for exec stop */

    printf("[LAUNCHER] Target program loaded (pid=%d)\n", pid);

    /* STEP 3 – get runtime base */
    // unsigned long base = get_base_address_of_pid(pid, program);

    // printf("[LAUNCHER] Runtime base address = 0x%lx\n", base);

    /* STEP 4 – compute real addresses */
    for (int i = 0; i < varcount; i++) {
        addresses[i] = offsets[i];
        printf("[LAUNCHER] %s runtime addr = 0x%lx\n", vars[i], addresses[i]);
    }

    /* STEP 5 – generate watchlist */
    write_watchlist(addresses, varcount);

    printf("[LAUNCHER] Resuming target program...\n");

    /* STEP 6 – continue execution */
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    /* STEP 7 – wait for program to finish */
    waitpid(pid, &status, 0);

    printf("[LAUNCHER] Target program finished\n");

    return 0;
}
