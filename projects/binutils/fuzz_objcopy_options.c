/* =======================================================================
 *  fuzz_objcopy.c   –   robust, deterministic C harness for GNU objcopy
 * =======================================================================
 */
#include "config.h" /* must precede any system header */

#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static jmp_buf fuzz_jmp;

// patch out exit() from <stdlib.h>

#undef exit
#define exit(code)                           \
    do {                                     \
        fprintf(stderr, "[FUZZ-EXIT] ");     \
        fputc('\n', stderr);                 \
        longjmp(fuzz_jmp, 1);                \
    } while (0)

// patch out fatal() from bucomm.h
#include "sysdep.h"
#include "bfd.h"
#include "bucomm.h"

#undef fatal
#define fatal(fmt, ...)                      \
    do {                                     \
        fprintf(stderr, "[FUZZ-FATAL] ");    \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
        fputc('\n', stderr);                 \
        longjmp(fuzz_jmp, 1);                \
    } while (0)

// aaaand print_version, as it exits too
#undef print_version
#define print_version(name)                  \
    do {                                     \
        longjmp(fuzz_jmp, 1);                \
    } while (0)

// also reimplement parse_vma without fatal
#undef parse_vma
#define parse_vma(s, opt) parse_vma_longjmp((s), (opt))

static bfd_vma parse_vma_longjmp(const char* s, const char* arg)
{
    bfd_vma ret;
    const char* end;
    ret = bfd_scan_vma(s, &end, 0);
    if (*end != '\0')
        longjmp(fuzz_jmp, 1);
    return ret;
}

#define is_strip 0
#include "fuzz_objcopy.h" /* converted objcopy.c */

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    /* BFD global init */
    if (bfd_init() != BFD_INIT_MAGIC)
        abort();
    set_default_bfd_target();

    /* set program name for objcopy messages */
    program_name = (char*)"fuzz_objcopy";
    return 0;
}

void init_objcopy_global_state()
{
    // status is a global variable that is set to 0 initially,
    // and we should ensure the state is not maintained for each iteration.
    status = 0;
    pe_file_alignment = (bfd_vma)-1;
    pe_heap_commit = (bfd_vma)-1;
    pe_heap_reserve = (bfd_vma)-1;
    pe_image_base = (bfd_vma)-1;
    pe_section_alignment = (bfd_vma)-1;
    pe_stack_commit = (bfd_vma)-1;
    pe_stack_reserve = (bfd_vma)-1;
    pe_subsystem = -1;
    pe_major_subsystem_version = -1;
    pe_minor_subsystem_version = -1;
    section_rename_list = NULL;
    isympp = NULL;
    osympp = NULL;
    copy_byte = -1;
    interleave = 0;
    copy_width = 1;
    keep_section_symbols = false;
    deterministic = -1;
    status = 0;
    merge_notes = false;
    strip_symbols = STRIP_UNDEF;
    change_sections = NULL;
    change_start = 0;
    set_start_set = false;
    change_section_address = 0;
    gap_fill_set = false;
    gap_fill = 0;
    pad_to_set = false;
    use_alt_mach_code = 0;
    add_sections = NULL;
    update_sections = NULL;
    dump_sections = NULL;
    gnu_debuglink_filename = NULL;
    convert_debugging = false;
    change_leading_char = false;
    remove_leading_char = false;
    wildcard = false;
    localize_hidden = false;
    strip_specific_htab = NULL;
    strip_unneeded_htab = NULL;
    keep_specific_htab = NULL;
    localize_specific_htab = NULL;
    globalize_specific_htab = NULL;
    keepglobal_specific_htab = NULL;
    weaken_specific_htab = NULL;
    redefine_specific_htab = NULL;
    redefine_specific_reverse_htab = NULL;
    add_sym_tail = &add_sym_list;
    add_symbols = 0;
    strip_specific_buffer = NULL;
    strip_unneeded_buffer = NULL;
    keep_specific_buffer = NULL;
    localize_specific_buffer = NULL;
    globalize_specific_buffer = NULL;
    keepglobal_specific_buffer = NULL;
    weaken_specific_buffer = NULL;
    weaken = false;
    keep_file_symbols = false;
    prefix_symbols_string = 0;
    prefix_sections_string = 0;
    prefix_alloc_sections_string = 0;
    extract_symbol = false;

    create_symbol_htabs();
}

/* ---------- argv builder ----------------------------------------------- */

#define MAX_ARGC 64 /* maximum number of argv entries */
#define MAX_ARGV 2048 /* bytes in the flat buffer       */

char* fake_argv_pointer[MAX_ARGC];
char fake_argv[MAX_ARGV];

static bool write_space(char* buf, size_t* pos, size_t cap)
{
    if (*pos + 1 >= cap)
        return false;
    buf[(*pos)++] = ' ';
    return true;
}

/* append LEN bytes of TOK to BUF at *POS; returns false
   on overflow, true on success                                            */
static bool write_token(char* buf, size_t* pos, size_t cap,
    const char* tok, size_t len)
{
    if (*pos + len >= cap) /* +1 for final NUL */
        return false;

    memcpy(&buf[*pos], tok, len);
    *pos += len;
    return true;
}

static bool writeRandomString(char* buf, size_t* pos, size_t cap,
    const uint8_t* Data, size_t* data_pos,
    size_t DataSize)
{
    if (*data_pos >= DataSize)
        return false;

    uint8_t lenB = Data[(*data_pos)++] % 20; /* 0–19 */
    size_t len = (size_t)lenB + 1; /* 1–20 */

    if (*data_pos + len > DataSize)
        len = DataSize - *data_pos;

    if (*pos + len >= cap)
        return false;

    /* generate directly in destination buffer */
    for (size_t i = 0; i < len; i++) {
        uint8_t c = Data[*data_pos + i];
        buf[*pos + i] = (c <= 0x20 || c > 0x7E)
            ? (char)('A' + (c & 0x0F))
            : (char)c;
    }
    *data_pos += len;
    *pos += len;
    return true;
}

static const size_t option_count = sizeof(copy_options) / sizeof(copy_options[0]) - 1; // "no_argument"

static int build_argv(const uint8_t* Data, size_t Size, const char* in_file)
{
    if (Size < 1)
        return 0;

    size_t data_pos = 0;
    size_t buf_pos = 0;

    uint8_t n_opts = Data[data_pos++] & 0x0F; /* 0…15 */

    /* program name ------------------------------------------------------- */
    char* prog_name = "fake_argv "; 
    if (!write_token(fake_argv, &buf_pos, MAX_ARGV,
            prog_name, strlen(prog_name)))
        return 0;

    /* emit options ------------------------------------------------------- */
    for (uint8_t i = 0; i < n_opts; i++) {
        if (data_pos + 2 > Size)
            break;

        const struct option* opt = &copy_options[Data[data_pos++] % option_count];
        const uint8_t flags = Data[data_pos++];

        /* “--name ” */
        if (
            !write_token(fake_argv, &buf_pos, MAX_ARGV, "--", 2) || 
            !write_token(fake_argv, &buf_pos, MAX_ARGV, opt->name, strlen(opt->name)) || 
            !write_space(fake_argv, &buf_pos, MAX_ARGV))
            break;

        /* argument? */
        bool want_arg =
         (opt->has_arg == required_argument) || 
         (opt->has_arg == optional_argument && (flags & 0x01));

        if (
            want_arg && 
            (!writeRandomString(fake_argv, &buf_pos, MAX_ARGV, Data, &data_pos, Size) || 
            !write_space(fake_argv, &buf_pos, MAX_ARGV)))
            break;
    }

    write_token(fake_argv, &buf_pos, MAX_ARGV, in_file, strlen(in_file));
    write_space(fake_argv, &buf_pos, MAX_ARGV);
    write_token(fake_argv, &buf_pos, MAX_ARGV, "/tmp/random.out", strlen("/tmp/random.out"));

    if (buf_pos == 0)
        return 0;
    fake_argv[buf_pos - 1] = '\0';

    if (getenv("FUZZ_PRINT_ARGS") || 1)
        printf("[ARGV] \"%s\"\n", fake_argv);

    /* split into argv pointers ------------------------------------------ */
    int fake_argc = 0;
    fake_argv_pointer[0] = fake_argv;
    fake_argc++;

    for (char* p = fake_argv; *p && fake_argc < MAX_ARGC; ++p) {
        if (*p == ' ') {
            *p = '\0';
            if (p[1] != '\0')
                fake_argv_pointer[fake_argc++] = p + 1;
        }
    }
    return fake_argc;
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    /* require at least 256 bytes */
    if (Size < 256)
        return -1;

    /* write tail (bytes 256…Size-1) to a temp file */
    char in_file[64];
    snprintf(in_file, sizeof in_file, "/tmp/libfuzzer.%d", getpid());
    FILE* fp = fopen(in_file, "wb");
    if (!fp)
        return 0;
    fwrite(Data + 256, Size - 256, 1, fp);
    fclose(fp);

    int argc = build_argv(Data, 256, in_file);
    if (argc < 0)
        goto cleanup_files;
    if (!argc)
        goto cleanup_files;

    /* full reset of objcopy globals                                     */
    init_objcopy_global_state();
    /* getopt() reset (glibc)                                            */
    optind = 1;
    opterr = 0;
    optopt = 0;

    /* ---- call objcopy core, recovering on any fatal() -------------- */
    if (setjmp(fuzz_jmp) == 0) {
        copy_main(argc, fake_argv_pointer);
    } else {
        goto cleanup_files;
    }

    // Cleanup
    
    /* BFD keeps a process-wide cache of open files; close everything    */
    bfd_cache_close_all();

    free (strip_specific_buffer);
    free (strip_unneeded_buffer);
    free (keep_specific_buffer);
    free (localize_specific_buffer);
    free (globalize_specific_buffer);
    free (keepglobal_specific_buffer);
    free (weaken_specific_buffer);
    delete_symbol_htabs ();

cleanup_files:
    unlink(in_file);
    unlink("/tmp/random.out");
    return 0;
}