/*
    Copyright 2004-2011 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#ifdef WIN32
    #include <direct.h>
    #include <windows.h>
    #define PATH_SLASH  '\\'
#else
    #include <unistd.h>
    #define stricmp strcasecmp
    #define NOGUI
    #define PATH_SLASH  '/'
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "md5.h"



#define VER         "0.4.4b" // modify mlpatch.c too
#define PATCH       0
#define UNPATCH     1
#define ORIGINAL    UNPATCH
#define ISORIGINAL  "File is already the original"
#define ISPATCHED   "File is already patched"
#define SUCCESSX    "File has been successfully patched!\n"             \
                    "\n"                                                \
                    "%d bytes changed\n"
#define SUCCESS     SUCCESSX \
                    "\n"                                                \
                    "Do you want to see the report of the changes?\n"
#define MD5DIFF     "Different MD5 checksum, file is not the original\n"                        \
                    "Want you try to force the patching???\n"                                   \
                    "\n"                                                                        \
                    "The process terminates automatically if finds a byte to modify that is\n"  \
                    "different than the original so you can recover your original file using\n" \
                    "the UNPATCH option of this tool\n"                                         \
                    "\n"                                                                        \
                    "Anyway I highly suggest to make a temporary BACKUP of your file if you\n"  \
                    "decide to choose YES and forcing the patching\n"
#define BYTEDIFF    "A byte in your file is not equal to the original file, I cannot continue\n"    \
                    "If you have not made a backup copy of your file you can recover it using\n"    \
                    "the UNPATCH option (NO button) from the initial menu\n"                        \
                    "\n"                                                                            \
                    "%d bytes changed during the process\n"                                         \
                    "\n"                                                                            \
                    "Do you want to see the report of the changes?\n"
#define MSG         "# Lame patcher "VER"\n"                                \
                    "# by Luigi Auriemma\n"                                 \
                    "# e-mail: aluigi@autistici.org\n"                      \
                    "# web:    aluigi.org\n"                                \
                    "\n"                                                    \
                    "Main folder  \t%s\n"                                   \
                    "Data file    \t%s\n"                                   \
                    "Filename     \t%s\n"                                   \
                    "Filesize     \t%u\n"                                   \
                    "Original MD5 \t%s\n"                                   \
                    "Patched MD5  \t%s\n"                                   \
                    "\n"                                                    \
                    "Usage:\n"                                              \
                    "      YES:    \tPATCH \t\t(original => patched)\n"     \
                    "      NO:     \tUNPATCH \t(restore the original)\n"    \
                    "      CANCEL: \tEXIT\n"
#define REPORTHEAD  "OFFSET    \tFROM \tTO\n"
#define REPORTMSG   "%08X \t%02X \t%02X\n"
                    //  "11223344 \t11 \t22\n" <= output is the same size
                    //  anyway I use sizeof(REPORT) so the length is ever +1



#include "iofuncs.h"



head_t  head;
FILE    *lpatch             = NULL;
int     forced              = 0,
        autoyes             = 0,
        run_process         = 0,
        patch_process       = 0;
u8      *title              = NULL,
        *intro              = NULL,
        *comment            = NULL,
        *report             = NULL,
        *newmode_fname_arg  = NULL; // avoids problems if there are multiple FILE in the lpatch file



#include "lpatch_newmode.h"



int debug_privileges(void);
int lpatch_apply(FILE *patchfile, int patch_unpatch);
void patch(u8 *name, int choice);
FILE *lpatch_fopen(u8 **fname, u8 *mode, u8 *filter, u8 *notfound_msg);   // %s required!!!
void newmode(void);



int main(int argc, char *argv[]) {
    struct stat xstat;
    int     i,
            ans,
            bytes;
    u8      md5_original[33],
            md5_patch[33],
            *filename   = NULL,
            *lpach_file = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    //setbuf(stdin,  NULL);

#ifdef NOGUI    // I can't use the double gui-command-line mode
    fputs("\n"
        "Lame patcher "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stderr);

    if(argc < 2) {
        printf("\n"
            "Usage: %s [options] <lpatch.dat/file.LPATCH> [file] [yes]\n"
#ifdef WIN32
            "\n"
            "Options:\n"
            "-r     launch the program specified by \"file\" or inserted at runtime,\n"
            "       wait one second and try to patch its process, example\n"
            "         lpatch -r c:\\file.lpatch \"c:\\folder\\myprogram.exe -c server.cfg\"\n"
            "-p     patch a running process through its pid or name specified by \"file\"\n"
            "       or inserted at runtime), example:\n"
            "         lpatch -p c:\\file.lpatch 1234\n"
            "         lpatch -p c:\\file.lpatch process_name\n"
#else
            // the functions have not been tuned for Linux
#endif
            "-y     exactly the same thing as specifying \"yes\" as last argument\n"
            "\n"
            "* the last argument is used to force the patching and creation of the\n"
            "  backup without requesting the confirmation of the user\n"
            "\n", argv[0]);
        exit(1);
    }
#endif

    get_main_path(argv[0]);

    for(i = 1; i < argc; i++) {
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
            break;
            //printf("\nError: wrong argument (%s)\n", argv[i]);
            //exit(1);
        }
        switch(argv[i][1]) {
            case 'r': run_process   = 1;    break;
            case 'p': patch_process = 1;    break;
            case 'y': autoyes       = 1;    break;
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                exit(1);
            }
        }
    }
    argc -= i;

    lpach_file = "lpatch.dat";
    if(argc >= 1) lpach_file = argv[i];
    if(argc >= 2) newmode_fname_arg = argv[i + 1];
    if((argc >= 3) && !stricmp(argv[i + 2], "yes")) autoyes = 1;

    if(run_process || patch_process) {
        debug_privileges();
    }

    lpatch = lpatch_fopen(
        &lpach_file,
        "rb",
        "*.dat;*.lpatch;*.txt",
        "# Lame patcher "VER"\n"
        "The file %s doesn't exist in the current directory or can't be read\n"
        "This tool supports two types of patches:\n"
        "- lpatch.dat: patch informations in binary format\n"
        "- *.lpatch files: advanced patch informations in textual format\n"
        "Do you want to select a .dat or .lpatch file?\n");

    read_head(lpatch, &head);
    if(!memcmp(&head, "================================", 32)) {
        newmode();
        fclose(lpatch);
        return(0);
    }

    filename = frss(lpatch, NULL, head.namelen);

    title    = frss(lpatch, NULL, head.titlelen);

    if(head.commlen > 0) {
        comment = frss(lpatch, NULL, head.commlen);
    }

    make_md5_string(head.md51, md5_original);
    make_md5_string(head.md52, md5_patch);

    fstat(fileno(lpatch), &xstat);
    bytes = (xstat.st_size - ftell(lpatch)) / sizeof(fix_t);
    report = malloc(sizeof(REPORTHEAD) + (sizeof(REPORTMSG) * bytes));
    if(!report) std_err(NULL);
    sprintf(report, REPORTHEAD);

    if(autoyes) {
        ans = IDYES;
    } else {
        ans = msgbox(
            MB_YESNOCANCEL | MB_ICONINFORMATION,
            title,
            MSG,
                current_folder,
                lpach_file,
                filename,
                head.size,
                md5_original,
                md5_patch);
    }

    switch(ans) {
        case IDYES:     patch(filename, PATCH);     break;
        case IDNO:      patch(filename, UNPATCH);   break;
        case IDCANCEL:                              break;
        default:                                    break;
    }

    fclose(lpatch);
    FREEX(filename);
    FREEX(title);
    FREEX(comment);
    FREEX(report);
    return(0);
}



int debug_privileges(void) {
#ifdef WIN32
    TOKEN_PRIVILEGES tp;
    HANDLE  hp;

    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hp)) return(-1);
    memset(&tp, 0, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) return FALSE;
    if(!AdjustTokenPrivileges(hp, FALSE, &tp, sizeof(tp), NULL, NULL)) return(-1);
    CloseHandle(hp);
#endif
    return(0);
}



int lpatch_apply(FILE *patchfile, int patch_unpatch) {
    fix_t   fix;
    int     crc_err    = 0,
            t,
            ans,
            changed    = 0,
            byte_patch = 0;
    u8      *hash,
            *x1,
            *x2,
            *rep;

    hash = calc_md5(patchfile);

    if(patch_unpatch == PATCH) {
        if(memcmp(hash, head.md51, 16)) crc_err = 1;
        x1 = &fix.original;
        x2 = &fix.patch;
    } else {
        if(memcmp(hash, head.md52, 16)) crc_err = 1;
        x1 = &fix.patch;
        x2 = &fix.original;
    }

    if(crc_err) {
        if(!memcmp(hash, head.md51, 16)) {
            std_err(ISORIGINAL);
        } else if(!memcmp(hash, head.md52, 16)) {
            std_err(ISPATCHED);
        } else {
            ans = msgbox(
                MB_YESNO | MB_ICONERROR,
                "Error",
                MD5DIFF);
            if(ans == IDNO) exit(1);
            forced = 1;
        }
    }

    rep = report + strlen(report);
    for(;;) {
        if(fgetc(lpatch) < 0) break;    // feof(lpatch) doesn't work!!!
        fseek(lpatch, -1, SEEK_CUR);    // so I must use this work-around

        read_fix(lpatch, &fix);

        if(fseek(patchfile, fix.offset, SEEK_SET)
          < 0) std_err(NULL);

        if(forced) {
            t = fgetc(patchfile);
            if(t < 0) std_err("wrong file offset");
            if(t == *x2) {
                byte_patch++;
            } else if(t != *x1) {
                ans = msgbox(
                    MB_YESNO | MB_ICONERROR,
                    "Alert",
                    BYTEDIFF,
                        changed);
                if(ans == IDYES) {
                    msgbox(
                        MB_ICONINFORMATION,
                        "Report",
                        "%s",
                            report);
                }
                return(-1);
            }
            fseek(patchfile, -1, SEEK_CUR);
        }
        if(fputc(*x2, patchfile) < 0) std_err(NULL);
        fflush(patchfile);
        changed++;

        fputc('.', stdout);
        rep += sprintf(rep, REPORTMSG, fix.offset, *x1, *x2);
    }

    if(forced && (byte_patch == changed)) {
        std_err((patch_unpatch == PATCH) ? ISPATCHED : ISORIGINAL);
    }

    return(changed);
}



void patch(u8 *name, int choice) {
    FILE    *patchfile;
    int     ans,
            changed;

    patchfile = lpatch_fopen(
        &name,
        "r+b",
        NULL,
        "The file %s has not been found in the current directory\n"
        "Do you want to select this file manually?");

    changed = lpatch_apply(patchfile, choice);

    fclose(patchfile);

    if(changed < 0) return;

    if(autoyes) {
        ans = msgbox(
            MB_OK | MB_ICONINFORMATION,
            "Success",
            SUCCESSX,
                changed);
        ans = IDNO;
    } else {
        ans = msgbox(
            MB_YESNO | MB_ICONINFORMATION,
            "Success",
            SUCCESS,
                changed);
    }

    if(ans == IDYES) {
        msgbox(
            MB_ICONINFORMATION,
            "Report",
            "%s",
                report);
    }

    if(comment) {
        msgbox(
            MB_ICONINFORMATION,
            "Comment",
            "%s",
                comment);
    }
}



FILE *lpatch_fopen(u8 **fname, u8 *mode, u8 *filter, u8 *notfound_msg) {
    int     ans;
    FILE    *fd;
    u8      *name = NULL;

    if(fname) name = *fname;

    if(name) {
        if(strchr(mode, '+') || strchr(mode, 'w')) set_rwmode(name);
        fd = fopen(name, mode);
        if(fd) return(fd);
        if(newmode_fname_arg && strchr(mode, '+')) {    // so file patching only
            fd = fopen(newmode_fname_arg, mode);
            if(fd) return(fd);
        }

        ans = msgbox(
            MB_YESNO | MB_ICONINFORMATION,
            "File not found",
            notfound_msg,
                name);
        if(ans == IDNO) exit(1);
    }

    name = get_file(filter);
    if(strchr(mode, '+') || strchr(mode, 'w')) set_rwmode(name);
    fd = fopen(name, mode);
    if(!fd) std_err(NULL);
    if(fname) *fname = name;
    return(fd);
}


