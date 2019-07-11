/*
    Copyright 2004,2005,2006,2007,2008,2009,2010 Luigi Auriemma

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


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "md5.h"

#ifdef WIN32
    #include <direct.h>
#else
    #include <dirent.h>
#endif



#define VER         "0.4.4b"    // modify lpatch.c too



#define NOGUI
#include "iofuncs.h"



u32     off = 0;
FILE    *lpatch;



void find_diff(u8 *buff1, u8 *buff2, int size);



int main(int argc, char *argv[]) {
    struct stat xstat;
    md5_context md5t1,
                md5t2;
    head_t  head;
    FILE    *fd1,
            *fd2,
            *fdcomment;
    int     len1,
            len2;
    u8      buff1[BUFFSZ],
            buff2[BUFFSZ],
            md51[33],
            md52[33],
            *comment  = NULL,
            *fname1,
            *fname2,
            *title,
            *fcomment = NULL;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "Lame patcher: data file maker "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 4) {
        printf("\n"
            "Usage: %s <original> <patched> <title> [comment]\n"
            "\n", argv[0]);
        exit(1);
    }

    fname1   = argv[1];
    fname2   = argv[2];
    title    = argv[3];
    fcomment = argv[4];

    head.commlen = 0;
    if(argc > 4) {
        printf("- open comment file \"%s\"\n", fcomment);
        fdcomment = fopen(fcomment, "rb");
        if(!fdcomment) std_err(NULL);

        fstat(fileno(fdcomment), &xstat);
        head.commlen = xstat.st_size;
        comment = malloc(head.commlen);
        if(!comment) std_err(NULL);
        fread(comment, 1, head.commlen, fdcomment);
        fclose(fdcomment);
    }

    printf("- open original file \"%s\"\n", fname1);
    fd1 = fopen(fname1, "rb");
    if(!fd1) std_err(NULL);
    fstat(fileno(fd1), &xstat);
    len1 = xstat.st_size;

    printf("- open patched file \"%s\"\n", fname2);
    fd2 = fopen(fname2, "rb");
    if(!fd2) std_err(NULL);
    fstat(fileno(fd2), &xstat);
    len2 = xstat.st_size;

    if(len1 != len2) {
        printf("\nError: original and patched files have different size!\n\n");
        exit(1);
    }

    printf("- create new LPATCH.DAT file\n");
    lpatch = fopen("lpatch.dat", "wb");
    if(!lpatch) std_err(NULL);

    head.size     = len1;
    head.namelen  = strlen(fname1);
    head.titlelen = strlen(title);

    // write_head (later)
    fseek(lpatch, sizeof(head), SEEK_SET);
    if(fwrite(fname1, 1, head.namelen,  lpatch) != head.namelen) write_err();
    if(fwrite(title,  1, head.titlelen, lpatch) != head.titlelen) write_err();
    if(head.commlen > 0) {
        if(fwrite(comment, 1, head.commlen, lpatch) != head.commlen) write_err();
    }

    printf("\n"
        "  Offset   Original Patched\n"
        "---------------------------\n");

    md5_starts(&md5t1);
    md5_starts(&md5t2);

    while((len1 = fread(buff1, 1, BUFFSZ, fd1))) {
        len2 = fread(buff2, 1, BUFFSZ, fd2);

        md5_update(&md5t1, buff1, len1);
        md5_update(&md5t2, buff2, len2);

        find_diff(buff1, buff2, len1);
        off += len1;
    }

    md5_finish(&md5t1, head.md51);
    md5_finish(&md5t2, head.md52);

    fflush(lpatch);
    rewind(lpatch);
    write_head(lpatch, &head);

    fclose(fd1);
    fclose(fd2);
    fclose(lpatch);

    make_md5_string(head.md51, md51);
    make_md5_string(head.md52, md52);

    printf("\n"
        "%s MD5: %s\n"
        "%s MD5: %s\n"
        "\n",
        fname1, md51,
        fname2, md52);

    FREEX(comment);
    return(0);
}



void find_diff(u8 *p1, u8 *p2, int size) {
    fix_t   fix;
    int     i;

    for(i = 0; i < size; i++, p1++, p2++) {
        if(*p1 == *p2) continue;
        printf("%08X   %02X       %02X\n",
            off + i,   *p1,       *p2);

        fix.offset   = off + i;
        fix.original = *p1;
        fix.patch    = *p2;
        write_fix(lpatch, &fix);
    }
}


