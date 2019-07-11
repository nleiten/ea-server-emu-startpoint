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

#ifdef NOGUI
    #define MessageBoxX MessageBox_cli
#else
    #define MessageBoxX MessageBox
#endif

typedef uint8_t     u8;
typedef int16_t     i16;
typedef uint16_t    u16;
typedef uint32_t    u32;



#define BUFFSZ      8192



#pragma pack(1)

typedef struct {
    u8      md51[16];
    u8      md52[16];
    u32     size;
    u8      namelen;
    u8      titlelen;
    u16     commlen;
    /* filename < 256   */
    /* title    < 256   */
    /* comment  < 65536 */
} head_t;

typedef struct {
    u32     offset;
    u8      original;
    u8      patch;
} fix_t;

#pragma pack()



u8      current_folder[4096] = "";



#define FREEX(X)    freex((void *)&X)
void freex(void **buff) {
    if(!buff || !*buff) return;
    free(*buff);
    *buff = NULL;
}



int vspr(u8 **buff, u8 *fmt, va_list ap) {
    int     len,
            mlen;
    u8      *ret;

    mlen = strlen(fmt) + 256;

    for(;;) {
        ret = malloc(mlen);
        if(!ret) {
            *buff = NULL;
            return(0);
        }
        len = vsnprintf(ret, mlen, fmt, ap);
        if(len < 0) {               // Windows style
            mlen += 256;
        } else if(len >= mlen) {    // POSIX style
            mlen = len + 1;
        } else {
            break;
        }
        FREEX(ret);
    }

    *buff = ret;
    return(len);
}



#ifdef NOGUI

u8 get_char(u8 *ans) {
    u8      tmp[16],
            keyfound,
            key,
            *p;

    keyfound = 0;
    key      = 0;
    while(!keyfound) {
        if(key < ' ') {
            if(keyfound) break;
            printf("- choice (");
            for(p = ans; *p; p++) {
                fputc(*p, stdout);
                if(p[1]) fputc('/', stdout);
            }
            printf("): ");
        }

        //fflush(stdin);
        fgets(tmp, sizeof(tmp), stdin);
        key = tolower(tmp[0]);
        for(p = ans; *p; p++) {
            if(key == *p) keyfound = key;
        }
    }
    return(keyfound);
}



int MessageBox_cli(int hWnd, u8 *lpText, u8 *lpCaption, int uType) {
#define IDOK                    1
#define IDCANCEL                2
#define IDABORT                 3
#define IDRETRY                 4
#define IDIGNORE                5
#define IDYES                   6
#define IDNO                    7
#define IDCLOSE                 8
#define IDHELP                  9
#define IDTRYAGAIN              10
#define IDCONTINUE              11
#define MB_USERICON             128
#define MB_ICONASTERISK         64
#define MB_ICONEXCLAMATION      0x30
#define MB_ICONWARNING          0x30
#define MB_ICONERROR            16
#define MB_ICONHAND             16
#define MB_ICONQUESTION         32
#define MB_OK                   0
#define MB_ABORTRETRYIGNORE     2
#define MB_APPLMODAL            0
#define MB_DEFAULT_DESKTOP_ONLY 0x20000
#define MB_HELP                 0x4000
#define MB_RIGHT                0x80000
#define MB_RTLREADING           0x100000
#define MB_TOPMOST              0x40000
#define MB_DEFBUTTON1           0
#define MB_DEFBUTTON2           256
#define MB_DEFBUTTON3           512
#define MB_DEFBUTTON4           0x300
#define MB_ICONINFORMATION      64
#define MB_ICONSTOP             16
#define MB_OKCANCEL             1
#define MB_RETRYCANCEL          5
#define MB_SERVICE_NOTIFICATION 0x00200000
#define MB_SERVICE_NOTIFICATION_NT3X 0x00040000
#define MB_SETFOREGROUND        0x10000
#define MB_SYSTEMMODAL          4096
#define MB_TASKMODAL            0x2000
#define MB_YESNO                4
#define MB_YESNOCANCEL          3
#define MB_ICONMASK             240
#define MB_DEFMASK              3840
#define MB_MODEMASK             0x00003000
#define MB_MISCMASK             0x0000C000
#define MB_NOFOCUS              0x00008000
#define MB_TYPEMASK             15
#define MB_TOPMOST              0x40000
#define MB_CANCELTRYCONTINUE    6
#define uType_key(A,B)          if(uType & A) {         \
                                    key = get_char(B);  \
                                } else

    u8      key;

    printf("\n");
    if(strcmp(lpCaption, "Lame patcher "VER)) printf("\n%s:", lpCaption);
    printf("\n%s\n", lpText);

    key = 0;
    uType_key(MB_YESNOCANCEL,       "ync")
    uType_key(MB_YESNO,             "yn")
    uType_key(MB_RETRYCANCEL,       "rc")
    uType_key(MB_ABORTRETRYIGNORE,  "ari")
    uType_key(MB_OKCANCEL,          "oc")
    uType_key(MB_CANCELTRYCONTINUE, "ct")
    {}

    switch(key) {
        case 'o': return(IDOK);         break;
        case 'c': return(IDCANCEL);     break;
        case 'a': return(IDABORT);      break;
        case 'r': return(IDRETRY);      break;
        case 'i': return(IDIGNORE);     break;
        case 'y': return(IDYES);        break;
        case 'n': return(IDNO);         break;
        case 'h': return(IDHELP);       break;
        case 't': return(IDTRYAGAIN);   break;
        default:                        break;
    }
    return(0);
}

#endif



int msgbox(int uType, u8 *lpCaption, u8 *lpText, ...) {
    va_list ap;
    int     ans;
    u8      *text;

    va_start(ap, lpText);
    vspr(&text, lpText, ap);
    va_end(ap);

    ans = MessageBoxX(0, text, lpCaption, uType | MB_TASKMODAL);
    FREEX(text);
    return(ans);
}



void std_err(u8 *err) {
    if(!err) err = strerror(errno);
    MessageBoxX(0, err, "Error", MB_ICONERROR | MB_TASKMODAL);
    exit(1);
}



void read_err(void) {
    std_err("the data file is incomplete or corrupted");
}



void write_err(void) {
    std_err("impossible to write the output file, probably your disk space is finished");
}



u8 fr08(FILE *fd) {
    int     t1;

    t1 = fgetc(fd);
    if(t1 < 0) read_err();
    return(t1);
}



u16 fr16(FILE *fd) {
    int     t1,
            t2;

    t1 = fgetc(fd);
    t2 = fgetc(fd);
    if((t1 < 0) || (t2 < 0)) read_err();
    return(t1 | (t2 << 8));
}



u32 fr32(FILE *fd) {
    int     t1,
            t2,
            t3,
            t4;

    t1 = fgetc(fd);
    t2 = fgetc(fd);
    t3 = fgetc(fd);
    t4 = fgetc(fd);
    if((t1 < 0) || (t2 < 0) || (t3 < 0) || (t4 < 0)) read_err();
    return(t1 | (t2 << 8) | (t3 << 16) | (t4 << 24));
}



u8 *frss(FILE *fd, u8 *data, int size) {
    if(!data) {
        data = malloc(size + 1);
        if(!data) std_err(NULL);
    }
    if(fread(data, 1, size, fd) != size) read_err();
    data[size] = 0;
    return(data);
}



void fw08(FILE *fd, int num) {
    if(fputc((num      ) & 0xff, fd) < 0) write_err();
}



void fw16(FILE *fd, int num) {
    if(fputc((num      ) & 0xff, fd) < 0) write_err();
    if(fputc((num >>  8) & 0xff, fd) < 0) write_err();
}



void fw32(FILE *fd, int num) {
    if(fputc((num      ) & 0xff, fd) < 0) write_err();
    if(fputc((num >>  8) & 0xff, fd) < 0) write_err();
    if(fputc((num >> 16) & 0xff, fd) < 0) write_err();
    if(fputc((num >> 24) & 0xff, fd) < 0) write_err();
}



void fwss(FILE *fd, u8 *data) {
    int     len;

    len = strlen(data);
    if(fwrite(data, 1, len, fd) != len) write_err();
}



void read_head(FILE *fd, head_t *head) {
    if(fread(head->md51, 1, 16, fd) != 16) read_err();
    if(fread(head->md52, 1, 16, fd) != 16) read_err();
    head->size     = fr32(fd);
    head->namelen  = fr08(fd);
    head->titlelen = fr08(fd);
    head->commlen  = fr16(fd);
}



void write_head(FILE *fd, head_t *head) {
    if(fwrite(head->md51, 1, 16, fd) != 16) write_err();
    if(fwrite(head->md52, 1, 16, fd) != 16) write_err();
    fw32(fd, head->size);
    fw08(fd, head->namelen);
    fw08(fd, head->titlelen);
    fw16(fd, head->commlen);
}



void read_fix(FILE *fd, fix_t *fix) {
    fix->offset   = fr32(fd);
    fix->original = fr08(fd);
    fix->patch    = fr08(fd);
}



void write_fix(FILE *fd, fix_t *fix) {
    fw32(fd, fix->offset);
    fw08(fd, fix->original);
    fw08(fd, fix->patch);
}



void make_md5_string(u8 *in, u8 *out) {
    static const u8 hex[16] = "0123456789abcdef";
    int     i;

    for(i = 0; i < 16; i++) {
        *out++ = hex[*in >> 4];
        *out++ = hex[*in & 0xf];
        in++;
    }
    *out = 0;
}



int delimit(u8 *data) {
    u8      *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    *p = 0;
    return(p - data);
}



u8 *get_file(u8 *filter) {
    static u8   filename[1024];

#ifdef NOGUI
    if(!filter) filter = "";
    printf("\n"
        "Specify the name of the file (%s): ",
        filter);
    fgets(filename, sizeof(filename), stdin);
    delimit(filename);
    if(!*filename && *filter) {
        strncpy(filename, filter, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = 0;
    }
    return(filename);

#else
    OPENFILENAME    ofn;
    int             len;
    static const u8 anyfile[] = "(*.*)\0" "*.*\0" "\0\0";
    u8              *flt,
                    *f;

    if(filter) {
        len = strlen(filter) + 1;
        flt = malloc((len * 2) + sizeof(anyfile));
        if(!flt) std_err(NULL);
        f = flt;
        f += sprintf(f, "%s", filter) + 1;  // filter name
        f += sprintf(f, "%s", filter) + 1;  // filter
        memcpy(f, anyfile, sizeof(anyfile) - 1);
    } else {
        filter = "";
        flt = (u8 *)anyfile;
    }

    filename[0] = 0;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize     = sizeof(ofn);
    ofn.lpstrInitialDir = current_folder;
    ofn.lpstrFilter     = flt;
    ofn.nFilterIndex    = 1;
    ofn.lpstrFile       = filename;
    ofn.nMaxFile        = sizeof(filename) - 1;
    ofn.lpstrTitle      = "Select the file";
    ofn.Flags           = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;

    if(!GetOpenFileName(&ofn)) {
        if(!CommDlgExtendedError()) exit(1);
        std_err("Error while creating the dialog box for the selection of the file");
    }

    if(ofn.nFileOffset) {
        filename[ofn.nFileOffset - 1] = 0;
        chdir(filename);
    }
    
    getcwd(current_folder, sizeof(current_folder));
    return(filename + ofn.nFileOffset);
#endif
}



u8 *calc_md5(FILE *fd) {
    md5_context md5t;
    int     len;
    u8      buff[BUFFSZ];
    static u8   hash[16];

    rewind(fd);
    md5_starts(&md5t);
    while((len = fread(buff, 1, BUFFSZ, fd))) {
        md5_update(&md5t, buff, len);
    }
    md5_finish(&md5t, hash);

    return(hash);
}



u32 readbin(u8 *data) {
    u32     out = 0;

    for(;;) {
        if(*data == '1') {
            out = (out << 1) | 1;
        } else if(*data == '0') {
            out <<= 1;
        } else {
            break;
        }
        data++;
    }
    return(out);
}



void get_main_path(u8 *argv0) {
    u8      *p;

#ifdef WIN32
    #ifdef NOGUI
        getcwd(current_folder, sizeof(current_folder));
    #else 
        GetModuleFileName(NULL, current_folder, sizeof(current_folder));
    #endif
#else
    sprintf(current_folder, "%.*s", sizeof(current_folder), argv0);
#endif

    p = strrchr(current_folder, '\\');
    if(!p) p = strrchr(current_folder, '/');
    if(p) *p = 0;
}



void set_rwmode(u8 *fname) {
    struct stat xstat;

    stat(fname, &xstat);
    if(!(xstat.st_mode & S_IWUSR)) {
        chmod(fname, xstat.st_mode | S_IWUSR);
    }
}


