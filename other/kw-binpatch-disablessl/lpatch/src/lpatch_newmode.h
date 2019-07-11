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

#ifdef WIN32
    #include <windows.h>
    #define sleep(X)    Sleep(X * 1000)
    #define pid_t   HANDLE
#else
    #include "pe_nonwin.h"
#endif
#include "process.h"



#define MAXMEMORYFILE   0x4000000   // 64 megabytes max for in-memory file mapping
                                    // otherwise the tool will patch the file on disk with an
                                    // almost unexistent loss of performances and with the
                                    // possibility of being able to patch any huge file < 2Gb

enum {
    CMD_TITLE,
    CMD_INTRO,
    CMD_MD5,
    CMD_FILE,
    CMD_RVA,
    CMD_COMMENT,
    CMD_OFFSET,
    CMD_ONLY_ONE,
    CMD_STRING,
    CMD_BYTES_ORIGINAL,
    CMD_BYTES_PATCH,
    CMD_BYTES_ORIGINALX,
    CMD_BYTES_PATCHX,
    CMD_MAX_CHANGES,
    CMD_EXECUTABLE,
    CMD_NONE = -1
};



    /* NEWMODE_NUM is studied for 8 bit numbers (1 byte) */
#define NEWMODE_NUM_ADD         0x0100
#define NEWMODE_NUM_SUB         0x0200
#define NEWMODE_TYPE_SKIP       0x0400
#define NEWMODE_TYPE_32_OFFSET  0x0800
#define NEWMODE_TYPE_32         0x1000



typedef struct {    // needed for handling the processes easily because this
    FILE    *fd;    // tool is a file patcher (processes are a secondary thing)
    int     size;
    // the following are non file related
    u8      *data;
    int     pos;
    pid_t   pid;
    void    *baddr;
} fd_newmode_t;
fd_newmode_t *fd_newmode        = NULL;
fix_t   **offbyte               = NULL;
u32     max_changes             = 0;
int     offbyte_num             = 0,
        offbyte_alloc_size      = 0,
        newmode_original_size   = 0,
        newmode_patch_size      = 0,
        only_one                = 0,
        newmode_md5_hash_num    = 0,
        filememsz               = 0,
        rva                     = 0,
        executable              = 0;
i16     *newmode_original       = NULL,   /* int16 is needed for dynamic bytes  */
        *newmode_patch          = NULL,
        newmode_num_type        = 0;
u8      *newmode_fname          = NULL,
        **newmode_md5_hash      = NULL,
        *fd_newmode_md5         = NULL,
        *filemem                = NULL;



int myfseek(fd_newmode_t *fdn, int offset, int type) {
    int     err = 0;

    if(!fdn->fd) {
        switch(type) {
            case SEEK_SET: fdn->pos = offset;                    break;
            case SEEK_CUR: fdn->pos += offset;                   break;
            case SEEK_END: fdn->pos = fdn->size + offset; break;
            default: break;
        }
        if((fdn->pos < 0) || (fdn->pos > fdn->size)) {
            err = -1;
        }
    } else {
        err = fseek(fdn->fd, offset, type);
    }
    return(err);
}

int myfread(u8 *data, int x, int size, fd_newmode_t *fdn) {
    int     len;

    if(!fdn->fd) {
        size *= x;
        len = size;
        if((fdn->pos + size) > fdn->size) {
            len = fdn->size - fdn->pos;
        }
        memcpy(data, fdn->data + fdn->pos, len);
        fdn->pos += len;
    } else {
        len = fread(data, x, size, fdn->fd);
    }
    return(len);
}

int myfgetc(fd_newmode_t *fdn) {
    u8      chr;
    if(myfread(&chr, 1, 1, fdn) != 1) return(-1);
    return(chr);
}

int myfwrite(u8 *data, int x, int size, fd_newmode_t *fdn) {
    int     len;

    if(!fdn->fd) {
        size *= x;
        len = size;
        if((fdn->pos + size) > fdn->size) {
            return(-1);
        }
        if(fdn->pid && fdn->baddr) {
#ifdef WIN32
            DWORD   tmp;
            VirtualProtectEx(
                fdn->pid,
                (u8 *)fdn->baddr + fdn->pos,
                size,
                PAGE_EXECUTE_READWRITE,
                &tmp);
            if(!WriteProcessMemory(
                fdn->pid,
                (u8 *)fdn->baddr + fdn->pos,
                data,
                size,
                NULL)) len = -1;
            VirtualProtectEx(
                fdn->pid,
                (u8 *)fdn->baddr + fdn->pos,
                size,
                PAGE_EXECUTE_READWRITE,
                &tmp);
#else
            u32     tmp;    // does NOT work!
            int     i,
                    rem;

            //ptrace(PTRACE_ATTACH, fdn->pid, NULL, NULL);
            // mprotect?
            rem = size & 3;
            size &= (~3);
            for(i = 0; i < size; i++) {
                tmp = *(u32 *)(data + i);
                if((ptrace(PTRACE_PEEKDATA, fdn->pid, (u8 *)fdn->baddr + fdn->pos + i, &tmp) == -1) && errno) {
                    len = - 1;
                    break;
                }
            }
            if(rem) {
                tmp = *(u32 *)(fdn->data + fdn->pos + i);
                tmp >>= (rem * 8);
                tmp <<= (rem * 8);
                switch(rem) {
                    case 3: tmp |= data[i + 2] << 16;
                    case 2: tmp |= data[i + 1] << 8;
                    case 1: tmp |= data[i];
                    default: break;
                }
                if((ptrace(PTRACE_PEEKDATA, fdn->pid, (u8 *)fdn->baddr + fdn->pos + i, &tmp) == -1) && errno) {
                    len = - 1;
                    //break;
                }
            }
            //ptrace(PTRACE_DETACH, fdn->pid, NULL, NULL);
#endif
        }
        if(len > 0) {
            memcpy(fdn->data + fdn->pos, data, len);    // maintain a fresh copy (needed for Linux and possibly in future)
            fdn->pos += len;
        }
    } else {
        len = fwrite(data, x, size, fdn->fd);
    }
    return(len);
}

int myfputc(u8 chr, fd_newmode_t *fdn) {
    if(myfwrite(&chr, 1, 1, fdn) != 1) return(-1);
    return(chr);
}



#define SECNAMESZ   32
#define MYPAD(X)    ((X + (sec_align - 1)) & (~(sec_align - 1)))
#define MYALIGNMENT 0x1000  // default in case not available


typedef struct {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} MYIMAGE_NT_HEADERS32;

typedef struct {    // from http://hte.sf.net
    u32     vsize;
    u32     base_reloc_addr;
    u32     flags;
    u32     page_map_index;
    u32     page_map_count;
    u8      name[4];
} vxd_section_t;

typedef struct {
    u8      e_ident[16];
    u16     e_type;
    u16     e_machine;
    u32     e_version;
    u32     e_entry;
    u32     e_phoff;
    u32     e_shoff;
    u32     e_flags;
    u16     e_ehsize;
    u16     e_phentsize;
    u16     e_phnum;
    u16     e_shentsize;
    u16     e_shnum;
    u16     e_shstrndx;
} elf32_header_t;

typedef struct {
    u32     sh_name;
    u32     sh_type;
    u32     sh_flags;
    u32     sh_addr;     
    u32     sh_offset;
    u32     sh_size;
    u32     sh_link;
    u32     sh_info;
    u32     sh_addralign;
    u32     sh_entsize;
} elf32_section_t;

typedef struct {
    u8      Name[SECNAMESZ + 1];
    u32     VirtualAddress;
    u32     VirtualSize;
    int     VirtualSize_off;
    u32     PointerToRawData;
    u32     SizeOfRawData;
    u32     Characteristics;
} section_t;



section_t   *section            = NULL;
u32     imagebase               = 0;
int     isprocess               = 0,
        sections                = 0;



int parse_PE(void) {
    IMAGE_DOS_HEADER        *doshdr;
    MYIMAGE_NT_HEADERS32    *nt32hdr;
    IMAGE_ROM_HEADERS       *romhdr;
    IMAGE_OS2_HEADER        *os2hdr;
    IMAGE_VXD_HEADER        *vxdhdr;
    IMAGE_SECTION_HEADER    *sechdr;
    vxd_section_t           *vxdsechdr;
    u32     tmp;
    int     i;
    u8      *p;
    u32     sec_align,
            entrypoint;

    if(!filemem) return(-1);
    p = filemem;
    doshdr  = (IMAGE_DOS_HEADER *)p;
    if(doshdr->e_magic != IMAGE_DOS_SIGNATURE) return(-1);

    if(doshdr->e_cs) {  // note that the following instructions have been tested on various executables but I'm not sure if they are perfect
        tmp = doshdr->e_cparhdr * 16;
        if(doshdr->e_cs < 0x8000) tmp += doshdr->e_cs * 16;
        p += tmp;
    } else {
        if(doshdr->e_lfanew && (doshdr->e_lfanew < filememsz)) {
            p += doshdr->e_lfanew;
        } else {
            p += sizeof(IMAGE_DOS_HEADER);
        }
    }

    nt32hdr = (MYIMAGE_NT_HEADERS32 *)p;
    romhdr  = (IMAGE_ROM_HEADERS *)p;
    os2hdr  = (IMAGE_OS2_HEADER *)p;
    vxdhdr  = (IMAGE_VXD_HEADER *)p;

    if(nt32hdr->Signature == IMAGE_NT_SIGNATURE) {
        if(nt32hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            p += sizeof(MYIMAGE_NT_HEADERS32);
            imagebase   = nt32hdr->OptionalHeader.ImageBase;
            sec_align   = nt32hdr->OptionalHeader.SectionAlignment;
            entrypoint  = imagebase + nt32hdr->OptionalHeader.AddressOfEntryPoint;
            sections    = nt32hdr->FileHeader.NumberOfSections;
        //} else if(nt64hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { not supported, the tool is 32 bit oriented
        } else if(romhdr->OptionalHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
            p += sizeof(IMAGE_ROM_HEADERS);
            imagebase   = 0;
            sec_align   = MYALIGNMENT;
            entrypoint  = imagebase + romhdr->OptionalHeader.AddressOfEntryPoint;
            sections    = 0;
            section     = NULL;
            return(0);
        } else {
            return(-1);
        }

        section = calloc(sizeof(section_t), sections);
        if(!section) std_err(NULL);

        sechdr = (IMAGE_SECTION_HEADER *)p;
        for(i = 0; i < sections; i++) {
            strncpy(section[i].Name, sechdr[i].Name, IMAGE_SIZEOF_SHORT_NAME);
            section[i].VirtualAddress   = sechdr[i].VirtualAddress;
            section[i].VirtualSize      = sechdr[i].Misc.VirtualSize;
            section[i].VirtualSize_off  = ((u8 *)&(sechdr[i].Misc.VirtualSize)) - filemem;
            section[i].PointerToRawData = sechdr[i].PointerToRawData;
            section[i].SizeOfRawData    = sechdr[i].SizeOfRawData;
            section[i].Characteristics  = sechdr[i].Characteristics;
            if(!section[i].VirtualSize) section[i].VirtualSize = section[i].SizeOfRawData;  // Watcom
        }

    } else if(os2hdr->ne_magic == IMAGE_OS2_SIGNATURE) {
        p += sizeof(IMAGE_OS2_HEADER);
        imagebase   = 0;
        sec_align   = os2hdr->ne_align;
        entrypoint  = imagebase + os2hdr->ne_csip;
        sections    = 0;
        sechdr      = NULL;

    } else if(
      (vxdhdr->e32_magic == IMAGE_OS2_SIGNATURE_LE) ||  // IMAGE_VXD_SIGNATURE is the same signature
      (vxdhdr->e32_magic == 0x3357) ||                  // LX, W3 and W4: I guess they are the same... I hope
      (vxdhdr->e32_magic == 0x3457) ||
      (vxdhdr->e32_magic == 0x584C)) {
        p += sizeof(IMAGE_VXD_HEADER);
        imagebase   = 0;
        sec_align   = vxdhdr->e32_pagesize;
        entrypoint  = 0;    // handled later
        sections    = vxdhdr->e32_objcnt;

        section = calloc(sizeof(section_t), sections);
        if(!section) std_err(NULL);

        tmp = vxdhdr->e32_datapage;
        vxdsechdr = (vxd_section_t *)p;
        for(i = 0; i < sections; i++) {
            strncpy(section[i].Name, vxdsechdr[i].name, 4);
            section[i].VirtualAddress   = vxdsechdr[i].base_reloc_addr;
            section[i].VirtualSize      = vxdsechdr[i].vsize;
            section[i].VirtualSize_off  = ((u8 *)&(vxdsechdr[i].vsize)) - filemem;
            section[i].PointerToRawData = tmp;
            section[i].SizeOfRawData    = vxdsechdr[i].vsize;
            section[i].Characteristics  = vxdsechdr[i].flags;
            tmp += MYPAD(section[i].SizeOfRawData);
            if(!entrypoint && (tmp > vxdhdr->e32_eip)) {    // I'm not totally sure if this is correct but it's not an important field
                entrypoint = section[i].VirtualAddress + vxdhdr->e32_eip;
            }
        }
    } else {
        imagebase   = 0;
        sec_align   = 0;
        entrypoint  = imagebase + (doshdr->e_cs < 0x8000) ? doshdr->e_ip : 0;
        sections    = 0;
    }
    return(p - filemem);
}



int parse_ELF32(void) {
    elf32_header_t  *elfhdr;
    elf32_section_t *elfsec;
    int     i;
    u8      *p;
    u32     sec_align,
            entrypoint;

    if(!filemem) return(-1);
    p = filemem;
    elfhdr = (elf32_header_t *)p;     p += sizeof(elf32_header_t);
    if(memcmp(elfhdr->e_ident, "\x7f""ELF", 4)) return(-1);
    if(elfhdr->e_ident[4] != 1) return(-1); // only 32 bit supported
    if(elfhdr->e_ident[5] != 1) return(-1); // only little endian

    imagebase   = 0;
    sec_align   = 0;
    entrypoint  = elfhdr->e_entry;

    sections = elfhdr->e_shnum;
    section = calloc(sizeof(section_t), sections);
    if(!section) std_err(NULL);

    elfsec = (elf32_section_t *)(filemem + elfhdr->e_shoff);
    for(i = 0; i < sections; i++) {
        strncpy(section[i].Name, filemem + elfsec[elfhdr->e_shstrndx].sh_offset + elfsec[i].sh_name, SECNAMESZ);
        section[i].Name[SECNAMESZ]  = 0;
        section[i].VirtualAddress   = elfsec[i].sh_addr;
        section[i].VirtualSize      = elfsec[i].sh_size;
        section[i].VirtualSize_off  = ((u8 *)&(elfsec[i].sh_size)) - filemem;
        section[i].PointerToRawData = elfsec[i].sh_offset;
        section[i].SizeOfRawData    = elfsec[i].sh_size;
        section[i].Characteristics  = elfsec[i].sh_flags;
        if(!section[i].VirtualSize) section[i].VirtualSize = section[i].SizeOfRawData;  // Watcom
    }
    return(p - filemem);
}



u32 rva2file(u32 va) {
    u32     diff;
    int     i,
            ret;

    va  -= imagebase;
    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((sections > 1) && !section[i].VirtualAddress) continue;
        if((va >= section[i].VirtualAddress) && (va < (section[i].VirtualAddress + section[i].VirtualSize))) {
            if((va - section[i].VirtualAddress) < diff) {
                diff = va - section[i].VirtualAddress;
                ret  = i;
            }
        }
    }
    if(ret < 0) return(-1);
    return(section[ret].PointerToRawData + va - section[ret].VirtualAddress);
}



u32 file2rva(u32 file) {
    u32     diff;
    int     i,
            ret;

    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((file >= section[i].PointerToRawData) && (file < (section[i].PointerToRawData + section[i].SizeOfRawData))) {
            if((file - section[i].PointerToRawData) < diff) {
                diff = file - section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    if(ret < 0) return(-1);
    return(imagebase + section[ret].VirtualAddress + file - section[ret].PointerToRawData);
}



int get_section(u32 file) {
    u32     diff;
    int     i,
            ret;

    ret  = -1;
    diff = -1;
    for(i = 0; i < sections; i++) {
        if((file >= section[i].PointerToRawData) && (file < (section[i].PointerToRawData + section[i].SizeOfRawData))) {
            if((file - section[i].PointerToRawData) < diff) {
                diff = file - section[i].PointerToRawData;
                ret  = i;
            }
        }
    }
    return(ret);
}



void newmode_backup(void) {
    FILE    *fd;
    int     len;
    u8      buff[BUFFSZ],
            *bckname;

    if(run_process || patch_process) return;    // nothing to backup

    bckname = malloc(strlen(newmode_fname) + 32);
    if(!bckname) std_err(NULL);
    sprintf(bckname, "%s.LPATCH_BACKUP", newmode_fname);

    fd = fopen(bckname, "wb");
    if(!fd) std_err(NULL);
        // although the file is mapped in memory I prefer to be 100% sure that the file is copied from the disk
    //if(filemem) {   // direct dump from the memory
        //if(fwrite(filemem, 1, filememsz, fd) != filememsz) write_err();
    //} else {
        myfseek(fd_newmode, 0, SEEK_SET);
        while((len = myfread(buff, 1, BUFFSZ, fd_newmode))) {
            if(fwrite(buff, 1, len, fd) != len) write_err();
        }
    //}
    fclose(fd);

    FREEX(bckname);
}



u32 get_num(u8 *data) {
    u32    num = 0;
    u8     *p;

    newmode_num_type = 0;
    if(*data == '+') { newmode_num_type |= NEWMODE_NUM_ADD;         data++; }
    if(*data == '-') { newmode_num_type |= NEWMODE_NUM_SUB;         data++; }
    if(*data == '*') { newmode_num_type |= NEWMODE_TYPE_SKIP;       data++; }
    if(*data == '^') { newmode_num_type |= NEWMODE_TYPE_32_OFFSET;  data++; }
    if(*data == '|') { newmode_num_type |= NEWMODE_TYPE_32;         data++; }

    if(!data[0])        return(0);
    if(data[0] == '?')  return(-1);     // dynamic byte

    if(data[0] == '\'') {
        if(data[1] == '\\') {           // \n and so on
            for(p = data; *p; p++) *p = tolower(*p);
            num = 0;
            switch(data[2]) {
                case '0':  num = '\0';  break;
                case 'a':  num = '\a';  break;
                case 'b':  num = '\b';  break;
                case 'e':  num = '\e';  break;
                case 'f':  num = '\f';  break;
                case 'n':  num = '\n';  break;
                case 'r':  num = '\r';  break;
                case 't':  num = '\t';  break;
                case 'v':  num = '\v';  break;
                case '\"': num = '\"';  break;
                case '\'': num = '\'';  break;
                case '\\': num = '\\';  break;
                case '?':  num = '\?';  break;
                case '.':  num = '.';   break;
                case 'x':  sscanf(data + 3, "%x", &num);    break;  // hex
                default:   sscanf(data + 2, "%o", &num);    break;  // octal
            }
        } else {
            num = data[1];              // 'a'
        }
    } else {
        for(p = data; *p; p++) *p = tolower(*p);
        if((strlen(data) > 2) && (data[0] == '0') && (data[1] == 'x')) {
            data += 2;
        } else if((strlen(data) > 1) && (data[0] == '$')) {
            data++;
        }
        sscanf(data, "%x", &num);
    }

    if(newmode_num_type & NEWMODE_NUM_ADD) num |= NEWMODE_NUM_ADD;
    if(newmode_num_type & NEWMODE_NUM_SUB) num |= NEWMODE_NUM_SUB;
    return(num);
}



void add_offset(u32 offset, int original, int patch) {
    int     i;

    if(patch & NEWMODE_NUM_ADD) patch = original + patch;
    if(patch & NEWMODE_NUM_SUB) patch = original - patch;
    original &= 0xff;
    patch    &= 0xff;

    if(original == patch) return;
    for(i = 0; i < offbyte_num; i++) {
        if(offset == offbyte[i]->offset) {
            if(offbyte[i]->patch == patch) return;
            //offbyte[i]->offset   = offset;    // update the current byte to patch (needed for calc_jmp)
            //offbyte[i]->original = original;
            offbyte[i]->patch    = patch;
            return;
        }
    }

    if(!offbyte) {
        offbyte_num         = 0;
        offbyte_alloc_size  = 128;
        offbyte             = malloc(sizeof(fix_t *) * offbyte_alloc_size);
        if(!offbyte) std_err(NULL);
    }
    offbyte_num++;
    if(offbyte_num > offbyte_alloc_size) {
        offbyte_alloc_size += 128;
        offbyte             = realloc(offbyte, sizeof(fix_t *) * offbyte_alloc_size);
        if(!offbyte) std_err(NULL);
    }
    offbyte[offbyte_num - 1]           = malloc(sizeof(fix_t));
    if(!offbyte[offbyte_num - 1]) std_err(NULL);
    offbyte[offbyte_num - 1]->offset   = offset;
    offbyte[offbyte_num - 1]->original = original;
    offbyte[offbyte_num - 1]->patch    = patch;
}



u8 *get_newmode_cmd(u8 *line, int *cmdnum) {
    int     i,
            cmdret;
    u8      *cmd,
            *p,
            *l;
    static const u8 *command[] = {
            "TITLE",
            "INTRO",
            "MD5",
            "FILE",
            "RVA",
            "COMMENT",
            "OFFSET",
            "ONLY_ONE",
            "STRING",
            "BYTES_ORIGINAL",
            "BYTES_PATCH",
            "BYTES_ORIGINALX",
            "BYTES_PATCHX",
            "MAX_CHANGES",
            "EXECUTABLE",
            NULL
    };

    cmdret  = CMD_NONE;
    *cmdnum = CMD_NONE;

    l = line + delimit(line);

    for(p = line; *p; p++) {        // clear start
        if((*p != ' ') && (*p != '\t')) break;
    }
    if(!*p) return(NULL);

    cmd = p;                        // cmd

    for(l--; l > p; l--) {          // clear end
        if(*l > ' ') break;
    }
    *(l + 1) = 0;

    if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return(NULL);

    for(p = cmd; *p > ' '; p++);    // find where the command ends

    for(i = 0; command[i]; i++) {
        if(!memcmp(cmd, command[i], p - cmd)) {
            cmdret = i;
            break;
        }
    }

    if(cmdret != CMD_NONE) {        // skip the spaces between the comamnd and the instructions
        for(; *p; p++) {
            if((*p != ' ') && (*p != '\t')) break;
        }
        cmd = p;
    }

    // do not enable this or will not work!
    // if((*cmd == '=') || (*cmd == '#') || (*cmd == '/') || (*cmd == ';')) return("");

    *cmdnum = cmdret;
    return(cmd);
}



    /* here we catch each line (till line feed) */
    /* returns a pointer to the next line       */
u8 *get_line(u8 *data) {
    u8      *p;

    for(p = data; *p && (*p != '\n') && (*p != '\r'); p++);
    if(!*p) return(NULL);
    *p = 0;
    for(p++; *p && ((*p == '\n') || (*p == '\r')); p++);
    if(!*p) return(NULL);
    return(p);
}



    /* here we catch each element of the line */
    /* returns a pointer to the next element  */
u8 *get_element(u8 **data) {
    u8      *p;

    p = *data;
    if(*p == '"') {     // string
        p++;
        *data = p;
        while(*p && (*p != '"')) p++;
    } else {
        while(*p && (*p != '\t') && (*p != ' ')) p++;
    }

    if(!*p) return(NULL);
    *p = 0;

    for(p++; *p && ((*p == '\t') || (*p == ' ')); p++);
    if(!*p) return(NULL);
    return(p);
}



int search_file(int *ret_offset) {
    u32     offset,
            poff,
            bit32;
    int     i,
            flen,
            blen,
            difflen,
            changes = 0;
    u8      *buff   = NULL,
            *limit,
            *p,
            *l;

    // printf("newmode_original_size: %d -> %d\n", newmode_original_size, newmode_patch_size);

    if(only_one > 1) goto quit;

    if(
         (!newmode_original_size || !newmode_patch_size)
      || (newmode_original_size > fd_newmode->size)
      || (newmode_patch_size    > fd_newmode->size)) {
        goto quit;
    }

    difflen = 0;
    if(newmode_patch_size > newmode_original_size) difflen = newmode_patch_size - newmode_original_size;

    blen   = 0;
    offset = 0;
    if(filemem) {
        buff = filemem;
        flen = filememsz;
    } else {
        buff = malloc(BUFFSZ + newmode_original_size + difflen);
        if(!buff) std_err(NULL);
        myfseek(fd_newmode, 0, SEEK_SET);
        if(ret_offset) {
            offset = *ret_offset;
            myfseek(fd_newmode, offset, SEEK_SET);
        }
        flen = myfread(buff, 1, BUFFSZ + newmode_original_size, fd_newmode);
    }

    do {
        // if(flen < newmode_original_size) break;
        limit = buff + flen + blen;                     // limit is just the end of buff
        l     = (limit - newmode_original_size) + 1;    // used later, in short we need to
                                                        // place the original_size-1 buffer
                                                        // at the beginning of buff

        p = buff;
        if(filemem) {
            if(ret_offset) p += *ret_offset;
        }
        for(; p < limit; p++) {
            for(i = 0; i < newmode_original_size; i++) {
                if(newmode_original[i] & NEWMODE_TYPE_SKIP) continue;
                if(p[i] != newmode_original[i]) break;
            }
            if(i != newmode_original_size) continue;

            if((p + newmode_patch_size) > limit) {
                if(myfread(limit, 1, difflen, fd_newmode) != difflen) goto quit;
                myfseek(fd_newmode, -difflen, SEEK_CUR);
            }

            poff = offset + (p - buff) - blen;
            if(ret_offset) *ret_offset = poff;

            for(i = 0; i < newmode_patch_size; i++) {
                if(newmode_patch[i] & NEWMODE_TYPE_SKIP) continue;

                if(newmode_patch[i] & NEWMODE_TYPE_32_OFFSET) {
                    bit32 = ((newmode_patch[i    ] & 0xff)      )
                          | ((newmode_patch[i + 1] & 0xff) <<  8)
                          | ((newmode_patch[i + 2] & 0xff) << 16)
                          | ((newmode_patch[i + 3] & 0xff) << 24);

                    bit32 -= poff + i + 4;
                    if(rva < 0) {                       /* absolute offset */
                        bit32 = rva2file(bit32);
                    } else {
                        bit32 -= rva;
                    }

                            add_offset(poff + i, p[i], (bit32      ) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >>  8) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >> 16) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >> 24) & 0xff);

                } else if(newmode_patch[i] & NEWMODE_TYPE_32) {
                    bit32 = ((newmode_patch[i    ] & 0xff)      )
                          | ((newmode_patch[i + 1] & 0xff) <<  8)
                          | ((newmode_patch[i + 2] & 0xff) << 16)
                          | ((newmode_patch[i + 3] & 0xff) << 24);

                            add_offset(poff + i, p[i], (bit32      ) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >>  8) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >> 16) & 0xff);
                    ++i;    add_offset(poff + i, p[i], (bit32 >> 24) & 0xff);

                } else {
                    add_offset(poff + i, p[i], newmode_patch[i]);
                }
            }
            p += newmode_original_size - 1; // -1 because we already increment p each time
            changes++;
            if(only_one == 1) only_one = 2;
            /* would be useful to increment p for the size of newmode_patch_size or not? */
            if(max_changes) {
                if(changes >= max_changes) goto quit;
            }
        }

        if(filemem) break;
        blen = limit - l;           // blen is usually newmode_original_size-1
        memmove(buff, l, blen);     // copy the unread data at the beginning of buff
        offset += flen;             // set the correct offset
        flen = myfread(buff + blen, 1, BUFFSZ + newmode_original_size - blen, fd_newmode);
    } while(flen);

quit:
    if(filemem) buff = NULL;
    FREEX(buff);

    FREEX(newmode_original);
    newmode_original_size = 0;

    FREEX(newmode_patch);
    newmode_patch_size    = 0;

    return(changes);
}



i16 *create_newmode_string(u8 *in, int *outlen) {
    int     i,
            inlen;
    i16     *out;

    inlen   = strlen(in);
    *outlen = inlen;

    out = malloc(sizeof(i16) * inlen);
    if(!out) std_err(NULL);
    for(i = 0; i < inlen; i++) {
        out[i] = in[i];
        if(out[i] == '?') out[i] = NEWMODE_TYPE_SKIP;
    }
    return(out);
}



void newmode_apply_patch(void) {
    int     i,
            ans = IDNO;
    u8      *rep;

    if(!fd_newmode) return;
    if(!offbyte_num) {
        msgbox(
            MB_ICONINFORMATION,
            "Alert",
            "there are no bytes to change in the file");
        return;
    }

    if(run_process || patch_process) {
        //autoyes = 1;
        ans = IDNO;
    } else if(autoyes) {
        msgbox(
            MB_OK | MB_ICONINFORMATION,
            "Success",
            "I'm ready for starting the patching of the file\n");
        ans = IDYES;
    } else {
        ans = msgbox(
            MB_YESNO | MB_ICONINFORMATION,
            "Success",
            "I'm ready for starting the patching of the file\n"
            "Do you want to create a backup file (%s.LPATCH_BACKUP)?",
                newmode_fname);
    }
    if(ans == IDYES) newmode_backup();

    report = malloc(sizeof(REPORTHEAD) + (sizeof(REPORTMSG) * offbyte_num));
    if(!report) std_err(NULL);
    rep = report +
        sprintf(report, REPORTHEAD);

    for(i = 0; i < offbyte_num; i++) {
        myfseek(fd_newmode, offbyte[i]->offset, SEEK_SET);
        if(myfputc(offbyte[i]->patch, fd_newmode) < 0) write_err();
        rep += sprintf(rep, REPORTMSG, offbyte[i]->offset, offbyte[i]->original, offbyte[i]->patch);
        FREEX(offbyte[i]);
    }
    FREEX(offbyte);
    if(fd_newmode->fd) fflush(fd_newmode->fd);

    if(autoyes) {
        msgbox(
            MB_OK | MB_ICONINFORMATION,
            "Success",
            SUCCESSX,
                offbyte_num);
        ans = IDNO;
    } else {
        ans = msgbox(
            MB_YESNO | MB_ICONINFORMATION,
            "Success",
            SUCCESS,
                offbyte_num);
    }
    offbyte_num = 0;

    if(ans == IDYES) {
        msgbox(
            MB_ICONINFORMATION,
            "Report",
            "%s",
                report);
    }
    FREEX(report);

    if(comment) {
        msgbox(
            MB_ICONINFORMATION,
            "Comment",
            "%s",
                comment);
        FREEX(comment);
    }
}



void newmode_title(u8 *line) {
    FREEX(title);      // remove duplicates
    title = strdup(line);
}



void newmode_intro(u8 *line) {
    FREEX(intro);      // remove duplicates
    intro = strdup(line);
}



void newmode_md5(u8 *line) {
    int     i,
            c;
    u8      *next;

    next = NULL;
    do {
        next = get_line(line);

        newmode_md5_hash = realloc(newmode_md5_hash, sizeof(u8 *) * (newmode_md5_hash_num + 1));
        if(!newmode_md5_hash) std_err(NULL);
        newmode_md5_hash[newmode_md5_hash_num] = malloc(16);

        for(i = 0; i < 16; i++) {
            while(line[0] <= ' ') line++;
            line[0] = tolower(line[0]);
            line[1] = tolower(line[1]);
            if(!line[0] || !line[1]) {
                FREEX(newmode_md5_hash[newmode_md5_hash_num]);
                return;
            }
            sscanf(line, "%02x", &c);
            line += 2;
            newmode_md5_hash[newmode_md5_hash_num][i] = c;
        }
        newmode_md5_hash_num++;

        line = next;
    } while(next);
}



void newmode_apply_close(void) {
    if(fd_newmode) {
        newmode_apply_patch();  /* it's time to apply the patch */
        if(fd_newmode->fd) fclose(fd_newmode->fd);
        if(fd_newmode->pid) {
#ifdef WIN32
            CloseHandle(fd_newmode->pid);
#else
            ptrace(PTRACE_DETACH, fd_newmode->pid, NULL, NULL);
#endif
        }
        free(fd_newmode);
        fd_newmode = NULL;
    }
}



void newmode_file(u8 *line) {
#ifdef WIN32
	STARTUPINFO         si;
	PROCESS_INFORMATION pi;
#endif
    struct stat xstat;
    int     i;
    u8      tmp[64];
    void    *baddr;
    pid_t   pid;

    get_line(line);             /* initialize line */

    newmode_apply_close();
    rva             = 0;
    executable      = 0;
    only_one        = 0;
    max_changes     = 0;
    imagebase       = 0;
    fd_newmode_md5  = NULL;
    FREEX(filemem);
    filememsz       = 0;
    FREEX(section);
    sections        = 0;

    if(title) {
        msgbox(
            MB_ICONINFORMATION,
            "Lame patcher "VER,
            "%s",
                title);
        FREEX(title);
    }
    if(intro) {
        msgbox(
            MB_ICONINFORMATION,
            "Lame patcher "VER,
            "%s",
                intro);
        FREEX(intro);
    }

    for(i = 0; line[i]; i++) {
        if(line[i] == ',') line[i] = ';';   // simple fix for some common errors
        if(line[i] == ':') line[i] = ';';   // when specifying multiple files
    }

    if(newmode_fname_arg) {
        newmode_fname = newmode_fname_arg;
        newmode_fname_arg = NULL;   // only the first
    } else {
        newmode_fname = get_file(line);
    }

    fd_newmode = calloc(sizeof(fd_newmode_t), 1);
    if(!fd_newmode) std_err(NULL);

    if(run_process || patch_process) {
#ifdef WIN32
#else
        std_err("at the moment the -r/-p options are not supported on this operating system");
#endif
        if(!newmode_fname || !newmode_fname[0])  {
            process_list(NULL, NULL, NULL);
            exit(1);
        }
        if(run_process) {
#ifdef WIN32
            GetStartupInfo(&si);
            if(!CreateProcess(NULL, newmode_fname, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) winerr();
            sleep(2);
            SuspendThread(pi.hThread);
            sprintf(tmp, "%d", (int)pi.dwProcessId);    // portability at first place
            filemem = process_read(tmp, &filememsz, &baddr, &pid);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
#else
            std_err("at the moment the -r option is not supported on this operating system");
#endif
        } else {
            filemem = process_read(newmode_fname, &filememsz, &baddr, &pid);
        }
        if(!filemem) std_err("something wrong during the reading of the process");
        fd_newmode->pid   = pid;
        fd_newmode->baddr = baddr;
        fd_newmode->data  = filemem;
        fd_newmode->size  = filememsz;
    } else {
        set_rwmode(newmode_fname);
        fd_newmode->fd = fopen(newmode_fname, "r+b");
        if(!fd_newmode->fd) std_err(NULL);

        fstat(fileno(fd_newmode->fd), &xstat);
        fd_newmode->size = xstat.st_size;
        if(!fd_newmode->size) std_err("the file is empty, size of 0 bytes");

        if(newmode_md5_hash) {
            fd_newmode_md5 = calc_md5(fd_newmode->fd);

            for(i = 0; i < newmode_md5_hash_num; i++) {
                if(!memcmp(fd_newmode_md5, newmode_md5_hash[i], 16)) break;
            }

            if(i == newmode_md5_hash_num) {
                std_err("the MD5 hash specified in the data file differs from that of your file");
            }
            newmode_md5_hash     = NULL;
            newmode_md5_hash_num = 0;
        }

        if(fd_newmode->size < MAXMEMORYFILE) {
            filememsz = fd_newmode->size;    // load all the file in memory
            filemem   = malloc(filememsz);
            if(filemem) myfread(filemem, 1, filememsz, fd_newmode);
        }   // if filemem can't be allocated will be used automatically the normal mode!
    }
}



int newmode_executable(void) {
    int     ret                 = -1,
            offset,
            filemem_work_around = 0;

    if(executable) return(0);

    if(!filemem) {
        filemem_work_around = 1;
        filememsz = 0xffff;         // enough?
        filemem = malloc(filememsz);
        if(!filemem) std_err(NULL);
        filememsz = myfread(filemem, 1, filememsz, fd_newmode);
    }

                   offset = parse_PE();
    if(offset < 0) offset = parse_ELF32();
    if(offset < 0) goto quit;

    if(!sections || !section) { // possible work-around in case of errors
        sections = 1;
        FREEX(section);
        section = calloc(sizeof(section_t), sections);
        if(!section) std_err(NULL);
        section[0].VirtualAddress   = 0;
        section[0].VirtualSize      = filememsz - offset;
        section[0].VirtualSize_off  = -1;
        section[0].PointerToRawData = offset;
        section[0].SizeOfRawData    = filememsz - offset;
        section[0].Characteristics  = 0;
    }
    ret = 0;
    executable = 1;
quit:
    if(filemem_work_around) {
        FREEX(filemem);
        filememsz = 0;
    }
    return(ret);
}



void newmode_rva(u8 *line) {
    if(rva) return;
    if(line[0]) {
        rva = get_num(line);
        if(rva) return;
    }

    rva = 0;
    if(!newmode_executable()) rva = -1;
}



void newmode_comment(u8 *line) {
    FREEX(comment);  // remove duplicates
    comment = strdup(line);
}



void newmode_offset(u8 *line) {
    u32     offset,
            old_offset = 0,
            bit32      = 0;
    int     x1,
            x2,
            fc;
    u8      *next,
            *soffset,
            *sx1,
            *sx2;

    if(!fd_newmode) std_err("the file to patch (FILE) has not been opened or specified yet, check the data file");

    next = NULL;
    do {
        next = get_line(line);          /* get the current line */

        soffset = line;                 /* read all the elements */
        sx1     = get_element(&soffset);    if(!sx1) return;
        sx2     = get_element(&sx1);        if(!sx2) return;
                  get_element(&sx2);

                                        /* offset */
        if(soffset[0] == '+') {         /* next offsets */
            if(!soffset[1] || (soffset[1] == '+')) {
                offset = old_offset + 1;
            } else {
                offset = old_offset + get_num(soffset + 1);
            }
        } else if(soffset[0] == '-') {  /* previous offsets */
            if(!soffset[1] || (soffset[1] == '-')) {
                offset = old_offset - 1;
            } else {
                offset = old_offset - get_num(soffset + 1);
            }
        } else {
            offset = get_num(soffset);
        }

        x1      = get_num(sx1);         /* original byte */

        x2      = get_num(sx2);         /* patched byte */

        if(newmode_num_type & NEWMODE_TYPE_32_OFFSET) bit32 = x2 - (offset + 4);
        if(newmode_num_type & NEWMODE_TYPE_32)        bit32 = x2;

        if(rva < 0) {                   /* convert in file offset */
            offset = rva2file(offset);
        } else {
            offset -= rva;
        }

        if(offset > fd_newmode->size) {
            std_err("the offset specified in the data file cannot be reached in your input file, probably smaller");
        }

        myfseek(fd_newmode, offset, SEEK_SET);
        fc = myfgetc(fd_newmode);
        if(fc < 0) std_err("the offset specified in the data file cannot be reached in your input file, probably smaller");

        if((x1 >= 0) && (fc != x1)) {
            std_err("one or more bytes in the file to patch are not the originals, probably your file is not the same of the author of this patch");
        }
        x1 = fc;    // in case we used a skip byte

        if(bit32) {
                                        add_offset(offset++, x1, (bit32      ) & 0xff);
            x1 = myfgetc(fd_newmode);   add_offset(offset++, x1, (bit32 >>  8) & 0xff);
            x1 = myfgetc(fd_newmode);   add_offset(offset++, x1, (bit32 >> 16) & 0xff);
            x1 = myfgetc(fd_newmode);   add_offset(offset,   x1, (bit32 >> 24) & 0xff);
            bit32 = 0;
        } else {
            add_offset(offset, x1, x2);
        }

        if(rva < 0) {                   /* convert */
            old_offset = file2rva(offset);
        } else {
            old_offset = offset + rva;
        }

        line = next;
    } while(next);
}


void newmode_only_one(void) {
    only_one = 1;
}



void newmode_string(u8 *line) {
    u8      *next,
            *original,
            *patch;

    if(!fd_newmode) std_err("the file to patch (FILE) has not been opened or specified yet, check the data file");

    next = NULL;
    do {
        next = get_line(line);

        original = line;
        patch    = get_element(&original);  if(!patch) return;
                   get_element(&patch);

        newmode_original = create_newmode_string(original, &newmode_original_size);
        newmode_patch    = create_newmode_string(patch,    &newmode_patch_size);

        if(!search_file(NULL)) {
            // msgbox(
            //     MB_ICONERROR,
            //     "Alert",
            //     "there are no bytes to change in the file, I continue with the next patch");
            return;
        }

        line = next;
    } while(next);
}



void lame_calc_jmp(u32 src, u32 dst, int dstsz) {
    u32     jmp;
    u8      tmp[5];

    if(dstsz < 5) return;

    if(filemem) {
        memcpy(tmp, filemem + src, 5);
    } else {
        myfseek(fd_newmode, src, SEEK_SET);
        myfread(tmp, 1, 5, fd_newmode);
    }
    jmp = dst - (src + 5);
    add_offset(src,     tmp[0], 0xe9);
    add_offset(src + 1, tmp[1], (jmp      ) & 0xff);
    add_offset(src + 2, tmp[2], (jmp >>  8) & 0xff);
    add_offset(src + 3, tmp[3], (jmp >> 16) & 0xff);
    add_offset(src + 4, tmp[4], (jmp >> 24) & 0xff);

    if(filemem) {
        memcpy(tmp, filemem + dst, 5);
    } else {
        myfseek(fd_newmode, dst, SEEK_SET);
        myfread(tmp, 1, 5, fd_newmode);
    }
    dst += dstsz - 5;
    jmp = (src + 5) - (dst + 5);
    add_offset(dst,     tmp[0], 0xe9);
    add_offset(dst + 1, tmp[1], (jmp      ) & 0xff);
    add_offset(dst + 2, tmp[2], (jmp >>  8) & 0xff);
    add_offset(dst + 3, tmp[3], (jmp >> 16) & 0xff);
    add_offset(dst + 4, tmp[4], (jmp >> 24) & 0xff);
}



void newmode_bytes(u8 *line, int original_patch) {
    int     i,
            bytex,
            oplen = 0;
    i16     *op   = NULL;
    u8      *next,
            *sc,
            *scn;

    u32     old_max_changes,
            tmpx;
    int     newmode_patchx_size = 0,
            code_offset         = 0,
            patch_offset        = 0,
            vsize_offset        = 0,
            idx;
    i16     *newmode_patchx     = NULL;
    u8      tmp[4];

    if(!fd_newmode) std_err("the file to patch (FILE) has not been opened or specified yet, check the data file");

    next = NULL;
    do {
        next = get_line(line);

        sc  = line;
        scn = NULL;
        do {
            scn = get_element(&sc);

            if((sc[0] == '#') || (sc[0] == '/') || (sc[0] == ';')) break; // comments
            bytex = get_num(sc);

            if(newmode_num_type & NEWMODE_TYPE_SKIP) {
                oplen += bytex;
                op = realloc(op, sizeof(i16) * oplen);
                if(!op) std_err(NULL);
                for(i = oplen - bytex; i < oplen; i++) op[i] = NEWMODE_TYPE_SKIP;

            } else if(newmode_num_type & NEWMODE_TYPE_32_OFFSET) {
                oplen += 4;
                op = realloc(op, sizeof(i16) * oplen);
                if(!op) std_err(NULL);
                op[oplen - 4] = ((bytex      ) & 0xff) | NEWMODE_TYPE_32_OFFSET;
                op[oplen - 3] = ((bytex >>  8) & 0xff) | NEWMODE_TYPE_32_OFFSET;
                op[oplen - 2] = ((bytex >> 16) & 0xff) | NEWMODE_TYPE_32_OFFSET;
                op[oplen - 1] = ((bytex >> 24) & 0xff) | NEWMODE_TYPE_32_OFFSET;

            } else if(newmode_num_type & NEWMODE_TYPE_32) {
                oplen += 4;
                op = realloc(op, sizeof(i16) * oplen);
                if(!op) std_err(NULL);
                op[oplen - 4] = ((bytex      ) & 0xff) | NEWMODE_TYPE_32;
                op[oplen - 3] = ((bytex >>  8) & 0xff) | NEWMODE_TYPE_32;
                op[oplen - 2] = ((bytex >> 16) & 0xff) | NEWMODE_TYPE_32;
                op[oplen - 1] = ((bytex >> 24) & 0xff) | NEWMODE_TYPE_32;

            } else {
                oplen++;
                op = realloc(op, sizeof(i16) * oplen);
                if(!op) std_err(NULL);
                op[oplen - 1] = bytex;
            }

            sc = scn;
        } while(scn);

        line = next;
    } while(next);

    if(original_patch == CMD_BYTES_ORIGINAL) {
        newmode_original      = op;
        newmode_original_size = oplen;

    } else if(original_patch == CMD_BYTES_PATCH) {
        newmode_patch         = op;
        newmode_patch_size    = oplen;

        if(!search_file(NULL)) {
            // msgbox(
            //     MB_ICONERROR,
            //     "Alert",
            //     "there are no bytes to change in the file, I continue with the next patch");
            return;
        }

    } else if(original_patch == CMD_BYTES_ORIGINALX) {
        newmode_original      = op;
        newmode_original_size = oplen;

        newmode_patch         = malloc(sizeof(i16) * oplen);
        newmode_patch_size    = oplen;
        for(i = 0; i < oplen; i++) newmode_patch[i] = newmode_original[i];

    } else if(original_patch == CMD_BYTES_PATCHX) {
        old_max_changes = max_changes;  // needed!
        max_changes = 1;

        newmode_patchx        = op;
        newmode_patchx_size   = oplen - 1;  // the last is the number of nopped bytes at the beginning!

        tmpx = newmode_patchx[newmode_patchx_size] & 0xff;
        for(i = 0; i < tmpx; i++) {
            newmode_patch[i] = newmode_patchx[(newmode_patchx_size - tmpx) + i];
        }
        newmode_patchx_size -= tmpx;

        newmode_patchx_size += 5;           // jmp back
        newmode_patchx = realloc(newmode_patchx, sizeof(i16) * newmode_patchx_size);
        if(!newmode_patchx) std_err(NULL);
        for(i = newmode_patchx_size - 5; i < newmode_patchx_size; i++) newmode_patchx[i] = 0x90;

        if(!search_file(&code_offset)) return;
        if(only_one > 1) only_one = 1;      // work-around

        newmode_original      = calloc(sizeof(i16), newmode_patchx_size);   // automatic memset 0
        newmode_original_size = newmode_patchx_size;    // so it will catch the zeroes at the end of the .text section

        newmode_patch         = newmode_patchx;
        newmode_patch_size    = newmode_patchx_size;

        patch_offset = code_offset;
        if(search_file(&patch_offset)) {
            lame_calc_jmp(code_offset, patch_offset, newmode_patchx_size);
        }

        idx = get_section(patch_offset - 1);   // the patched zone should be included within the aligned zone, 99% of the times
        if((idx >= 0) && (section[idx].VirtualSize_off >= 0)) {
            vsize_offset = section[idx].VirtualSize_off;
            if(filemem) {
                memcpy(tmp, filemem + vsize_offset, 4);
            } else {
                myfseek(fd_newmode, vsize_offset, SEEK_SET);
                myfread(tmp, 1, 4, fd_newmode);
            }

            section[idx].VirtualSize += newmode_patchx_size;
            add_offset(vsize_offset,     tmp[0], (section[idx].VirtualSize      ) & 0xff);
            add_offset(vsize_offset + 1, tmp[1], (section[idx].VirtualSize >>  8) & 0xff);
            add_offset(vsize_offset + 2, tmp[2], (section[idx].VirtualSize >> 16) & 0xff);
            add_offset(vsize_offset + 3, tmp[3], (section[idx].VirtualSize >> 24) & 0xff);
        }

        max_changes = old_max_changes;
    }
}



void newmode_max_changes(u8 *line) {
    max_changes = atoi(line);
}



void newmode_cmd(int cmdnum, u8 *line) {
    switch(cmdnum) {
        case CMD_TITLE:             newmode_title(line);                        break;
        case CMD_INTRO:             newmode_intro(line);                        break;
        case CMD_MD5:               newmode_md5(line);                          break;
        case CMD_FILE:              newmode_file(line);                         break;
        case CMD_RVA:               newmode_rva(line);                          break;
        case CMD_COMMENT:           newmode_comment(line);                      break;
        case CMD_OFFSET:            newmode_offset(line);                       break;
        case CMD_ONLY_ONE:          newmode_only_one();                         break;
        case CMD_STRING:            newmode_string(line);                       break;
        case CMD_BYTES_ORIGINAL:    newmode_bytes(line, CMD_BYTES_ORIGINAL);    break;
        case CMD_BYTES_PATCH:       newmode_bytes(line, CMD_BYTES_PATCH);       break;
        case CMD_BYTES_ORIGINALX:   newmode_bytes(line, CMD_BYTES_ORIGINALX);   break;
        case CMD_BYTES_PATCHX:      newmode_bytes(line, CMD_BYTES_PATCHX);      break;
        case CMD_MAX_CHANGES:       newmode_max_changes(line);                  break;
        case CMD_EXECUTABLE:        newmode_executable();                       break;
        default:                                                                break;
    }
}



void newmode(void) {
    int     len,
            currlen,
            bufflen,
            oldnum,
            cmdnum,
            tmp;
    u8      line[1024],
            *buff,
            *buff_limit,
            *data,
            *ins;

    fseek(lpatch, 0, SEEK_SET);

    bufflen    = 1024;
    buff       = malloc(bufflen);
    if(!buff) std_err(NULL);
    data       = buff;
    buff_limit = buff + bufflen;
    buff[0]    = 0;
    line[0]    = 0;
    oldnum     = CMD_NONE;

    while(fgets(line, sizeof(line), lpatch)) {
        ins = get_newmode_cmd(line, &cmdnum);
        if(!ins) continue;

        if(oldnum == CMD_NONE) oldnum = cmdnum;
        if(cmdnum == CMD_NONE) cmdnum = oldnum;
        if(cmdnum != oldnum) {
            tmp    = cmdnum;
            cmdnum = oldnum;
            oldnum = tmp;

            newmode_cmd(cmdnum, buff);

            data = buff;
        }

        len = strlen(ins);  // allocation
        if((data + len) >= buff_limit) {
            currlen    = data - buff;
            bufflen    = currlen + 1 + len + 1; // 1 for \n and 1 for the final NULL byte
            buff       = realloc(buff, bufflen);
            if(!buff) std_err(NULL);
            data       = buff + currlen;
            buff_limit = buff + bufflen;
        }

        if(data > buff) data += sprintf(data, "\n");
        data += sprintf(data, "%s", ins);
        line[0] = 0;
    }
        // the remaining line
    cmdnum = oldnum;
    if((cmdnum != CMD_NONE) && (data != buff)) newmode_cmd(cmdnum, buff);

    //newmode_apply_patch();
    newmode_apply_close();

    FREEX(buff);
}


