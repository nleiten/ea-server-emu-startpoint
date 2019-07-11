/*
    Copyright 2010 Luigi Auriemma

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
    #include <tlhelp32.h>
#else
    #include <sys/ptrace.h>
#endif



u8 *process_list(u8 *myname, DWORD *mypid, DWORD *size) {
#ifdef WIN32
    PROCESSENTRY32  Process;
    MODULEENTRY32   Module;
    HANDLE          snapProcess,
                    snapModule;
    DWORD           retpid = 0;
    int             len;
    BOOL            b;
    u8              tmpbuff[60],
                    *process_name,
                    *module_name,
                    *module_print,
                    *tmp;

    if(mypid) retpid = *mypid;
    if(!myname && !retpid) {
        printf(
            "  pid/addr/size       process/module name\n"
            "  ---------------------------------------\n");
    }

#define START(X,Y) \
            snap##X = CreateToolhelp32Snapshot(Y, Process.th32ProcessID); \
            X.dwSize = sizeof(X); \
            for(b = X##32First(snap##X, &X); b; b = X##32Next(snap##X, &X)) { \
                X.dwSize = sizeof(X);
#define END(X) \
            } \
            CloseHandle(snap##X);

    Process.th32ProcessID = 0;
    START(Process, TH32CS_SNAPPROCESS)
        process_name = Process.szExeFile;

        if(!myname && !retpid) {
            printf("  %-10lu ******** %s\n",
                Process.th32ProcessID,
                process_name);
        }
        if(myname && stristr(process_name, myname)) {
            retpid = Process.th32ProcessID;
        }

        START(Module, TH32CS_SNAPMODULE)
            module_name = Module.szExePath; // szModule?

            len = strlen(module_name);
            if(len >= 60) {
                tmp = strrchr(module_name, '\\');
                if(!tmp) tmp = strrchr(module_name, '/');
                if(!tmp) tmp = module_name;
                len -= (tmp - module_name);
                sprintf(tmpbuff,
                    "%.*s...%s",
                    54 - len,
                    module_name,
                    tmp);
                module_print = tmpbuff;
            } else {
                module_print = module_name;
            }

            if(!myname && !retpid) {
                printf("    %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
            }
            if(!retpid) {
                if(myname && stristr(module_name, myname)) {
                    retpid = Process.th32ProcessID;
                }
            }
            if(retpid && mypid && (Process.th32ProcessID == retpid)) {
                printf("- %p %08lx %s\n",
                    Module.modBaseAddr,
                    Module.modBaseSize,
                    module_print);
                *mypid = retpid;
                if(size) *size = Module.modBaseSize;
                return(Module.modBaseAddr);
            }

        END(Module)

    END(Process)

#undef START
#undef END

#else

    //system("ps -eo pid,cmd");
    printf("\n"
        "- use ps to know the pids of your processes, like:\n"
        "  ps -eo pid,cmd\n");

#endif

    return(NULL);
}



#ifdef WIN32
void winerr(void) {
    u8      *message = NULL;

    FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL,
      GetLastError(),
      0,
      (char *)&message,
      0,
      NULL);

    if(message) {
        printf("\nError: %s\n", message);
        LocalFree(message);
    } else {
        printf("\nError: unknown Windows error\n");
    }
    //exit(1);
}
#endif



u8 *process_read(u8 *pname, int *fdlen, void **ret_baddr,
#ifdef WIN32
HANDLE  *ret_pid) {

    HANDLE  process;
    DWORD   pid,
            size;
    int     len;
    u8      *buff;
    void    *baddr;

    if(!pname && !pname[0]) return(NULL);

    if(pname) {
        len = 0;
        sscanf(pname, "%lu%n", &pid, &len);
        if(len != strlen(pname)) pid = 0;
    }

    baddr = process_list(pid ? NULL : pname, &pid, &size);
    if(!baddr) {
        printf("\nError: process name/PID not found\n");
        //exit(1);
        return(NULL);
    }

    printf(
        "- pid %u\n"
        "- base address %p\n",
        (u32)pid, baddr);

    process = OpenProcess(
        PROCESS_VM_READ | (ret_pid ? (PROCESS_VM_WRITE | PROCESS_VM_OPERATION) : 0),
        FALSE,
        pid);
    if(!process) {
        winerr();
        return(NULL);
    }

    buff = malloc(size);
    if(!buff) return(NULL); // std_err(NULL);

    if(!ReadProcessMemory(
        process,
        (LPCVOID)baddr,
        buff,
        size,
        &size)
    ) {
        winerr();
        return(NULL);
    }

    if(!ret_pid) {
        CloseHandle(process);
    } else {
#else
pid_t   *ret_pid) {

    pid_t   pid,
            process;
    u32     data,
            size,
            memsize;
    u8      *buff;
    void    *baddr;

    pid = atoi(pname);
    baddr = (void *)0x8048000;  // sorry, not completely supported at the moment

    printf(
        "- pid %u\n"
        "- try using base address %p\n",
        pid, baddr);

    process = pid;
    if(ptrace(PTRACE_ATTACH, process, NULL, NULL) < 0) return(NULL); // std_err(NULL);

    size     = 0;
    memsize  = 0;
    buff     = NULL;

    for(errno = 0; ; size += 4) {
        if(!(size & 0xfffff)) fputc('.', stdout);

        data = ptrace(PTRACE_PEEKDATA, process, (u8 *)baddr + size, NULL);
        if((data == -1) && errno) {
            if(errno != EIO) return(NULL); // std_err(NULL);
            break;
        }

        if(size >= memsize) {
            memsize += 0x80000;
            buff = realloc(buff, memsize);
            if(!buff) return(NULL); // std_err(NULL);
        }
        memcpy(buff + size, &data, 4);
    }
    fputc('\n', stdout);
    buff = realloc(buff, size);
    if(!buff) return(NULL); // std_err(NULL);

    if(!ret_pid) {
        if(ptrace(PTRACE_DETACH, process, NULL, NULL) < 0) return(NULL); // std_err(NULL);
    } else {
#endif
        memcpy((void *)ret_pid, (void *)&process, sizeof(process));
    }

    if(ret_baddr) *ret_baddr = baddr;
    if(fdlen) *fdlen = size;
    return(buff);
}

