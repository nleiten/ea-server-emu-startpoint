/*
   This file has been generated by IDA.
   It contains local type definitions from
   the type library 'cnconline'
*/

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct HWND__;
struct tagWNDCLASSEXA;
struct HINSTANCE__;
struct HICON__;
struct HBRUSH__;
struct HDC__;
struct HMENU__;
struct HBITMAP__;
struct tagPROCESSENTRY32;
struct _SHELLEXECUTEINFOA;
struct HKEY__;
union _LARGE_INTEGER;

/* 1 */
struct _EH4_SCOPETABLE_RECORD
{
  int EnclosingLevel;
  void *FilterFunc;
  void *HandlerFunc;
};

/* 15 */
typedef unsigned __int32 DWORD;

/* 2 */
struct _EH4_SCOPETABLE
{
  DWORD GSCookieOffset;
  DWORD GSCookieXOROffset;
  DWORD EHCookieOffset;
  DWORD EHCookieXOROffset;
  struct _EH4_SCOPETABLE_RECORD ScopeRecord[];
};

/* 3 */
typedef struct _SCOPETABLE_ENTRY *PSCOPETABLE_ENTRY;

/* 55 */
typedef void *PVOID;

/* 4 */
struct _EH3_EXCEPTION_REGISTRATION
{
  struct _EH3_EXCEPTION_REGISTRATION *Next;
  PVOID ExceptionHandler;
  PSCOPETABLE_ENTRY ScopeTable;
  DWORD TryLevel;
};

/* 5 */
typedef struct _EH3_EXCEPTION_REGISTRATION EH3_EXCEPTION_REGISTRATION;

/* 6 */
typedef struct _EH3_EXCEPTION_REGISTRATION *PEH3_EXCEPTION_REGISTRATION;

/* 7 */
struct CPPEH_RECORD
{
  DWORD old_esp;
  EXCEPTION_POINTERS *exc_ptr;
  struct _EH3_EXCEPTION_REGISTRATION registration;
};

/* 9 */
typedef HWND__ *HWND;

/* 11 */
typedef unsigned int UINT;

/* 12 */
typedef UINT WPARAM;

/* 14 */
typedef __int32 LONG;

/* 13 */
typedef LONG LPARAM;

/* 17 */
struct tagPOINT
{
  LONG x;
  LONG y;
};

/* 16 */
typedef tagPOINT POINT;

/* 8 */
struct tagMSG
{
  HWND hwnd;
  UINT message;
  WPARAM wParam;
  LPARAM lParam;
  DWORD time;
  POINT pt;
};

/* 10 */
struct HWND__
{
  int unused;
};

/* 18 */
typedef tagWNDCLASSEXA WNDCLASSEXA;

/* 21 */
typedef LONG LRESULT;

/* 20 */
typedef LRESULT (__stdcall *WNDPROC)(HWND, UINT, WPARAM, LPARAM);

/* 22 */
typedef HINSTANCE__ *HINSTANCE;

/* 24 */
typedef HICON__ *HICON;

/* 26 */
typedef HICON HCURSOR;

/* 27 */
typedef HBRUSH__ *HBRUSH;

/* 30 */
typedef char CHAR;

/* 29 */
typedef const CHAR *LPCSTR;

/* 19 */
struct tagWNDCLASSEXA
{
  UINT cbSize;
  UINT style;
  WNDPROC lpfnWndProc;
  int cbClsExtra;
  int cbWndExtra;
  HINSTANCE hInstance;
  HICON hIcon;
  HCURSOR hCursor;
  HBRUSH hbrBackground;
  LPCSTR lpszMenuName;
  LPCSTR lpszClassName;
  HICON hIconSm;
};

/* 23 */
struct HINSTANCE__
{
  int unused;
};

/* 25 */
struct HICON__
{
  int unused;
};

/* 28 */
struct HBRUSH__
{
  int unused;
};

/* 32 */
typedef HDC__ *HDC;

/* 34 */
typedef int BOOL;

/* 36 */
struct tagRECT
{
  LONG left;
  LONG top;
  LONG right;
  LONG bottom;
};

/* 35 */
typedef tagRECT RECT;

/* 37 */
typedef unsigned __int8 BYTE;

/* 31 */
struct tagPAINTSTRUCT
{
  HDC hdc;
  BOOL fErase;
  RECT rcPaint;
  BOOL fRestore;
  BOOL fIncUpdate;
  BYTE rgbReserved[32];
};

/* 33 */
struct HDC__
{
  int unused;
};

/* 39 */
typedef HMENU__ *HMENU;

/* 41 */
typedef HBITMAP__ *HBITMAP;

/* 43 */
typedef CHAR *LPSTR;

/* 38 */
struct tagMENUITEMINFOA
{
  UINT cbSize;
  UINT fMask;
  UINT fType;
  UINT fState;
  UINT wID;
  HMENU hSubMenu;
  HBITMAP hbmpChecked;
  HBITMAP hbmpUnchecked;
  DWORD dwItemData;
  LPSTR dwTypeData;
  UINT cch;
  HBITMAP hbmpItem;
};

/* 40 */
struct HMENU__
{
  int unused;
};

/* 42 */
struct HBITMAP__
{
  int unused;
};

/* 45 */
typedef unsigned __int16 WORD;

/* 46 */
typedef BYTE *LPBYTE;

/* 47 */
typedef void *HANDLE;

/* 44 */
struct _STARTUPINFOA
{
  DWORD cb;
  LPSTR lpReserved;
  LPSTR lpDesktop;
  LPSTR lpTitle;
  DWORD dwX;
  DWORD dwY;
  DWORD dwXSize;
  DWORD dwYSize;
  DWORD dwXCountChars;
  DWORD dwYCountChars;
  DWORD dwFillAttribute;
  DWORD dwFlags;
  WORD wShowWindow;
  WORD cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
};

/* 48 */
struct _PROCESS_INFORMATION
{
  HANDLE hProcess;
  HANDLE hThread;
  DWORD dwProcessId;
  DWORD dwThreadId;
};

/* 56 */
typedef unsigned __int32 UINT_PTR;

/* 54 */
struct _EXCEPTION_RECORD
{
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  UINT_PTR ExceptionInformation[15];
};

/* 53 */
typedef _EXCEPTION_RECORD EXCEPTION_RECORD;

/* 52 */
struct _EXCEPTION_DEBUG_INFO
{
  EXCEPTION_RECORD ExceptionRecord;
  DWORD dwFirstChance;
};

/* 51 */
typedef _EXCEPTION_DEBUG_INFO EXCEPTION_DEBUG_INFO;

/* 59 */
typedef void *LPVOID;

/* 61 */
typedef DWORD (__stdcall *PTHREAD_START_ROUTINE)(LPVOID lpThreadParameter);

/* 60 */
typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

/* 58 */
struct _CREATE_THREAD_DEBUG_INFO
{
  HANDLE hThread;
  LPVOID lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
};

/* 57 */
typedef _CREATE_THREAD_DEBUG_INFO CREATE_THREAD_DEBUG_INFO;

/* 63 */
struct _CREATE_PROCESS_DEBUG_INFO
{
  HANDLE hFile;
  HANDLE hProcess;
  HANDLE hThread;
  LPVOID lpBaseOfImage;
  DWORD dwDebugInfoFileOffset;
  DWORD nDebugInfoSize;
  LPVOID lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
  LPVOID lpImageName;
  WORD fUnicode;
};

/* 62 */
typedef _CREATE_PROCESS_DEBUG_INFO CREATE_PROCESS_DEBUG_INFO;

/* 65 */
struct _EXIT_THREAD_DEBUG_INFO
{
  DWORD dwExitCode;
};

/* 64 */
typedef _EXIT_THREAD_DEBUG_INFO EXIT_THREAD_DEBUG_INFO;

/* 67 */
struct _EXIT_PROCESS_DEBUG_INFO
{
  DWORD dwExitCode;
};

/* 66 */
typedef _EXIT_PROCESS_DEBUG_INFO EXIT_PROCESS_DEBUG_INFO;

/* 69 */
struct _LOAD_DLL_DEBUG_INFO
{
  HANDLE hFile;
  LPVOID lpBaseOfDll;
  DWORD dwDebugInfoFileOffset;
  DWORD nDebugInfoSize;
  LPVOID lpImageName;
  WORD fUnicode;
};

/* 68 */
typedef _LOAD_DLL_DEBUG_INFO LOAD_DLL_DEBUG_INFO;

/* 71 */
struct _UNLOAD_DLL_DEBUG_INFO
{
  LPVOID lpBaseOfDll;
};

/* 70 */
typedef _UNLOAD_DLL_DEBUG_INFO UNLOAD_DLL_DEBUG_INFO;

/* 73 */
struct _OUTPUT_DEBUG_STRING_INFO
{
  LPSTR lpDebugStringData;
  WORD fUnicode;
  WORD nDebugStringLength;
};

/* 72 */
typedef _OUTPUT_DEBUG_STRING_INFO OUTPUT_DEBUG_STRING_INFO;

/* 75 */
struct _RIP_INFO
{
  DWORD dwError;
  DWORD dwType;
};

/* 74 */
typedef _RIP_INFO RIP_INFO;

/* 50 */
union _DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4
{
  EXCEPTION_DEBUG_INFO Exception;
  CREATE_THREAD_DEBUG_INFO CreateThread;
  CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
  EXIT_THREAD_DEBUG_INFO ExitThread;
  EXIT_PROCESS_DEBUG_INFO ExitProcess;
  LOAD_DLL_DEBUG_INFO LoadDll;
  UNLOAD_DLL_DEBUG_INFO UnloadDll;
  OUTPUT_DEBUG_STRING_INFO DebugString;
  RIP_INFO RipInfo;
};

/* 49 */
struct _DEBUG_EVENT
{
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;
  _DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4 u;
};

/* 76 */
typedef tagPROCESSENTRY32 PROCESSENTRY32;

/* 77 */
struct tagPROCESSENTRY32
{
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ProcessID;
  DWORD th32DefaultHeapID;
  DWORD th32ModuleID;
  DWORD cntThreads;
  DWORD th32ParentProcessID;
  LONG pcPriClassBase;
  DWORD dwFlags;
  CHAR szExeFile[260];
};

/* 78 */
typedef _SHELLEXECUTEINFOA SHELLEXECUTEINFOA;

/* 80 */
typedef unsigned __int32 ULONG;

/* 81 */
typedef HKEY__ *HKEY;

/* 83 */
#pragma pack(push, 1)
union _SHELLEXECUTEINFOA::$D915D6B2B775D926C11EEA321E8940B4
{
  HANDLE hIcon;
  HANDLE hMonitor;
};
#pragma pack(pop)

/* 79 */
#pragma pack(push, 1)
struct _SHELLEXECUTEINFOA
{
  DWORD cbSize;
  ULONG fMask;
  HWND hwnd;
  LPCSTR lpVerb;
  LPCSTR lpFile;
  LPCSTR lpParameters;
  LPCSTR lpDirectory;
  int nShow;
  HINSTANCE hInstApp;
  LPVOID lpIDList;
  LPCSTR lpClass;
  HKEY hkeyClass;
  DWORD dwHotKey;
  #pragma pack(push, 1)
  union
  {
    HANDLE hIcon;
    HANDLE hMonitor;
  };
  #pragma pack(pop)
  HANDLE hProcess;
};
#pragma pack(pop)

/* 82 */
struct HKEY__
{
  int unused;
};

/* 84 */
struct _FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
};

/* 85 */
typedef _LARGE_INTEGER LARGE_INTEGER;

/* 87 */
struct _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E
{
  DWORD LowPart;
  LONG HighPart;
};

/* 88 */
typedef __int64 LONGLONG;

/* 86 */
union _LARGE_INTEGER
{
  struct
  {
    DWORD LowPart;
    LONG HighPart;
  };
  _LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E u;
  LONGLONG QuadPart;
};

/* 89 */
struct std::exception;

/* 90 */
struct std::bad_cast;

/* 91 */
struct type_info;

/* 92 */
struct std::_Lockit;

/* 93 */
union __declspec(align(8)) __m64
{
  unsigned __int64 m64_u64;
  float m64_f32[2];
  __int8 m64_i8[8];
  __int16 m64_i16[4];
  __int32 m64_i32[2];
  __int64 m64_i64;
  unsigned __int8 m64_u8[8];
  unsigned __int16 m64_u16[4];
  unsigned __int32 m64_u32[2];
};

/* 94 */
union __declspec(align(16)) __m128
{
  float m128_f32[4];
  unsigned __int64 m128_u64[2];
  __int8 m128_i8[16];
  __int16 m128_i16[8];
  __int32 m128_i32[4];
  __int64 m128_i64[2];
  unsigned __int8 m128_u8[16];
  unsigned __int16 m128_u16[8];
  unsigned __int32 m128_u32[4];
};

/* 95 */
struct __m128d
{
  double m128d_f64[2];
};

/* 96 */
union __declspec(align(16)) __m128i
{
  __int8 m128i_i8[16];
  __int16 m128i_i16[8];
  __int32 m128i_i32[4];
  __int64 m128i_i64[2];
  unsigned __int8 m128i_u8[16];
  unsigned __int16 m128i_u16[8];
  unsigned __int32 m128i_u32[4];
  unsigned __int64 m128i_u64[2];
};

/* 97 */
struct std::codecvt_base;

/* 98 */
struct std::_Container_base0;

