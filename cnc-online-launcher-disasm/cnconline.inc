; ---------------------------------------------------------------------------

_EH4_SCOPETABLE	struc ;	(sizeof=0x10, align=0x4, copyof_2, variable size)
					; XREF:	.rdata:stru_414530/r
					; .rdata:stru_414570/r ...
GSCookieOffset	dd ?
GSCookieXOROffset dd ?
EHCookieOffset	dd ?
EHCookieXOROffset dd ?
ScopeRecord	_EH4_SCOPETABLE_RECORD 0 dup(?)
_EH4_SCOPETABLE	ends

; ---------------------------------------------------------------------------

_EH4_SCOPETABLE_RECORD struc ; (sizeof=0xC, align=0x4, copyof_1)
					; XREF:	_EH4_SCOPETABLE/r
EnclosingLevel	dd ?
FilterFunc	dd ?			; offset
HandlerFunc	dd ?			; offset
_EH4_SCOPETABLE_RECORD ends

; ---------------------------------------------------------------------------

CPPEH_RECORD	struc ;	(sizeof=0x18, align=0x4, copyof_7) ; XREF: sub_4111F0/r
					; sub_410AC4/r ...
old_esp		dd ?			; XREF:	sub_4111F0+30/w
					; sub_4111F0:loc_41128C/r
exc_ptr		dd ?			; XREF:	sub_4110DB:loc_4110FE/r
					; sub_4111F0:loc_411279/r ; offset
registration	_EH3_EXCEPTION_REGISTRATION ? ;	XREF: sub_410AC4+36/w
					; sub_410AC4+85/w ...
CPPEH_RECORD	ends

; ---------------------------------------------------------------------------

_EH3_EXCEPTION_REGISTRATION struc ; (sizeof=0x10, align=0x4, copyof_4)
					; XREF:	CPPEH_RECORD/r
Next		dd ?			; XREF:	sub_4111F0+77/r	sub_4111F0+A8/r	; offset
ExceptionHandler dd ?			; offset
ScopeTable	dd ?			; XREF:	sub_4111F0+21/w	; offset
TryLevel	dd ?			; XREF:	sub_410AC4+36/w	sub_410AC4+85/w	...
_EH3_EXCEPTION_REGISTRATION ends

; ---------------------------------------------------------------------------

tagMSG		struc ;	(sizeof=0x1C, align=0x4, copyof_8) ; XREF: sub_401000/r
hwnd		dd ?			; offset
message		dd ?
wParam		dd ?
lParam		dd ?
time		dd ?
pt		POINT ?
tagMSG		ends

; ---------------------------------------------------------------------------

POINT		struc ;	(sizeof=0x8, align=0x4,	copyof_16) ; XREF: tagMSG/r
x		dd ?
y		dd ?
POINT		ends

; ---------------------------------------------------------------------------

WNDCLASSEXA	struc ;	(sizeof=0x30, align=0x4, copyof_18) ; XREF: sub_401170/r
cbSize		dd ?
style		dd ?
lpfnWndProc	dd ?			; offset
cbClsExtra	dd ?
cbWndExtra	dd ?
hInstance	dd ?			; offset
hIcon		dd ?			; offset
hCursor		dd ?			; offset
hbrBackground	dd ?			; offset
lpszMenuName	dd ?			; offset
lpszClassName	dd ?			; offset
hIconSm		dd ?			; offset
WNDCLASSEXA	ends

; ---------------------------------------------------------------------------

tagPAINTSTRUCT	struc ;	(sizeof=0x40, align=0x4, copyof_31) ; XREF: sub_4012A0/r
hdc		dd ?			; offset
fErase		dd ?
rcPaint		RECT ?
fRestore	dd ?
fIncUpdate	dd ?
rgbReserved	db 32 dup(?)
tagPAINTSTRUCT	ends

; ---------------------------------------------------------------------------

RECT		struc ;	(sizeof=0x10, align=0x4, copyof_35) ; XREF: tagPAINTSTRUCT/r
left		dd ?
top		dd ?
right		dd ?
bottom		dd ?
RECT		ends

; ---------------------------------------------------------------------------

tagMENUITEMINFOA struc ; (sizeof=0x30, align=0x4, copyof_38) ; XREF: sub_402530/r
cbSize		dd ?
fMask		dd ?
fType		dd ?
fState		dd ?
wID		dd ?
hSubMenu	dd ?			; offset
hbmpChecked	dd ?			; offset
hbmpUnchecked	dd ?			; offset
dwItemData	dd ?
dwTypeData	dd ?			; offset
cch		dd ?
hbmpItem	dd ?			; offset
tagMENUITEMINFOA ends

; ---------------------------------------------------------------------------

_STARTUPINFOA	struc ;	(sizeof=0x44, align=0x4, copyof_44) ; XREF: sub_407970/r
cb		dd ?
lpReserved	dd ?			; offset
lpDesktop	dd ?			; offset
lpTitle		dd ?			; offset
dwX		dd ?
dwY		dd ?
dwXSize		dd ?
dwYSize		dd ?
dwXCountChars	dd ?
dwYCountChars	dd ?
dwFillAttribute	dd ?
dwFlags		dd ?
wShowWindow	dw ?
cbReserved2	dw ?
lpReserved2	dd ?			; offset
hStdInput	dd ?			; offset
hStdOutput	dd ?			; offset
hStdError	dd ?			; offset
_STARTUPINFOA	ends

; ---------------------------------------------------------------------------

_PROCESS_INFORMATION struc ; (sizeof=0x10, align=0x4, copyof_48) ; XREF: sub_407970/r
hProcess	dd ?			; offset
hThread		dd ?			; offset
dwProcessId	dd ?
dwThreadId	dd ?
_PROCESS_INFORMATION ends

; ---------------------------------------------------------------------------

_DEBUG_EVENT	struc ;	(sizeof=0x60, align=0x4, copyof_49) ; XREF: sub_407970/r
dwDebugEventCode dd ?
dwProcessId	dd ?
dwThreadId	dd ?
u		_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4	?
_DEBUG_EVENT	ends

; ---------------------------------------------------------------------------

_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4	union ;	(sizeof=0x54, align=0x4, copyof_50)
					; XREF:	_DEBUG_EVENT/r
Exception	EXCEPTION_DEBUG_INFO ?
CreateThread	CREATE_THREAD_DEBUG_INFO ?
CreateProcessInfo CREATE_PROCESS_DEBUG_INFO ?
ExitThread	EXIT_THREAD_DEBUG_INFO ?
ExitProcess	EXIT_PROCESS_DEBUG_INFO	?
LoadDll		LOAD_DLL_DEBUG_INFO ?
UnloadDll	UNLOAD_DLL_DEBUG_INFO ?
DebugString	OUTPUT_DEBUG_STRING_INFO ?
RipInfo		RIP_INFO ?
_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4	ends

; ---------------------------------------------------------------------------

EXCEPTION_DEBUG_INFO struc ; (sizeof=0x54, align=0x4, copyof_51)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
ExceptionRecord	EXCEPTION_RECORD ?
dwFirstChance	dd ?
EXCEPTION_DEBUG_INFO ends

; ---------------------------------------------------------------------------

EXCEPTION_RECORD struc ; (sizeof=0x50, align=0x4, copyof_53)
					; XREF:	EXCEPTION_DEBUG_INFO/r
ExceptionCode	dd ?
ExceptionFlags	dd ?
ExceptionRecord	dd ?			; offset
ExceptionAddress dd ?			; offset
NumberParameters dd ?
ExceptionInformation dd	15 dup(?)
EXCEPTION_RECORD ends

; ---------------------------------------------------------------------------

CREATE_THREAD_DEBUG_INFO struc ; (sizeof=0xC, align=0x4, copyof_57)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
hThread		dd ?			; offset
lpThreadLocalBase dd ?			; offset
lpStartAddress	dd ?			; offset
CREATE_THREAD_DEBUG_INFO ends

; ---------------------------------------------------------------------------

CREATE_PROCESS_DEBUG_INFO struc	; (sizeof=0x28,	align=0x4, copyof_62)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
hFile		dd ?			; offset
hProcess	dd ?			; offset
hThread		dd ?			; offset
lpBaseOfImage	dd ?			; offset
dwDebugInfoFileOffset dd ?
nDebugInfoSize	dd ?
lpThreadLocalBase dd ?			; offset
lpStartAddress	dd ?			; offset
lpImageName	dd ?			; offset
fUnicode	dw ?
		db ? ; undefined
		db ? ; undefined
CREATE_PROCESS_DEBUG_INFO ends

; ---------------------------------------------------------------------------

EXIT_THREAD_DEBUG_INFO struc ; (sizeof=0x4, align=0x4, copyof_64)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
dwExitCode	dd ?
EXIT_THREAD_DEBUG_INFO ends

; ---------------------------------------------------------------------------

EXIT_PROCESS_DEBUG_INFO	struc ;	(sizeof=0x4, align=0x4,	copyof_66)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
dwExitCode	dd ?
EXIT_PROCESS_DEBUG_INFO	ends

; ---------------------------------------------------------------------------

LOAD_DLL_DEBUG_INFO struc ; (sizeof=0x18, align=0x4, copyof_68)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
hFile		dd ?			; offset
lpBaseOfDll	dd ?			; offset
dwDebugInfoFileOffset dd ?
nDebugInfoSize	dd ?
lpImageName	dd ?			; offset
fUnicode	dw ?
		db ? ; undefined
		db ? ; undefined
LOAD_DLL_DEBUG_INFO ends

; ---------------------------------------------------------------------------

UNLOAD_DLL_DEBUG_INFO struc ; (sizeof=0x4, align=0x4, copyof_70)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
lpBaseOfDll	dd ?			; offset
UNLOAD_DLL_DEBUG_INFO ends

; ---------------------------------------------------------------------------

OUTPUT_DEBUG_STRING_INFO struc ; (sizeof=0x8, align=0x4, copyof_72)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
lpDebugStringData dd ?			; offset
fUnicode	dw ?
nDebugStringLength dw ?
OUTPUT_DEBUG_STRING_INFO ends

; ---------------------------------------------------------------------------

RIP_INFO	struc ;	(sizeof=0x8, align=0x4,	copyof_74)
					; XREF:	_DEBUG_EVENT::$1CA59A7E570F154F98F56770E4FE79B4/r
dwError		dd ?
dwType		dd ?
RIP_INFO	ends

; ---------------------------------------------------------------------------

PROCESSENTRY32	struc ;	(sizeof=0x128, align=0x4, copyof_76) ; XREF: sub_408530/r
dwSize		dd ?
cntUsage	dd ?
th32ProcessID	dd ?
th32DefaultHeapID dd ?
th32ModuleID	dd ?
cntThreads	dd ?
th32ParentProcessID dd ?
pcPriClassBase	dd ?
dwFlags		dd ?
szExeFile	db 260 dup(?)
PROCESSENTRY32	ends

; ---------------------------------------------------------------------------

SHELLEXECUTEINFOA struc	; (sizeof=0x3C,	copyof_78) ; XREF: sub_409570/r
cbSize		dd ?
fMask		dd ?
hwnd		dd ?			; offset
lpVerb		dd ?			; offset
lpFile		dd ?			; offset
lpParameters	dd ?			; offset
lpDirectory	dd ?			; offset
nShow		dd ?
hInstApp	dd ?			; offset
lpIDList	dd ?			; offset
lpClass		dd ?			; offset
hkeyClass	dd ?			; offset
dwHotKey	dd ?
anonymous_0	_SHELLEXECUTEINFOA::$D915D6B2B775D926C11EEA321E8940B4 ?
hProcess	dd ?			; offset
SHELLEXECUTEINFOA ends

; ---------------------------------------------------------------------------

_SHELLEXECUTEINFOA::$D915D6B2B775D926C11EEA321E8940B4 union ; (sizeof=0x4, copyof_83)
					; XREF:	SHELLEXECUTEINFOA/r
hIcon		dd ?			; offset
hMonitor	dd ?			; offset
_SHELLEXECUTEINFOA::$D915D6B2B775D926C11EEA321E8940B4 ends

; ---------------------------------------------------------------------------

_FILETIME	struc ;	(sizeof=0x8, align=0x4,	copyof_84) ; XREF: sub_4112E1/r
dwLowDateTime	dd ?
dwHighDateTime	dd ?
_FILETIME	ends

; ---------------------------------------------------------------------------

LARGE_INTEGER	union ;	(sizeof=0x8, align=0x8,	copyof_85) ; XREF: sub_4112E1/r
anonymous_0	_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
u		_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ?
QuadPart	dq ?
LARGE_INTEGER	ends

; ---------------------------------------------------------------------------

_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E struc	; (sizeof=0x8, align=0x4, copyof_87)
					; XREF:	LARGE_INTEGER/r	LARGE_INTEGER/r
LowPart		dd ?
HighPart	dd ?
_LARGE_INTEGER::$837407842DC9087486FDFA5FEB63B74E ends

; ---------------------------------------------------------------------------

HINSTANCE__	struc ;	(sizeof=0x4, align=0x4,	copyof_23)
unused		dd ?
HINSTANCE__	ends


