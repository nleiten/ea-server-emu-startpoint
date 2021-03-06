/* This file has been generated by the Hex-Rays decompiler.
   Copyright (c) 2007-2017 Hex-Rays <info@hex-rays.com>

   Detected compiler: Visual C++
*/

#include <windows.h>
#include <defs.h>


//-------------------------------------------------------------------------
// Function declarations

#define __thiscall __cdecl // Test compile in C mode

_DWORD *__thiscall sub_10001000(_DWORD *this, char a2);
bool __thiscall sub_10001050(void *this, int a2, _DWORD *a3);
bool __thiscall sub_10001090(void *this, _DWORD *a2, int a3);
const char *sub_100010B0();
int __stdcall sub_100010C0(int a1, int a2);
const char *sub_10001140();
int __stdcall sub_10001150(int a1, int a2);
const char *sub_100011A0();
int __stdcall sub_100011B0(int a1, int a2);
_DWORD *__stdcall sub_10001230(_DWORD *a1, int a2);
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
size_t *__thiscall sub_100012A0(int this, void *a2, size_t a3);
_DWORD *__thiscall sub_100013A0(void *this, int a2, int a3, size_t a4);
BOOL __thiscall sub_10001480(_DWORD *this, unsigned int a2, int a3);
_DWORD *__thiscall sub_100014E0(void *this, int a2, int a3);
void *__thiscall sub_10001560(_DWORD *this, int a2, size_t a3);
void *__stdcall sub_100016B0(unsigned int a1);
struct hostent *__stdcall sub_100016E0(char *name);
signed int sub_100021D0();
// int __cdecl atexit(void (__cdecl *)());
void sub_10002BBB();
void __cdecl sub_10002BDB(); // idb
void __cdecl sub_10002C08(); // idb
// int __cdecl _clean_type_info_names_internal(_DWORD); weak
// int __stdcall CxxThrowException(_DWORD, _DWORD); weak
// int __fastcall _CxxFrameHandler3(_DWORD, _DWORD); weak
// void *__cdecl memcpy(void *, const void *, size_t);
int __thiscall SEH_10001560(void *this, int a2, int a3);
int sub_10002C70();
int sub_10002C80();
int sub_10002C90();
void __cdecl sub_10002CA0(); // idb
void __cdecl sub_10002CB0(); // idb
void __cdecl sub_10002CC0(); // idb
// int __stdcall LhInstallHook(_DWORD, _DWORD, _DWORD, _DWORD); weak
// _DWORD __stdcall LhUninstallAllHooks(); weak
// int __stdcall LhSetExclusiveACL(_DWORD, _DWORD, _DWORD); weak
// FARPROC __stdcall GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
// HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName);
// const char *__cdecl std::_Winerror_map(_DWORD); weak
// void __cdecl std::_Xbad_alloc(); weak
// void __cdecl std::_Xout_of_range(const char *); weak
// void __cdecl std::_Xlength_error(const char *); weak
// const char *__cdecl std::_Syserror_map(_DWORD); weak
// void *__cdecl operator new(unsigned int); weak
// void __cdecl operator delete(void *); weak
// void *__cdecl memmove(void *, const void *, size_t);
// struct hostent *__stdcall gethostbyname(const char *name);

//-------------------------------------------------------------------------
// Data declarations

void *std::error_category::`vftable' = &sub_10001000; // weak
_UNKNOWN unk_10003A5C; // weak
_UNKNOWN unk_10003A64; // weak
int (__stdcall **off_100050CC[3])(char) = { &off_10003188, &off_1000316C, &off_100031A4 }; // weak
int (__stdcall **off_100050D0[2])(char) = { &off_1000316C, &off_100031A4 }; // weak
int (__stdcall **off_100050D4)(char) = &off_100031A4; // weak
_UNKNOWN unk_10005400; // weak


//----- (10001000) --------------------------------------------------------
_DWORD *__thiscall sub_10001000(_DWORD *this, char a2)
{
  _DWORD *v2; // esi

  v2 = this;
  *this = &std::error_category::`vftable';
  if ( a2 & 1 )
    operator delete(this);
  return v2;
}
// 1000308C: using guessed type void __cdecl operator delete(void *);
// 100031C0: using guessed type void *std::error_category::`vftable';

//----- (10001050) --------------------------------------------------------
bool __thiscall sub_10001050(void *this, int a2, _DWORD *a3)
{
  _DWORD *v3; // eax
  char v5; // [esp+0h] [ebp-8h]

  v3 = (_DWORD *)(*(int (__stdcall **)(char *, int))(*(_DWORD *)this + 12))(&v5, a2);
  return v3[1] == a3[1] && *v3 == *a3;
}

//----- (10001090) --------------------------------------------------------
bool __thiscall sub_10001090(void *this, _DWORD *a2, int a3)
{
  return this == (void *)a2[1] && *a2 == a3;
}

//----- (100010B0) --------------------------------------------------------
const char *sub_100010B0()
{
  return "generic";
}

//----- (100010C0) --------------------------------------------------------
int __stdcall sub_100010C0(int a1, int a2)
{
  const char *v2; // eax
  char *v3; // edx

  v2 = std::_Syserror_map(a2);
  v3 = "unknown error";
  if ( v2 )
    v3 = (char *)v2;
  *(_DWORD *)(a1 + 20) = 15;
  *(_DWORD *)(a1 + 16) = 0;
  *(_BYTE *)a1 = 0;
  if ( *v3 )
    sub_100012A0(a1, v3, strlen(v3));
  else
    sub_100012A0(a1, v3, 0);
  return a1;
}
// 1000304C: using guessed type const char *__cdecl std::_Syserror_map(_DWORD);

//----- (10001140) --------------------------------------------------------
const char *sub_10001140()
{
  return "iostream";
}

//----- (10001150) --------------------------------------------------------
int __stdcall sub_10001150(int a1, int a2)
{
  if ( a2 == 1 )
  {
    *(_DWORD *)(a1 + 20) = 15;
    *(_DWORD *)(a1 + 16) = 0;
    *(_BYTE *)a1 = 0;
    sub_100012A0(a1, "iostream stream error", 0x15u);
  }
  else
  {
    sub_100010C0(a1, a2);
  }
  return a1;
}

//----- (100011A0) --------------------------------------------------------
const char *sub_100011A0()
{
  return "system";
}

//----- (100011B0) --------------------------------------------------------
int __stdcall sub_100011B0(int a1, int a2)
{
  const char *v2; // eax
  char *v3; // edx

  v2 = std::_Winerror_map(a2);
  v3 = "unknown error";
  if ( v2 )
    v3 = (char *)v2;
  *(_DWORD *)(a1 + 20) = 15;
  *(_DWORD *)(a1 + 16) = 0;
  *(_BYTE *)a1 = 0;
  if ( *v3 )
    sub_100012A0(a1, v3, strlen(v3));
  else
    sub_100012A0(a1, v3, 0);
  return a1;
}
// 1000303C: using guessed type const char *__cdecl std::_Winerror_map(_DWORD);

//----- (10001230) --------------------------------------------------------
_DWORD *__stdcall sub_10001230(_DWORD *a1, int a2)
{
  bool v2; // zf
  _DWORD *result; // eax

  v2 = std::_Syserror_map(a2) == 0;
  result = a1;
  *a1 = a2;
  if ( v2 )
    a1[1] = off_100050CC;
  else
    a1[1] = off_100050D0;
  return result;
}
// 1000304C: using guessed type const char *__cdecl std::_Syserror_map(_DWORD);
// 100050CC: using guessed type int (__stdcall **off_100050CC[3])(char);
// 100050D0: using guessed type int (__stdcall **off_100050D0[2])(char);

//----- (10001270) --------------------------------------------------------
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  if ( fdwReason )
  {
    if ( fdwReason == 1 )
    {
      sub_100021D0();
      return 1;
    }
  }
  else
  {
    LhUninstallAllHooks();
  }
  return 1;
}
// 10003004: using guessed type _DWORD __stdcall LhUninstallAllHooks();

//----- (100012A0) --------------------------------------------------------
size_t *__thiscall sub_100012A0(int this, void *a2, size_t a3)
{
  size_t *v3; // esi
  unsigned int v4; // ecx
  unsigned int v5; // eax
  size_t *v6; // edx
  size_t *result; // eax
  size_t v8; // eax
  size_t *v9; // eax
  bool v10; // cf

  v3 = (size_t *)this;
  if ( a2 )
  {
    v4 = *(_DWORD *)(this + 20);
    v5 = (unsigned int)(v4 < 0x10 ? v3 : *v3);
    if ( (unsigned int)a2 >= v5 )
    {
      v6 = v4 < 0x10 ? v3 : *v3;
      if ( (char *)v6 + v3[4] > a2 )
      {
        if ( v4 < 0x10 )
          result = sub_100013A0(v3, (int)v3, (_BYTE *)a2 - (_BYTE *)v3, a3);
        else
          result = sub_100013A0(v3, (int)v3, (int)a2 - *v3, a3);
        return result;
      }
    }
  }
  if ( a3 > 0xFFFFFFFE )
    std::_Xlength_error("string too long");
  v8 = v3[5];
  if ( v8 < a3 )
  {
    sub_10001560(v3, a3, v3[4]);
    if ( !a3 )
      return v3;
LABEL_17:
    if ( v3[5] < 0x10 )
      v9 = v3;
    else
      v9 = (size_t *)*v3;
    if ( a3 )
      memcpy(v9, a2, a3);
    v10 = v3[5] < 0x10;
    v3[4] = a3;
    if ( !v10 )
    {
      *(_BYTE *)(*v3 + a3) = 0;
      return v3;
    }
    *((_BYTE *)v3 + a3) = 0;
    return v3;
  }
  if ( a3 )
    goto LABEL_17;
  v3[4] = 0;
  if ( v8 < 0x10 )
  {
    result = v3;
    *(_BYTE *)v3 = 0;
  }
  else
  {
    *(_BYTE *)*v3 = 0;
    result = v3;
  }
  return result;
}
// 10003048: using guessed type void __cdecl std::_Xlength_error(const char *);

//----- (100013A0) --------------------------------------------------------
_DWORD *__thiscall sub_100013A0(void *this, int a2, int a3, size_t a4)
{
  int v4; // ebx
  unsigned int v5; // edi
  _DWORD *v6; // esi
  int v7; // ecx
  unsigned int v8; // edi
  int v9; // eax
  bool v10; // cf
  _DWORD *result; // eax
  void *v12; // ecx

  v4 = a2;
  v5 = *(_DWORD *)(a2 + 16);
  v6 = this;
  v7 = a3;
  if ( v5 < a3 )
    std::_Xout_of_range("invalid string position");
  v8 = v5 - v7;
  if ( a4 < v8 )
    v8 = a4;
  if ( v6 == (_DWORD *)a2 )
  {
    v9 = v8 + v7;
    if ( v6[4] < v8 + v7 )
      std::_Xout_of_range("invalid string position");
    v10 = v6[5] < 0x10u;
    v6[4] = v9;
    if ( v10 )
      *((_BYTE *)v6 + v9) = 0;
    else
      *(_BYTE *)(v9 + *v6) = 0;
    sub_100014E0(v6, v7, v7);
    result = v6;
  }
  else
  {
    if ( (unsigned __int8)sub_10001480(v6, v8, v7) )
    {
      if ( *(_DWORD *)(a2 + 20) >= 0x10u )
        v4 = *(_DWORD *)a2;
      if ( v6[5] < 0x10u )
        v12 = v6;
      else
        v12 = (void *)*v6;
      if ( v8 )
        memcpy(v12, (const void *)(v4 + a3), v8);
      v10 = v6[5] < 0x10u;
      v6[4] = v8;
      if ( !v10 )
      {
        *(_BYTE *)(*v6 + v8) = 0;
        return v6;
      }
      *((_BYTE *)v6 + v8) = 0;
    }
    result = v6;
  }
  return result;
}
// 10003044: using guessed type void __cdecl std::_Xout_of_range(const char *);

//----- (10001480) --------------------------------------------------------
BOOL __thiscall sub_10001480(_DWORD *this, unsigned int a2, int a3)
{
  unsigned int v3; // eax
  BOOL result; // eax

  if ( a2 > 0xFFFFFFFE )
    std::_Xlength_error("string too long");
  v3 = this[5];
  if ( v3 >= a2 )
  {
    if ( !a2 )
    {
      this[4] = 0;
      if ( v3 >= 0x10 )
        this = (_DWORD *)*this;
      *(_BYTE *)this = 0;
    }
    result = a2 > 0;
  }
  else
  {
    sub_10001560(this, a2, this[4]);
    result = a2 > 0;
  }
  return result;
}
// 10003048: using guessed type void __cdecl std::_Xlength_error(const char *);

//----- (100014E0) --------------------------------------------------------
_DWORD *__thiscall sub_100014E0(void *this, int a2, int a3)
{
  _DWORD *v3; // esi
  unsigned int v4; // edi
  bool v5; // cf
  _DWORD *result; // eax
  size_t v7; // edi

  v3 = this;
  v4 = *((_DWORD *)this + 4);
  if ( v4 > a3 )
  {
    if ( a3 )
    {
      if ( *((_DWORD *)this + 5) >= 0x10u )
        this = *(void **)this;
      v7 = v4 - a3;
      if ( v7 )
        memmove(this, (char *)this + a3, v7);
      v5 = v3[5] < 0x10u;
      v3[4] = v7;
      if ( !v5 )
      {
        *(_BYTE *)(*v3 + v7) = 0;
        return v3;
      }
      *((_BYTE *)v3 + v7) = 0;
    }
    result = v3;
  }
  else
  {
    v5 = *((_DWORD *)this + 5) < 0x10u;
    *((_DWORD *)this + 4) = 0;
    if ( v5 )
    {
      result = this;
      *(_BYTE *)this = 0;
    }
    else
    {
      **(_BYTE **)this = 0;
      result = this;
    }
  }
  return result;
}

//----- (10001560) --------------------------------------------------------
void *__thiscall sub_10001560(_DWORD *this, int a2, size_t a3)
{
  int v3; // esi
  unsigned int v4; // edi
  unsigned int v5; // ebx
  unsigned int v6; // ecx
  void *v7; // eax
  const void *v8; // ecx
  void *result; // eax
  int v10; // [esp+0h] [ebp-28h]
  _DWORD *v11; // [esp+10h] [ebp-18h]
  void *v12; // [esp+14h] [ebp-14h]
  int *v13; // [esp+18h] [ebp-10h]
  unsigned int v14; // [esp+24h] [ebp-4h]
  int savedregs; // [esp+28h] [ebp+0h]

  v13 = &v10;
  v3 = (int)this;
  v11 = this;
  v4 = a2 | 0xF;
  if ( (a2 | 0xFu) <= 0xFFFFFFFE )
  {
    v5 = this[5];
    v6 = this[5] >> 1;
    if ( v6 > v4 / 3 )
    {
      v4 = v6 + v5;
      if ( v5 > -2 - v6 )
        v4 = -2;
    }
  }
  else
  {
    v4 = a2;
  }
  v7 = 0;
  v14 = 0;
  v12 = 0;
  if ( v4 != -1 )
  {
    if ( v4 + 1 > 0xFFFFFFFF || (v7 = operator new(v4 + 1), (v12 = v7) == 0) )
    {
      std::_Xbad_alloc();
      v13 = &savedregs;
      v14 = a2 + 1;
      LOBYTE(v14) = 2;
      v12 = sub_100016B0(v14);
      v7 = v12;
      v3 = (int)v11;
      v4 = a2;
    }
  }
  if ( a3 )
  {
    v8 = (const void *)(*(_DWORD *)(v3 + 20) < 0x10u ? v3 : *(_DWORD *)v3);
    if ( a3 )
      memcpy(v7, v8, a3);
  }
  if ( *(_DWORD *)(v3 + 20) >= 0x10u )
    operator delete(*(void **)v3);
  result = v12;
  *(_BYTE *)v3 = 0;
  *(_DWORD *)v3 = result;
  *(_DWORD *)(v3 + 20) = v4;
  *(_DWORD *)(v3 + 16) = a3;
  if ( v4 >= 0x10 )
    v3 = (int)result;
  *(_BYTE *)(v3 + a3) = 0;
  return result;
}
// 10002C3E: using guessed type int __stdcall CxxThrowException(_DWORD, _DWORD);
// 10003040: using guessed type void __cdecl std::_Xbad_alloc();
// 10003088: using guessed type void *__cdecl operator new(unsigned int);
// 1000308C: using guessed type void __cdecl operator delete(void *);

//----- (100016B0) --------------------------------------------------------
void *__stdcall sub_100016B0(unsigned int a1)
{
  void *v1; // ecx

  v1 = 0;
  if ( a1 )
  {
    if ( a1 > 0xFFFFFFFF || (v1 = operator new(a1)) == 0 )
      std::_Xbad_alloc();
  }
  return v1;
}
// 10003040: using guessed type void __cdecl std::_Xbad_alloc();
// 10003088: using guessed type void *__cdecl operator new(unsigned int);

//----- (100016E0) --------------------------------------------------------
struct hostent *__stdcall sub_100016E0(char *name)
{
  int v1; // eax
  int v2; // eax
  int v3; // eax
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  struct hostent *result; // eax
  int v11; // eax
  int v12; // eax
  int v13; // eax
  int v14; // eax
  int v15; // eax
  int v16; // eax
  int v17; // eax
  int v18; // eax
  int v19; // eax
  int v20; // eax
  int v21; // eax
  int v22; // eax
  int v23; // eax
  int v24; // eax
  int v25; // eax
  int v26; // eax
  int v27; // eax
  int v28; // eax
  int v29; // eax
  int v30; // eax
  int v31; // eax
  int v32; // eax
  int v33; // eax
  int v34; // eax
  int v35; // eax
  int v36; // eax
  int v37; // eax
  int v38; // eax
  int v39; // eax
  int v40; // eax
  int v41; // eax
  int v42; // eax
  int v43; // eax
  int v44; // eax
  int v45; // eax
  int v46; // eax
  int v47; // eax
  int v48; // eax
  int v49; // eax
  int v50; // eax
  int v51; // eax

  v1 = strcmp(name, "servserv.generals.ea.com");
  if ( v1 )
    v1 = -(v1 < 0) | 1;
  if ( !v1 )
    return gethostbyname("http.server.cnc-online.net");
  v2 = strcmp(name, "na.llnet.eadownloads.ea.com");
  if ( v2 )
    v2 = -(v2 < 0) | 1;
  if ( !v2 )
    return gethostbyname("http.server.cnc-online.net");
  v3 = strcmp(name, "bfme.fesl.ea.com");
  if ( v3 )
    v3 = -(v3 < 0) | 1;
  if ( !v3 )
    return gethostbyname("login.server.cnc-online.net");
  v4 = strcmp(name, "bfme2.fesl.ea.com");
  if ( v4 )
    v4 = -(v4 < 0) | 1;
  if ( !v4 )
    return gethostbyname("login.server.cnc-online.net");
  v5 = strcmp(name, "bfme2-ep1-pc.fesl.ea.com");
  if ( v5 )
    v5 = -(v5 < 0) | 1;
  if ( !v5 )
    return gethostbyname("login.server.cnc-online.net");
  v6 = strcmp(name, "cnc3-pc.fesl.ea.com");
  if ( v6 )
    v6 = -(v6 < 0) | 1;
  if ( !v6 )
    return gethostbyname("login.server.cnc-online.net");
  v7 = strcmp(name, "cnc3-ep1-pc.fesl.ea.com");
  if ( v7 )
    v7 = -(v7 < 0) | 1;
  if ( !v7 )
    return gethostbyname("login.server.cnc-online.net");
  v8 = strcmp(name, "cncra3-pc.fesl.ea.com");
  if ( v8 )
    v8 = -(v8 < 0) | 1;
  if ( !v8 )
    return gethostbyname("login.server.cnc-online.net");
  v9 = strcmp(name, "gpcm.gamespy.com");
  if ( v9 )
    v9 = -(v9 < 0) | 1;
  if ( !v9 )
    return gethostbyname("gpcm.server.cnc-online.net");
  v11 = strcmp(name, "peerchat.gamespy.com");
  if ( v11 )
    v11 = -(v11 < 0) | 1;
  if ( !v11 )
    return gethostbyname("peerchat.server.cnc-online.net");
  v12 = strcmp(name, "lotrbme.available.gamespy.com");
  if ( v12 )
    v12 = -(v12 < 0) | 1;
  if ( !v12 )
    return gethostbyname("master.server.cnc-online.net");
  v13 = strcmp(name, "lotrbme.master.gamespy.com");
  if ( v13 )
    v13 = -(v13 < 0) | 1;
  if ( !v13 )
    return gethostbyname("master.server.cnc-online.net");
  v14 = strcmp(name, "lotrbme.ms13.gamespy.com");
  if ( v14 )
    v14 = -(v14 < 0) | 1;
  if ( !v14 )
    return gethostbyname("master.server.cnc-online.net");
  v15 = strcmp(name, "lotrbme2r.available.gamespy.com");
  if ( v15 )
    v15 = -(v15 < 0) | 1;
  if ( !v15 )
    return gethostbyname("master.server.cnc-online.net");
  v16 = strcmp(name, "lotrbme2r.master.gamespy.com");
  if ( v16 )
    v16 = -(v16 < 0) | 1;
  if ( !v16 )
    return gethostbyname("master.server.cnc-online.net");
  v17 = strcmp(name, "lotrbme2r.ms9.gamespy.com");
  if ( v17 )
    v17 = -(v17 < 0) | 1;
  if ( !v17 )
    return gethostbyname("master.server.cnc-online.net");
  v18 = strcmp(name, "ccgenerals.ms19.gamespy.com");
  if ( v18 )
    v18 = -(v18 < 0) | 1;
  if ( !v18 )
    return gethostbyname("master.server.cnc-online.net");
  v19 = strcmp(name, "ccgenzh.ms6.gamespy.com");
  if ( v19 )
    v19 = -(v19 < 0) | 1;
  if ( !v19 )
    return gethostbyname("master.server.cnc-online.net");
  v20 = strcmp(name, "cc3tibwars.available.gamespy.com");
  if ( v20 )
    v20 = -(v20 < 0) | 1;
  if ( !v20 )
    return gethostbyname("master.server.cnc-online.net");
  v21 = strcmp(name, "cc3tibwars.master.gamespy.com");
  if ( v21 )
    v21 = -(v21 < 0) | 1;
  if ( !v21 )
    return gethostbyname("master.server.cnc-online.net");
  v22 = strcmp(name, "cc3tibwars.ms17.gamespy.com");
  if ( v22 )
    v22 = -(v22 < 0) | 1;
  if ( !v22 )
    return gethostbyname("master.server.cnc-online.net");
  v23 = strcmp(name, "cc3xp1.available.gamespy.com");
  if ( v23 )
    v23 = -(v23 < 0) | 1;
  if ( !v23 )
    return gethostbyname("master.server.cnc-online.net");
  v24 = strcmp(name, "cc3xp1.master.gamespy.com");
  if ( v24 )
    v24 = -(v24 < 0) | 1;
  if ( !v24 )
    return gethostbyname("master.server.cnc-online.net");
  v25 = strcmp(name, "cc3xp1.ms18.gamespy.com");
  if ( v25 )
    v25 = -(v25 < 0) | 1;
  if ( !v25 )
    return gethostbyname("master.server.cnc-online.net");
  v26 = strcmp(name, "redalert3pc.available.gamespy.com");
  if ( v26 )
    v26 = -(v26 < 0) | 1;
  if ( !v26 )
    return gethostbyname("master.server.cnc-online.net");
  v27 = strcmp(name, "redalert3pc.master.gamespy.com");
  if ( v27 )
    v27 = -(v27 < 0) | 1;
  if ( !v27 )
    return gethostbyname("master.server.cnc-online.net");
  v28 = strcmp(name, "redalert3pc.ms1.gamespy.com");
  if ( v28 )
    v28 = -(v28 < 0) | 1;
  if ( !v28 )
    return gethostbyname("master.server.cnc-online.net");
  v29 = strcmp(name, "master.gamespy.com");
  if ( v29 )
    v29 = -(v29 < 0) | 1;
  if ( !v29 )
    return gethostbyname("master.server.cnc-online.net");
  v30 = strcmp(name, "redalert3pc.natneg1.gamespy.com");
  if ( v30 )
    v30 = -(v30 < 0) | 1;
  if ( !v30 )
    return gethostbyname("natneg.server.cnc-online.net");
  v31 = strcmp(name, "redalert3pc.natneg2.gamespy.com");
  if ( v31 )
    v31 = -(v31 < 0) | 1;
  if ( !v31 )
    return gethostbyname("natneg.server.cnc-online.net");
  v32 = strcmp(name, "redalert3pc.natneg3.gamespy.com");
  if ( v32 )
    v32 = -(v32 < 0) | 1;
  if ( !v32 )
    return gethostbyname("natneg.server.cnc-online.net");
  v33 = strcmp(name, "lotrbme.gamestats.gamespy.com");
  if ( v33 )
    v33 = -(v33 < 0) | 1;
  if ( !v33 )
    return gethostbyname("gamestats.server.cnc-online.net");
  v34 = strcmp(name, "lotrbme2r.gamestats.gamespy.com");
  if ( v34 )
    v34 = -(v34 < 0) | 1;
  if ( !v34 )
    return gethostbyname("gamestats.server.cnc-online.net");
  v35 = strcmp(name, "gamestats.gamespy.com");
  if ( v35 )
    v35 = -(v35 < 0) | 1;
  if ( !v35 )
    return gethostbyname("gamestats.server.cnc-online.net");
  v36 = strcmp(name, "cc3tibwars.auth.pubsvs.gamespy.com");
  if ( v36 )
    v36 = -(v36 < 0) | 1;
  if ( !v36 )
    return gethostbyname("sake.server.cnc-online.net");
  v37 = strcmp(name, "cc3tibwars.comp.pubsvs.gamespy.com");
  if ( v37 )
    v37 = -(v37 < 0) | 1;
  if ( !v37 )
    return gethostbyname("sake.server.cnc-online.net");
  v38 = strcmp(name, "cc3tibwars.sake.gamespy.com");
  if ( v38 )
    v38 = -(v38 < 0) | 1;
  if ( !v38 )
    return gethostbyname("sake.server.cnc-online.net");
  v39 = strcmp(name, "cc3xp1.auth.pubsvs.gamespy.com");
  if ( v39 )
    v39 = -(v39 < 0) | 1;
  if ( !v39 )
    return gethostbyname("sake.server.cnc-online.net");
  v40 = strcmp(name, "cc3xp1.comp.pubsvs.gamespy.com");
  if ( v40 )
    v40 = -(v40 < 0) | 1;
  if ( !v40 )
    return gethostbyname("sake.server.cnc-online.net");
  v41 = strcmp(name, "cc3xp1.sake.gamespy.com");
  if ( v41 )
    v41 = -(v41 < 0) | 1;
  if ( !v41 )
    return gethostbyname("sake.server.cnc-online.net");
  v42 = strcmp(name, "redalert3pc.auth.pubsvs.gamespy.com");
  if ( v42 )
    v42 = -(v42 < 0) | 1;
  if ( !v42 )
    return gethostbyname("sake.server.cnc-online.net");
  v43 = strcmp(name, "redalert3pc.comp.pubsvs.gamespy.com");
  if ( v43 )
    v43 = -(v43 < 0) | 1;
  if ( !v43 )
    return gethostbyname("sake.server.cnc-online.net");
  v44 = strcmp(name, "redalert3pc.sake.gamespy.com");
  if ( v44 )
    v44 = -(v44 < 0) | 1;
  if ( !v44 )
    return gethostbyname("sake.server.cnc-online.net");
  v45 = strcmp(name, "redalert3services.gamespy.com");
  if ( v45 )
    v45 = -(v45 < 0) | 1;
  if ( !v45 )
    return gethostbyname("sake.server.cnc-online.net");
  v46 = strcmp(name, "psweb.gamespy.com");
  if ( v46 )
    v46 = -(v46 < 0) | 1;
  if ( !v46 )
    return gethostbyname("sake.server.cnc-online.net");
  v47 = strcmp(name, "lotrbfme.arenasdk.gamespy.com");
  if ( v47 )
    v47 = -(v47 < 0) | 1;
  if ( !v47 )
    goto LABEL_163;
  v48 = strcmp(name, "arenasdk.gamespy.com");
  if ( v48 )
    v48 = -(v48 < 0) | 1;
  if ( !v48 )
    goto LABEL_163;
  v49 = strcmp(name, "launch.gamespyarcade.com");
  if ( v49 )
    v49 = -(v49 < 0) | 1;
  if ( !v49 )
    goto LABEL_163;
  v50 = strcmp(name, "www.gamespy.com");
  if ( v50 )
    v50 = -(v50 < 0) | 1;
  if ( !v50 )
    goto LABEL_163;
  v51 = strcmp(name, "ingamead.gamespy.com");
  if ( v51 )
    v51 = -(v51 < 0) | 1;
  if ( v51 )
    result = gethostbyname(name);
  else
LABEL_163:
    result = gethostbyname("server.cnc-online.net");
  return result;
}

//----- (100021D0) --------------------------------------------------------
signed int sub_100021D0()
{
  HMODULE v0; // edi
  _DWORD *v1; // eax
  _DWORD *v2; // esi
  FARPROC v3; // eax
  int v5; // [esp+8h] [ebp-4h]

  v0 = LoadLibraryA("Ws2_32.dll");
  v1 = operator new(4u);
  v2 = v1;
  if ( v1 )
    *v1 = 0;
  else
    v2 = 0;
  v5 = 0;
  v3 = GetProcAddress(v0, "gethostbyname");
  LhInstallHook(v3, sub_100016E0, 591751049, v2);
  LhSetExclusiveACL(&v5, 1, v2);
  return 1;
}
// 10003000: using guessed type int __stdcall LhInstallHook(_DWORD, _DWORD, _DWORD, _DWORD);
// 10003008: using guessed type int __stdcall LhSetExclusiveACL(_DWORD, _DWORD, _DWORD);
// 10003088: using guessed type void *__cdecl operator new(unsigned int);

//----- (10002BBB) --------------------------------------------------------
void sub_10002BBB()
{
  void (**i)(void); // esi

  for ( i = (void (**)(void))&unk_10003A5C; i < (void (**)(void))&unk_10003A5C; ++i )
  {
    if ( *i )
      (*i)();
  }
}

//----- (10002BDB) --------------------------------------------------------
void __cdecl sub_10002BDB()
{
  void (**i)(void); // esi

  for ( i = (void (**)(void))&unk_10003A64; i < (void (**)(void))&unk_10003A64; ++i )
  {
    if ( *i )
      (*i)();
  }
}

//----- (10002C08) --------------------------------------------------------
void __cdecl sub_10002C08()
{
  _clean_type_info_names_internal(&unk_10005400);
}
// 10002C32: using guessed type int __cdecl _clean_type_info_names_internal(_DWORD);

//----- (10002C50) --------------------------------------------------------
int __thiscall SEH_10001560(void *this, int a2, int a3)
{
  return _CxxFrameHandler3(this, a3);
}
// 10002C44: using guessed type int __fastcall _CxxFrameHandler3(_DWORD, _DWORD);

//----- (10002C70) --------------------------------------------------------
int sub_10002C70()
{
  return atexit(sub_10002CC0);
}

//----- (10002C80) --------------------------------------------------------
int sub_10002C80()
{
  return atexit(sub_10002CB0);
}

//----- (10002C90) --------------------------------------------------------
int sub_10002C90()
{
  return atexit(sub_10002CA0);
}

//----- (10002CA0) --------------------------------------------------------
void __cdecl sub_10002CA0()
{
  off_100050CC[0] = (int (__stdcall **)(char))&std::error_category::`vftable';
}
// 100031C0: using guessed type void *std::error_category::`vftable';
// 100050CC: using guessed type int (__stdcall **off_100050CC[3])(char);

//----- (10002CB0) --------------------------------------------------------
void __cdecl sub_10002CB0()
{
  off_100050D4 = (int (__stdcall **)(char))&std::error_category::`vftable';
}
// 100031C0: using guessed type void *std::error_category::`vftable';
// 100050D4: using guessed type int (__stdcall **off_100050D4)(char);

//----- (10002CC0) --------------------------------------------------------
void __cdecl sub_10002CC0()
{
  off_100050D0[0] = (int (__stdcall **)(char))&std::error_category::`vftable';
}
// 100031C0: using guessed type void *std::error_category::`vftable';
// 100050D0: using guessed type int (__stdcall **off_100050D0[2])(char);

// ALL OK, 29 function(s) have been successfully decompiled
