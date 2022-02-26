ifndef OLLCREBG_H
OLLCREBG_H equ 0

include windows.inc
include kernel32.inc
include msvcrt.inc
include Linker.inc
include psapi.inc
include macros.asm
include masm32.inc
include Comdlg32.inc



includelib Comdlg32.lib
includelib masm32.lib
includelib kernel32.lib
includelib msvcrt.lib
includelib MyUdis86.lib ;反汇编dll
includelib psapi.lib

;includelib ossvcs.lib
;---------------------------------------------------------
;全局变量
;---------------------------------------------------------
externdef g_hProcess:dword
externdef g_hThread:dword
externdef g_bIsStepCommand:dword
externdef g_dwMemBpAddr :dword
externdef g_dwOldProtect:dword

;---------------------------------------------------------
;工具函数
;---------------------------------------------------------

MODULEINFO struc
    lpBaseOfDll dd 0
    SizeOfImage dd 0
    EntryPoint dd 0
MODULEINFO ends

ReadMemory proto  dwAddr:DWORD, pBuf:LPVOID, dwSize:DWORD
WriteMemory proto dwAddr:DWORD, pBuf:LPVOID, dwSize:DWORD

;参数：机器码，机器码长度，eip，反汇编的缓冲区，反汇编对应的机器码，反汇编的机器码的长度
DisAsm proto stdcall pMachineCode:LPBYTE,  dwCodeSize:DWORD, dwEip:DWORD, pDisAsm:LPSTR, pCodeHex:LPSTR, pdwCodeLen:LPDWORD

SaveFilePath proto pPath:DWORD
OpenFilePath proto pPath:DWORD
;----------------------------------------------------------
;软件断点相关
;----------------------------------------------------------
BpData struc
    m_dwAddr dd 0
    m_bIsTmp dd 0
    m_dwNumber dd 0
    m_btOldCode db 0 ;原来的指令
BpData ends

externdef g_pBpListHead:dword

;bIsTmp:是否是临时断点
SetBreakPoint proto dwAddr:DWORD, bIsTmp:BOOL
DelBreakPoint proto dwNumber:DWORD
DelBreakPoint2 proto BPaddr:DWORD
ListBreakPoint proto 
ResCode proto pBpData:ptr BpData
SetTFAndDecEip proto bTF:BOOL, dwDec:DWORD
FindBreakPoint proto dwNumber:DWORD
FindBreakPoint2 proto BPaddr:DWORD
ParseCommand proto

endif
