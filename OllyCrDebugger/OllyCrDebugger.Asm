.386
.model flat, stdcall
option casemap:none

include ollycrdebugger.inc

public g_hProcess
public g_hThread
public g_bIsStepCommand

.data 
    g_hProcess dd 0
    g_hThread  dd 0

.data
    
    
    g_szInput db 0
   	g_szFilter	db	'TXT Files(*.txt)',0,'*.txt',0,'DLL Files(*.dll)',0,'*.dll',0,'All Files(*.*)',0,'*.*',0,0
   	g_szFilterExe db	'EXE Files(*.exe)',0,'*.exe',0,'DLL Files(*.dll)',0,'*.dll',0,'All Files(*.*)',0,'*.*',0,0
	g_szFileName db  1024 dup(0)
    ;g_szExePath db "calc.exe", 0
    g_szExePath db  1024 dup(0)
    g_szErrCreateProcess db "创建进程失败",0dh, 0ah, 0
    g_szEXCEPTION_DEBUG_EVENT      db "EXCEPTION_DEBUG_EVENT      ",0dh,0ah,0
    g_szCREATE_THREAD_DEBUG_EVENT  db "CREATE_THREAD_DEBUG_EVENT  ",0dh,0ah,0
    g_szCREATE_PROCESS_DEBUG_EVENT db "CREATE_PROCESS_DEBUG_EVENT ",0dh,0ah,0
    g_szEXIT_THREAD_DEBUG_EVENT    db "EXIT_THREAD_DEBUG_EVENT    ",0dh,0ah,0
    g_szEXIT_PROCESS_DEBUG_EVENT   db "EXIT_PROCESS_DEBUG_EVENT   ",0dh,0ah,0
    g_szLOAD_DLL_DEBUG_EVENT       db "LOAD_DLL_DEBUG_EVENT       ",0dh,0ah,0
    g_szUNLOAD_DLL_DEBUG_EVENT     db "UNLOAD_DLL_DEBUG_EVENT     ",0dh,0ah,0
    g_szOUTPUT_DEBUG_STRING_EVENT  db "OUTPUT_DEBUG_STRING_EVENT  ",0dh,0ah,0
    g_szLodDllFmt                  db "[event] LodDll Base:%08X ImageName:%s", 0dh, 0ah, 0
    g_dwLoadDllFmtLen              dd $ - offset g_szLodDllFmt
    
    g_bIsSystemCC                  dd FALSE ;系统断点标志位
    g_pBpDataToReset               dd NULL ;断步配合，重设断点
    g_bIsStepCommand               dd FALSE;是否有单步命令
    g_bIsHardwareBpStep            dd FALSE;是否是硬件断点的单步
    b_bIsMemBpStep                 dd FALSE;是否是内存断点的单步

.code

;------------------------------------------------------
;判断是否是自己的断点
;------------------------------------------------------
OnBreakPoint proc uses esi edi ebx pER:ptr EXCEPTION_RECORD
    LOCAL @dwStatus:DWORD
    LOCAL @dwOldProtect:DWORD
    LOCAL @btCodeCC:BYTE
    LOCAL @dwBytesWrited:DWORD
    LOCAL @dwBytesReaded:DWORD
    LOCAL @ctx:CONTEXT
    LOCAL @mi:MODULEINFO
    
    mov @dwStatus, DBG_CONTINUE
    
    mov esi, pER
    assume esi: ptr EXCEPTION_RECORD
    
    ;系统断点，忽略
    .if g_bIsSystemCC == FALSE
        mov g_bIsSystemCC, TRUE
        
        invoke GetModuleInformation,g_hProcess, 1000000h, addr @mi, size @mi

        invoke ParseCommand
        ret
    .endif
    
    ;判断是否是自己的断点，遍历链表
    mov edi, g_pBpListHead
    assume edi:ptr Node
    .while edi != NULL
    
        mov ebx, [edi].m_pUserData
        assume ebx:ptr BpData
        mov eax, [esi].ExceptionAddress
        .if [ebx].m_dwAddr == eax
        
            ;是自己的断点,恢复原来的指令
            mov g_pBpDataToReset, ebx
            invoke ResCode, ebx
            
            .if [ebx].m_bIsTmp == TRUE
                ;临时断点，不设单步
                invoke SetTFAndDecEip, FALSE, 1
                invoke DelBreakPoint,[ebx].m_dwNumber
            .else
                ;永久断点，设置单步，用于重设断点
                invoke SetTFAndDecEip, TRUE, 1
            .endif

            
            ;输入新命令
            invoke ParseCommand
            mov @dwStatus, eax

            .break
        .endif
        assume ebx:nothing
        
        mov edi, [edi].m_pNext
    .endw
    
    assume edi:nothing

    mov eax, @dwStatus
    ret

OnBreakPoint endp


;单步
OnSingleStep proc pER:ptr EXCEPTION_RECORD
    LOCAL @dwOldProtect:DWORD
    LOCAL @btCodeCC:BYTE
    LOCAL @dwBytesWrited:DWORD
    LOCAL @dwBytesReaded:DWORD
    LOCAL @dwStatus:DWORD
    LOCAL @ctx:CONTEXT
    
    mov @dwStatus, DBG_CONTINUE
    
    ;重设断点
    .if g_pBpDataToReset != NULL
    
        mov esi, g_pBpDataToReset
        assume esi:ptr BpData
        
        mov @btCodeCC, 0cch
        invoke WriteMemory,[esi].m_dwAddr, addr @btCodeCC, type @btCodeCC
        
        assume esi:nothing
        
        mov g_pBpDataToReset, NULL
    .endif
    
    ;有单步命令
    .if g_bIsStepCommand == TRUE
         mov g_bIsStepCommand, FALSE
         
         ;获取命令
         invoke ParseCommand
         mov  @dwStatus, eax
    .endif
    
    
     ;有内存单步
    .if b_bIsMemBpStep == TRUE
        invoke VirtualProtectEx,g_hProcess, g_dwMemBpAddr, 4, PAGE_NOACCESS, offset g_dwOldProtect
    
        mov b_bIsMemBpStep, FALSE
    .endif
    
    
    ;判断是否有硬件断点命令
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
    invoke GetThreadContext,g_hThread, addr @ctx
    
    .if g_bIsHardwareBpStep == TRUE
       or @ctx.iDr7, 11b
    
       and @ctx.iDr6, 0
       invoke SetThreadContext,g_hThread, addr @ctx
       mov g_bIsHardwareBpStep, FALSE
       mov eax, DBG_CONTINUE
       ret
    .endif
    
    .if @ctx.iDr6 & 1
        .if @ctx.iDr7 &0000c0000h
            
        .endif
        
       ;and @ctx.iDr7,0fffffffch ;清掉Dr0的硬件断点
       ;or @ctx.regFlag, 100h;将TF位设为1，设置断点
       and @ctx.iDr6, 0
       invoke SetThreadContext,g_hThread, addr @ctx
       ;mov g_bIsHardwareBpStep, TRUE
    
       invoke ParseCommand
       mov @dwStatus, eax        
    .endif

    mov eax, @dwStatus
    ret

OnSingleStep endp





OnAccessVoilation proc uses esi pER:ptr EXCEPTION_RECORD
    LOCAL @dwStatus:DWORD
    LOCAL @ctx:CONTEXT
    LOCAL @dwOldProtect:dword
    
    mov @dwStatus, DBG_CONTINUE

    mov esi, pER
    assume esi:ptr EXCEPTION_RECORD
    
    
    ;恢复内存属性
    invoke VirtualProtectEx,g_hProcess, g_dwMemBpAddr, 4, g_dwOldProtect, addr @dwOldProtect
    
    ;设置单步
    invoke SetTFAndDecEip,TRUE, 0
    mov b_bIsMemBpStep, TRUE
    
    lea eax, [esi].ExceptionInformation
    mov eax, [eax+4];获取异常访问的地址
    
    mov ebx, g_dwMemBpAddr
    add ebx, 4

        
    .if g_dwMemBpAddr <= eax && eax <= ebx
        invoke ParseCommand
        mov eax, DBG_CONTINUE
        ret
    .endif
    
    assume esi:nothing
    
    mov eax, @dwStatus
    ret

OnAccessVoilation endp

;------------------------------------------------------
;判断异常类型,是系统异常还是自己下的异常
;------------------------------------------------------
OnException proc uses esi pDe:ptr DEBUG_EVENT
    LOCAL @dwStatus:DWORD
    
    mov @dwStatus, DBG_CONTINUE
    
    mov esi, pDe
    assume esi:ptr DEBUG_EVENT
    lea esi, [esi].u.Exception
    assume esi:ptr EXCEPTION_RECORD
    
    
    .if [esi].ExceptionCode == EXCEPTION_BREAKPOINT
        invoke OnBreakPoint, esi
        ret
        
    .elseif [esi].ExceptionCode == EXCEPTION_SINGLE_STEP
        invoke OnSingleStep, esi
        ret
        
     .elseif [esi].ExceptionCode == EXCEPTION_ACCESS_VIOLATION
        invoke OnAccessVoilation, esi
        ret
         
    .endif
    
    
    assume esi:nothing
    
    mov eax, @dwStatus
    ret

OnException endp

OnCreateProcess proc uses esi pDe:ptr DEBUG_EVENT
    LOCAL @dwOldProtect:DWORD
    LOCAL @btCodeCC:BYTE
    LOCAL @dwBytesWrited:DWORD
    LOCAL @dwBytesReaded:DWORD

    ret

OnCreateProcess endp



OnLoadDll proc uses esi pDe:ptr DEBUG_EVENT
    LOCAL @szFileName[MAX_PATH*2]:CHAR
    LOCAL @dwAddr:DWORD
    LOCAL @dwBytesReaded:DWORD
    LOCAL @szwLoadDllFmt[MAXBYTE]:WORD
    LOCAL @mi:MODULEINFO
    
    mov esi, pDe
    assume esi:ptr DEBUG_EVENT
    
    invoke GetModuleInformation,g_hProcess, 1000000h, addr @mi, size @mi
    
    
    ;读取地址
    invoke ReadProcessMemory,g_hProcess, [esi].u.LoadDll.lpImageName, addr @dwAddr, type @dwAddr, addr @dwBytesReaded
    .if eax == FALSE || @dwAddr == NULL
        ret
    .endif
    
    ;读取字符串
    invoke ReadProcessMemory, g_hProcess, @dwAddr,addr @szFileName, MAX_PATH*2, addr @dwBytesReaded
    
    .if   [esi].u.LoadDll.fUnicode  == TRUE
        invoke crt_mbstowcs, addr @szwLoadDllFmt, offset g_szLodDllFmt, g_dwLoadDllFmtLen
        invoke crt_wprintf, addr @szwLoadDllFmt, [esi].u.LoadDll.lpBaseOfDll, addr @szFileName
    .else
        invoke crt_printf, offset g_szLodDllFmt, [esi].u.LoadDll.lpBaseOfDll, addr @szFileName
    .endif
    
    assume esi:nothing
    ret

OnLoadDll endp


main proc 
    LOCAL @si:STARTUPINFO
    LOCAL @pi:PROCESS_INFORMATION
    LOCAL @de:DEBUG_EVENT 
    LOCAL @dwStatus:DWORD
    
    invoke RtlZeroMemory,addr @si, type  @si
    mov @si.cb, type @si
    invoke RtlZeroMemory,addr @pi, type @pi
    
    invoke CreateProcess,offset g_szExePath, NULL, NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,addr @si, addr @pi
    .if eax == FALSE
        invoke crt_printf, offset g_szErrCreateProcess
        ret
    .endif
    
    push @pi.hProcess
    pop g_hProcess
    
    .while TRUE
        ;等待调试事件
        invoke RtlZeroMemory,addr @de, type @de
        invoke WaitForDebugEvent, addr @de, INFINITE
        
        ;获取线程句柄
        invoke OpenThread,THREAD_ALL_ACCESS, FALSE, @de.dwThreadId
        mov g_hThread, eax
        
        ;处理调试事件
        mov @dwStatus, DBG_CONTINUE
        .if @de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            ;invoke crt_printf, offset g_szEXCEPTION_DEBUG_EVENT 
            invoke OnException,addr @de
            mov @dwStatus, eax
       
        .elseif @de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT
            invoke crt_printf, offset g_szCREATE_THREAD_DEBUG_EVENT 
             
        .elseif @de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT
            invoke crt_printf, offset g_szCREATE_PROCESS_DEBUG_EVENT 
            invoke OnCreateProcess, addr @de
            
        .elseif @de.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT
            invoke crt_printf, offset g_szEXIT_THREAD_DEBUG_EVENT 
            
        .elseif @de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
            invoke crt_printf, SADD("EXIT_PROCESS_DEBUG_EVENT",0)
            
        .elseif @de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT
            ;invoke crt_printf, offset g_szLOAD_DLL_DEBUG_EVENT 
            invoke OnLoadDll,addr @de 
            
        .elseif @de.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT
            invoke crt_printf, offset g_szUNLOAD_DLL_DEBUG_EVENT 
            
        .elseif @de.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT
            invoke crt_printf, offset g_szOUTPUT_DEBUG_STRING_EVENT  
        .endif
        
        invoke CloseHandle,g_hThread
        invoke ContinueDebugEvent,@de.dwProcessId, @de.dwThreadId, @dwStatus
    .endw
    
    
    ret

main endp

;打开文件
OpenPeFile	proc  hWinMain:HWND
    LOCAL @dwBytesRead:DWORD
	LOCAL	@stOF:OPENFILENAME
	LOCAL	@hFile
	LOCAL   @dwFileSize
	LOCAL   @hMapFile
	LOCAL   @lpMemory
	
	invoke	RtlZeroMemory,offset  g_szExePath,sizeof g_szExePath
	
	invoke	RtlZeroMemory,addr @stOF,sizeof @stOF
	mov	@stOF.lStructSize,sizeof @stOF
	push hWinMain
	pop	@stOF.hwndOwner
	mov	@stOF.lpstrFilter,offset g_szFilterExe
	mov	@stOF.lpstrFile,offset g_szExePath
	mov	@stOF.nMaxFile,1024
	mov	@stOF.Flags,OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST
	invoke	GetOpenFileName,addr @stOF
	.if eax == 0
	    invoke crt_printf, SADD("打开失败",0dh,0ah)
		ret
	.endif
		
    ret

OpenPeFile	endp

START:
 
    invoke crt_printf, SADD("-----------------",0dh,0ah)
    invoke crt_printf, SADD(" 1. 创建调试进程 ",0dh,0ah)
    invoke crt_printf, SADD(" 2. 退出本程序   ",0dh,0ah)
    invoke crt_printf, SADD("-----------------",0dh,0ah)
    
    
	invoke crt_gets,addr g_szInput
	.if g_szInput[0] =='1'
		invoke OpenPeFile,NULL
        invoke main
	.elseif g_szInput[0] =='2'
		xor eax,eax
		invoke ExitProcess,eax
	.endif
    xor eax, eax
    invoke ExitProcess,eax
end START