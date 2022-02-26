.386
.model flat, stdcall
option casemap:none

include ollycrdebugger.inc
.data
    
    g_szDefaultPath db ".\",0
    g_szDefaultType db "*.exe",0;
.code

ReadMemory proc  dwAddr:DWORD, pBuf:LPVOID, dwSize:DWORD
    LOCAL @dwOldProtect:DWORD
    LOCAL @dwBytesReaded:DWORD
    
    invoke ReadProcessMemory,g_hProcess, dwAddr, pBuf,dwSize, addr @dwBytesReaded

    ret
ReadMemory endp


WriteMemory proc dwAddr:DWORD, pBuf:LPVOID, dwSize:DWORD
    LOCAL @dwOldProtect:DWORD
    LOCAL @dwBytesWrited:DWORD
    
    
    invoke VirtualProtectEx,g_hProcess,dwAddr,dwSize, PAGE_EXECUTE_READWRITE, addr @dwOldProtect
    invoke WriteProcessMemory,g_hProcess, dwAddr, pBuf,dwSize, addr @dwBytesWrited
    invoke VirtualProtectEx,g_hProcess,dwAddr,dwSize, @dwOldProtect, addr @dwOldProtect
    
    ret
WriteMemory endp



;�򿪱���Ի��� ������pPath �������� - �����·��
SaveFilePath proc uses edi esi pPath:DWORD
    LOCAL @ofn:OPENFILENAME

    invoke RtlZeroMemory, addr @ofn, sizeof @ofn
    
    
    ;ѡ�񱣴�λ��
    mov @ofn.lStructSize, sizeof @ofn
    mov @ofn.hwndOwner, NULL
    mov eax, pPath
    mov @ofn.lpstrFile, eax     ;����·��������
    mov @ofn.nMaxFile, MAX_PATH
    mov @ofn.lpstrInitialDir, offset g_szDefaultPath  ;Ĭ�ϱ��浽��ǰ�ļ�����
    mov @ofn.lpstrFileTitle, NULL
    mov @ofn.nMaxFileTitle, 0
    mov @ofn.nFilterIndex, 0
    mov @ofn.Flags, OFN_PATHMUSTEXIST or OFN_FILEMUSTEXIST or OFN_EXPLORER     
    invoke GetSaveFileName, addr @ofn
    .if	 eax == NULL
        mov eax, FALSE
        ret
    .endif
    
    mov eax, TRUE
    ret
    
SaveFilePath endp


OpenFilePath proc uses edi esi pPath:DWORD
    LOCAL @ofn:OPENFILENAME

    invoke RtlZeroMemory, addr @ofn, sizeof @ofn
    
    ;ѡ�񱣴�λ��
    mov @ofn.lStructSize, sizeof @ofn
    mov @ofn.hwndOwner, NULL
    mov eax, pPath
    mov @ofn.lpstrFile, eax     ;����·��������
    mov @ofn.nMaxFile, MAX_PATH
    mov @ofn.lpstrInitialDir, offset g_szDefaultPath  ;Ĭ�ϱ��浽��ǰ�ļ�����
    mov @ofn.lpstrFileTitle, NULL
    mov @ofn.nMaxFileTitle, 0
    mov @ofn.nFilterIndex, 1
    mov @ofn.Flags, OFN_PATHMUSTEXIST or OFN_FILEMUSTEXIST     
    invoke GetOpenFileName, addr @ofn
    .if	 eax == NULL
        mov eax, FALSE
        ret
    .endif
    mov eax, TRUE
    ret
    
OpenFilePath endp



end