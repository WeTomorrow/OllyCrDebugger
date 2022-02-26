.386
.model flat, stdcall
option casemap:none

include ollycrdebugger.inc


public g_dwMemBpAddr 
public g_dwOldProtect

.data

    g_szCmdBuf db MAXBYTE dup(0)
    g_szErrCmd db "���������", 0dh, 0ah, 0
    
    
    g_aryCode db 32 dup(0)
    g_dwCodeLen dd $-offset g_aryCode
    g_aryDisAsm db 256 dup(0)
    g_aryHex db 256 dup(0)
    g_dwDisCodeLen dd 0
    g_dwEip dd 0
    g_szShowDisasmFmt db "%08X |%- 16s %s", 0dh, 0ah, 0
    
    g_bIsAutoStep dd FALSE
    g_dwMemBpAddr dd 0
    g_dwOldProtect dd 0
    
    
    g_bIsImport     dd FALSE
    g_bIsSystemBp   dd TRUE
    g_pImageBuffer dd NULL
    g_pImPortTableAddr dd NULL
    
    g_szExportScriptBuff db 200h dup (0)
    g_szImportScriptBuff db 200h dup (0)
    g_dwImportScriptLen dd 0
    g_pTempImPortAddr dd 0 ; ִ�е���ű��ĸ���
    
    
.code

;�����հ��ַ�
SkipWhiteChar proc uses edi pCommand:dword  
     mov edi,pCommand
     .while byte ptr[edi] == ' ' || byte ptr [edi] == 9 ;9��tab��
         add edi,1
     .endw
     mov eax,edi
     ret
SkipWhiteChar endp

;es��������ű�
DeriveES_Script proc 
    LOCAL @szFilePath[MAX_PATH]:CHAR
    LOCAL @hFile:HANDLE
    
    ;��ʼ���ֲ�����
    invoke RtlZeroMemory,addr @szFilePath, sizeof @szFilePath
    
    ;��ȡ����·��
    invoke SaveFilePath, addr @szFilePath
    invoke crt_strcat,addr @szFilePath, SADD(".txt")
    
    ;д�뵽�ļ�
    invoke CreateFile,addr @szFilePath,GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL
    mov @hFile, eax
    .if @hFile == NULL
        ret
    .endif
   
    invoke crt_strlen,offset g_szExportScriptBuff
    invoke WriteFile, @hFile,offset g_szExportScriptBuff, eax, NULL, NULL
    
     .if @hFile != NULL
        invoke CloseHandle, @hFile
    .endif
    
    ret
DeriveES_Script endp 


;��ʾ�����
ShowDisAsm proc
    LOCAL @ctx:CONTEXT
    
    ;��ȡEIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop g_dwEip
    
    ;��ȡeipλ�õĻ�����
    invoke ReadMemory,g_dwEip,offset g_aryCode, g_dwCodeLen
    
    ;�����;�����������룬�����볤�ȣ�eip�������Ļ�������������Ӧ�Ļ����룬�����Ļ�����ĳ���
    invoke DisAsm, offset g_aryCode, g_dwCodeLen, g_dwEip, offset g_aryDisAsm, offset g_aryHex, offset g_dwDisCodeLen
    
    ;;��ʾ����Ļ
    invoke crt_printf, offset g_szShowDisasmFmt, g_dwEip, offset g_aryHex, offset g_aryDisAsm

    ret

ShowDisAsm endp


;u�����ʾ�����
PrintUDisasm proc UAddress:DWORD
    LOCAL @aryCode[MAXBYTE]:WORD 
    LOCAL @dwCodeLen:DWORD 
    LOCAL @dwEip:DWORD 
    LOCAL @aryDisAsm[MAXBYTE]:WORD 
    LOCAL @aryHex[MAXBYTE]:WORD 
    LOCAL @dwDisCodeLen:DWORD 
    
    LOCAL @ctx:CONTEXT
    
    ;��ȡEIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop @dwEip
    
    mov @dwCodeLen,80h
    
    ;�ж�U������û�и���ַ
    .if UAddress ==NULL
        ;��ȡeipλ�õĻ�����
        
        ;invoke crt_printf,SADD("u����û�е�ַ%x", 0dh, 0ah, 0),@dwEip
        invoke ReadMemory,@dwEip,addr @aryCode,@dwCodeLen
    .elseif UAddress !=NULL
        ;��ȡָ��λ�õĻ�����
        ;invoke crt_printf,SADD("u�����е�ַ%x", 0dh, 0ah, 0),UAddress
        invoke ReadMemory,UAddress,addr @aryCode,@dwCodeLen
        
        push UAddress
        pop @dwEip
    .endif
    
    lea esi,@aryCode;����ȡ���Ļ������esi
    mov ebx,8
    .while ebx != 0
        
        ;������      �����룬�����볤�ȣ�eip�������Ļ�������������Ӧ�Ļ����룬�����Ļ�����ĳ���
        invoke DisAsm, esi,10h,@dwEip,addr @aryDisAsm,addr @aryHex,addr @dwDisCodeLen
    
        ;��ʾ
        invoke crt_printf, offset g_szShowDisasmFmt, @dwEip, addr @aryHex, addr @aryDisAsm
        invoke RtlZeroMemory,addr @aryDisAsm,type @aryDisAsm
        
        add esi,@dwDisCodeLen
        mov edx,@dwDisCodeLen
        add @dwEip,edx
        
        dec ebx;ѭ��һ�μ�һ
    .endw
    
    ret

PrintUDisasm endp

;r�����ʾ�Ĵ�������
PringtR_Disasm proc uses esi
    
    LOCAL @ctx:CONTEXT
    
    ;��ȡ�Ĵ�������
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("eax=%08x  ", 0),@ctx.regEax
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("ebx=%08x  ", 0),@ctx.regEbx
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("ecx=%08x  ", 0),@ctx.regEcx
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("edx=%08x  ", 0),@ctx.regEdx
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("esi=%08x  ", 0),@ctx.regEsi
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("edi=%08x  ", 0dh, 0ah, 0),@ctx.regEdi
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("eip=%08x  ", 0),@ctx.regEip
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("esp=%08x  ", 0),@ctx.regEsp
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("ebp=%08x      ", 0),@ctx.regEbp
    
    
    mov ebx,@ctx.regFlag;��ȡ��־
     ;OF �ڵ�11λ
    .if ebx & 800h
        invoke crt_printf, SADD("OV ")
    .else 
        invoke crt_printf, SADD("NV ")
    .endif
    
    ;DF �ڵ�10λ
    .if ebx & 400h
        invoke crt_printf, SADD("DN ")
    .else    
        invoke crt_printf, SADD("UP ")
    .endif
    
     ;IF �ڵ�9λ
    .if ebx & 200h
        invoke crt_printf, SADD("EI ")
    .else    
        invoke crt_printf, SADD("DI ")
    .endif
    
    
     ;TF ��8λ
    .if ebx & 100h
        invoke crt_printf, SADD("TF ")
    .else    
        invoke crt_printf, SADD("NF ")
    .endif
    
     ;SF �ڵ�7λ
    .if ebx & 80h
        invoke crt_printf, SADD("NG ")
    .else    
        invoke crt_printf, SADD("PL ")
    .endif
    
    
     ;ZF �ڵ�6λ
    .if ebx & 40h
        invoke crt_printf, SADD("ZR ")
    .else    
        invoke crt_printf, SADD("NZ ")
    .endif
    
     ;AF �ڵ�4λ
    .if ebx & 10h
        invoke crt_printf, SADD("AC ")
    .else    
        invoke crt_printf, SADD("NA ")
    .endif
    
     ;PF �ڵ�2λ
    .if ebx & 4h
        invoke crt_printf, SADD("PE ")
    .else    
        invoke crt_printf, SADD("PO ")
    .endif
    
     ;CF �ڵ�0λ
    .if ebx & 1h
        invoke crt_printf, SADD("CY ", 0dh, 0ah, 0)
    .else    
        invoke crt_printf, SADD("NC ", 0dh, 0ah, 0)
    .endif

    
    
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Cs=%04x  ", 0),@ctx.regCs
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Ss=%04x  ", 0),@ctx.regSs
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Ds=%04x  ", 0),@ctx.regDs
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Es=%04x  ", 0),@ctx.regEs
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Fs=%04x  ", 0),@ctx.regFs
    
    ;��ȡָ��λ�õĻ�����
    invoke crt_printf,SADD("Gs=%04x  ", 0dh, 0ah, 0),@ctx.regGs
    
    ;��ȡָ��λ�õĻ�����
    ;invoke crt_printf,SADD("Flag=%08x  ", 0dh, 0ah, 0),@ctx.regFlag
    
    
    
    
    ret
PringtR_Disasm endp

;dd�����ʾ�ڴ滷��
PrintDD_Menory proc MenoryAddr:DWORD
    LOCAL @aryCode[MAXBYTE]:WORD 
    LOCAL @dwCodeLen:DWORD 
    LOCAL @dwEip:DWORD 
    LOCAL @aryDisAsm[MAXBYTE]:WORD 
    LOCAL @aryHex:DWORD 
    LOCAL @dwDisCodeLen:DWORD 
    LOCAL @MemoryData[MAXBYTE]:CHAR 
    LOCAL @ctx:CONTEXT
    
    ;��ȡEIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop @dwEip
    
    mov @dwCodeLen,100h
    
    ;�ж�U������û�и���ַ
    .if MenoryAddr ==NULL
        ;��ȡeipλ�õĻ�����
        ;invoke crt_printf,SADD("u����û�е�ַ%x", 0dh, 0ah, 0),@dwEip
        invoke ReadMemory,@dwEip,addr @aryCode,@dwCodeLen
    .elseif MenoryAddr !=NULL
        ;��ȡָ��λ�õĻ�����
        invoke ReadMemory,MenoryAddr,addr @aryCode,@dwCodeLen
        
        push MenoryAddr
        pop @dwEip
    .endif
    
    lea esi,@aryCode;����ȡ���Ļ������esi
    mov ebx,8
    .while ebx != 0
        
        ;������      �����룬�����볤�ȣ�eip�������Ļ�������������Ӧ�Ļ����룬�����Ļ�����ĳ���
        ;invoke DisAsm, esi,10h,@dwEip,addr @aryDisAsm,addr @aryHex,addr @dwDisCodeLen
        ;��ʾ
        invoke crt_printf, SADD("%08X |"), @dwEip
        mov edi,4H
        .while edi != 0
;            push ebx
;            mov bl,[esi]
;            ;int 3
;            invoke crt_printf, SADD("%0x") , bl
;            .if bl =='0'
;                mov bl,'.'
;            .endif
;            mov @aryHex,bl
;            invoke RtlZeroMemory, addr @MemoryData, type @MemoryData
;            invoke crt_strcat,addr @MemoryData,addr @aryHex
;            pop ebx
;            .IF edi == 1
;                invoke crt_printf, SADD(" %s"),addr @MemoryData
;            .endif
;            add esi,1H
;            dec edi;ѭ��һ�μ�һ

            push ebx
            mov ebx,[esi]
            mov @aryHex,ebx
            invoke crt_printf, SADD(" %08x"), @aryHex 

            mov edx,4H
            add @dwEip,edx
            add esi,4H
            dec edi;ѭ��һ�μ�һ
            pop ebx
        .endw
        
        invoke crt_printf, SADD(0dh, 0ah, 0)
        
        
        dec ebx;ѭ��һ�μ�һ
    .endw
    
    ret

PrintDD_Menory endp

;E����޸��ڴ�
AlterE_Menory proc dwAddr:DWORD,pMemData:DWORD
    LOCAL @pEnd:DWORD
    LOCAL @dwArg2:DWORD
    
    
    ;invoke crt_printf, SADD(" %08x  %s"), dwAddr , pMemData
    
    invoke crt_strtoul, pMemData, addr @pEnd, 16 ;ת16������ֵ
    mov edx, @pEnd
    mov esi, pMemData
    .if eax == 0 || esi == edx
        invoke crt_printf, SADD("��ֵ��������",0dh,0ah)
        ret
     .endif
     mov @dwArg2, eax
    ;----------------------------------------------------------------------------
    
    ;���ַ���д���ַ
    invoke WriteMemory, dwAddr, addr @dwArg2, type @dwArg2
    
    invoke crt_printf,SADD(0dh,0ah,0)
    ret

AlterE_Menory endp


;t�����������
ExcuteTCmd proc
    LOCAL @ctx:CONTEXT
    
    ;TF��λ
    invoke RtlZeroMemory, addr @ctx, type @ctx;��ջ���
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    or @ctx.regFlag, 100h;TFλת��
    invoke SetThreadContext,g_hThread, addr @ctx
    
    ;���ñ�־
    mov g_bIsStepCommand,TRUE

    ret

ExcuteTCmd endp

;p����ж������ǲ���call���ǵĻ��Ͳ��룬���ǵĻ��Ͳ���
ExcutePCmd proc
    LOCAL @ctx:CONTEXT
    
    ;�ж��Ƿ���callָ��
    mov esi, offset g_aryDisAsm
    .if byte ptr [esi] == 'c' && byte ptr [esi+1] == 'a' && byte ptr [esi+2] == 'l' && byte ptr [esi+3] == 'l'
    
        ;callָ�����һ��������ʱ�ϵ�
        mov ebx, g_dwEip
        add ebx, g_dwDisCodeLen ;call��һ��ָ��ĵ�ַ
        
        invoke SetBreakPoint,ebx,TRUE
        
    .elseif
        ;��callָ���t������ͬ
        invoke ExcuteTCmd
    .endif

    ret

ExcutePCmd endp

;����Ӳ���ϵ�
SetHardwareBp proc dwAddr:DWORD,BPLen:DWORD,BPType:DWORD
    LOCAL @ctx:CONTEXT
    
    ;TF��λ
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
    invoke GetThreadContext,g_hThread, addr @ctx
    
    
    ;����
    push dwAddr
    pop @ctx.iDr0
    
    ;and @ctx.iDr7, 0
    or @ctx.iDr7, 00000011b
    or @ctx.iDr7, 000f0000h
    
    invoke SetThreadContext,g_hThread, addr @ctx

    ret

SetHardwareBp endp

;�����ڴ�ϵ�
SetMemoryBp proc dwAddr:DWORD
    
    push dwAddr
    pop g_dwMemBpAddr
    
    ;�޸��ڴ�����
    invoke VirtualProtectEx,g_hProcess, g_dwMemBpAddr, 4, PAGE_NOACCESS, offset g_dwOldProtect

    ret

SetMemoryBp endp




;�������
ParseCommand proc uses esi
    LOCAL @dwStatus:DWORD
    LOCAL @pCmd:DWORD
    LOCAL @pEnd:DWORD
    LOCAL @Num:DWORD
    LOCAL @Memaddr[10h]:CHAR 
    LOCAL @MemData[100h]:CHAR 
    LOCAL @Memaddr2:DWORD
    
    invoke ShowDisAsm;��ʾһ�������
    
    mov @dwStatus, DBG_CONTINUE; ��ʾ�Ѵ����쳣������ִ�����쳣����
    
    
    .if g_bIsAutoStep ==TRUE && g_dwEip != 010124e1h
            mov g_bIsAutoStep, TRUE
            invoke ExcutePCmd
            mov eax, DBG_CONTINUE
            ret
    .else 
        mov g_bIsAutoStep, FALSE
    .endif

    ;����
    .while TRUE
        
        invoke RtlZeroMemory,addr g_szCmdBuf,sizeof g_szCmdBuf
        ;��ȡһ��
        invoke crt_gets, offset g_szCmdBuf
        
        ;��¼����
        .if byte ptr [esi] != 'e' && byte ptr [esi+1] != 's' && byte ptr [esi+2] == NULL 
            invoke crt_strcat,offset g_szExportScriptBuff,addr g_szCmdBuf
            invoke crt_strcat,offset g_szExportScriptBuff,SADD(0Ah)
        .endif
        
        
        
        ;��������ǰ��Ŀհ��ַ�
        invoke SkipWhiteChar,offset g_szCmdBuf
        mov @pCmd, eax
        
        ;�ж�����
        mov esi, @pCmd
        
        
        
        
        
        ;------------------һ��ϵ�------------------------------------------------------
        .if byte ptr [esi]=='b' && byte ptr [esi+1]=='p'
            add @pCmd, 2;����bp�ַ�
            mov esi, @pCmd
            
            .if byte ptr [esi] == 'l' ;��ʾ�ϵ��б�
                invoke ListBreakPoint
            
            .elseif byte ptr[esi] == 'c' ;����ϵ�
                inc @pCmd;����c�ַ�
                
                ;��������ǰ��Ŀհ��ַ�
                invoke SkipWhiteChar, @pCmd
                
                mov @pCmd, eax;�õ����
                ;����bpc�������
                invoke crt_strtoul, @pCmd, addr @pEnd, 10 ;ת10������ֵ
                mov @Num,eax
                invoke FindBreakPoint,@Num
                .if eax == FALSE
                    invoke crt_printf, offset g_szErrCmd
                    .continue
                .endif
                
                invoke DelBreakPoint,@Num;�ڶϵ�������ɾ��
                
                
            ;���öϵ� 
            .else      
                ;��������ǰ��Ŀհ��ַ�
                invoke SkipWhiteChar, @pCmd
                mov @pCmd, eax
                
                ;����bp�����ַ
                invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
                mov edx, @pEnd
                .if eax == 0 || @pCmd == edx
                    ;invoke crt_printf, offset g_szErrCmd
                    ;.continue
                .endif
                
                ;���öϵ�
                invoke SetBreakPoint, eax, FALSE
            
            .endif
            
        ;---------------------Ӳ���ϵ�---------------------------------------------------  
        .elseif byte ptr [esi]=='b' && byte ptr [esi+1]=='h';Ӳ���ϵ�
            add @pCmd, 2;����bp�ַ�
            
            
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;����bh�����ַ
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx
                invoke crt_printf, offset g_szErrCmd
                .continue
            .endif
            
            ;���öϵ�
            ;invoke SetHardwareBp, eax
        ;------------------�ڴ�ϵ�------------------------------------------------------    
        .elseif byte ptr [esi]=='b' && byte ptr [esi+1]=='m';�ڴ�ϵ�
            add @pCmd, 2;����bp�ַ�
            
            
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;����bm�����ַ
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx
                invoke crt_printf, offset g_szErrCmd
                .continue
            .endif
            
            ;���öϵ�
            invoke SetMemoryBp, eax
        ;-------------------��ʾ�Ĵ�������-----------------------------------------------------
        .elseif byte ptr [esi]=='r'
            
            add @pCmd, 1;����r�ַ�
            
            invoke PringtR_Disasm
            
        ;-------------------��ʾ�����-----------------------------------------------------
        .elseif byte ptr [esi]=='u'
            
            add @pCmd, 1;����u�ַ�
            
            ;��������ǰ��Ŀհ��ַ�
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;����u�����ַ
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx;u����û��ֵ
                invoke PrintUDisasm,NULL;ֱ����ʾ����ķ����
            .else
                invoke PrintUDisasm,eax;���ո����ĵ�ַ��ʾ����ķ����
            .endif
            
        ;------------------���г���------------------------------------------------------
        .elseif byte ptr [esi]=='g'
            
            
            add @pCmd, 1;����g�ַ�
            
            ;��������ǰ��Ŀհ��ַ�
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;����g�����ַ
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
            mov ebx,eax
            mov edx, @pEnd
            .if eax != 0 || @pCmd != edx;g������ֵ
                invoke SetBreakPoint,ebx,TRUE;��ʱ�ϵ㣬���Զ�ɾ��
                ;invoke DelBreakPoint2,ebx
                
            .endif
                mov eax, DBG_CONTINUE
                ret
        
        ;------------------��������------------------------------------------------------
        .elseif byte ptr [esi]=='t'
            invoke ExcuteTCmd
            ;invoke ShowDisAsm
            mov eax, DBG_CONTINUE
            ret
        ;-----------------��������-------------------------------------------------------
        .elseif byte ptr [esi]=='p'
            invoke ExcutePCmd
            mov eax, DBG_CONTINUE
            ret
        ;------------------------------------------------------------------------    
        .elseif byte ptr [esi] == 'T'
            mov g_bIsAutoStep, TRUE
            invoke ExcutePCmd
            mov eax, DBG_CONTINUE
            ret
        
        ;---------------����ű�---------------------------------------------------------    
        .elseif byte ptr [esi]=='l' && byte ptr [esi+1]=='s' 
            ;mov eax, DBG_CONTINUE
            ;ret
        ;---------------�����ű�---------------------------------------------------------    
        .elseif byte ptr [esi]=='e' && byte ptr [esi+1]=='s'     
            invoke DeriveES_Script  
        
        
        
        ;---------------��ʾ�ڴ�����---------------------------------------------------------    
        .elseif byte ptr [esi]=='d' && byte ptr [esi+1]=='d'
        
            add @pCmd, 2;����dd�ַ�
            
            ;��������ǰ��Ŀհ��ַ�
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;����dd�����ַ
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;ת16������ֵ
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx;dd����û��ֵ
                invoke PrintDD_Menory,NULL;ֱ����ʾ�ڴ�
            .else
                invoke PrintDD_Menory,eax;���ո����ĵ�ַ��ʾ�ڴ�
            .endif 
        ;-----------------�޸��ڴ�-------------------------------------------------------
        .elseif byte ptr [esi]=='e'
            add @pCmd, 1;����e�ַ�
            
            ;��������ǰ��Ŀհ��ַ�
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;��ȡ�޸ĵ�ַ
            invoke RtlZeroMemory, addr @Memaddr, type @Memaddr;��ջ���
            invoke crt_memcpy,addr @Memaddr,@pCmd ,8
            
            ;invoke crt_printf,SADD("%s",0dh,0ah,0), @pCmd
            
            add @pCmd,8;������ַ
            ;���Ҫ�޸ĵ�ֵ
            invoke RtlZeroMemory, addr @MemData, type @MemData;��ջ���
            invoke crt_strcpy,addr @MemData,@pCmd
            
            ;invoke crt_printf,SADD("%s   %s   ",0dh,0ah,0), addr @MemData, @pCmd
            
            ;����e�����ַ
            invoke crt_strtoul, addr @Memaddr, addr @pEnd, 16 ;ת16������ֵ
            mov @Memaddr2,eax;16���Ƶ�ַ
            lea edx, @Memaddr;�ַ����͵�ַ
            
            ;��Ҫ
            
            ;invoke crt_printf,SADD("%08x",0dh,0ah,0),@Memaddr2
            .if eax != 0 ||  @pEnd != edx;e����û��ֵ
                invoke AlterE_Menory,@Memaddr2,addr @MemData;���ո����ĵ�ַ�޸��ڴ�
            .else
                
                invoke crt_printf,SADD("��ַ���������׼��",0dh,0ah,0)
                ;invoke AlterE_Menory,NULL,NULL;ֱ����ʾ�ڴ�
            .endif 
        .else
            invoke crt_printf, offset g_szErrCmd;
        .endif
    .endw
    
    
    mov eax, @dwStatus
    ret

ParseCommand endp




end
