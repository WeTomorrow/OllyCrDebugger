.386
.model flat, stdcall
option casemap:none

include ollycrdebugger.inc


public g_dwMemBpAddr 
public g_dwOldProtect

.data

    g_szCmdBuf db MAXBYTE dup(0)
    g_szErrCmd db "错误的命令", 0dh, 0ah, 0
    
    
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
    g_pTempImPortAddr dd 0 ; 执行导入脚本的个数
    
    
.code

;跳过空白字符
SkipWhiteChar proc uses edi pCommand:dword  
     mov edi,pCommand
     .while byte ptr[edi] == ' ' || byte ptr [edi] == 9 ;9是tab键
         add edi,1
     .endw
     mov eax,edi
     ret
SkipWhiteChar endp

;es命令，导出脚本
DeriveES_Script proc 
    LOCAL @szFilePath[MAX_PATH]:CHAR
    LOCAL @hFile:HANDLE
    
    ;初始化局部变量
    invoke RtlZeroMemory,addr @szFilePath, sizeof @szFilePath
    
    ;获取保存路径
    invoke SaveFilePath, addr @szFilePath
    invoke crt_strcat,addr @szFilePath, SADD(".txt")
    
    ;写入到文件
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


;显示反汇编
ShowDisAsm proc
    LOCAL @ctx:CONTEXT
    
    ;获取EIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop g_dwEip
    
    ;读取eip位置的机器码
    invoke ReadMemory,g_dwEip,offset g_aryCode, g_dwCodeLen
    
    ;反汇编;参数：机器码，机器码长度，eip，反汇编的缓冲区，反汇编对应的机器码，反汇编的机器码的长度
    invoke DisAsm, offset g_aryCode, g_dwCodeLen, g_dwEip, offset g_aryDisAsm, offset g_aryHex, offset g_dwDisCodeLen
    
    ;;显示到屏幕
    invoke crt_printf, offset g_szShowDisasmFmt, g_dwEip, offset g_aryHex, offset g_aryDisAsm

    ret

ShowDisAsm endp


;u命令，显示反汇编
PrintUDisasm proc UAddress:DWORD
    LOCAL @aryCode[MAXBYTE]:WORD 
    LOCAL @dwCodeLen:DWORD 
    LOCAL @dwEip:DWORD 
    LOCAL @aryDisAsm[MAXBYTE]:WORD 
    LOCAL @aryHex[MAXBYTE]:WORD 
    LOCAL @dwDisCodeLen:DWORD 
    
    LOCAL @ctx:CONTEXT
    
    ;获取EIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop @dwEip
    
    mov @dwCodeLen,80h
    
    ;判断U后面有没有跟地址
    .if UAddress ==NULL
        ;读取eip位置的机器码
        
        ;invoke crt_printf,SADD("u后面没有地址%x", 0dh, 0ah, 0),@dwEip
        invoke ReadMemory,@dwEip,addr @aryCode,@dwCodeLen
    .elseif UAddress !=NULL
        ;读取指定位置的机器码
        ;invoke crt_printf,SADD("u后面有地址%x", 0dh, 0ah, 0),UAddress
        invoke ReadMemory,UAddress,addr @aryCode,@dwCodeLen
        
        push UAddress
        pop @dwEip
    .endif
    
    lea esi,@aryCode;将读取到的机器码给esi
    mov ebx,8
    .while ebx != 0
        
        ;参数：      机器码，机器码长度，eip，反汇编的缓冲区，反汇编对应的机器码，反汇编的机器码的长度
        invoke DisAsm, esi,10h,@dwEip,addr @aryDisAsm,addr @aryHex,addr @dwDisCodeLen
    
        ;显示
        invoke crt_printf, offset g_szShowDisasmFmt, @dwEip, addr @aryHex, addr @aryDisAsm
        invoke RtlZeroMemory,addr @aryDisAsm,type @aryDisAsm
        
        add esi,@dwDisCodeLen
        mov edx,@dwDisCodeLen
        add @dwEip,edx
        
        dec ebx;循环一次减一
    .endw
    
    ret

PrintUDisasm endp

;r命令，显示寄存器环境
PringtR_Disasm proc uses esi
    
    LOCAL @ctx:CONTEXT
    
    ;获取寄存器环境
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("eax=%08x  ", 0),@ctx.regEax
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("ebx=%08x  ", 0),@ctx.regEbx
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("ecx=%08x  ", 0),@ctx.regEcx
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("edx=%08x  ", 0),@ctx.regEdx
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("esi=%08x  ", 0),@ctx.regEsi
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("edi=%08x  ", 0dh, 0ah, 0),@ctx.regEdi
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("eip=%08x  ", 0),@ctx.regEip
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("esp=%08x  ", 0),@ctx.regEsp
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("ebp=%08x      ", 0),@ctx.regEbp
    
    
    mov ebx,@ctx.regFlag;获取标志
     ;OF 在第11位
    .if ebx & 800h
        invoke crt_printf, SADD("OV ")
    .else 
        invoke crt_printf, SADD("NV ")
    .endif
    
    ;DF 在第10位
    .if ebx & 400h
        invoke crt_printf, SADD("DN ")
    .else    
        invoke crt_printf, SADD("UP ")
    .endif
    
     ;IF 在第9位
    .if ebx & 200h
        invoke crt_printf, SADD("EI ")
    .else    
        invoke crt_printf, SADD("DI ")
    .endif
    
    
     ;TF 在8位
    .if ebx & 100h
        invoke crt_printf, SADD("TF ")
    .else    
        invoke crt_printf, SADD("NF ")
    .endif
    
     ;SF 在第7位
    .if ebx & 80h
        invoke crt_printf, SADD("NG ")
    .else    
        invoke crt_printf, SADD("PL ")
    .endif
    
    
     ;ZF 在第6位
    .if ebx & 40h
        invoke crt_printf, SADD("ZR ")
    .else    
        invoke crt_printf, SADD("NZ ")
    .endif
    
     ;AF 在第4位
    .if ebx & 10h
        invoke crt_printf, SADD("AC ")
    .else    
        invoke crt_printf, SADD("NA ")
    .endif
    
     ;PF 在第2位
    .if ebx & 4h
        invoke crt_printf, SADD("PE ")
    .else    
        invoke crt_printf, SADD("PO ")
    .endif
    
     ;CF 在第0位
    .if ebx & 1h
        invoke crt_printf, SADD("CY ", 0dh, 0ah, 0)
    .else    
        invoke crt_printf, SADD("NC ", 0dh, 0ah, 0)
    .endif

    
    
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Cs=%04x  ", 0),@ctx.regCs
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Ss=%04x  ", 0),@ctx.regSs
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Ds=%04x  ", 0),@ctx.regDs
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Es=%04x  ", 0),@ctx.regEs
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Fs=%04x  ", 0),@ctx.regFs
    
    ;读取指定位置的机器码
    invoke crt_printf,SADD("Gs=%04x  ", 0dh, 0ah, 0),@ctx.regGs
    
    ;读取指定位置的机器码
    ;invoke crt_printf,SADD("Flag=%08x  ", 0dh, 0ah, 0),@ctx.regFlag
    
    
    
    
    ret
PringtR_Disasm endp

;dd命令，显示内存环境
PrintDD_Menory proc MenoryAddr:DWORD
    LOCAL @aryCode[MAXBYTE]:WORD 
    LOCAL @dwCodeLen:DWORD 
    LOCAL @dwEip:DWORD 
    LOCAL @aryDisAsm[MAXBYTE]:WORD 
    LOCAL @aryHex:DWORD 
    LOCAL @dwDisCodeLen:DWORD 
    LOCAL @MemoryData[MAXBYTE]:CHAR 
    LOCAL @ctx:CONTEXT
    
    ;获取EIP
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    push @ctx.regEip
    pop @dwEip
    
    mov @dwCodeLen,100h
    
    ;判断U后面有没有跟地址
    .if MenoryAddr ==NULL
        ;读取eip位置的机器码
        ;invoke crt_printf,SADD("u后面没有地址%x", 0dh, 0ah, 0),@dwEip
        invoke ReadMemory,@dwEip,addr @aryCode,@dwCodeLen
    .elseif MenoryAddr !=NULL
        ;读取指定位置的机器码
        invoke ReadMemory,MenoryAddr,addr @aryCode,@dwCodeLen
        
        push MenoryAddr
        pop @dwEip
    .endif
    
    lea esi,@aryCode;将读取到的机器码给esi
    mov ebx,8
    .while ebx != 0
        
        ;参数：      机器码，机器码长度，eip，反汇编的缓冲区，反汇编对应的机器码，反汇编的机器码的长度
        ;invoke DisAsm, esi,10h,@dwEip,addr @aryDisAsm,addr @aryHex,addr @dwDisCodeLen
        ;显示
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
;            dec edi;循环一次减一

            push ebx
            mov ebx,[esi]
            mov @aryHex,ebx
            invoke crt_printf, SADD(" %08x"), @aryHex 

            mov edx,4H
            add @dwEip,edx
            add esi,4H
            dec edi;循环一次减一
            pop ebx
        .endw
        
        invoke crt_printf, SADD(0dh, 0ah, 0)
        
        
        dec ebx;循环一次减一
    .endw
    
    ret

PrintDD_Menory endp

;E命令，修改内存
AlterE_Menory proc dwAddr:DWORD,pMemData:DWORD
    LOCAL @pEnd:DWORD
    LOCAL @dwArg2:DWORD
    
    
    ;invoke crt_printf, SADD(" %08x  %s"), dwAddr , pMemData
    
    invoke crt_strtoul, pMemData, addr @pEnd, 16 ;转16进制数值
    mov edx, @pEnd
    mov esi, pMemData
    .if eax == 0 || esi == edx
        invoke crt_printf, SADD("数值输入有误",0dh,0ah)
        ret
     .endif
     mov @dwArg2, eax
    ;----------------------------------------------------------------------------
    
    ;将字符串写入地址
    invoke WriteMemory, dwAddr, addr @dwArg2, type @dwArg2
    
    invoke crt_printf,SADD(0dh,0ah,0)
    ret

AlterE_Menory endp


;t命令，单步步过
ExcuteTCmd proc
    LOCAL @ctx:CONTEXT
    
    ;TF置位
    invoke RtlZeroMemory, addr @ctx, type @ctx;清空缓冲
    mov @ctx.ContextFlags, CONTEXT_FULL
    invoke GetThreadContext,g_hThread, addr @ctx
    or @ctx.regFlag, 100h;TF位转换
    invoke SetThreadContext,g_hThread, addr @ctx
    
    ;设置标志
    mov g_bIsStepCommand,TRUE

    ret

ExcuteTCmd endp

;p命令，判断命令是不是call，是的话就步入，不是的话就补过
ExcutePCmd proc
    LOCAL @ctx:CONTEXT
    
    ;判断是否是call指令
    mov esi, offset g_aryDisAsm
    .if byte ptr [esi] == 'c' && byte ptr [esi+1] == 'a' && byte ptr [esi+2] == 'l' && byte ptr [esi+3] == 'l'
    
        ;call指令，在下一行设置临时断点
        mov ebx, g_dwEip
        add ebx, g_dwDisCodeLen ;call下一条指令的地址
        
        invoke SetBreakPoint,ebx,TRUE
        
    .elseif
        ;非call指令，与t命令相同
        invoke ExcuteTCmd
    .endif

    ret

ExcutePCmd endp

;设置硬件断点
SetHardwareBp proc dwAddr:DWORD,BPLen:DWORD,BPType:DWORD
    LOCAL @ctx:CONTEXT
    
    ;TF置位
    invoke RtlZeroMemory, addr @ctx, type @ctx
    mov @ctx.ContextFlags, CONTEXT_FULL or CONTEXT_DEBUG_REGISTERS
    invoke GetThreadContext,g_hThread, addr @ctx
    
    
    ;设置
    push dwAddr
    pop @ctx.iDr0
    
    ;and @ctx.iDr7, 0
    or @ctx.iDr7, 00000011b
    or @ctx.iDr7, 000f0000h
    
    invoke SetThreadContext,g_hThread, addr @ctx

    ret

SetHardwareBp endp

;设置内存断点
SetMemoryBp proc dwAddr:DWORD
    
    push dwAddr
    pop g_dwMemBpAddr
    
    ;修改内存属性
    invoke VirtualProtectEx,g_hProcess, g_dwMemBpAddr, 4, PAGE_NOACCESS, offset g_dwOldProtect

    ret

SetMemoryBp endp




;命令处理函数
ParseCommand proc uses esi
    LOCAL @dwStatus:DWORD
    LOCAL @pCmd:DWORD
    LOCAL @pEnd:DWORD
    LOCAL @Num:DWORD
    LOCAL @Memaddr[10h]:CHAR 
    LOCAL @MemData[100h]:CHAR 
    LOCAL @Memaddr2:DWORD
    
    invoke ShowDisAsm;显示一条反汇编
    
    mov @dwStatus, DBG_CONTINUE; 表示已处理异常，继续执行在异常代码
    
    
    .if g_bIsAutoStep ==TRUE && g_dwEip != 010124e1h
            mov g_bIsAutoStep, TRUE
            invoke ExcutePCmd
            mov eax, DBG_CONTINUE
            ret
    .else 
        mov g_bIsAutoStep, FALSE
    .endif

    ;解析
    .while TRUE
        
        invoke RtlZeroMemory,addr g_szCmdBuf,sizeof g_szCmdBuf
        ;获取一行
        invoke crt_gets, offset g_szCmdBuf
        
        ;记录命令
        .if byte ptr [esi] != 'e' && byte ptr [esi+1] != 's' && byte ptr [esi+2] == NULL 
            invoke crt_strcat,offset g_szExportScriptBuff,addr g_szCmdBuf
            invoke crt_strcat,offset g_szExportScriptBuff,SADD(0Ah)
        .endif
        
        
        
        ;跳过命令前面的空白字符
        invoke SkipWhiteChar,offset g_szCmdBuf
        mov @pCmd, eax
        
        ;判断命令
        mov esi, @pCmd
        
        
        
        
        
        ;------------------一般断点------------------------------------------------------
        .if byte ptr [esi]=='b' && byte ptr [esi+1]=='p'
            add @pCmd, 2;跳过bp字符
            mov esi, @pCmd
            
            .if byte ptr [esi] == 'l' ;显示断点列表
                invoke ListBreakPoint
            
            .elseif byte ptr[esi] == 'c' ;清除断点
                inc @pCmd;跳过c字符
                
                ;跳过命令前面的空白字符
                invoke SkipWhiteChar, @pCmd
                
                mov @pCmd, eax;拿到编号
                ;解析bpc命令序号
                invoke crt_strtoul, @pCmd, addr @pEnd, 10 ;转10进制数值
                mov @Num,eax
                invoke FindBreakPoint,@Num
                .if eax == FALSE
                    invoke crt_printf, offset g_szErrCmd
                    .continue
                .endif
                
                invoke DelBreakPoint,@Num;在断点链表中删除
                
                
            ;设置断点 
            .else      
                ;跳过命令前面的空白字符
                invoke SkipWhiteChar, @pCmd
                mov @pCmd, eax
                
                ;解析bp命令地址
                invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
                mov edx, @pEnd
                .if eax == 0 || @pCmd == edx
                    ;invoke crt_printf, offset g_szErrCmd
                    ;.continue
                .endif
                
                ;设置断点
                invoke SetBreakPoint, eax, FALSE
            
            .endif
            
        ;---------------------硬件断点---------------------------------------------------  
        .elseif byte ptr [esi]=='b' && byte ptr [esi+1]=='h';硬件断点
            add @pCmd, 2;跳过bp字符
            
            
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;解析bh命令地址
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx
                invoke crt_printf, offset g_szErrCmd
                .continue
            .endif
            
            ;设置断点
            ;invoke SetHardwareBp, eax
        ;------------------内存断点------------------------------------------------------    
        .elseif byte ptr [esi]=='b' && byte ptr [esi+1]=='m';内存断点
            add @pCmd, 2;跳过bp字符
            
            
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;解析bm命令地址
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx
                invoke crt_printf, offset g_szErrCmd
                .continue
            .endif
            
            ;设置断点
            invoke SetMemoryBp, eax
        ;-------------------显示寄存器环境-----------------------------------------------------
        .elseif byte ptr [esi]=='r'
            
            add @pCmd, 1;跳过r字符
            
            invoke PringtR_Disasm
            
        ;-------------------显示反汇编-----------------------------------------------------
        .elseif byte ptr [esi]=='u'
            
            add @pCmd, 1;跳过u字符
            
            ;跳过命令前面的空白字符
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;解析u命令地址
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx;u后面没有值
                invoke PrintUDisasm,NULL;直接显示后面的反汇编
            .else
                invoke PrintUDisasm,eax;按照给出的地址显示后面的反汇编
            .endif
            
        ;------------------运行程序------------------------------------------------------
        .elseif byte ptr [esi]=='g'
            
            
            add @pCmd, 1;跳过g字符
            
            ;跳过命令前面的空白字符
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;解析g命令地址
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
            mov ebx,eax
            mov edx, @pEnd
            .if eax != 0 || @pCmd != edx;g后面有值
                invoke SetBreakPoint,ebx,TRUE;临时断点，会自动删除
                ;invoke DelBreakPoint2,ebx
                
            .endif
                mov eax, DBG_CONTINUE
                ret
        
        ;------------------单步步入------------------------------------------------------
        .elseif byte ptr [esi]=='t'
            invoke ExcuteTCmd
            ;invoke ShowDisAsm
            mov eax, DBG_CONTINUE
            ret
        ;-----------------单步步过-------------------------------------------------------
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
        
        ;---------------导入脚本---------------------------------------------------------    
        .elseif byte ptr [esi]=='l' && byte ptr [esi+1]=='s' 
            ;mov eax, DBG_CONTINUE
            ;ret
        ;---------------导出脚本---------------------------------------------------------    
        .elseif byte ptr [esi]=='e' && byte ptr [esi+1]=='s'     
            invoke DeriveES_Script  
        
        
        
        ;---------------显示内存数据---------------------------------------------------------    
        .elseif byte ptr [esi]=='d' && byte ptr [esi+1]=='d'
        
            add @pCmd, 2;跳过dd字符
            
            ;跳过命令前面的空白字符
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;解析dd命令地址
            invoke crt_strtoul, @pCmd, addr @pEnd, 16 ;转16进制数值
            mov edx, @pEnd
            .if eax == 0 || @pCmd == edx;dd后面没有值
                invoke PrintDD_Menory,NULL;直接显示内存
            .else
                invoke PrintDD_Menory,eax;按照给出的地址显示内存
            .endif 
        ;-----------------修改内存-------------------------------------------------------
        .elseif byte ptr [esi]=='e'
            add @pCmd, 1;跳过e字符
            
            ;跳过命令前面的空白字符
            invoke SkipWhiteChar, @pCmd
            mov @pCmd, eax
            
            ;获取修改地址
            invoke RtlZeroMemory, addr @Memaddr, type @Memaddr;清空缓冲
            invoke crt_memcpy,addr @Memaddr,@pCmd ,8
            
            ;invoke crt_printf,SADD("%s",0dh,0ah,0), @pCmd
            
            add @pCmd,8;跳过地址
            ;获得要修改的值
            invoke RtlZeroMemory, addr @MemData, type @MemData;清空缓冲
            invoke crt_strcpy,addr @MemData,@pCmd
            
            ;invoke crt_printf,SADD("%s   %s   ",0dh,0ah,0), addr @MemData, @pCmd
            
            ;解析e命令地址
            invoke crt_strtoul, addr @Memaddr, addr @pEnd, 16 ;转16进制数值
            mov @Memaddr2,eax;16进制地址
            lea edx, @Memaddr;字符串型地址
            
            ;将要
            
            ;invoke crt_printf,SADD("%08x",0dh,0ah,0),@Memaddr2
            .if eax != 0 ||  @pEnd != edx;e后面没有值
                invoke AlterE_Menory,@Memaddr2,addr @MemData;按照给出的地址修改内存
            .else
                
                invoke crt_printf,SADD("地址或参数不标准！",0dh,0ah,0)
                ;invoke AlterE_Menory,NULL,NULL;直接显示内存
            .endif 
        .else
            invoke crt_printf, offset g_szErrCmd;
        .endif
    .endw
    
    
    mov eax, @dwStatus
    ret

ParseCommand endp




end
