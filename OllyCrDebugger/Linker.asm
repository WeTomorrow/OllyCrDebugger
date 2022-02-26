.586
.model flat,stdcall
option casemap:none

include Linker.inc

.code

;������������½ڵ�
;������ͷ��㣬�����Ľڵ㣬�����ڵ�Ĵ�С
;����ֵ���µ�ͷ���
PushBack proc  pHead:ptr Node, pUserData:LPVOID, dwDataSize:DWORD
    LOCAL @pNewNode:ptr Node
    
    ;�����½ڵ�
    invoke crt_malloc, sizeof Node
    mov @pNewNode, eax;������Ķѵ�ָ�����pNewNode

    ;Ϊ�û����������ڴ�
    invoke crt_malloc, dwDataSize
    mov esi, @pNewNode;���ѵĵ�ַ����esi
    assume esi:ptr Node
    mov [esi].m_pUserData, eax;��Node�ѵĻ����ϸ�m_pUserDataҲ��һ���ѵĵ�ַָ��
    
    ;�洢�û�����
    invoke crt_memcpy, [esi].m_pUserData, pUserData, dwDataSize
    
    ;�����½ڵ㣬��ͷ�ڵ�ӵ��½ڵ����һ��
    push pHead
    pop [esi].m_pNext
    
    assume esi:nothing

    mov eax, @pNewNode;�����½ڵ�
    ret
PushBack endp

;���ã�FindNode�Ļص��������������Ƚ�
;����ֵ���ҵ�����true,û�ҵ�����false
;pfnCompare proc uses edx ebx

;	.if edx == ebx
;		mov eax,TRUE 
;	.else
;		mov eax,FALSE 
;	.endif
;	ret
;pfnCompare endp


;����ֵ�������ҵ��Ľڵ�
FindNode proc uses esi  pHead:ptr Node, pfnCompare:DWORD, pData:DWORD

    mov esi, pHead;��ȡ��ͷ���
    assume esi:ptr Node
    .while esi != NULL
        
        push pData
        push [esi].m_pUserData
        call pfnCompare
        .if eax == TRUE
            mov eax, esi
            ret
        .endif
        
        
        mov esi, [esi].m_pNext
    .endw
    assume esi:nothing
    
    xor eax, eax
    ret 
FindNode endp

;���ã�ɾ���ڵ�
;������ͷ�ڵ㣬Ҫɾ���Ľڵ�
;����ֵ���µ�ͷ�ڵ�
DeleteNode proc uses esi   pHead:ptr Node, pNodeToDel :ptr Node
    LOCAL @pNewHead:ptr Node
   
    mov esi, pHead
    assume esi:ptr Node
    
    ;�洢�µ�ͷ���
    mov eax, [esi].m_pNext
    mov @pNewHead, eax;��ͷ�ڵ����һ���ڵ��pNewHead
   
 
    mov eax, pNodeToDel
    assume eax:ptr Node
    
    ;�������ݣ���ͷ�ڵ�����ݸ�Ҫɾ���Ľڵ�����ݽ�����
    push [eax].m_pUserData
    push [esi].m_pUserData
    pop [eax].m_pUserData
    pop [esi].m_pUserData
    

    ;ɾ���ڴ�
    mov eax, pHead
    invoke crt_free, [eax].m_pUserData
    invoke crt_free, pHead
    assume eax:nothing
    assume esi:nothing

    mov eax, @pNewHead
    ret
DeleteNode endp

;����:�ͷ����нڵ�
;����:ͷ�ڵ�
FreeList proc uses esi pHead:ptr Node
    
    mov esi, pHead
    assume esi:ptr Node
    
    .while esi != NULL
        invoke DeleteNode, esi, esi
        mov esi, eax
    .endw
    
    assume esi:nothing
    
    xor eax, eax
    ret
FreeList endp

end