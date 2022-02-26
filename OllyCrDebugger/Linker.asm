.586
.model flat,stdcall
option casemap:none

include Linker.inc

.code

;函数功能添加新节点
;参数：头结点，新来的节点，新来节点的大小
;返回值：新的头结点
PushBack proc  pHead:ptr Node, pUserData:LPVOID, dwDataSize:DWORD
    LOCAL @pNewNode:ptr Node
    
    ;创建新节点
    invoke crt_malloc, sizeof Node
    mov @pNewNode, eax;将申请的堆的指针给了pNewNode

    ;为用户数据申请内存
    invoke crt_malloc, dwDataSize
    mov esi, @pNewNode;将堆的地址给了esi
    assume esi:ptr Node
    mov [esi].m_pUserData, eax;在Node堆的基础上给m_pUserData也给一个堆的地址指针
    
    ;存储用户数据
    invoke crt_memcpy, [esi].m_pUserData, pUserData, dwDataSize
    
    ;链接新节点，把头节点接到新节点的下一个
    push pHead
    pop [esi].m_pNext
    
    assume esi:nothing

    mov eax, @pNewNode;返回新节点
    ret
PushBack endp

;作用：FindNode的回调函数，用来作比较
;返回值：找到返回true,没找到返回false
;pfnCompare proc uses edx ebx

;	.if edx == ebx
;		mov eax,TRUE 
;	.else
;		mov eax,FALSE 
;	.endif
;	ret
;pfnCompare endp


;返回值：返回找到的节点
FindNode proc uses esi  pHead:ptr Node, pfnCompare:DWORD, pData:DWORD

    mov esi, pHead;获取到头结点
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

;作用：删除节点
;参数：头节点，要删除的节点
;返回值：新的头节点
DeleteNode proc uses esi   pHead:ptr Node, pNodeToDel :ptr Node
    LOCAL @pNewHead:ptr Node
   
    mov esi, pHead
    assume esi:ptr Node
    
    ;存储新的头结点
    mov eax, [esi].m_pNext
    mov @pNewHead, eax;将头节点的下一个节点给pNewHead
   
 
    mov eax, pNodeToDel
    assume eax:ptr Node
    
    ;交换数据（将头节点的数据跟要删除的节点的数据交换）
    push [eax].m_pUserData
    push [esi].m_pUserData
    pop [eax].m_pUserData
    pop [esi].m_pUserData
    

    ;删除内存
    mov eax, pHead
    invoke crt_free, [eax].m_pUserData
    invoke crt_free, pHead
    assume eax:nothing
    assume esi:nothing

    mov eax, @pNewHead
    ret
DeleteNode endp

;作用:释放所有节点
;参数:头节点
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