

include windows.inc
include user32.inc
include kernel32.inc
include msvcrt.inc

includelib user32.lib
includelib kernel32.lib
includelib msvcrt.lib


Node struc
    m_pNext dd 0
    m_pUserData LPVOID 0
Node ends


PushBack proto  pHead:ptr Node, pUserData:LPVOID, dwDataSize:DWORD

FindNode proto  pHead:ptr Node, pfnCompare:DWORD, pData:DWORD

DeleteNode proto pHead:ptr Node, pNodeToDel :ptr Node

FreeList proto pHead:ptr Node