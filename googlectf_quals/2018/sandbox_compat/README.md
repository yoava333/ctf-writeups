# Sandbox Compat - Google CTF qualifiers 2018 

Category: pwn
Points: 420

I participated in Google CTF qualifications with 5BC, we drew first blood on this 
challenge. I really enjoyed working on it and it was a satisfying solution.

## Introduction

The challenge, as the name implies, is a sandbox escape. The idea behind the 
sandbox is really cool - our code lies in a 32-bit memory space and the "kernel" 
runs outside the 32-bit range. 

Ok... that doesn't sound so hard. Let's dive into the details. 

The sandbox setup is as follows:
The challenge binary is 64-bit, the sandbox code allocates static addresses for
user stack (0xbeef0000) and code (0xdead0000). It also creates a new _LDT_ entry for 32-bit code:

```c
  struct user_desc desc;

  // ...

  memset(&desc, 0, sizeof(desc));
  desc.entry_number = 1;
  desc.base_addr = 0;
  desc.limit = (1L << 32) - 1;
  desc.seg_32bit = 1;
  desc.contents = 2;
  desc.read_exec_only = 0;
  desc.limit_in_pages = 1;
  desc.seg_not_present = 0;
  desc.useable = 1;

  if (modify_ldt(1, &desc, sizeof(desc)) != 0)
    err(1, "failed to setup 32-bit segment");
```

For those of you who aren't familiar with [_LDT_](https://wiki.osdev.org/LDT)'s, they are a processor feature from the days of 8086 that are responsible for setup and usage of segment selectors (_cs_,_ds_,_fs_,_gs_,...).
Today they are mostly used to inter-op between 32-bit code and 64-bit, and
jumping from 32 to 64 is as simple as `jmp 33:0x13371337'deadbeef`.

The sandbox will accept user code, filter all opcodes that allow changing the 
_cs_ to 64-bit:

```C
static struct opcode { char *name; char opcode; } opcodes[] = {
  { "iret",          0xcf },
  { "far jmp",       0xea },
  { "far call",      0x9a },
  { "far ret",       0xca },
  { "far ret",       0xcb },
  { "far jmp/call",  0xff },
  { NULL,            0x00 },
};

// ...

  /* ensure that there are no forbidden instructions */
  for (opcode = opcodes; opcode->name != NULL; opcode++) {
    if (memchr(code, opcode->opcode, size) != NULL)
      errx(1, "opcode %s is not allowed", opcode->name);
  }
```

There's also the mandatory _seccomp_ filter, which allows some syscalls but 
forbids running them from the 32bit address space:

```C
  struct sock_filter filter[] = {
    /* No syscalls allowed if instruction pointer is lower than 4G.
     * That should not be necessary, but better be safe. */
    VALIDATE_IP,
    /* Grab the system call number. */
    EXAMINE_SYSCALL,
    /* List allowed syscalls. */
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(write),
    ALLOW_SYSCALL(open),
    ALLOW_SYSCALL(close),
    ALLOW_SYSCALL(mprotect),
    ALLOW_SYSCALL(exit_group),
    KILL_PROCESS,
  };
```

The sandbox also has a "kernel" component running outside the 32-bit memory range.
It executes a few syscalls on your behalf, but first validates that: 
* Pointers passed to the "kernel" are in user space (in 32-bit memory)
* Path for open doesn't contain the word "flag"

How can we communicate with the kernel if we can't use syscalls? 
The sandbox allocates two pages, one in the last address of 32-bit memory (0xfffff000) and next page (0x1'00000000). The code in the last page of the 32-bit memory will switch to 64-bit code and continue to slide into 64-bit memory space: 

```asm
BITS 32

	;; small gadget to restore esp and return to caller
	jmp	trampoline
	mov	esp, ebx
	ret	

	;; trampoline to 64-bit code
	;; there is a NOP at 0xffffffff, followed by kernel entry
trampoline:
	jmp	dword 0x33:0xffffffff
```

In the next page the code switches the stack to kernel stack and jumps to 
the "kernel" syscall handler, which is in the main binary of the sandbox.

The challenge authors were really nice and provided an example of using their
"kernel":

```asm
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Sample 32-bit user code that writes "hello\n" to stdout.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	BITS 32

	mov	esp, 0xbef00000
	sub	esp, 4

	push	0x00000a6f
	push	0x6c6c6568

	;; kernel arguments
	mov	edi, 1		; __NR_write
	mov	esi, 1		; fd
	mov	edx, esp	; buf
	mov	ecx, 6		; size

	;; jmp to trampoline 64-bit kernel
	;; not straightforward because of restricted characters
	mov	eax, 0xdead0000 + done
	push	eax

	xor	eax, eax	;; mov  eax, 0xfffff000
	dec	eax
	shl	eax, 12

	push	eax
	ret

done:
	int	3

```

So the goal of this task is to read the flag from disk, but we are "stuck" in 
32-bit memory and can't execute any syscalls.

# Failed attempts
Before coming up with the solution we had many failed attempts.

We thought that maybe the stack address of the kernel will magically fall within
32-bit memory address (it could happen due to ASLR) - but there's a check for it 
and the sandbox will not start.

We tried to modify the _LDT_ back - it didn't work because of the syscall filter.

Syscall numbers in 32/64-bit have different numbers and if an interesting
syscall is blocked in 64-bit maybe it's not blocked in 32-bits and vice versa.
Unfortunately it doesn't work because of the _IP_ address filter.

We thought about jumping to the kernel code (in the last page) and see if there are interesting opcodes there that can change cs, but we couldn't find any.

We had a crazy idea of jumping to the last 32-bit byte and see what happens - we hoped that we might slide to 64 bit code - but it just wrapped around.

We looked in the Intel manuals for opcodes that might change the _cs_ that are
not filtered, but we couldn't find any.

# The bug

While auditing the "kernel" we found that the _open_ syscall uses _memcpy_ to copy a user buffer safely to the kernel stack.

```C
int path_ok(char *pathname, const char *p)
{
  if (!access_ok(p, MAX_PATH))
    return 0;

  memcpy(pathname, p, MAX_PATH);
  pathname[MAX_PATH - 1] = '\x00';

  if (strstr(pathname, "flag") != NULL)
    return 0;

  return 1;
}

static int op_open(const char *p)
{
  // buffer on "kernel" stack
  char pathname[MAX_PATH];

  if (!path_ok(pathname, p))
    return -1;

  return syscall(__NR_open, pathname, O_RDONLY);
}
```

This code is perfectly fine if the assumptions of the compiler are correct, e.g.
that this code is run from the executable and no other code runs before it and
changed the state of the world.

I opened the code in IDA and saw that the _memcpy_ function was reduced to 
`rep movsq` opcode. The `movsq` opcode is quite complex, enough that it has a
[pseudo code](https://c9x.me/x86/html/file_module_x86_id_203.html) describing it's operation.

As you can see from the code, it uses the direction flag to determine the
direction of the copy, so we can set the direction flag such that the `rep movsq` will copy _backward_!

The kernel code doesn't sanitize the _eflags_ register from user's code and uses it as is.
Which means we can make _memcpy_ corrupt the stack backwards, which is usually not interesting but in this challenge the buffer is passed from an outer function `op_open` to an inner function `path_ok` so we can overflow our return address!

The rest of the [exploit](ex.S) is simple, return to our code open the flag file, 
read it and write it _stdout_.

We run it and we get the flag:
`CTF{Hell0_N4Cl_Issue_51!}`

If you're interested, [_NACL_ issue #51](https://bugs.chromium.org/p/nativeclient/issues/detail?id=51) is the exact same bug!

