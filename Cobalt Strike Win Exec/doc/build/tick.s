.intel_syntax noprefix

.global cpu_clock
.type cpu_clock, @function

cpu_clock:
	rdtsc
	shl rdx, 32
	or rax, rdx
	ret
