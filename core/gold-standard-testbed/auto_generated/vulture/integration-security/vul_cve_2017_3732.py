# Vulnerable: VUL-CVE-2017-3732
.align	32
.L8x_tail_done:
	add	(%rdx),%r8		# can this overflow?
	adc	\$0,%r9
...
	adc	\$0,%r13
	adc	\$0,%r14
	adc	\$0,%r15		# can't overflow, because we
					# started with "overhung" part
					# of multiplication
	xor	%rax,%rax
...
	adc	%rax,%rax		# top-most carry

	mov	32+8(%rsp),%rbx		# n0
