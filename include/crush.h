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
#include <standard.h>

/* I'm not MPlayer, I just crush a lot */
#define PROGNAM "crush"

/* set a default size for the payload buffer
 * if particular platforms can exceed this, then they should specify and
 * tweak the parameter within their module
 */
#define NSIZE 512

#define nelem(x) (int)(sizeof(x)/sizeof((x)[0]))

enum
Boolean
{
	False = 0,
	True
};

enum
Platform
{
	Platform_Linux,
	Platform_FreeBSD,
	Platform_OpenBSD,
	Platform_NetBSD,
	Platform_Dragonfly,
	Platform_Solaris,
	Platform_Windows,
	Platform_QNX,
	Platform_iOS,
	Platform_Android,
	Platform_Plan9
};

enum
Architecture
{
	Architecture_x86,
	Architecture_x86_64,
	Architecture_ARM,
	Architecture_ARM64,
	Architecture_PowerPC,
	Architecture_MIPS,
	Architecture_SPARC64,
	Architecture_AVR
};

typedef enum Boolean Boolean;
typedef enum Platform Platform;
typedef enum Architecture Architecture;

struct
Crushlet
{
	char const * const name;

	Platform platform;
	Architecture architecture;

	Boolean (*finalize)(void);
	Boolean (*initialize)(void);
	Boolean (*build)(unsigned char const *, int, unsigned char **, int * );
};

typedef struct Crushlet Crushlet;

#include <msg.h>
#include <talloc.h>
#include <payload.h>
#include <debugging.h>

