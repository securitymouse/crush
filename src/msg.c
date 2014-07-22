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
#include <crush.h>

static const char * m2s(Msg);

void
msg(Msg m, const char * f, ... )
{
	const char * s;
	va_list v;

	/* if we don't receive a type, the message isn't to be sent */
	s = m2s(m);
	if(!s)
		return;

	va_start(v, f);
	fprintf(stdout, "%s: %s", PROGNAM, s);
	vfprintf(stdout, f, v);
	fprintf(stdout, "\n");
	fflush(stdout);
	va_end(v);
}

void
error(Boolean t, const char * f, ... )
{
	char b[1024];
	va_list v;
	int e;

	/* don't let errno get clobbered */
	e = errno;

	fprintf(stderr, "error: ");

	va_start(v, f);
	vfprintf(stderr, f, v);
	va_end(v);

	/* print out a standard error if requested */
	if(t)
	{
		strerror_r(e, b, sizeof b);
		fprintf(stderr, ": %s", b);
	}

	fprintf(stderr, "\n");
}

static const char *
m2s(Msg m)
{
	if(m == MsgDebug)
	{
		if(!debugging())
			return NULL;
		return "debug: ";
	}
	else if(m == MsgError)
	{
		return "error: ";
	}
	else if(m == MsgVerbose)
	{
		return "";
	}
	else if(m == MsgWarning)
	{
		return "warning: ";
	}

	error(False, "invalid m2s %d", m);
	return NULL;
}

