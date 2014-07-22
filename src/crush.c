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

static char * target;
static char * infile;
static char * outfile;
static int payload = -1;

static void list(void);
static void usage(void);
static Boolean gettarget(void);
static Boolean run(int, char *[]);
static Boolean arguments(int, char *[]);
static Boolean putdata(unsigned char *, int);
static Boolean getinput(unsigned char **, int * );

int
main(int argc, char * argv[])
{
	return run(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE ;
}

static void
usage(void)
{
	fprintf(stderr, "usage: crush [-l|-h] [-i infile] <-t targetfile | -p id> -o outfile\n");
	exit(EXIT_SUCCESS);
}

static Boolean
run(int argc, char * argv[])
{
	unsigned char * output;
	unsigned char * input;
	Crushlet * c;
	int noutput;
	int ninput;
	int r;

	if(!arguments(argc, argv))
	{
		return False;
	}

	if(!gettarget())
	{
		return False;
	}

	if(!getinput(&input, &ninput))
	{
		return False;
	}

	c = payloads[payload];
	msg(MsgVerbose, "building payload from module %d: \"%s\"", payload, c->name);

	if(c->initialize)
		c->initialize();

	noutput = 0;
	output = NULL;

	r = c->build(input, ninput, &output, &noutput);
	if(!r)
		error(False, "unable to build payload");
	else
		if(!(r = putdata(output, noutput)))
			error(False, "unable to write out data to %s", outfile);

	if(input)
		free(input);
	if(output)
		free(output);

	return r;
}

static Boolean
arguments(int argc, char * argv[])
{
	int i;
	int r;

	for(i = 1; i < argc; i++)
	{
		if(strcmp(argv[i], "-h") == 0)
		{
			usage();
			/* not reached */
			return False;
		}
		else if(strcmp(argv[i], "-l") == 0)
		{
			list();
			/* not reached */
			return False;
		}
		else if(strcmp(argv[i], "-i") == 0)
		{
			if(i == (argc - 1))
			{
				error(False, "option -%c needs an argument", 'i');
				return False;
			}
			infile = argv[++i];
		}
		else if(strcmp(argv[i], "-o") == 0)
		{
			if(i == (argc - 1))
			{
				error(False, "option -%c needs an argument", 'o');
				return False;
			}
			outfile = argv[++i];
		}
		else if(strcmp(argv[i], "-p") == 0)
		{
			if(i == (argc - 1))
			{
				error(False, "option -%c needs an argument", 'p');
				return False;
			}

			payload = strtoul(argv[++i], NULL, 0);
			if(payload < 0 || payload >= nelem(payloads))
			{
				error(False, "payload %d not found", payload);
				return False;
			}
		}
		else if(strcmp(argv[i], "-t") == 0)
		{
			if(i == (argc - 1))
			{
				error(False, "option -%c needs an argument", 't');
				return False;
			}
			target = argv[++i];
		}
	}

	r = True;
	if(!outfile)
	{
		error(False, "outfile not defined");
		r = False;
	}

	if(payload < 0 && !target)
	{
		error(False, "payload id not defined");
		r = False;
	}

	return r;
}

static Boolean
gettarget(void)
{
	struct stat s;
	char * b;
	int i;
	int f;

	if(!target)
		return True;

	f = open(target, O_RDONLY);
	if(f < 0)
	{
		error(True, "unable to open target file %s", target);
		return False;
	}

	fstat(f, &s);
	if(s.st_size <= 0)
	{
		error(True, "empty target file");
		close(f);
		return False;
	}

	b = calloc(1, s.st_size);
	if(read(f, b, s.st_size) != s.st_size)
	{
		error(True, "unable to read entire target file");
		close(f);
		free(b);
		return False;
	}

	if(b[s.st_size-1] == '\n')
		b[s.st_size-1] = 0;

	close(f);

	for(i = 0; i < nelem(payloads); i++)
	{
		if(strcasecmp(payloads[i]->name, b) != 0)
		{
			continue;
		}

		msg(MsgVerbose, "found requested payload: %d/%s", i, b);
		payload = i;
		break;
	}

	free(b);
	return payload > -1;
}

static void
list(void)
{
	Crushlet * c;
	int i;

	for(i = 0; i < nelem(payloads); i++)
	{
		fprintf(stderr, "id[%d]: %s\n", i, payloads[i]->name);
	}

	exit(EXIT_SUCCESS);
}

static Boolean
getinput(unsigned char ** input, int * ninput)
{
	unsigned char * b;
	struct stat s;
	int f;

	if(!infile)
	{
		*input = NULL;
		*ninput = 0;
		return True;
	}

	f = open(infile, O_RDONLY);
	if(f < 0)
	{
		error(True, "unable to open or access file %s", infile);
		return False;
	}

	if(fstat(f, &s) < 0)
	{
		error(True, "unable to obtain the file status for %s", infile);
		return False;
	}

	b = calloc(1, s.st_size);
	if(!b)
	{
		error(True, "can't allocate buffer to read %ld bytes from %s", s.st_size, infile);
		return False;
	}

	if(read(f, b, s.st_size) != s.st_size)
	{
		error(True, "couldn't read %ld bytes from %s", s.st_size, infile);
		free(b);
		return False;
	}

	close(f);

	*ninput = s.st_size;
	*input = b;

	return True;
}

static Boolean
putdata(unsigned char * output, int noutput)
{
	int f;
	int r;

	f = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(f < 0)
	{
		error(True, "unable to open %s for writing", outfile);
		return False;
	}

	r = write(f, output, noutput) == noutput;
	if(!r)
		error(True, "unable to write %d bytes to %s", noutput, outfile);
	close(f);

	return r;
}

