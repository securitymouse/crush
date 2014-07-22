#
# Copyright (C) 2014 Lab Mouse Security
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

include ../Makefile.conf
BIN=crush
FILES=\
	payloads.o\
	debian_7.0.0_x86.o\
	debian_7.0.0_x86_64.o\
	freebsd_9.1_amd64.o\
	opensuse_12.3_x86_64.o\
	ubuntu_12.04.2_x86.o\
	ubuntu_12.04.2_x86_64.o

all: $(FILES) 

$(FILES):
	$(CC) -c -o $@ $(@:%.o=%.c) $(CFLAGS) 

$(BIN):
	$(CC) -o $@ ./*.o ../payload/*.o $(CFLAGS) $(LFLAGS)

clean:
	$(RM) -f ./*.o $(BIN) 

