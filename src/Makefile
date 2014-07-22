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
	msg.o\
	debugging.o\
	crush.o

all: $(FILES) $(BIN)

$(FILES):
	$(CC) -c -o $@ $(@:%.o=%.c) $(CFLAGS) 

$(BIN):
	$(CC) -o $@ ./*.o ../payloads/*.o $(CFLAGS) $(LFLAGS)

clean:
	$(RM) -f ./*.o $(BIN) 

