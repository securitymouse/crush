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

Crushlet * 
payloads[NPAYLOADS] =
{
	&debian_7_0_0_x86,
	&debian_7_0_0_x86_64,
	&freebsd_9_1_amd64,
	&opensuse_12_3_x86_64,
	&ubuntu_12_04_2_x86,
	&ubuntu_12_04_2_x86_64
};

