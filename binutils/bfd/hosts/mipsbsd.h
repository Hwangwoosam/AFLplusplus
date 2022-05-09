/* Copyright (C) 2007-2022 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include <machine/param.h>
#include <machine/vmparam.h>
#undef ALIGN

#define	HOST_PAGE_SIZE		NBPG
/* #define	HOST_SEGMENT_SIZE	NBPG -- we use HOST_DATA_START_ADDR */
#define	HOST_MACHINE_ARCH	bfd_arch_mips
/* #define	HOST_MACHINE_MACHINE	 */

#define	HOST_TEXT_START_ADDR		USRTEXT
#define	HOST_STACK_END_ADDR		USRSTACK
#define NO_CORE_COMMAND
