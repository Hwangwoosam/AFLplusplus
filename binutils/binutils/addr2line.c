/* addr2line.c -- convert addresses to line number and function name
   Copyright (C) 1997-2022 Free Software Foundation, Inc.
   Contributed by Ulrich Lauther <Ulrich.Lauther@mchp.siemens.de>

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


/* Derived from objdump.c and nm.c by Ulrich.Lauther@mchp.siemens.de

   Usage:
   addr2line [options] addr addr ...
   or
   addr2line [options]

   both forms write results to stdout, the second form reads addresses
   to be converted from stdin.  */

#include "sysdep.h"
#include "bfd.h"
#include "getopt.h"
#include "libiberty.h"
#include "demangle.h"
#include "bucomm.h"
#include "elf-bfd.h"
#include "safe-ctype.h"
#include "addr2line.h"

static bool unwind_inlines;	/* -i, unwind inlined functions. */
static bool with_addresses;	/* -a, show addresses.  */
static bool with_functions = true;	/* -f, show function names.  */
static bool do_demangle;	/* -C, demangle names.  */
static bool pretty_print;	/* -p, print on one line.  */
static bool base_names;		/* -s, strip directory names.  */

/* Flags passed to the name demangler.  */
static int demangle_flags = DMGL_PARAMS | DMGL_ANSI;

static int naddr;		/* Number of addresses to process.  */
static char *addr;		/* Hex addresses to process.  */

static long symcount;
static asymbol **syms;		/* Symbol table.  */
const char *name;
char ret_value[40] = {0,};

static void slurp_symtab (bfd *);
static void find_address_in_section (bfd *, asection *, void *);
static void find_offset_in_section (bfd *, asection *);
static void translate_addresses (bfd *, asection *);

/* Print a usage message to STREAM and exit with STATUS.  */


/* Read in the symbol table.  */

static void
slurp_symtab (bfd *abfd)
{
  long storage;
  bool dynamic = false;

  if ((bfd_get_file_flags (abfd) & HAS_SYMS) == 0)
    return;

  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage == 0)
    {
      storage = bfd_get_dynamic_symtab_upper_bound (abfd);
      dynamic = true;
    }
  if (storage < 0)
    bfd_fatal (bfd_get_filename (abfd));

  syms = (asymbol **) xmalloc (storage);
  if (dynamic)
    symcount = bfd_canonicalize_dynamic_symtab (abfd, syms);
  else
    symcount = bfd_canonicalize_symtab (abfd, syms);
  if (symcount < 0)
    bfd_fatal (bfd_get_filename (abfd));

  /* If there are no symbols left after canonicalization and
     we have not tried the dynamic symbols then give them a go.  */
  if (symcount == 0
      && ! dynamic
      && (storage = bfd_get_dynamic_symtab_upper_bound (abfd)) > 0)
    {
      free (syms);
      syms = xmalloc (storage);
      symcount = bfd_canonicalize_dynamic_symtab (abfd, syms);
    }

  /* PR 17512: file: 2a1d3b5b.
     Do not pretend that we have some symbols when we don't.  */
  if (symcount <= 0)
    {
      free (syms);
      syms = NULL;
    }
}

/* These global variables are used to pass information between
   translate_addresses and find_address_in_section.  */

static bfd_vma pc;
static const char *filename;
static const char *functionname;
static unsigned int line;
static unsigned int discriminator;
static bool found;

/* Look for an address in a section.  This is called via
   bfd_map_over_sections.  */

static void
find_address_in_section (bfd *abfd, asection *section,
			 void *data ATTRIBUTE_UNUSED)
{
  bfd_vma vma;
  bfd_size_type size;

  if (found)
    return;

  if ((bfd_section_flags (section) & SEC_ALLOC) == 0)
    return;

  vma = bfd_section_vma (section);
  if (pc < vma)
    return;

  size = bfd_section_size (section);
  if (pc >= vma + size)
    return;

  found = bfd_find_nearest_line_discriminator (abfd, section, syms, pc - vma,
                                               &filename, &functionname,
                                               &line, &discriminator);
}

/* Look for an offset in a section.  This is directly called.  */

static void
find_offset_in_section (bfd *abfd, asection *section)
{
  bfd_size_type size;

  if (found)
    return;

  if ((bfd_section_flags (section) & SEC_ALLOC) == 0)
    return;

  size = bfd_section_size (section);
  if (pc >= size)
    return;

  found = bfd_find_nearest_line_discriminator (abfd, section, syms, pc,
                                               &filename, &functionname,
                                               &line, &discriminator);
}

/* Lookup a symbol with offset in symbol table.  */

static bfd_vma
lookup_symbol (bfd *abfd, char *sym, size_t offset)
{
  long i;

  for (i = 0; i < symcount; i++)
    {
      if (!strcmp (syms[i]->name, sym))
	return syms[i]->value + offset + bfd_asymbol_section (syms[i])->vma;
    }
  /* Try again mangled */
  for (i = 0; i < symcount; i++)
    {
      char *d = bfd_demangle (abfd, syms[i]->name, demangle_flags);
      bool match = d && !strcmp (d, sym);
      free (d);

      if (match)
	return syms[i]->value + offset + bfd_asymbol_section (syms[i])->vma;
    }
  return 0;
}

/* Split an symbol+offset expression. adr is modified.  */

static bool
is_symbol (char *adr, char **symp, size_t *offset)
{
  char *end;

  while (ISSPACE (*adr))
    adr++;
  if (ISDIGIT (*adr) || *adr == 0)
    return false;
  /* Could be either symbol or hex number. Check if it has +.  */
  if (TOUPPER(*adr) >= 'A' && TOUPPER(*adr) <= 'F' && !strchr (adr, '+'))
    return false;

  *symp = adr;
  while (*adr && !ISSPACE (*adr) && *adr != '+')
    adr++;
  end = adr;
  while (ISSPACE (*adr))
    adr++;
  *offset = 0;
  if (*adr == '+')
    {
      adr++;
      *offset = strtoul(adr, NULL, 0);
    }
  *end = 0;
  return true;
}

/* Read hexadecimal or symbolic with offset addresses from stdin, translate into
   file_name:line_number and optionally function name.  */

static void
translate_addresses (bfd *abfd, asection *section)
{
  // int read_stdin = (naddr == 0);
  char *adr;
  // char addr_hex[100];
  char *symp;
  size_t offset;

  for (;;)
    {
  
	  if (naddr <= 0){
	    break;
    }

	  --naddr;
	  adr = addr;

      if (is_symbol (adr, &symp, &offset))
        pc = lookup_symbol (abfd, symp, offset);
      else
        pc = bfd_scan_vma (adr, NULL, 16);
      if (bfd_get_flavour (abfd) == bfd_target_elf_flavour)
	{
	  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
	  bfd_vma sign = (bfd_vma) 1 << (bed->s->arch_size - 1);

	  pc &= (sign << 1) - 1;
	  if (bed->sign_extend_vma)
	    pc = (pc ^ sign) - sign;
	}

      if (with_addresses)
        {
          // printf ("0x");
          bfd_printf_vma (abfd, pc);

          if (pretty_print){
            // printf (": ");
          }else{}
            // printf ("\n");
        }

      found = false;
      if (section)
	find_offset_in_section (abfd, section);
      else
	bfd_map_over_sections (abfd, find_address_in_section, NULL);

      if (! found)
	{
	  if (with_functions)
	    {
	      if (pretty_print){
		// printf ("?? ");
        }else{}
		// printf ("??\n");
	    }
	  // printf ("??:0\n");
	}
      else
	{
	  while (1)
            {
              if (with_functions)
                {
                  // const char *name;
                  char *alloc = NULL;

                  name = functionname;
                  if (name == NULL || *name == '\0')
                    name = "??";
                  else if (do_demangle)
                    {
                      alloc = bfd_demangle (abfd, name, demangle_flags);
                      if (alloc != NULL)
                        name = alloc;
                    }
                  
                  // printf ("name: %s", name);
                  if (pretty_print){
		    /* Note for translators:  This printf is used to join the
		       function name just printed above to the line number/
		       file name pair that is about to be printed below.  Eg:

		         foo at 123:bar.c  */
                    // printf (_(" at "));
                  }else{}
                    // printf ("\n");

		  free (alloc);
                }

              if (base_names && filename != NULL)
                {
                  char *h;

                  h = strrchr (filename, '/');
                  if (h != NULL)
                    filename = h + 1;
                }

              // printf ("%s:", filename ? filename : "??");
	      if (line != 0)
                {
                  if (discriminator != 0){}
                    // printf ("%u (discriminator %u)\n", line, discriminator);
                  else{}
                    // printf ("%u\n", line);
                }
	      else{}
		// printf ("?\n");
              if (!unwind_inlines)
                found = false;
              else
                found = bfd_find_inliner_info (abfd, &filename, &functionname,
					       &line);
              if (! found)
                break;
              if (pretty_print){}
		/* Note for translators: This printf is used to join the
		   line number/file name pair that has just been printed with
		   the line number/file name pair that is going to be printed
		   by the next iteration of the while loop.  Eg:

		     123:bar.c (inlined by) 456:main.c  */
                // printf (_(" (inlined by) "));
            }
	}

      /* fflush() is essential for using this command as a server
         child process that reads addresses from a pipe and responds
         with line number information, processing one address at a
         time.  */
      fflush (stdout);
    }
}

/* Process a file.  Returns an exit value for main().  */

static int
process_file (const char *file_name, const char *section_name,
	      const char *target)
{
  bfd *abfd;
  asection *section;
  char **matching;

  if (get_file_size (file_name) < 1)
    return 1;

  abfd = bfd_openr (file_name, target);
  if (abfd == NULL)
    bfd_fatal (file_name);

  /* Decompress sections.  */
  abfd->flags |= BFD_DECOMPRESS;

  if (bfd_check_format (abfd, bfd_archive))
    fatal (_("%s: cannot get addresses from archive"), file_name);

  if (! bfd_check_format_matches (abfd, bfd_object, &matching))
    {
      bfd_nonfatal (bfd_get_filename (abfd));
      if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
	{
	  list_matching_formats (matching);
	  free (matching);
	}
      xexit (1);
    }

  if (section_name != NULL)
    {
      section = bfd_get_section_by_name (abfd, section_name);
      if (section == NULL)
	fatal (_("%s: cannot find section %s"), file_name, section_name);
    }
  else
    section = NULL;

  slurp_symtab (abfd);

  translate_addresses (abfd, section);

  free (syms);
  syms = NULL;

  bfd_close (abfd);

  return 0;
}

int addr2line (char* file_name, char *argv, char* f_name)
{

  const char *section_name;
  char *target;

#ifdef HAVE_LC_MESSAGES
  setlocale (LC_MESSAGES, "");
#endif
  setlocale (LC_CTYPE, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  // program_name = *argv;
  // xmalloc_set_program_name (program_name);
  // bfd_set_error_program_name (program_name);

  if (bfd_init () != BFD_INIT_MAGIC)
    fatal (_("fatal error: libbfd ABI mismatch"));
  set_default_bfd_target ();

  // file_name = NULL;
  section_name = NULL;
  target = NULL;

  if (file_name == NULL)
    file_name = "a.out";

  addr = argv;
  naddr = 1;
  process_file (file_name, section_name, target);

  strcpy(f_name,name);
  // printf("name: %s\n",f_name);
  return 0;
}
