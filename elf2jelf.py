#!/user/bin/env python3

'''
Converts an ELF file to a JELF file for The ESP32 Jolt

ELF File Structure that esp-idf creates:
+--------------+
| ELF Header   |
+--------------+
| Section 1    |
+--------------+
| Section 2    |
+--------------+
|   . . .      |
+--------------+

The Section Header Table is a Section like any other
   * Theres a pointer to the Section Header Table Section in the ELF Header.
'''

__author__  = 'Brian Pugh'
__email__   = 'bnp117@gmail.com'
__version__ = '0.0.1'
__status__  = 'development'

import argparse
import os, sys
import logging
from collections import OrderedDict, namedtuple
import bitstruct as bs
from common_structs import index_strtab

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from elf32_structs import \
        Elf32_Ehdr, Elf32_Shdr, Elf32_Sym, Elf32_Rela, \
        Elf32_SHT_RELA, Elf32_SHT_NOBITS, \
        Elf32_SHF_ALLOC, Elf32_SHF_EXECINSTR

from jelf_structs import \
        Jelf_Ehdr, Jelf_Shdr, Jelf_Sym, Jelf_Rela, \
        Jelf_SHT_OTHER, Jelf_SHT_RELA, Jelf_SHT_NOBITS, \
        Jelf_SHF_ALLOC, Jelf_SHF_EXECINSTR


# Debugging Utilities
import ipdb as pdb

_JELF_MAJOR_VERSION = 0
_JELF_MINOR_VERSION = 1

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_elf', type=str,
            help='Input ELF32 file to convert')
    parser.add_argument('--output', '-o', type=str, default=None,
            help='''
                Output Filename. Defaults to same as input name with a JELF
                extension''')
    parser.add_argument('--coin', '-c', type=str, default=None,
            help='''
            Coin Derivation (2 integers); for example "44'/165'"
                 ''')
    parser.add_argument('--verbose', '-v', type=str, default='INFO',
            help='''
            Valid options:
            SILENT
            INFO
            DEBUG
            ''')
    args = parser.parse_args()
    dargs = vars(args)
    return (args, dargs)

def validate_esp32_ehdr(ehdr: namedtuple):
    '''
    Some sanity checks in what the produced elf header should be
    '''
    assert(ehdr.e_ident == '\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    assert(ehdr.e_machine == 94)

def main():
    args, dargs = parse_args()

    ######################
    # Instantiate Logger #
    ######################
    log = logging.getLogger('elf2jelf')
    logging_level = args.verbose.upper()
    if logging_level == 'SILENT':
        pass
    elif logging_level == 'INFO':
        log.setLevel(logging.INFO)
    elif logging_level == 'DEBUG':
        log.setLevel(logging.DEBUG)
    else:
        raise("Invalid Logging Verbosity")

    ####################
    # Read In ELF File #
    ####################
    log.info("Reading in %s" % args.input_elf)
    with open(args.input_elf, 'rb') as f:
        # Reads in the binary contents to an object of type 'bytes'
        # A 'bytes' object shares many properties with a conventional string
        elf_contents = f.read()
    log.info("Read in %d bytes" % len(elf_contents))

    #####################
    # Unpack ELF Header #
    #####################
    assert( Elf32_Ehdr.size_bytes() == 52 )
    ehdr = Elf32_Ehdr.unpack(elf_contents[0:])
    validate_esp32_ehdr(ehdr)
    log.debug("Number of Sections: %d" % ehdr.e_shnum)
    log.debug("SectionHeader Offset: %d" % ehdr.e_shoff)

    ##########################################
    # Read SectionHeaderTable Section Header #
    ##########################################
    assert( Elf32_Shdr.size_bytes() == 40 )
    offset = ehdr.e_shoff + ehdr.e_shstrndx * Elf32_Shdr.size_bytes()
    shstrtab_shdr = Elf32_Shdr.unpack(elf_contents[offset:])
    # Read the actual SectionHeaderTable
    shstrtab = elf_contents[shstrtab_shdr.sh_offset:
            shstrtab_shdr.sh_offset+shstrtab_shdr.sh_size]
    # for some reason, this is incorrect
    shstrtab_name = index_strtab(shstrtab, shstrtab_shdr.sh_name)
    assert( shstrtab_name == b'.shstrtab' )

    ####################
    # Read The .strtab #
    ####################

    ################################
    # Iterate Through All Sections #
    ################################
    Jelf_Ehdr.size_bytes()

    elf32_shdrs = []
    elf32_symtab_index = None
    elf32_strtab_index = None
    for i in range(0, ehdr.e_shnum):
        offset = ehdr.e_shoff + i * Elf32_Shdr.size_bytes()
        elf32_shdrs.append( Elf32_Shdr.unpack(elf_contents[offset:]) )
        shdr_name = index_strtab(shstrtab, elf32_shdrs[-1].sh_name)
        if( shdr_name == '.symtab' ):
            elf32_symtab_index = i
        elif( shdr_name == '.strtab' ):
            elf32_strtab_index = i

    # Convert all sections to JELF equivalents
    jelf_shdrs_bytes = []
    for i, elf32_shdr in enumerate(elf32_shdrs):
        jelf_shdr_d = OrderedDict()

        # Convert the "sh_type" field
        if elf32_shdr.sh_type == Elf32_SHT_RELA:
            jelf_shdr_d['sh_type'] = Jelf_SHT_RELA
        elif elf32_shdr.sh_type == Elf32_SHT_NOBITS:
            jelf_shdr_d['sh_type'] = Jelf_SHT_NOBITS
        else:
            jelf_shdr_d['sh_type'] = Jelf_SHT_OTHER

        # Convert the "sh_flag" field
        jelf_shdr_d['sh_flags'] = 0
        if elf32_shdr.sh_flags & Elf32_SHF_ALLOC:
            jelf_shdr_d['sh_flags'] |= Jelf_SHF_ALLOC
        if elf32_shdr.sh_flags & Elf32_SHF_EXECINSTR:
            jelf_shdr_d['sh_flags'] |= Jelf_SHF_EXECINSTR

        # Todo:
        #    * Update Offset to new value
        if elf32_shdr.sh_offset > 2**19:
            raise("Overflow Detected")
        else:
            jelf_shdr_d['sh_offset']    = elf32_shdr.sh_offset

        if elf32_shdr.sh_size > 2**19:
            raise("Overflow Detected")
        else:
            jelf_shdr_d['sh_size']      = elf32_shdr.sh_size

        if elf32_shdr.sh_info > 2**14:
            raise("Overflow Detected")
        else:
            jelf_shdr_d['sh_info']      = elf32_shdr.sh_info

        jelf_shdrs_bytes.append( Jelf_Shdr.pack( *(jelf_shdr_d.values()) ) )

    pdb.set_trace()


    ##############################
    # Create the new JELF Header #
    ##############################
    log.info("Complete!")

if __name__=='__main__':
    main()
