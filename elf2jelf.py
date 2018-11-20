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

Assumes symtab is at the end (ignoring strtab and shstrtab)

Todo:
    * Generate Signature
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
import math

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from elf32_structs import \
        Elf32_Ehdr, Elf32_Shdr, Elf32_Sym, Elf32_Rela, \
        Elf32_SHT_RELA, Elf32_SHT_NOBITS, \
        Elf32_SHF_ALLOC, Elf32_SHF_EXECINSTR, \
        Elf32_R_XTENSA_NONE, Elf32_R_XTENSA_32, \
        Elf32_R_XTENSA_ASM_EXPAND, Elf32_R_XTENSA_SLOT0_OP
from jelf_structs import \
        Jelf_Ehdr, Jelf_Shdr, Jelf_Sym, Jelf_Rela, \
        Jelf_SHT_OTHER, Jelf_SHT_RELA, Jelf_SHT_NOBITS, \
        Jelf_SHF_ALLOC, Jelf_SHF_EXECINSTR, \
        Jelf_R_XTENSA_NONE, Jelf_R_XTENSA_32, \
        Jelf_R_XTENSA_ASM_EXPAND, Jelf_R_XTENSA_SLOT0_OP

# Debugging Utilities
import ipdb as pdb

HARDEN = 0x80000000

def align(x, base=4):
    return int( base * math.ceil(float(x)/base))

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
            Coin Derivation (2 integers); for example "44'/165'. Note: you must wrap the argument in double quotes to be properly parsed."
                 ''')
    parser.add_argument('--bip32key', type=str, default='bitcoin_seed',
            help='''
                BIP32 Derivation Seed String Key
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

    ##################################
    # Read in the JoltOS Export List #
    ##################################
    with open('export_list.txt', 'r') as f:
        version_header = f.readline().rstrip()
        version_name, version_str = version_header.split(' ')
        assert(version_name == 'VERSION')
        _JELF_VERSION_MAJOR, _JELF_VERSION_MINOR = version_str.split('.')
        _JELF_VERSION_MAJOR = int(_JELF_VERSION_MAJOR)
        _JELF_VERSION_MINOR = int(_JELF_VERSION_MINOR)
        export_list = [line.rstrip() for line in f]

    ###################################
    # Generate jolt_lib.h export list #
    ###################################
    with open('export_list.h', 'w') as f:
        f.write('''_JELF_VERSION_MAJOR = %d;\n''' % _JELF_VERSION_MAJOR)
        f.write('''_JELF_VERSION_MINOR = %d;\n\n''' % _JELF_VERSION_MINOR)
        f.write('''#define EXPORT_SYMBOL(x) &x\n\n''')
        f.write('''static void *exports[] = {\n''')

        for f_name in export_list:
            f.write('''    EXPORT_SYMBOL( %s ),\n''' % f_name)
        f.write('''};\n''')

    ####################
    # Read In ELF File #
    ####################
    log.info("Reading in %s" % args.input_elf)
    with open(args.input_elf, 'rb') as f:
        # Reads in the binary contents to an object of type 'bytes'
        # A 'bytes' object shares many properties with a conventional string
        elf_contents = f.read()
    log.info("Read in %d bytes" % len(elf_contents))

    # Allocate space for JELF contents, this is larger than necessary
    jelf_contents = bytearray(len(elf_contents))

    #####################
    # Unpack ELF Header #
    #####################
    assert( Elf32_Ehdr.size_bytes() == 52 )
    ehdr = Elf32_Ehdr.unpack(elf_contents[0:])
    jelf_ehdr_shnum = ehdr.e_shnum
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
    del(offset)

    ################################
    # Iterate Through All Sections #
    ################################
    Jelf_Ehdr.size_bytes()

    elf32_shdrs = []
    elf32_shdr_names = []
    elf32_symtab = None
    elf32_symtab_shdr = None
    elf32_strtab = None
    elf32_strtab_shdr = None
    for i in range(ehdr.e_shnum):
        # The Shdr Table is wayyyyyy at the end
        offset = ehdr.e_shoff + i * Elf32_Shdr.size_bytes()
        elf32_shdr = Elf32_Shdr.unpack(elf_contents[offset:])
        del(offset)
        shdr_name = index_strtab(shstrtab, elf32_shdr.sh_name)
        log.debug("Read in Section Header %d. %s " % (i, shdr_name))
        if( shdr_name == b'.symtab' ):
            elf32_symtab_shdr = elf32_shdr
            elf32_symtab = elf_contents[elf32_symtab_shdr.sh_offset:
                    elf32_symtab_shdr.sh_offset+elf32_symtab_shdr.sh_size]
        elif( shdr_name == b'.strtab' ):
            elf32_strtab_shdr = elf32_shdr
            elf32_strtab = elf_contents[elf32_strtab_shdr.sh_offset:
                    elf32_strtab_shdr.sh_offset+elf32_strtab_shdr.sh_size]
        elf32_shdrs.append( elf32_shdr )
        elf32_shdr_names.append(shdr_name)

    # Convert ALL section headers to JELF equivalents
    jelf_shdrs = []
    elf32_offsets = []
    elf32_sizes = []
    for i, elf32_shdr in enumerate(elf32_shdrs):
        # shdr_name = elf32_shdr_names[i]
        shdr_name = index_strtab(shstrtab, elf32_shdr.sh_name)
        log.debug( "Processing Sector %d. %s" % (i, shdr_name) )
        log.debug( "Data Offset: %d" % elf32_shdr.sh_offset )
        elf32_offsets.append(elf32_shdr.sh_offset)
        log.debug( "Data Size: %d" % elf32_shdr.sh_size )
        elf32_sizes.append(elf32_shdr.sh_size)
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

        jelf_shdr_d['sh_offset']    = elf32_shdr.sh_offset # This is a placeholder and will be updated later

        if elf32_shdr.sh_size > 2**19:
            raise("Overflow Detected")
        else:
            # for symtab, this will be updated later
            # All other sections maintain the same size
            jelf_shdr_d['sh_size']      = elf32_shdr.sh_size

        if elf32_shdr.sh_info > 2**14:
            raise("Overflow Detected")
        else:
            jelf_shdr_d['sh_info']      = elf32_shdr.sh_info

        jelf_shdrs.append(jelf_shdr_d)

    ###########################################################
    # Sort the offsets to improve locality caching on loading #
    ###########################################################
    elf32_offsets, elf32_sizes, elf32_shdr_names, jelf_shdrs = (
            list(t) for t in zip(*sorted(zip(
        elf32_offsets, elf32_sizes, elf32_shdr_names, jelf_shdrs))))

    ###########################################
    # Convert the ELF32 symtab to JELF Format #
    ###########################################
    # Revisit this later, do we need all these symbols?
    elf32_sym_size = Elf32_Sym.size_bytes()
    jelf_sym_size = Jelf_Sym.size_bytes()
    symtab_nent = int(len(elf32_symtab)/elf32_sym_size)
    jelf_symtab = bytearray(symtab_nent * jelf_sym_size)
    for i in range(symtab_nent):
        begin = i * elf32_sym_size
        end = begin + elf32_sym_size
        elf32_symbol = Elf32_Sym.unpack(elf32_symtab[begin:end])

        # Lookup Symbol name in exported function list
        sym_name = index_strtab(elf32_strtab, elf32_symbol.st_name).decode('ascii')
        if sym_name == '':
            # 0 means no name
            jelf_name_index = 0;
            log.debug("Symbol index %d has no name %d." % \
                    (i, elf32_symbol.st_name))
        else:
            try:
                # Plus one because 0 means no name
                jelf_name_index = export_list.index(sym_name) + 1
                if elf32_symbol.st_info == b'\x12':
                    #print("FOUNDFOUNDFOUNDFOUND")
                    pass
            except ValueError:
                #pdb.set_trace()
                jelf_name_index=0
                if elf32_symbol.st_info != b'\x12':
                    pass
                    #print("%d %s" % (i, sym_name))
                    #print(elf32_symbol)
                #raise("Could not find %s in export_list" % sym_name)

        begin = i * jelf_sym_size
        end = begin + jelf_sym_size
        jelf_symtab[begin:end] = Jelf_Sym.pack(
                jelf_name_index,
                elf32_symbol.st_shndx,
                elf32_symbol.st_value,
                )
        if sym_name == "app_main":
            #todo; this may not be the most correct
            jelf_ehdr_entrypoint = i
        '''
        log.debug("%d - 0x%04x 0x%04X 0x%08X" %
                ( i,
                jelf_name_index,
                elf32_symbol.st_shndx,
                elf32_symbol.st_value,
                    ))
        '''

    #########################################
    # Convert the ELF32 RELA to JELF Format #
    #########################################
    jelf_relas = {}
    for i in range(len(jelf_shdrs)):
        if jelf_shdrs[i]['sh_type'] != Jelf_SHT_RELA:
            continue

        n_relas = int(jelf_shdrs[i]['sh_size'] / Elf32_Rela.size_bytes())
        jelf_shdrs[i]['sh_size'] = n_relas * Jelf_Rela.size_bytes()
        jelf_sec_relas = bytearray(jelf_shdrs[i]['sh_size'])
        for j in range(n_relas):
            elf32_offset = jelf_shdrs[i]['sh_offset'] + j * Elf32_Rela.size_bytes()
            jelf_offset  = j * Jelf_Rela.size_bytes()
            rela = Elf32_Rela.unpack(elf_contents[elf32_offset:])

            elf32_r_type = rela.r_info & 0xFF
            jelf_r_info = (rela.r_info & ~0xFF) >> 6

            if rela.r_offset > 2**16:
                pdb.set_trace()
                raise("Overflow Detected")
            if jelf_r_info > 2**16:
                pdb.set_trace()
                raise("Overflow Detected")
            if rela.r_addend > 2**16:
                pdb.set_trace()
                raise("Overflow Detected")

            if elf32_r_type == Elf32_R_XTENSA_NONE:
                jelf_r_info |= Jelf_R_XTENSA_NONE
            elif elf32_r_type == Elf32_R_XTENSA_32:
                jelf_r_info |= Jelf_R_XTENSA_32
            elif elf32_r_type == Elf32_R_XTENSA_ASM_EXPAND:
                jelf_r_info |= Jelf_R_XTENSA_ASM_EXPAND
            elif elf32_r_type == Elf32_R_XTENSA_SLOT0_OP:
                jelf_r_info |= Jelf_R_XTENSA_SLOT0_OP
            else:
                log.error("Failed on %d %s" % (i, elf32_shdr_names[i]))
                pdb.set_trace()
                raise("Unexpected RELA Type")

            jelf_sec_relas[jelf_offset:jelf_offset+Jelf_Rela.size_bytes()] = \
                    Jelf_Rela.pack(rela.r_offset, jelf_r_info, rela.r_addend)
        jelf_relas[i] = jelf_sec_relas

    #######################
    # Write JELF Sections #
    #######################
    # Skip the JELF Header for now
    jelf_ptr = Jelf_Ehdr.size_bytes()
    for i, name in enumerate(elf32_shdr_names):
        jelf_shdrs[i]['sh_offset'] = jelf_ptr
        if name == b'.symtab':
            # Copy over our updated Jelf symtab
            jelf_shdrs[i]['sh_size'] = len(jelf_symtab)
            new_jelf_ptr = jelf_ptr + jelf_shdrs[i]['sh_size']
            jelf_contents[jelf_ptr:new_jelf_ptr] = jelf_symtab
        elif name == b'.strtab':
            # Dont copy over strtab since we're stripping it
            jelf_ehdr_shnum -= 1
            continue
        elif name == b'.shstrtab':
            # Dont copy over shstrtab since we're stripping it
            jelf_ehdr_shnum -= 1
            continue
        elif jelf_shdrs[i]['sh_type'] == Jelf_SHT_RELA:
            new_jelf_ptr = jelf_ptr + jelf_shdrs[i]['sh_size']
            jelf_contents[jelf_ptr:new_jelf_ptr] = jelf_relas[i]

        else:
            new_jelf_ptr = jelf_ptr + jelf_shdrs[i]['sh_size']
            jelf_contents[jelf_ptr:new_jelf_ptr] = \
                    elf_contents[
                            jelf_shdrs[i]['sh_offset']:
                            jelf_shdrs[i]['sh_offset']+jelf_shdrs[i]['sh_size']
                            ]
        if jelf_shdrs[i]['sh_offset'] > 2**19:
            raise("Overflow Detected")
        jelf_ptr = new_jelf_ptr

    ##################################################
    # Write Section Header Table to end of JELF File #
    ##################################################
    jelf_shdrtbl = jelf_ptr
    log.info("SectionHeaderTable Offset: 0x%08X" % jelf_shdrtbl)
    for i, jelf_shdr in enumerate(jelf_shdrs):
        new_jelf_ptr = jelf_ptr + Jelf_Shdr.size_bytes()
        jelf_contents[jelf_ptr:new_jelf_ptr] = \
                Jelf_Shdr.pack( *(jelf_shdr.values()) )
        jelf_ptr = new_jelf_ptr

    ##################################
    # Trim Jelf Binary to final size #
    ##################################
    jelf_contents = jelf_contents[:jelf_ptr]
    log.info("Jelf Final Size: %d" % len(jelf_contents))

    ###########################
    # Parse Coin CLI Argument #
    ###########################
    if args.coin is None:
        raise("must specify coin derivation path")
    purpose_str, coin_str = args.coin.split('/')
    # Check for harden specifier
    if purpose_str[-1] == "'":
        purpose = int(purpose_str[:-1])
        purpose |= HARDEN
    else:
        purpose = int(purpose_str)
    log.info("Coin Purpose: 0x%08X" % purpose)
    if purpose_str[-1] == "'":
        coin = int(coin_str[:-1])
        coin |= HARDEN
    else:
        coin = int(coin_str)
    log.info("Coin Path: 0x%08X" % coin)

    if len(args.bip32key) >= 32:
        raise("BIP32Key too long!")

    #####################
    # Write JELF Header #
    #####################
    jelf_ehdr_d = OrderedDict()
    jelf_ehdr_d['e_ident']          = '\x7fJELF\x00'
    jelf_ehdr_d['e_version_major']  = _JELF_VERSION_MAJOR
    jelf_ehdr_d['e_version_minor']  = _JELF_VERSION_MINOR
    jelf_ehdr_d['e_entry_offset']   = jelf_ehdr_entrypoint # todo: refine
    jelf_ehdr_d['e_shnum']          = jelf_ehdr_shnum
    jelf_ehdr_d['e_shoff']          = jelf_shdrtbl
    jelf_ehdr_d['e_coin_purpose']   = purpose
    jelf_ehdr_d['e_coin_path']      = coin
    jelf_ehdr_d['e_bip32key']       = args.bip32key
    jelf_ehdr_d['e_signature']      = b'\x00'*32           # Placeholder
    jelf_contents[:Jelf_Ehdr.size_bytes()] = Jelf_Ehdr.pack(
            *jelf_ehdr_d.values() )

    ######################
    # Generate Signature #
    ######################
    # todo

    #############################
    # Write JELF binary to file #
    #############################
    if args.output is None:
        path_bn, ext = os.path.splitext(args.input_elf)
        output_fn = path_bn + '.jelf'
    else:
        output_fn = args.output
    with open(output_fn, 'wb') as f:
        f.write(jelf_contents)

    log.info("Complete!")

if __name__=='__main__':
    main()
