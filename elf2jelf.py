#!/user/bin/env python3

'''
Converts an ELF file to a JELF file for The ESP32 Jolt
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

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

from elf32_structs import \
        Elf32_Ehdr, Elf32_Shdr, Elf32_Sym, Elf32_Rela

# Debugging Utilities
import ipdb as pdb

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_elf', type=str,
            help='Input ELF32 file to convert')
    parser.add_argument('--output', '-o', type=str, default=None,
            help='''
                Output Filename. Defaults to same as input name with a JELF
                extension''')
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
        elf_content = f.read()
    log.info("Read in %d bytes" % len(elf_content))

    #####################
    # Unpack ELF Header #
    #####################
    ehdr = Elf32_Ehdr.unpack(elf_content[0:])
    pdb.set_trace()
    validate_esp32_ehdr(ehdr)

    log.info("Complete!")

if __name__=='__main__':
    main()
