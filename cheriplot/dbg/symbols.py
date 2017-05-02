#-
# Copyright (c) 2016-2017 Alfredo Mazzinghi
# All rights reserved.
#
# This software was developed by SRI International and the University of
# Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
# ("CTSRD"), as part of the DARPA CRASH research programme.
#
# @BERI_LICENSE_HEADER_START@
#
# Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  BERI licenses this
# file to you under the BERI Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.beri-open-systems.org/legal/license-1-0.txt
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @BERI_LICENSE_HEADER_END@
#

import logging
import os

from sortedcontainers import SortedDict
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)

class SymReader:
    """
    Helper class that looks for symbols in multiple binaries given
    a memory map where they are loaded and an address.
    """

    def __init__(self, vmmap, path):
        """
        """

        self.vmmap = vmmap
        """Memory map used to locate the start address of sections."""

        self.paths = path
        """Search paths for binaries that contain symbols."""

        self.files = SortedDict()
        """
        Map memory base address to the ELFFile that provided the 
        section mapped at that address.
        """

        self._load_mapped()

    def _load_mapped(self):
        """
        Load the binary files for each vnode-backed vmmap region.
        """
        for vme in self.vmmap.get_model():
            fname = os.path.basename(vme.path)
            if not fname:
                continue
            logger.debug("looking for %s", fname)
            for path in self.paths:
                bin_file = os.path.join(path, fname)
                if os.path.exists(bin_file):
                    logger.debug("Found symbols for %s (%s)", fname, bin_file)
                    break
            else:
                continue
            # is the file already been opened?
            for found in self.files.values():
                _, base, elf, symtab = found
                if elf.stream.name == bin_file:
                    self.files[vme.start] = (vme.end, base, elf, symtab)
                    break
            else:
                elf_file = ELFFile(open(bin_file, "rb"))
                symtab = elf_file.get_section_by_name(".symtab")
                if symtab is None:
                    logger.debug("No symbol table for file %s, skipping",
                                 elffile.stream.name)
                    continue
                self.files[vme.start] = (vme.end, vme.start, elf_file, symtab)

    def find_file(self, addr):
        """
        Find the file where the symbol at the given address is defined.        
        """
        idx = self.files.bisect(addr)
        match = idx - 1

        if match < 0:
            return None
        key = self.files.iloc[match]
        if len(self.files) and self.files[key][0] >= addr:
            base, elf_file, symtab = self.files[key][1:4]
            return (base, elf_file, symtab)

    def find_symbol(self, addr):
        """
        Return the symbol and file where the address is found,
        if possible.
        """
        match = self.find_file(addr)
        if match is None:
            return None
        base, elf_file, symtab = match
        for sym in symtab:
            if sym["st_value"] + base == addr:
                return sym.name
        return None

    def find_function(self, addr):
        """
        Return the symbol and file of the function containing the
        given address, if possible.
        
        XXX useless
        """
        match = self.find_file(addr)
        if match is None:
            return None
        base, elf_file, symtab = match
        fn_sym = None
        for sym in symtab:
            if sym["st_value"] + base <= addr:
                if not fn_sym or fn_sym["st_value"] < sym["st_value"]:
                    fn_sym = sym
        return None
