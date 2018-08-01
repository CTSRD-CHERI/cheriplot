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
import io
import numpy as np

from sortedcontainers import SortedDict
from elftools.elf.elffile import ELFFile

from cheriplot.core import ProgressTimer

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

        self._symbol_map = SortedDict()
        """Internal mapping of address to symbol name"""

        self.loaded = []
        """List of loaded executables"""

        with ProgressTimer("Load symbols", logger):
            self._load_mapped()
            logger.debug("Symbol map %s", self)

    def _find_elf(self, vme_path):
        fname = os.path.basename(vme_path)
        if not fname:
            return None
        logger.debug("looking for %s", fname)
        for path in self.paths:
            bin_file = os.path.join(path, fname)
            if os.path.exists(bin_file):
                logger.info("Found symbols for %s (%s)", fname, bin_file)
                return bin_file
        logger.debug("No ELF found for %s", bin_file)
        return None

    def map_base(self, vme_path):
        """
        Find the base address where this file has been mapped
        in the vmmap
        """
        lower_addr = np.inf
        for vme in self.vmmap.get_model():
            if vme.path == vme_path and vme.start < lower_addr:
                lower_addr = vme.start
        return lower_addr

    def _load_mapped(self):
        for vme in self.vmmap.get_model():
            bin_file = self._find_elf(vme.path)
            if bin_file is None or bin_file in self.loaded:
                # is the file already been loaded?
                continue

            self.loaded.append(bin_file)
            elf_file = ELFFile(open(bin_file, "rb"))
            symtab = elf_file.get_section_by_name(".symtab")

            # do we need to relocate the addresses?
            if elf_file.header["e_type"] == "ET_DYN":
                map_base = self.map_base(vme.path)
            else:
                map_base = 0

            for sym in symtab.iter_symbols():
                self._symbol_map[map_base + sym["st_value"]] = (sym.name, bin_file)
        kern_image = self._find_elf("kernel")
        kern_full = self._find_elf("kernel.full")
        if kern_full is not None:
            self.loaded.append(kern_full)
            self._load_kernel(kern_full)
        elif kern_image is not None:
            self.loaded.append(kern_image)
            self._load_kernel(kern_image)

    def _load_kernel(self, path):
        elf_file = ELFFile(open(path, "rb"))
        symtab = elf_file.get_section_by_name(".symtab")

        # the kernel should not be ET_DYN
        assert elf_file.header["e_type"] != "ET_DYN"
        for sym in symtab.iter_symbols():
            self._symbol_map[sym["st_value"]] = (sym.name, path)

    def __str__(self):
        data = io.StringIO()
        data.write("SymReader loaded symbols:\n")
        for addr, (sym, fname) in self._symbol_map.items():
            data.write("0x{:x} {} {}\n".format(addr, fname, sym))
        return data.getvalue()

    def find_file(self, addr):
        """
        Find the file where the symbol at the given address is defined.
        """
        try:
            sym, fname = self.symbol_map[addr]
            return fname
        except KeyError:
            return None

    def find_symbol(self, addr):
        """
        Return the symbol where the address is found,
        if possible.
        """
        entry = self.find_address(addr)
        if entry:
            return entry[0]
        return None

    def find_address(self, addr):
        """
        Return the symbol and file where the address is found.
        """
        try:
            sym, fname = self._symbol_map[addr]
            return (sym, os.path.basename(fname))
        except KeyError:
            return None

    def find_function(self, addr):
        """
        Return the symbol and file of the function containing the
        given address, if possible.
        """
        index = self._symbol_map.bisect(addr) - 1
        if index < 0:
            return None
        key = self._symbol_map.iloc[index]
        sym, fname = self._symbol_map[key]
        return (sym, os.path.basename(fname))


            
