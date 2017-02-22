#-
# Copyright (c) 2016 Alfredo Mazzinghi
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

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

class VMMap:
    """
    Parse a vmmap csv file generated with libprocstat or procstat -v
    """

    class MapEntry:

        def __init__(self, vmmap, index):
            self.vmmap = vmmap
            self.index = index

        @property
        def start(self):
            return self.vmmap["start"][self.index]
            # return self.vmmap[self.index][0]

        @property
        def end(self):
            return self.vmmap["end"][self.index]
            # return self.vmmap[self.index][1]

        @property
        def offset(self):
            if "offset" in self.vmmap.columns:
                return self.vmmap["offset"][self.index]
            else:
                return 0
            # return self.vmmap[self.index][2]

        @property
        def perm_read(self):
            return "r" in self.vmmap["perm"][self.index]

        @property
        def perm_write(self):
            return "w" in self.vmmap["perm"][self.index]

        @property
        def perm_exec(self):
            return "x" in self.vmmap["perm"][self.index]

        @property
        def perms(self):
            return self.vmmap["perm"][self.index].strip()

        @property
        def resident(self):
            return self.vmmap["res"][self.index]

        @property
        def priv_resident(self):
            return self.vmmap["pres"][self.index]

        @property
        def refcount(self):
            return self.vmmap["ref"][self.index]

        @property
        def shadow(self):
            return self.vmmap["shd"][self.index]

        @property
        def grows_down(self):
            return "D" in self.vmmap["flag"][self.index]

        @property
        def path(self):
            return self.vmmap["path"][self.index].strip()

    def __init__(self, map_file):

        try:
            self.map_file = open(map_file, "r")
            # try to guess the format of the file
            line = self.map_file.readline()
            try:
                line.index(",")
                has_csv_delim = True
            except ValueError:
                has_csv_delim = False
        except IOError:
            logger.error("Can not open %s", map_file)
            raise

        if has_csv_delim:
            logger.info("Try to load vmmap_dump memory map file")
            vmmap_dump_cols = ["start", "end", "offset", "perm", "res", "pres",
                               "ref", "shd", "flag", "tp", "path"]
            self.vmmap = pd.read_csv(map_file, names=vmmap_dump_cols)
            # dtype_spec = np.dtype("u8,u8,u8,U16,u8,u8,u8,u8,U16,U16,U1024")
            # self.vmmap = np.genfromtxt(map_file, delimiter=',',
            #                            dtype=dtype_spec)
        else:
            logger.info("Try to load procstat memory map file")
            procstat_cols = ["pid", "start", "end", "perm", "res", "pres",
                             "ref", "shd", "flag", "tp", "path"]
            self.vmmap = pd.read_table(map_file, names=procstat_cols,
                                       sep="\s+")
        self.vmmap = self.vmmap.fillna("")
        logger.debug(self.vmmap)

    def is_stack(self, vmmap_row):
        return False

    def __iter__(self):
        for index in range(self.vmmap.shape[0]):
            yield self.MapEntry(self.vmmap, index)
