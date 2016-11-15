"""
Copyright 2016 Alfredo Mazzinghi

Copyright and related rights are licensed under the BERI Hardware-Software
License, Version 1.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the License at:

http://www.beri-open-systems.org/legal/license-1-0.txt

Unless required by applicable law or agreed to in writing, software,
hardware and materials distributed under this License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
express or implied.  See the License for the specific language governing
permissions and limitations under the License.
"""

import logging

import numpy as np

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
            return self.vmmap[self.index][0]

        @property
        def end(self):
            return self.vmmap[self.index][1]

        @property
        def offset(self):
            return self.vmmap[self.index][2]

        @property
        def perm_read(self):
            return "r" in str(self.vmmap[self.index][3])

        @property
        def perm_write(self):
            return "w" in str(self.vmmap[self.index][3])

        @property
        def perm_exec(self):
            return "x" in str(self.vmmap[self.index][3])

        @property
        def perms(self):
            return self.vmmap[self.index][3].strip()

        @property
        def resident(self):
            return self.vmmap[self.index][4]

        @property
        def priv_resident(self):
            return self.vmmap[self.index][5]

        @property
        def refcount(self):
            return self.vmmap[self.index][6]

        @property
        def shadow(self):
            return self.vmmap[self.index][7]

        @property
        def grows_down(self):
            return "D" in self.vmmap[self.index][8]

        @property
        def path(self):
            return self.vmmap[self.index][10].strip()

    def __init__(self, map_file):

        try:
            self.map_file = open(map_file, "r")
        except IOError:
            logger.error("Can not open %s", map_file)
            raise

        dtype_spec = np.dtype("u8,u8,u8,U16,u8,u8,u8,u8,U16,U16,U1024")
        self.vmmap = np.genfromtxt(map_file, delimiter=',',
                                   dtype=dtype_spec)
        logger.debug(self.vmmap)

    def is_stack(self, vmmap_row):
        return False

    def __iter__(self):
        for index in range(self.vmmap.shape[0]):
            yield self.MapEntry(self.vmmap, index)
