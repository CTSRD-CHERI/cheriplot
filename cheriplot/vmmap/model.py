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
import pandas as pd

logger = logging.getLogger(__name__)

class VMMapEntry:

    def __init__(self, row):
        self.row = row

    @property
    def start(self):
        return self.row["start"]

    @property
    def end(self):
        return self.row["end"]

    @property
    def perm_read(self):
        return "r" in self.row["perm"]

    def perm_write(self):
        return "w" in self.row["perm"]

    @property
    def perm_exec(self):
        return "x" in self.row["perm"]

    @property
    def perms(self):
        return self.row["perm"].strip()

    @property
    def grows_down(self):
        return "D" in self.row["flag"]

    @property
    def path(self):
        return self.row["path"].strip()


class VMMapModel:
    """
    Model the mapped memory regions of a process over time.
    """

    def __init__(self):
        self.vmmap = pd.DataFrame(columns=["start", "end", "perm", "flag", "path"])

    def __iter__(self):
        for idx, row in self.vmmap.iterrows():
            yield VMMapEntry(row)
