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

from cheriplot.core import ConfigurableComponent, Argument
from cheriplot.vmmap.model import VMMapModel

logger = logging.getLogger(__name__)

__all__ = ("VMMapFileParser",)

class VMMapFileParser(ConfigurableComponent):
    """
    Parse a vmmap file created by procstat or libprocstat-based vmmap_dump tool
    """
    vmmap_file = Argument(
        help="File that specify the VM mappings for the traced process")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        try:
            self.map_file = open(self.config.vmmap_file, "r")
        except IOError:
            logger.error("Can not open %s", self.config.vmmap_file)
            raise
        # try to guess the format of the file
        line = self.map_file.readline()
        self.map_file.seek(0)
        try:
            line.index(",")
            has_csv_delim = True
        except ValueError:
            has_csv_delim = False
        self.csv_style = has_csv_delim

        self.vmmap = VMMapModel()

    def get_model(self):
        return self.vmmap

    def parse(self):
        if self.csv_style:
            logger.info("Try to load vmmap_dump memory map file")
            vmmap_dump_cols = ["start", "end", "offset", "perm", "res", "pres",
                               "ref", "shd", "flag", "tp", "path"]
            vmmap = pd.read_csv(self.map_file, names=vmmap_dump_cols)
        else:
            logger.info("Try to load procstat memory map file")
            procstat_cols = ["pid", "start", "end", "perm", "res", "pres",
                             "ref", "shd", "flag", "tp", "path"]
            vmmap = pd.read_table(self.map_file, names=procstat_cols, sep="\s+")
        vmmap = vmmap.fillna("")
        logger.debug("Parsed vmmap")
        self.vmmap.vmmap = vmmap.ix[:, ["start", "end", "perm", "flag", "path"]]
