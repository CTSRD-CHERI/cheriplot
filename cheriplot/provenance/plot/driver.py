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

from cheriplot.core import Option, NestedConfig, TaskDriver
from cheriplot.vmmap import VMMapFileParser

logger = logging.getLogger(__name__)

class VMMapPlotDriver(TaskDriver):
    """
    Base driver for plots that require a vmmap file as an input
    """
    outfile = Option(help="Output file", default=None)

    def __init__(self, pgm_list, vmmap, **kwargs):
        """
        :param pgm: provenance graph manager
        :param kwargs: TaskDriver arguments
        """
        super().__init__(**kwargs)
        self._pgm_list = pgm_list
        """List of graph managers for every input graph."""

        self._vmmap = vmmap
        """The process memory mapping model."""

        default_outfile = "{}_%s.png".format(self.__class__.__name__.lower())
        self._outfile = self.config.outfile or default_outfile
        """Output file name for the plot."""
