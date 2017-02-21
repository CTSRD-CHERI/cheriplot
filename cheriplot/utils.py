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
import sys

logger = logging.getLogger(__name__)


class ProgressPrinter:
    """
    Print progress information based on the log-level
    """

    def __init__(self, end, desc="Progress", start=0, step=1,
                 level=logging.INFO):
        self.start = start
        self.end = end
        self.desc = desc
        self.progress = 0
        self.curr = 0
        self.step = step
        self.level = level

    def advance(self, step=1):
        if logger.getEffectiveLevel() > self.level:
            return
        self.curr += step
        progress = int(self.curr * 100 / (self.end - self.start))
        if (progress != self.progress):
            self.progress = progress
            sys.stdout.write("\r%s [%d%%]" % (self.desc, progress))
            sys.stdout.flush()
            
    def finish(self):
        """
        Add newline to separate upcoming output
        """
        if logger.getEffectiveLevel() < self.level:
            return
        print("\n")
