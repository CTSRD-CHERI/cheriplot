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

from matplotlib import transforms, scale
from matplotlib.ticker import Formatter

logger = logging.getLogger(__name__)

class UnitFormatter(Formatter):

    def __init__(self, unit, **kwargs):
        super().__init__(**kwargs)
        self._unit = unit

    def __call__(self, x, pos=None):
        return "{:.3f}".format(x * self._unit)

class LinearUnitScale(scale.LinearScale):
    """
    Linear scale that allows to set a unit conversion factor
    from the data coordinates. (eg. number of cycles to millions of cycles)
    """

    name = "linear_unit"

    def __init__(self, axis, unit=1, **kwargs):
        super().__init__(axis, **kwargs)

        self._unit = unit
        self._sx = unit if axis.axis_name == "x" else 1
        self._sy = unit if axis.axis_name == "y" else 1
        logger.debug("Axis linear scale with units sx:%d, sy:%d",
                     self._sx, self._sy)

    def set_default_locators_and_formatters(self, axis):
        super().set_default_locators_and_formatters(axis)
        axis.set_major_formatter(UnitFormatter(self._unit))    
    
    def get_transform(self):
        t = transforms.Affine2D()
        return t.scale(sx=self._sx, sy=self._sy)

scale.register_scale(LinearUnitScale)
