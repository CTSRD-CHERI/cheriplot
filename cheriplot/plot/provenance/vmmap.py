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

from matplotlib import collections, text, patches, transforms
from matplotlib.colors import colorConverter

from cheriplot.plot.patch import PatchBuilder

logger = logging.getLogger(__name__)

class VMMapPatchBuilder(PatchBuilder):
    """
    Build the patches that highlight the vmmap boundaries in and
    address-space plot
    """

    def __init__(self, axes):
        """
        Construct the VM-map patch builder.

        :param axes: the address-space axes where the patches
        will be rendered
        :type axes: :class:`matplotlib.axes.Axes`
        """
        super(VMMapPatchBuilder, self).__init__()

        self.patches = []
        """List of rectangles"""

        self.patch_colors = []
        """List of colors for the patches"""

        self.annotations = []
        """Text labels"""

        self.label_y = 0.5
        """ Y position of the label in Axes coordinates (in [0,1])"""

        self._colors = {
            "": colorConverter.to_rgb("#bcbcbc"),
            "r": colorConverter.to_rgb("k"),
            "w": colorConverter.to_rgb("y"),
            "x": colorConverter.to_rgb("m"),
            "rw": colorConverter.to_rgb("c"),
            "rx": colorConverter.to_rgb("b"),
            "wx": colorConverter.to_rgb("g"),
            "rwx": colorConverter.to_rgb("r")
        }
        """Map section permission to line colors"""

        self.transform = transforms.blended_transform_factory(
            axes.transData, axes.transAxes)
        """Transform used by the patches"""

    def inspect(self, vmentry):
        # the patches use axes transform on the y coordinate to
        # set the height position of the label independently of
        # the Y scale
        # rect = patches.Rectangle((vmentry.start, 0),
        #                          vmentry.end - vmentry.start, self.y_max)
        rect = patches.Rectangle((vmentry.start, 0.01),
                                 vmentry.end - vmentry.start, 0.98)
        self.patches.append(rect)
        self.patch_colors.append(self._colors[vmentry.perms])

        # the label position is centered based on the axes transform
        label_position = ((vmentry.start + vmentry.end) / 2, self.label_y)
        vme_path = str(vmentry.path).split("/")[-1] if str(vmentry.path) else ""
        if not vme_path and vmentry.grows_down:
            vme_path = "stack"
        vme_label = "%s %s" % (vmentry.perms, vme_path)
        label = text.Text(text=vme_label, rotation="vertical",
                          position=label_position,
                          horizontalalignment="center",
                          verticalalignment="center",
                          transform=self.transform)
        self.annotations.append(label)

    def get_patches(self):
        coll = collections.PatchCollection(self.patches, alpha=0.1,
                                           facecolors=self.patch_colors,
                                           transform=self.transform)
        return [coll]

    def get_annotations(self):
        return self.annotations
