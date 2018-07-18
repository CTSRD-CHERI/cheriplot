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

import numpy as np
import logging

from operator import attrgetter
from scipy.optimize import linprog
from matplotlib.text import Text

logger = logging.getLogger(__name__)

class AutoText(Text):
    """
    Special text instance that uses the given label manager to
    automatically avoid overlap with other AutoText instances
    in the same manager.
    """

    def __init__(self, *args, **kwargs):
        self._label_manager = kwargs.pop("label_manager")
        super().__init__(*args, **kwargs)

        self._label_manager.add_labels([self])

    def draw(self, renderer):
        self._label_manager.update_label_position(renderer)
        super().draw(renderer)


class LabelManager:
    """
    Automatically adjust label position to avoid overlapping labels
    """

    fix_deltas = None

    def __init__(self, direction="horizontal"):

        self.sort_direction = None
        """Direction along which the overlapping is resolved"""

        if direction == "horizontal" or direction == "h":
            self.sort_direction = "h"
        elif direction == "vertical" or direction == "v":
            self.sort_direction = "v"
        else:
            raise ValueError("Invalid label manager sort direction %s" %
                             direction)

        self.labels = []
        """List of managed labels"""

        self.limits = (-np.inf, np.inf)
        """Upper and lower limits of the label coordinates"""

        self.stale = False
        """Labels need to be adjusted"""

    def set_limits(self, inf, sup):
        """Set the upper and lower bounds on the coordinates of the labels."""
        self.limits = (inf, sup)

    def add_labels(self, labels):
        """Add a list of labels to the managed labels."""
        self.stale = True
        self.labels.extend(labels)

    def _get_bboxes(self, renderer):
        return [label.get_window_extent(renderer) for label in self.labels]

    def _get_align_delta(self, label, bbox):
        """
        Get the delta needed to set the position from the
        bbox coordinate taking into account the anchoring of the
        label
        """
        if self.sort_direction == "v":
            va = label.get_va()
            if va == "top":
                return bbox.ymax - bbox.ymin
            elif va == "center":
                return (bbox.ymax - bbox.ymin) / 2
            else:
                # bottom or baseline
                return 0
        else:
            ha = label.get_ha()
            if ha == "right":
                return bbox.xmax - bbox.xmin
            elif ha == "center":
                return (bbox.xmax - bbox.xmin) / 2
            elif ha == "left":
                return 0

    def update_label_position(self, renderer):
        """
        Solve the overlap problem as a linear programming minimization problem.        
        The overlap problem is represented as the following L1 norm minimization
        problem:

        Let :math:`n` be the number of labels.
        Let :math:`x \in \mathbb{R}^n` be the vector of offsets
        for each label that resolve the overlap problem.
        Let :math:`x^0 \in \mathbb{R}^n` be the vector of
        initial coordinates of the labels.
        Let :math:`l \in \mathbb{R}^n` be the vector of widths of the labels.
        Let :math:`\varepsilon in \mathbb{R}` be the minimum
        distance between labels.
        Let :math:`M,m \in \mathbb{R}` respectively be the maxium and minimum
        coordinate that the labels can occupy.

        :math:`\min \norm{x}`
        subject to:

        :math:`n - 1` ordering constraints of the form
        :math:`x_i^0 + x_i \geq x_{i-1}^0 + x_{i-1} + l_{i-1} + \varepsilon`

        :math:`2n` limit constraints of the form
        :math:`x_i^0 + x_i + \varepsilon \leq M`
        :math:`x_i^0 + x_i \geq m`
        """
        if len(self.labels) == 0 or not self.stale:
            return
        self.stale = False

        trans = self.labels[0].get_transform()
        inv = trans.inverted()

        bboxes = self._get_bboxes(renderer)
        align_fixup = np.fromiter(
            map(self._get_align_delta, self.labels, bboxes), dtype=float)
        n = len(bboxes)
        m = n * 3 - 1
        # limits
        if self.sort_direction == "h":
            inf, _ = trans.transform((self.limits[0], 0))
            sup, _ = trans.transform((self.limits[1], 0))
        else:
            _, inf = trans.transform((0, self.limits[0]))
            _, sup = trans.transform((0, self.limits[1]))
        logger.debug("inf %s sup %s", inf ,sup)

        # build the constant vectors
        if self.sort_direction == "h":
            x_start = np.fromiter(map(attrgetter("xmin"), bboxes), dtype=float)
            l = np.fromiter(map(attrgetter("width"), bboxes), dtype=float)
        else:
            x_start = np.fromiter(map(attrgetter("ymin"), bboxes), dtype=float)
            l = np.fromiter(map(attrgetter("height"), bboxes), dtype=float)
        logger.debug("x_0 %s, l %s", x_start, l)
        # min space between adjacent labels
        epsilon = np.mean(l) / 4
        # build the matrix
        I = np.eye(n)
        # original constraints problem without taking into account the represention
        # of the L1 norm problem
        # min ||x||_1 subject to Ax <= b
        A = np.zeros((m, n))
        b = np.zeros(m)

        A[:n] = I
        A[n:2*n] = -I
        A[2*n:] = I[:-1] - I[1:]

        b[:n] = sup - x_start - l
        b[n:2*n] = x_start - inf
        b[2*n:] = x_start[1:] - x_start[:-1] - l[:-1] - epsilon

        # expanded matrix for the L1 norm minimization problem
        # min u*y subject to Ty <= r
        # expanded dimensions
        e_n = 2 * n
        e_m = n * 6 - 1
        # unknowns vector
        y = np.zeros(e_n)
        # objective function coefficients
        u = np.zeros(e_n)
        u[:n] = 1
        # expanded matrix and constant terms vector
        T = np.zeros((e_m, e_n))
        r = np.zeros(e_m)

        # s >= 0
        T[:n, :n] = -I
        # -s <= x <= s
        T[n:2*n, :n] = -I
        T[n:2*n, n:] = -I
        T[2*n:3*n, :n] = -I
        T[2*n:3*n, n:] = I
        # Ax <= b
        T[3*n:, n:] = A
        # all the rest in r is 0
        r[3*n:] = b

        result = linprog(u, T, r, bounds=(-np.inf, np.inf))
        logger.debug("Label manager solution %s", result)
        if result.status != 0:
            # error in the optimization
            logger.warning("Label manager can not adjust labels: %s", result.message)
            return

        if self.fix_deltas:
            deltas = self.fix_deltas
        else:
            deltas = result.x[n:]
        x_result = x_start + align_fixup + deltas
        for idx, label in enumerate(self.labels):
            if self.sort_direction == "h":
                newpos, _ = inv.transform((x_result[idx], 0))
                label.set_position((newpos, label.get_position()[1]))
            else:
                _, newpos = inv.transform((0, x_result[idx]))
                label.set_position((label.get_position()[0], newpos))
