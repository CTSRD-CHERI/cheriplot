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

logger = logging.getLogger(__name__)

class LabelManager:
    """
    Automatically adjust label position to avoid overlapping labels    
    """

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

        self._shift_state = []
        """Hold the current direction of shift for each label"""

        self.constraint = None
        """Constrain the labels within the given range (in data coords).
        XXX if they do not fit you get an endless loop for now
        """

    def _get_bboxes(self, renderer):
        return [label.get_window_extent(renderer) for label in self.labels]

    def _get_overlap(self, bboxes):
        """Return the indices of the first two boxes that overlap"""
        for idx, bbox in enumerate(bboxes):
            for other_idx, other_box in enumerate(bboxes):
                if idx == other_idx:
                    continue                
                if bbox.overlaps(other_box):
                    return (idx, other_idx)
        return None

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

    def _check_constraint(self, idx, position):
        """
        Check that the new position is not overflowing the
        manager constraints, if so pin the label and prevent
        it from moving further.
        XXX not working yet
        """
        if self.constraint is None:
            return position

        low, high = self.constraint
        if position < low or position > high:
            # bounce the label
            self._shift_state[idx] = "r" if position < low else "l"
            # reset position
            position = low if position < low else high
        return position

    def update_label_position(self, renderer):
        """
        Shift overlapping labels. The renderer is
        needed to compute the bounding boxes of the labels
        in display coordinates.
        
        The function have a loop that checks for pairs of 
        labels that overlap until there are none. For each
        pair of labels, the overlap is resolved based on the
        previous shift direction.

        XXX may want to see this as a minimization problem..
        min(f(X)) where X is the vector of tick coordinates        
        """
        bboxes = self._get_bboxes(renderer)
        overlapping = self._get_overlap(bboxes)

        # reset shift state
        self._shift_state = [None] * len(self.labels)

        # define functions used to parametrize the overlap resolution
        # loop so that both vertical and horizontal adjustment of labels
        # can be done
        if self.sort_direction == "v":
            bbox_min = lambda bb: bb.ymin
            bbox_max = lambda bb: bb.ymax            
            # update_pos = lambda oldx, oldy, new_pos: (oldx, new_pos)
            update_pos = lambda label, new_pos: (
                label.get_position()[0], new_pos)
        else:
            bbox_min = lambda bb: bb.xmin
            bbox_max = lambda bb: bb.xmax
            # update_pos = lambda oldx, oldy, new_pos: (new_pos, oldy)
            update_pos = lambda label, new_pos: (
                new_pos, label.get_position()[1])

        loopbreak = 0
        while overlapping:
            if loopbreak == 1000:
                break
            loopbreak += 1

            logger.debug("overlapping items %s", overlapping)
            idx1, idx2 = overlapping
            if idx1 > idx2:
                # enforce ordering so that we can assume that below
                idx1, idx2 = idx2, idx1

            bb1 = bboxes[idx1]
            bb2 = bboxes[idx2]
            logger.debug("overlapping bboxes %s <-> %s",
                         bboxes[idx1], bboxes[idx2])
            logger.debug("state %s, %s", self._shift_state[idx1],
                         self._shift_state[idx2])
            label1 = self.labels[idx1]
            label2 = self.labels[idx2]
            direction1 = self._shift_state[idx1]
            direction2 = self._shift_state[idx2]
            # compute the delta to resolve the overlap
            if bbox_min(bb1) > bbox_min(bb2):
                delta = (bbox_max(bb2) - bbox_min(bb1))
            else:
                delta = (bbox_max(bb1) - bbox_min(bb2))
            # make sure that we move the labels by at least some amount
            delta = max(delta, (bbox_max(bb1) - bbox_min(bb1)) / 4)
            delta *= 1.1
            # init the new positions to the current position
            new_pos1 = bbox_min(bb1) + self._get_align_delta(label1, bb1)
            new_pos2 = bbox_min(bb2) + self._get_align_delta(label2, bb2)

            if direction1 == None and direction2 == None:
                logger.debug("d-none %s", delta)
                # if no preferred direction, shift left and right
                self._shift_state[idx1] = "l"
                self._shift_state[idx2] = "r"
                new_pos1 -= delta / 2
                new_pos2 += delta / 2
            elif direction1 == None:
                logger.debug("d1-none")
                # the one without direction moves away
                # the one already moved stays still
                self._shift_state[idx1] = "l"
                new_pos1 -= delta
            elif direction2 == None:
                logger.debug("d2-none")
                # same as direction1 == None
                self._shift_state[idx2] = "r"
                new_pos2 += delta
            else:
                logger.debug("d-all")
                # both are being moved, the direction of the
                # moving label with the lowest index is imposed
                # this prevents reordering of the labels during
                # shifting
                fixed = min(idx1, idx2)
                moving = max(idx1, idx2)
                force_direction = self._shift_state[fixed]
                if force_direction == "r":
                    if fixed == idx1:
                        new_pos2 += delta
                    else:
                        new_pos1 += delta
                elif force_direction == "l":
                    if fixed == idx1:
                        new_pos2 -= delta
                    else:
                        new_pos1 -= delta

            trans1 = self.labels[idx1].get_transform().inverted()
            trans2 = self.labels[idx2].get_transform().inverted()
            logger.debug("shift bboxes to %s, %s", new_pos1, new_pos2)
            if self.sort_direction == "v":
                _, new_pos1 = trans1.transform((0, new_pos1))
                _, new_pos2 = trans2.transform((0, new_pos2))
            else:
                new_pos1, _ = trans1.transform((new_pos1, 0))
                new_pos2, _ = trans2.transform((new_pos2, 0))
            # check for constrains
            new_pos1 = self._check_constraint(idx1, new_pos1)
            new_pos2 = self._check_constraint(idx2, new_pos2)
            # update the position
            self.labels[idx1].set_position(update_pos(label1, new_pos1))
            self.labels[idx2].set_position(update_pos(label2, new_pos2))
            # refresh boxes and get the new overlapping pair
            bboxes = self._get_bboxes(renderer)
            logger.debug("bboxes move to %s <-> %s",
                         bboxes[idx1], bboxes[idx2])
            logger.debug("state %s, %s", self._shift_state[idx1],
                         self._shift_state[idx2])
            overlapping = self._get_overlap(bboxes)
        logger.debug("-----")
