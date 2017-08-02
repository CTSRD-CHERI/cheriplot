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
import numpy as np

from datetime import datetime
from itertools import chain, repeat
from functools import reduce
from operator import methodcaller, itemgetter
from sortedcontainers import SortedDict

from matplotlib import pyplot as plt
from matplotlib.transforms import Bbox

from cheriplot.core.utils import ProgressTimer

logger = logging.getLogger(__name__)

__all__ = ("BasePlotBuilder", "ASAxesPlotBuilder", "ASAxesPlotBuilderNoTitle",
           "ExternalLegendTopPlotBuilder")

# XXX
#from memory_profiler import profile

class BasePlotBuilder:

    title = ""
    x_label = "X"
    y_label = "Y"

    style_defaults = {
        # viewport padding
        "vp_padding_top": 0.02,
        "vp_padding_bottom": 0.02,
        "vp_padding_left": 0.02,
        "vp_padding_right": 0.02,
        "font": None, # matplotlib FontProperties
    }

    def __init__(self, **kwargs):
        """
        Init the base plot. The accepted keyword arguments are style
        configuration parameters with defaults in
        BasePlotBuilder.style_defaults.
        """
        style = self._pop_style_kwargs(kwargs)
        super().__init__(**kwargs)
        fig, ax = self.make_axes()

        logger.debug("Initialize plot '%s'", self.title)

        self.fig = fig
        """The matplotlib figure"""

        self.ax = ax
        """The matplotlib axes"""

        self._patch_builders = []
        """
        List of tuples (dataset, [builders,...]) holding the
        registered patch builders for each dataset.
        """

        self._legend_handles = []
        """Legend handles created by the patch builders."""

        self._xticks = SortedDict()
        """X axis ticks returned by patch builders"""

        self._yticks = SortedDict()
        """Y axis ticks returned by patch builders"""

        self._view_box = Bbox.from_bounds(0, 0, 0, 0)
        """The viewport bounding box in data coordinates."""

        self._style = style
        """Style options."""

    def _pop_style_kwargs(self, kwargs):
        """
        Extract the style parameters from kwargs

        :return: dict with style parameters
        """
        return {k: kwargs.pop(k, self.style_defaults[k]) for k in
                self.style_defaults.keys()}

    def _get_axes_kwargs(self):
        """
        Return the kwargs used to add the axes to the figure

        :return: dict
        """
        return {}

    def _get_figure_kwargs(self):
        """
        Return the kwargs used to create the plot figure

        :return: kwargs dict for :func:`pyplot.figure`
        """
        return {"figsize": (15,10)}

    def _get_axes_rect(self):
        """
        Return the rect (in % of figure width and height)

        :return: list (4 floats, [left, bottom, width, height])
        """
        return [0.05, 0.15, 0.9, 0.8]

    def _get_legend_kwargs(self):
        """
        Return the kwargs used to add the legend to the figure

        :return: kwargs dict for :meth:`Axes.legend`
        """
        return {"handles": self._legend_handles, "prop": self._style["font"]}

    def _get_savefig_kwargs(self):
        """
        Return the kwargs for savefig() to control how
        the figure is saved to a file.

        :return: kwargs dict for :meth:`Figure.savefig`
        """
        return {}

    def _get_title_kwargs(self):
        """
        Return the kwargs for the axes.set_title call. This
        can be used to control the text properties of the title.

        :return: kwargs dict for :meth:`Axes.set_title`
        """
        if self._style["font"]:
            return {"fontproperties": self._style["font"]}
        return {}

    def _get_xlabels_kwargs(self):
        """
        Return the kwargs for the axes.set_xticklabels. This
        can be used to control the text properties of the labels.

        :return: kwargs dict for :meth:`Axes.set_xticklabels`
        """
        if self._style["font"]:
            return {"fontproperties": self._style["font"]}
        return {}

    def _get_ylabels_kwargs(self):
        """
        Return the kwargs for the axes.set_yticklabels. This
        can be used to control the text properties of the labels.

        :return: kwargs dict for :meth:`Axes.set_yticklabels`
        """
        if self._style["font"]:
            return {"fontproperties": self._style["font"]}
        return {}

    def _get_xlabel_kwargs(self):
        """
        Return the kwargs for the axes.set_xlabel.

        :return: kwargs dict for :meth:`Axes.set_xlabel`
        """
        if self._style["font"]:
            return {"fontproperties": self._style["font"]}
        return {}

    def _get_ylabel_kwargs(self):
        """
        Return the kwargs for the axes.set_ylabel.

        :return: kwargs dict for :meth:`Axes.set_ylabel`
        """
        if self._style["font"]:
            return {"fontproperties": self._style["font"]}
        return {}

    def make_axes(self):
        """
        Build the figure and axes for the plot

        :return: tuple containing the figure and the axes
        """
        fig = plt.figure(**self._get_figure_kwargs())
        rect = self._get_axes_rect()
        ax = fig.add_axes(rect, **self._get_axes_kwargs())
        return (fig, ax)

    def _dbg_repr_patch_builders(self):
        """
        Print a debug representation of the patch builders in the
        dict of patch builders in BasePlotBuilder.
        """
        pairs = map(lambda b: "dataset %s -> %s" % (b[0], list(map(str, b[1]))),
                    self._patch_builders)
        return reduce(lambda p,a: "%s\n%s" % (a, p), pairs, "")

#    @profile
    def make_patches(self):
        """
        Build the patches from all the registered patch builders
        The advantage is that a single iteration of each dataset
        is performed, all the patch-builders are invoked on the item
        during the iteration. Special handling can be done in subclasses
        at the expense of performance by passing a reduced set of
        patch_builders to this method.
        """
        # XXX experimental replace start
        logger.debug("Make patches:\n%s", self._dbg_repr_patch_builders())
        for idx, (dataset, builders) in enumerate(self._patch_builders):
            with ProgressTimer("Inspect dataset [%d/%d]" % (
                    idx + 1, len(self._patch_builders)), logger):
                for item in dataset:
                    for b in builders:
                        b.inspect(item)
        builders = list(chain(*map(itemgetter(1), self._patch_builders)))
        bboxes = []
        for idx, b in enumerate(builders):
            with ProgressTimer("Make patches [%d/%d]" % (
                    idx + 1, len(builders)), logger):
                # grab all the patches from the builders
                b.get_patches(self.ax)
            with ProgressTimer("Fetch plot elements [%d/%d]" % (
                    idx + 1, len(builders)), logger):
                # grab the viewport from the builders
                bboxes.append(b.get_bbox())
                # grab the legend from the builders
                self._legend_handles.extend(b.get_legend())
                # grab the x and y ticks
                xticks = b.get_xticks()
                xlabels = b.get_xlabels()
                yticks = b.get_yticks()
                ylabels = b.get_ylabels()
                if xlabels is None:
                    xlabels = repeat(None)
                if ylabels is None:
                    ylabels = repeat(None)
            self._xticks.update(zip(xticks, xlabels))
            self._yticks.update(zip(yticks, ylabels))
        # XXX integrated load / experimental
        # bboxes = []
        # for idx, (dataset, builders) in enumerate(self._patch_builders):
        #         with ProgressTimer("Build patches [%d/%d]" % (
        #                 idx + 1, len(self._patch_builders)), logger):
        #             for b in builders:
        #                 b.load(dataset)
        #                 b.get_patches(self.ax)
        #                 # grab the viewport from the builders
        #                 bboxes.append(b.get_bbox())
        #                 # grab the legend from the builders
        #                 self._legend_handles.extend(b.get_legend())
        #                 # grab the x and y ticks
        #                 xticks = b.get_xticks()
        #                 xlabels = b.get_xlabels()
        #                 yticks = b.get_yticks()
        #                 ylabels = b.get_ylabels()
        #                 if xlabels is None:
        #                     xlabels = repeat(None)
        #                 if ylabels is None:
        #                     ylabels = repeat(None)
        #                 self._xticks.update(zip(xticks, xlabels))
        #                 self._yticks.update(zip(yticks, ylabels))
        # XXX experimental end
        self._view_box = Bbox.union(bboxes)
        logger.debug("Plot viewport %s", self._view_box)
        logger.debug("Num ticks: x:%d y:%d", len(self._xticks),
                     len(self._yticks))
        logger.debug("Legend entries %s",
                     list(map(lambda h: h.get_label(), self._legend_handles)))

    def make_plot(self):
        """
        Set the plot labels, ticks, viewport and legend from the
        patch builders.
        """
        logger.debug("Make plot")
        # set global font properties
        if self._style["font"]:
            self.ax.tick_params(labelsize=self._style["font"].get_size())
        self.ax.set_title(self.title, **self._get_title_kwargs())
        self.ax.set_xlabel(self.x_label, **self._get_xlabel_kwargs())
        self.ax.set_ylabel(self.y_label, **self._get_ylabel_kwargs())
        # set viewport
        # grab the viewbox and make a bounding box with it.
        xmin = self._view_box.xmin * (1 - self._style["vp_padding_left"])
        xmax = self._view_box.xmax * (1 + self._style["vp_padding_right"])
        ymin = self._view_box.ymin * (1 - self._style["vp_padding_bottom"])
        ymax = self._view_box.ymax * (1 + self._style["vp_padding_top"])
        self.ax.set_xlim(xmin, xmax)
        self.ax.set_ylim(ymin, ymax)
        self.ax.legend(**self._get_legend_kwargs())
        if self._xticks:
            self.ax.set_xticks(self._xticks.keys())
            self.ax.set_xticklabels(self._xticks.values(),
                                    **self._get_xlabels_kwargs())
        if self._yticks:
            self.ax.set_yticks(self._yticks.keys())
            self.ax.set_yticklabels(self._yticks.values(),
                                    **self._get_ylabels_kwargs())

    def process(self, out_file=None, show=True):
        """
        Produce the plot and display it or write it to a file

        :param out_file: output file path
        :type out_file: str
        :param show: show the plot in an interactive window
        :type show: bool
        """
        with ProgressTimer("Plot builder processing", logger):
            self.make_patches()
            self.make_plot()
            if out_file:
                self.fig.savefig(out_file, **self._get_savefig_kwargs())
            if show:
                # the fig.show() method does not enter the backend main loop
                # self.fig.show()
                plt.show()

    def register_patch_builder(self, dataset, builder):
        """
        Add a patch builder for a dataset

        :param dataset: dataset object
        :type dataset: iterable
        :param builder: the patch builder for items of the dataset
        :type builder: :class:`PatchBuilder`
        """
        builder.set_style(self._style)
        for entry in self._patch_builders:
            entry_dataset, entry_builders = entry
            if entry_dataset == dataset:
                entry_builders.append(builder)
                break
        else:
           self._patch_builders.append((dataset, [builder]))


class ExternalLegendTopPlotBuilder(BasePlotBuilder):
    """
    Plot builder that places the legend on top of the axes
    """

    def _get_legend_kwargs(self):
        """
        Place the legend on top of the axes frame to
        avoid covering parts of the plot
        """
        kw = super()._get_legend_kwargs()
        kw.update({
            "bbox_to_anchor": (0., 1.02, 1., 0.102),
            "loc": 3,
            "ncol": 9,
            "mode": "expand",
            "borderaxespad": 0.
        })
        return kw

    def _get_axes_rect(self):
        # left, bot, w, h
        return [0.08, 0.12, 0.85, 0.81]

    def _get_title_kwargs(self):
        kw = super()._get_title_kwargs()
        kw.update({
            "y": 1.05
        })
        return kw


class ASAxesPlotBuilder(ExternalLegendTopPlotBuilder):
    """
    Base class the creates a plot with the AddressSpaceAxes projection
    """

    x_label = "Virtual Address"

    def _get_axes_kwargs(self):
        kw = super()._get_axes_kwargs()
        kw["projection"] = "custom_addrspace"
        return kw


class ASAxesPlotBuilderNoTitle(ASAxesPlotBuilder):
    """
    AS Axes plot without the tile string, this leaves more space for the
    plot
    """

    def _get_axes_rect(self):
        # left, bot, w, h
        return [0.08, 0.15, 0.85, 0.8]

    def _get_title_kwargs(self):
        kw = super()._get_title_kwargs()
        kw.update({"visible": False})
        return kw
