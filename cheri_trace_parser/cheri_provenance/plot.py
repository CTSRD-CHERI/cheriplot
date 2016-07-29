"""
Plot representation of a CHERI pointer provenance tree
"""

from matplotlib import pyplot as plt


class PointerProvenancePlot:

    def __init__(self, tree):
        self.tree = tree

    def plot(self):
        fig = plt.figure()
        ax = fig.add_axes([0., 0., 1., 1.,])
