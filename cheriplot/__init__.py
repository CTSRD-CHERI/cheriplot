import os
import matplotlib
# set the default backend here
if "DISPLAY" in os.environ:
    matplotlib.use("qt5agg")
else:
    matplotlib.use("Agg")
