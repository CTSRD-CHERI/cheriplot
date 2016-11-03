"""
Utilities
"""

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
        print("")
