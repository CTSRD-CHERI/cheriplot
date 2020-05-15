from setuptools import setup, find_packages

setup(name="cheriplot",
      version="2.0",
      description="Trace tools for CHERI trace analysis",
      author="Alfredo Mazzinghi",
      packages=find_packages(exclude=["tests.*"]),
      entry_points={
          "console_scripts": [
              "cheriplot-provenance = tools.provenance:main",
              "cheriplot-graphproc = tools.graphproc:main",
              "cheriplot-graphfilter = tools.graphfilter:main",
              "cheriplot-symparse = tools.symparse:main",
              "cheriplot-tracedump = tools.pytracedump:main",
              "cheriplot-tracecmp = tools.pytracecmp:main",
              "cheriplot-treedump = tools.treedump:main",
              "cheriplot-backtrace = tools.backtrace:main",
              "cheriplot-runner = tools.action:main",
              "cheriplot-cheriverify = tools.cheriverify:main"
          ]
      })
