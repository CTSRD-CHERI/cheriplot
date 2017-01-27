from setuptools import setup, find_packages

setup(name="cheriplot",
      version="1.0",
      description="Trace tools for CHERI trace analysis",
      author="Alfredo Mazzinghi",
      packages=find_packages(exclude=["tests.*"]),
      entry_points={
          "console_scripts": [
              "cheriplot-pointer-provenance = tools.pointer_provenance:main",
              "cheriplot-tracedump = tools.pytracedump:main",
              "cheriplot-pointer-density = tools.pointer_density:main",
              "cheriplot-pointer-oob = tools.pointer_oob:main",
              "cheriplot-capsize-cdf = tools.pointer_size_cdf:main",
          ]
      })
