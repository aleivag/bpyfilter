from Cython.Build import cythonize
from setuptools import Extension, setup

setup(
    ext_modules=cythonize(
        [Extension("bpyfilter._core", ["bpyfilter/_core.pyx"], libraries=["bpfilter"])],
        build_dir="build",  # keep generated .c files out of the source tree
        language_level=3,
    ),
)
