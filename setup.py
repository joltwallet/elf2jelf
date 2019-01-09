from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "jelf_loader",
        ["jelf_loader.pyx"],
        language="c",
    ),
]

setup(
    name = "jelf_loader",
    ext_modules = cythonize(extensions, gdb_debug=True)
)
