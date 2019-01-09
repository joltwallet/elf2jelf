# distutils: libraries = sodium c
# distutils: include_dirs = jolt-types/include jelf_loader/src jelf_loader/include
# distutils: sources = jelf_loader/src/loader.c jelf_loader/src/unaligned.c

cdef extern from "jelfloader.h":
    void jelfLoaderHash(char *fn, char *fn_basename, int n_exports);

def jelfLoader(fn: bytes, fn_basename: bytes, n_exports: int):
    jelfLoaderHash(fn, fn_basename, n_exports)
