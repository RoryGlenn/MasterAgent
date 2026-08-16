"""Build hooks that make packaged runtime permissions deterministic."""

from __future__ import annotations

import stat
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class HardenedBuildPy(_build_py):
    """Normalize packaged code independently of the builder's process umask."""

    def run(self) -> None:
        super().run()
        for output in self.get_outputs(include_bytecode=False):
            path = Path(output)
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"refusing non-regular package output: {path}")
            path.chmod(0o644)


setup(cmdclass={"build_py": HardenedBuildPy})
