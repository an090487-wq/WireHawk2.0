import re
from pathlib import Path
from setuptools import setup, find_packages

# Single source of truth for the version: wirehawk/__init__.py — read it
# without importing the package (avoids needing scapy/rich installed
# just to run setup.py).
_init_text = (Path(__file__).parent / "wirehawk" / "__init__.py").read_text()
_version_match = re.search(r'__version__\s*=\s*"([^"]+)"', _init_text)
VERSION = _version_match.group(1) if _version_match else "0.0.0"

setup(
    name="wirehawk",
    version=VERSION,
    description="WIREHAWK — per-device network traffic analyzer, no router access required.",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "gui": ["PySide6>=6.5.0"],
    },
    entry_points={
        "console_scripts": [
            "wirehawk=wirehawk.cli:main",
            "wirehawk-gui=wirehawk.gui:main",
        ],
    },
    python_requires=">=3.8",
)
