import re
from pathlib import Path
from setuptools import setup, find_packages

def get_version():
    content = Path("src/kek/__init__.py").read_text()
    return re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', content, re.M).group(1)

setup(
    name="zerodev-kek",
    version=get_version(),
    description="Kernel Examination Kit - A CLI tool for EIP-4337",
    author="taek lee",
    author_email="leekt216@gmail.com",
    url="https://github.com/zerodevapp/kek",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    entry_points={
        "console_scripts": ["kek = kek.cli:cli"]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
