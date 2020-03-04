from setuptools import setup, find_packages
import io
import os
import re

VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Reads complete file contents."""
    return io.open(os.path.join(HERE, *args), encoding="utf-8").read()


def get_version():
    """Reads the version from this module."""
    init = read("src", "aws_encryption_sdk_cli", "internal", "identifiers.py")
    return VERSION_RE.search(init).group(1)


def get_requirements():
    """Reads the requirements file."""
    requirements = read("requirements.txt")
    return list(requirements.strip().splitlines())


setup(
    name='kunming',
    version=get_version(),
    packages=find_packages("src"),
    package_dir={"": "src"},
    tests_require=['pytest'],
    url='',
    license='',
    author='kunming.liu',
    author_email='',
    description='',
    python_requires='>=3.7',
)
