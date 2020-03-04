from setuptools import setup, find_packages
import io
import os

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Reads complete file contents."""
    return io.open(os.path.join(HERE, *args), encoding="utf-8").read()


def get_requirements():
    """Reads the requirements file."""
    requirements = read("requirements.txt")
    return list(requirements.strip().splitlines())


setup(
    name='sygna-bridge-util',
    version='0.0.1',
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
