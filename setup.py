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
    version='0.0.5',
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=get_requirements(),
    tests_require=['pytest'],
    url='https://github.com/CoolBitX-Technology/sygna-bridge-util-py',
    license='MIT',
    author='kunming.liu',
    author_email='kunming@coolbitx.com',
    description='This is a Python library to help you build servers/services within Sygna Bridge Ecosystem.',
    long_description=read("README.md"),
    long_description_content_type='text/markdown',
    keywords="sygna-bridge-util sygna bridge sygna-bridge ecosystem",
    python_requires='>=3.7',
)