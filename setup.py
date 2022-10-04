from setuptools import setup, find_packages

# read the contents of your README file
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()


VERSION = '1.0.6'

setup(
    name='varc',
    version=VERSION,
    description='varc Volatile Artifact Collector',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Cado Security',
    author_email='varc@cadosecurity.com',
    url='https://github.com/cado-security/varc',
    download_url='https://github.com/cado-security/varc/archive/refs/heads/main.zip',
    py_modules=['varc'],
    install_requires=['psutil', 'mss', 'tqdm', 'pymem'],
    packages=find_packages()
)
