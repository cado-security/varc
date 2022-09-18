from setuptools import setup, find_packages

VERSION = '1.0.0'

setup(
    name='varc',
    version=VERSION,
    description='varc Volatile Artifact Collector',
    author='Cado Security',
    author_email='varc@cadosecurity.com',
    url='https://github.com/cado-security/varc',
    download_url=f'https://github.com/cado-security/varc/tarball/{VERSION}',
    py_modules=['varc'],
    install_requires=['psutil', 'mss', 'tqdm', 'pymem'],
    packages=find_packages()
)
