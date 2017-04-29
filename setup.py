"""P22P setup.py file"""
import os
from setuptools import setup


def read(fname):
    p = os.path.join(os.path.dirname(__file__), fname)
    if not os.path.exists(p):
        return ""
    with open(p, "r") as fin:
        return fin.read()


setup(
    name="p22p",
    version="0.4.2",
    author="bennr01",
    author_email="benjamin99.vogt@web.de",
    description="Relay data between clients using a central server",
    license="MIT",
    keywords="network twisted relay proxy peer peer2peer",
    url="https://github.com/bennr01/p22p",
    packages=["p22p"],
    install_requires=[
        "Twisted>=17.1.0",
        ],
    long_description=read("README.md"),
    classifiers=[
        "Topic :: Utilities",
        "Development Status :: 4 - Beta",
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        ],
    entry_points = {
        "console_scripts": ["p22p=p22p.cli:cli"],
        },
    )
