from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="pyNukiBT",
    version="0.0.1",
    author="Ronen Gruengras",
    author_email="ronengr@gmail.com",
    description="Nuki Bluetooth API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ronengr/pyNukiBT",
    packages=find_packages(),
    install_requires=[
        "bleak>=0.20",
        "fastcrc>=0.2.1",
        "PyNaCl>=1.3.0",
        "construct>=2.10.68",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
