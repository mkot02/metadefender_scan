from setuptools import find_namespace_packages, setup

setup(
    name="metadefender-scan",
    description="Command line tool which allows to send files to MetaDefender server and fetch scannig results.",
    author="mkot02",
    url="https://github.com/mkot02/metadefender_scan",
    version="0.1.0",
    packages=["metadefender"],
    package_dir={"": "src"},
    package_data={"metadefender": ["py.typed"]},
    python_requires=">=3.6",
    install_requires=[
        "PyYAML",
        "requests",
    ],
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Software Distribution",
    ],
    entry_points={
        "console_scripts": "metadefender-scan=metadefender:main",
    },
)
