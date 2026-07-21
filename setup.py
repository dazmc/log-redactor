"""Setup for log-redactor - installable as `redact` CLI command."""

from setuptools import setup, find_packages

setup(
    name="log-redactor",
    version="1.0.0",
    description="Deterministic secret redaction for log files",
    packages=find_packages(),
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "redact=redactor.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Logging",
    ],
)
