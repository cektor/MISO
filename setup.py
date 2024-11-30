from setuptools import setup

setup(
    name="MISO",
    version="1.0",
    packages=["miso"],
    data_files=[("share/applications", ["miso.desktop"])],
    entry_points={
        "console_scripts": [
            "miso=miso.main:main",
        ],
    },
    install_requires=[
        "PyQt5",
    ],    
)
