from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
long_description = (here / "README.md").read_text()

setup(
    name="lumen-scanner",
    version="0.1.1",
    description="Offensive Security Tool for Reconnaissance and Information Gathering",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Yahya Gholame",
    author_email="gholame.yahya@gmail.com",


    packages=find_packages(include=["lumen_src", "lumen_src.*"]),

    python_requires=">=3.9",
    install_requires=[
        "beautifulsoup4",
        "requests[socks]",
        "dnspython",
        "lxml",
        "click",
        "fake-useragent",
        "xmltodict"
    ],

    include_package_data=True,  # conserver wordlists/* déclarés ci‑dessous
    package_data={"lumen_src": ["wordlists/*"]},

    entry_points={
        "console_scripts": [
            # on pointe vers lumen_main.py
            "lumen = lumen_src.lumen_main:main",
        ]
    },
)
