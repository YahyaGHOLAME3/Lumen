from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
long_description = (here / "README.md").read_text()

setup(
    name="lumen-scanner",
    version="0.8.5",  # Update to match the version in lumen_main.py
    description="Offensive Security Tool for Reconnaissance and Information Gathering",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Yahya Gholame",
    author_email="gholame.yahya@gmail.com",


    packages=find_packages(include=["lumen_src", "lumen_src.*", "dashboard", "dashboard.*"]),

    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9",
        "beautifulsoup4>=4.12",
        "click>=8.1",
        "colorama>=0.4",
        "cryptography>=42.0",
        "dnspython>=2.6",
        "fake-useragent>=1.5",
        "lxml>=5.2",
        "python-nmap>=0.7",
        "requests[socks]>=2.32",
        "requests-doh>=1.0",
        "rich>=13.7",
        "tldextract>=5.1",
        "tqdm>=4.66",
        "xmltodict>=0.13",
        "pandas>=2.2",
        "plotly>=5.20",
        "streamlit>=1.36",
    ],

    include_package_data=True,
    package_data={
        "lumen_src": ["wordlists/*"],
        "dashboard": ["*.json"],
    },

    entry_points={
        "console_scripts": [
            "lumen = lumen_src.lumen_main:main",
            "lumen-dashboard = dashboard.launch:main",
        ]
    },
)
