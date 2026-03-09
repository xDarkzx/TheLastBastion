from setuptools import setup, find_packages

setup(
    name="lastbastion",
    version="1.0.0",
    description="Border police for agent ecosystems — verify agents, issue passports, protect endpoints",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.24",
        "pydantic>=2.0",
        "pynacl>=1.5",
    ],
    extras_require={
        "gateway": ["starlette>=0.27"],
        "mcp": ["mcp>=1.0"],
        "all": ["starlette>=0.27", "mcp>=1.0"],
        "dev": ["pytest", "pytest-asyncio"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
        "Programming Language :: Python :: 3",
    ],
)
