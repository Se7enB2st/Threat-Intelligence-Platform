from setuptools import setup, find_packages

setup(
    name="threat_analyzer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "streamlit",
        "pandas",
        "plotly",
        "sqlalchemy",
        "psycopg2-binary",
        "python-dotenv",
    ],
    python_requires=">=3.9",
) 