#!/usr/bin/env python3
"""Setup script for CyberAI Calion - Pentest Toolkit"""

from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
with open(readme_path, 'r') as f:
    long_description = f.read()

# Read requirements
req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
with open(req_path, 'r') as f:
    install_requires = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='cyberai-calion',
    version='1.0.0',
    description='CyberAI Calion - A lean penetration testing toolkit',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='mihraj',
    author_email='',
    url='https://github.com/mihrajmashoor8301/cyberai',
    packages=find_packages(exclude=['tests', 'tests.*']),
    package_data={
        'cyberai': ['config/*.yaml', 'data/*'],
    },
    python_requires='>=3.8',
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'cyberai=cyberai:main',
            'cyberai-calion=cyberai:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking',
    ],
)
