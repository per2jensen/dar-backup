from setuptools import setup
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='dar-backup',
    version='0.5.10',
    author='Per Jensen',
    author_email='per2jensen@gmail.com',
    description="""A script to do full, differential and incremental backups using `dar`. Some files are restored from the backups during verification, after which par2 redundancy files are created. The script also has a cleanup feature to remove old backups and par2 files.""",
    long_description = long_description,
    long_description_content_type='text/markdown',
    packages=['dar_backup'],
    url='https://github.com/per2jensen/dar-backup',
    include_package_data=True,  # Ensure package data is included
    package_data={
        '': ['.darrc']},
    license='General Public License version 3 or later',
    classifiers= [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3.9',
        'Topic :: System :: Archiving :: Backup',
    ],
    entry_points={
        'console_scripts': [
            'dar-backup = dar_backup.dar_backup:main',
            'cleanup = dar_backup.cleanup:main'
        ],
    },
)