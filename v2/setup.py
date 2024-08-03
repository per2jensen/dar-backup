from setuptools import setup

setup(
    name='dar-backup',
    version='0.4.0',
    author='Your Name',
    author_email='your@email.com',
    description="""A script to do full, differential and incremental backups using dar.
    Some files are restores from the backuos after which par2 redundancy files are created.
    The script also has a cleanup feature to remove old backups and par2 files.""",
    packages=['dar_backup'],
    license='General Public License version 3',
    #install_requires=[
        # Add any additional dependencies here
    #],
    entry_points={
        'console_scripts': [
            'dar-backup = dar_backup.dar_backup:main',
            'cleanup = dar_backup.cleanup:main'
        ],
    },
)