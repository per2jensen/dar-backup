from setuptools import setup

setup(
    name='dar-backup',
    version='0.4.0',
    author='Your Name',
    author_email='your@email.com',
    description='A backup utility using dar',
    packages=['dar_backup'],
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