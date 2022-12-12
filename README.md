rds-backup
==========

This script is for backing up snapshots of AWS RDS instances. To get
started, fire up a virtual environment, then run

    pip install git+https://github.com/harvard-lil/rds-backup.git
    backup --help

For development, [install
Poetry](https://python-poetry.org/docs/#installation) and run

    poetry install
    poetry run backup --help
