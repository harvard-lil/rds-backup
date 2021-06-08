from setuptools import setup

setup(
    name='rds-backup',
    version='0.1.1',
    py_modules=['backup'],
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        backup=backup:backup
    ''',
)
