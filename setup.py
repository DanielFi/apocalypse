from setuptools import setup


setup(
    name='apocalypse',
    version='0.1',
    packages=['apocalypse'],
    install_requires=[
        'lief',
        'click'
    ],
    entry_points='''
        [console_scripts]
        apocalypse=apocalypse.cli:main
    '''
)