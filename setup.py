from setuptools import setup


setup(
    name='apocalypse',
    version='0.2',
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
