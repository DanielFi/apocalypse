import click
import logging

import json

from apocalypse.differ import DexDiffer


@click.group()
@click.option('-v', '--verbose', is_flag=True)
def main(verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO)

@main.command()
@click.argument('old', type=click.Path(exists=True))
@click.argument('new', type=click.Path(exists=True))
def diff(old: str, new: str):
    """Diff two DEX files
    
    OLD is the old DEX file
    NEW is the new DEX file
    """
    differ = DexDiffer()
    click.echo(json.dumps(differ.diff(old, new)))

if __name__ == '__main__':
    main()
