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
@click.option('-r', '--reverse', is_flag=True)
@click.argument('old', type=click.Path(exists=True))
@click.argument('new', type=click.Path(exists=True))
def diff(old: str, new: str, reverse: bool):
    """Diff two DEX files
    
    OLD is the old DEX file
    NEW is the new DEX file
    """
    differ = DexDiffer()
    mapping, reverse_mapping = differ.diff(old, new)
    click.echo(json.dumps(reverse_mapping if reverse else mapping))

if __name__ == '__main__':
    main()
