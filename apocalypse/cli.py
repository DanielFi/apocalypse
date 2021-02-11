import click
import logging
import json
from pathlib import Path
from apocalypse.differ import DexDiffer
import apocalypse.timeline as timeline


@click.group()
@click.option('-v', '--verbose', is_flag=True)
def main(verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO)

@main.command()
@click.argument('name')
def init(name: str):
    """Initialize a new timeline. 
    """
    timeline.init(name)

@main.command()
@click.argument('version')
@click.argument('dex', type=click.Path(exists=True))
@click.option('-f', '--force', is_flag=True)
@click.option('--compute/--no-compute', default=True)
def insert(version: str, dex: str, force: bool, compute: bool):
    """Insert a version into the timeline. 
    """
    timeline.insert_version(version, dex, force, compute)

@main.command()
def versions():
    """Show versions in timeline. 
    """
    result = timeline.versions()
    if result:
        click.echo('\n'.join(result))

@main.command()
@click.option('--version/--dex', default=True, help='Chose whether to compare versions or dex files. ')
@click.argument('from_', metavar='FROM')
@click.argument('to')
def map(from_: str, to: str, version: bool):
    """Map classes from one version to another. 
    """
    if version:
        click.echo(timeline.map(from_, to))
    else:
        if not Path(from_).is_file():
            click.echo(f"Error: Invalid value for 'FROM': Path '{from_}' does not exist. \n")
            return
        if not Path(to).is_file():
            click.echo(f"Error: Invalid value for 'TO': Path '{to}' does not exist. \n")
            return
    
        differ = DexDiffer()
        mapping, _ = differ.diff(from_, to)
        click.echo(json.dumps(mapping))

@main.command()
@click.argument('version')
@click.argument('class_', metavar='CLASS')
def until(version, class_):
    """Print the last version where CLASS from VERSION existed. 
    """
    click.echo(f"Class '{class_}' existed until version {timeline.until(version, class_)}")

@main.command()
@click.argument('version')
@click.argument('class_', metavar='CLASS')
def since(version, class_):
    """Print the first version where CLASS from VERSION appeared. 
    """
    click.echo(f"Class '{class_}' existed since version {timeline.since(version, class_)}")


if __name__ == '__main__':
    main()
