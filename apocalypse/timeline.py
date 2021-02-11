from pathlib import Path
import shutil
from distutils.version import StrictVersion

import logging

import json

from apocalypse.differ import DexDiffer


DEXS_FOLDER = 'dexs'
DIFF_FOLDER = 'diffs'


logger = logging.getLogger(__name__)


def in_timeline():
    return Path(DEXS_FOLDER).is_dir() and Path(DIFF_FOLDER).is_dir()

def init(name):
    root = Path(name)
    root.mkdir()
    (root / DEXS_FOLDER).mkdir()
    (root / DIFF_FOLDER).mkdir()

def insert_version(version, dex_path, force=False, compute_maps=True):
    if not in_timeline():
        logger.error('Not in a timeline. ')
        return

    if not _is_version_valid(version):
        logger.error(f"'{version}' is not a valid version")
        return

    if (Path(DEXS_FOLDER) / version).is_file():
        if not force:
            logger.error(f'Version {version} already exists. \nUse --force to override. ')
            return
        else:
            (Path(DEXS_FOLDER) / version).unlink()

    shutil.copy(dex_path, Path(DEXS_FOLDER) / version)

    if compute_maps:
        previous_version = None
        next_version = None
        for some_version in versions():
            if StrictVersion(some_version) > StrictVersion(version):
                next_version = some_version
                break
            elif StrictVersion(version) > StrictVersion(some_version):
                previous_version = some_version

        if previous_version:
            _compute_maps(previous_version, version)
        if next_version:
            _compute_maps(version, next_version)

def map(version_from, version_to):
    if not in_timeline():
        logger.error('Not in a timeline. ')
        return

    if not _is_version_valid(version_from):
        logger.error(f"'{version_from}' is not a valid version")
        return
    if not _is_version_valid(version_to):
        logger.error(f"'{version_to}' is not a valid version")
        return

    if version_from == version_to:
        logger.error(f"Can't map version {version_from} to itself")
        return

    if not (Path(DEXS_FOLDER) / version_from).is_file():
        logger.error("Version {version_from} doesn't exist. ")
        return
    if not (Path(DEXS_FOLDER) / version_to).is_file():
        logger.error(f"Version {version_to} doesn't exist. ")
        return

    reverse = StrictVersion(version_from) > StrictVersion(version_to)
    lower_version = version_to if reverse else version_from
    uppder_version = version_from if reverse else version_to

    relevant_versions = sorted((version for version in versions() 
                        if StrictVersion(lower_version) <= StrictVersion(version) 
                        and StrictVersion(version) <= StrictVersion(uppder_version)))
    
    if reverse:
        relevant_versions.reverse()

    with open(Path(DIFF_FOLDER) / f'{relevant_versions[0]}-{relevant_versions[1]}') as f:
        total_map = json.load(f)
    for current_version, next_version in zip(relevant_versions[:-1], relevant_versions[2:]):
        current_map = Path(DIFF_FOLDER) / f'{current_version}-{next_version}'

        if not current_map.is_file():
            _compute_maps(current_version, next_version)

        with open(current_map, 'r') as f:
            current_map = json.load(f)
            for key, value in total_map.items():
                try:
                    total_map[key] = current_map[value]
                except KeyError:
                    pass

    return json.dumps(total_map)

def until(version, class_name):
    if not in_timeline():
        logger.error('Not in a timeline. ')
        return 
       
    if not (Path(DEXS_FOLDER) / version).is_file():
        logger.error("Version {version} doesn't exist. ")
        return

    for next_version in versions():
        if StrictVersion(next_version) <= StrictVersion(version):
            continue

        with open(Path(DIFF_FOLDER) / f'{version}-{next_version}', 'r') as f:
            mapping = json.load(f)
            try:
                class_name = mapping[class_name]
            except KeyError:
                break
            version = next_version

    return version

def since(version, class_name):
    if not in_timeline():
        logger.error('Not in a timeline. ')
        return 
       
    if not (Path(DEXS_FOLDER) / version).is_file():
        logger.error("Version {version} doesn't exist. ")
        return

    for previous_version in reversed(versions()):
        if StrictVersion(previous_version) >= StrictVersion(version):
            continue

        with open(Path(DIFF_FOLDER) / f'{version}-{previous_version}', 'r') as f:
            mapping = json.load(f)
            try:
                class_name = mapping[class_name]
            except KeyError:
                break
            version = previous_version

    return version

def versions():
    if not in_timeline():
        logger.error('Not in a timeline. ')
        return

    return sorted((p.name for p in Path(DEXS_FOLDER).iterdir()), key=StrictVersion)

def _is_version_valid(version):
    try:
        StrictVersion(version)
        return True
    except ValueError:
        return False

def _compute_maps(version_a, version_b):
    differ = DexDiffer()
    map_from_previous, map_to_previous = differ.diff(str(Path(DEXS_FOLDER) / version_a), str(Path(DEXS_FOLDER) / version_b))

    with open(Path(DIFF_FOLDER) / f'{version_a}-{version_b}', 'w') as f:
        json.dump(map_from_previous, f)
    with open(Path(DIFF_FOLDER) / f'{version_b}-{version_a}', 'w') as f:
        json.dump(map_to_previous, f)