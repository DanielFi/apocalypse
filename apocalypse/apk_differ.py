import logging

import itertools
from zipfile import ZipFile
from tempfile import TemporaryDirectory

import lief.DEX

from .heckel_diff import diff as heckel_diff
from .encoder import Encoder, DefaultEncoder
from .classes_differ import ClassesDiffer

import faulthandler
faulthandler.enable()


logger = logging.getLogger(__name__)


class APKDiffer:

    @staticmethod
    def filter_class(cls: lief.DEX.Class) -> bool:
        return True

    def __init__(self, class_filtering_function=None, encoder=DefaultEncoder):
        self._classes_differ = ClassesDiffer(
            class_filtering_function, encoder)

        # parsed dexs are stored while diffing is ongoing, in order to prevent GC which segfaults
        self._dexs = []

    def diff(self, old_apk_path: str, new_apk_path: str):
        old_classes = self._extract_apk_classes(old_apk_path)
        new_classes = self._extract_apk_classes(new_apk_path)

        logger.info(f'total classes: {len(old_classes)} -> {len(new_classes)}')

        result = self._classes_differ.diff(old_classes, new_classes)
        self._dexs = []
        return result

    def _extract_apk_classes(self, apk_path: str):
        classes = []
        tmp_dir = TemporaryDirectory()

        with ZipFile(apk_path) as z:
            namelist = z.namelist()
            for i in itertools.count(start=1):
                dex_filename = 'classes' + ('' if i == 1 else str(i)) + '.dex'
                if (dex_filename not in namelist):
                    logger.info(f'APK {apk_path} has {i-1} dex files')
                    break
                dex = lief.DEX.parse(z.extract(dex_filename, tmp_dir.name))
                self._dexs.append(dex)
                
                classes.extend(sorted(dex.classes, key=lambda c: c.index))

        return classes
