import logging

import lief.DEX

from .heckel_diff import diff as heckel_diff
from .encoder import Encoder, DefaultEncoder
from .classes_differ import ClassesDiffer


logger = logging.getLogger(__name__)


class DexDiffer:

    @staticmethod
    def filter_class(cls: lief.DEX.Class) -> bool:
        return True

    def __init__(self, class_filtering_function=None, encoder=DefaultEncoder):
        self._classes_differ = ClassesDiffer(
            class_filtering_function, encoder)

    def diff(self, old_dex_path: str, new_dex_path: str):
        old_dex = lief.DEX.parse(old_dex_path)
        new_dex = lief.DEX.parse(new_dex_path)

        logger.info(
            f'total classes: {len(old_dex.classes)} -> {len(new_dex.classes)}')

        old_dex_classes = sorted(old_dex.classes, key=lambda c: c.index)
        new_dex_classes = sorted(new_dex.classes, key=lambda c: c.index)

        return self._classes_differ.diff(old_dex_classes, new_dex_classes)
