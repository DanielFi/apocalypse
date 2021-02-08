import lief.DEX

from .heckel_diff import diff as heckel_diff
from .encoder import Encoder, DefaultEncoder


class DexDiffer:

    @staticmethod
    def filter_class(cls: lief.DEX.Class) -> bool:
        return True
    
    def __init__(self, passes=5, class_filtering_function=None, encoder=DefaultEncoder):
        self._passes = passes
        if class_filtering_function is None:
            class_filtering_function = self.filter_class
        self._class_filtering_function = class_filtering_function
        self._encoder = encoder()
    
    def diff(self, old_dex_path: str, new_dex_path: str):
        print('parsing DEXs... ')
        old_dex = lief.DEX.parse(old_dex_path)
        new_dex = lief.DEX.parse(new_dex_path)

        print(f'total classes: {len(old_dex.classes)} -> {len(new_dex.classes)}')

        print('filtering classes...')
        old_dex_classes = [cls for cls in old_dex.classes if self._class_filtering_function(cls)]
        new_dex_classes = [cls for cls in new_dex.classes if self._class_filtering_function(cls)]

        print(f'filtered classes: {len(old_dex_classes)} -> {len(new_dex_classes)}')

        successful_mappings = 0

        for i in range(self._passes):
            print(f'performing pass #{i + 1}:')

            print('encoding DEXs...')
            old_dex_encoding = [self._encoder.encode_old_class(cls) for cls in old_dex_classes]
            new_dex_encoding = [self._encoder.encode_new_class(cls) for cls in new_dex_classes]

            # print(old_dex_encoding[6000])

            print('performing diff...')
            mapping, reverse_mapping = heckel_diff(old_dex_encoding, new_dex_encoding)

            mapping = {old_dex_classes[i].fullname: new_dex_classes[mapping[i]].fullname for i in mapping}
            reverse_mapping = {new_dex_classes[i].fullname: old_dex_classes[reverse_mapping[i]].fullname for i in reverse_mapping}

            self._encoder.set_mapping(mapping, reverse_mapping)

            print(f'pass #{i + 1} resulted in {len(mapping)} mappings')

            if len(mapping) == successful_mappings:
                print('breaking early since no progress is being made')
                break

            successful_mappings = len(mapping)

        return mapping
    