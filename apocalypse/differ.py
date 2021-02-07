import lief.DEX

from .heckel_diff import diff as heckel_diff


class DexDiffer:

    @staticmethod
    def filter_class(cls: lief.DEX.Class) -> bool:
        return True

    @staticmethod
    def encode_class(cls: lief.DEX.Class):
        if len(cls.package_name) > 3 or len(cls.fullname) == 1:
            return cls.fullname
        
        types = [cls.fullname]

        def get_type_representation(type_: lief.DEX.Type):
            representation = ''

            if type(type_.value) is list:
                representation += '['
                type_ = type_.underlying_array_type
            
            if type_.type == lief.DEX.Type.TYPES.PRIMITIVE:
                representation += type_.value.name
            else:
                if type_.value.fullname in types:
                    representation += str(types.index(type_.value.fullname))
                else:
                    types.append(type_.value.fullname)
                    representation += str(len(types) - 1)
            
            return representation

        encoding = ''
        
        if cls.has_parent:
            if len(cls.parent.package_name) > 3:
                encoding += cls.parent.fullname
            else:
                encoding += '_'
        
        encoding += '$'

        encoding += str(sum(int(flag) for flag in cls.access_flags)) + ','
        encoding += cls.package_name

        for method in cls.methods:
            encoding += '|'

            if len(method.name) > 3:
                encoding += method.name + '!'

            prototype = [get_type_representation(t) for t in method.prototype.parameters_type]
            prototype.append(get_type_representation(method.prototype.return_type))

            for type_representation in prototype:
                encoding += type_representation + ','

            encoding += str(sum(int(flag) for flag in method.access_flags)) + ','
            encoding += str(len(method.bytecode))
        
        return encoding
    
    def __init__(self, class_filtering_function=None, class_encoding_function=None):
        if class_filtering_function is None:
            class_filtering_function = self.filter_class
        self._class_filtering_function = class_filtering_function
        if class_encoding_function is None:
            class_encoding_function = self.encode_class
        self._class_encoding_function = class_encoding_function
    
    def diff(self, old_dex_path: str, new_dex_path: str):
        print('parsing DEXs... ')
        old_dex = lief.DEX.parse(old_dex_path)
        new_dex = lief.DEX.parse(new_dex_path)

        print(f'total classes: {len(old_dex.classes)} -> {len(new_dex.classes)}')

        print('filtering classes...')
        old_dex_classes = [cls for cls in old_dex.classes if self._class_filtering_function(cls)]
        new_dex_classes = [cls for cls in new_dex.classes if self._class_filtering_function(cls)]

        print(f'filtered classes: {len(old_dex_classes)} -> {len(new_dex_classes)}')

        print('encoding DEXs...')
        old_dex_encoding = [self._class_encoding_function(cls) for cls in old_dex_classes]
        new_dex_encoding = [self._class_encoding_function(cls) for cls in new_dex_classes]

        # print(old_dex_encoding[6000])

        print('performing diff...')
        mapping, reverse_mapping = heckel_diff(old_dex_encoding, new_dex_encoding)

        for i in range(len(old_dex_classes)):
            if i not in mapping and i % 100 == 0:
                print('unmatched: ', old_dex_classes[i].fullname)

        return mapping
    