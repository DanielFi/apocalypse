from abc import ABC, abstractmethod
from collections import defaultdict

import lief.DEX


class Encoder(ABC):

    def __init__(self):
        self._mapping = {}
        self._reverse_mapping = {}
    
    def set_mapping(self, mapping, reverse_mapping):
        self._mapping = mapping
        self._reverse_mapping = reverse_mapping

    @abstractmethod
    def encode_old_class(self, cls: lief.DEX.Class):
        pass
    
    @abstractmethod
    def encode_new_class(self, cls: lief.DEX.Class):
        pass


class DefaultEncoder(Encoder):

    def __init__(self):
        super().__init__()

    def encode_old_class(self, cls: lief.DEX.Class):
        if cls.fullname in self._mapping:
            return self._mapping[cls.fullname]

        return self._encode_class(cls, True)
    
    def encode_new_class(self, cls: lief.DEX.Class):
        if cls.fullname in self._reverse_mapping:
            return cls.fullname

        return self._encode_class(cls, False)

    def _encode_class(self, cls: lief.DEX.Class, old: bool):
        if len(cls.package_name) > 3 or len(cls.fullname) == 1:
            return cls.fullname
        
        types = [cls.fullname]

        mapping = self._mapping if old else self._reverse_mapping

        def encode_type(type_: lief.DEX.Type):
            representation = ''

            if type(type_.value) is list:
                representation += '['
                type_ = type_.underlying_array_type
            
            if type_.type == lief.DEX.Type.TYPES.PRIMITIVE:
                representation += type_.value.name
            else:
                if old and type_.value.fullname in mapping:
                    return mapping[type_.value.fullname]
                elif not old and type_.value.fullname in mapping:
                    return type_.value.fullname

                if type_.value.fullname in types:
                    representation += str(types.index(type_.value.fullname))
                else:
                    types.append(type_.value.fullname)
                    representation += str(len(types) - 1)
            
            return representation
        
        def encode_method_signature(method: lief.DEX.Method):
            result = ''
            
            if len(method.name) > 4:
                result += '.'.join(method.name.split('$')[:2]) + '!'

            prototype = [encode_type(t) for t in method.prototype.parameters_type]
            prototype.append(encode_type(method.prototype.return_type))

            return result + ','.join(prototype)

        encoding = ''
        
        if cls.has_parent:
            if cls.parent.fullname in mapping:
                if old:
                    encoding += mapping[cls.parent.fullname]
                else:
                    encoding += cls.parent.fullname
            elif len(cls.parent.package_name) > 3:
                encoding += cls.parent.fullname
            else:
                encoding += '_'
        
        encoding += '$'

        encoding += str(sum(int(flag) for flag in cls.access_flags)) + ','
        encoding += cls.package_name

        for method in cls.methods:
            encoding += '|'

            encoding += encode_method_signature(method) + ','

            encoding += str(sum(int(flag) for flag in method.access_flags)) + ','
            encoding += str(len(method.bytecode))
            if method.bytecode:
                encoding += ':' + str(method.bytecode[0])
        
        return encoding