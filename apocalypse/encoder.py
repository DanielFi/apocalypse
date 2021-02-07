from abc import ABC, abstractmethod

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

    def encode_old_class(self, cls: lief.DEX.Class):
        return self._encode_class(cls)
    
    def encode_new_class(self, cls: lief.DEX.Class):
        return self._encode_class(cls)

    def _encode_class(self, cls: lief.DEX.Class):
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