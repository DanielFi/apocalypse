from typing import List, Any

from dataclasses import dataclass


@dataclass
class Symbol:
    old_count: int
    new_count: int
    olno: int


class SymbolTable:

    def __init__(self):
        self.entries = {}

    def insert_old(self, symbol, line):
        if symbol in self.entries:
            self.entries[symbol].old_count += 1
            self.entries[symbol].olno = line
        else:
            self.entries[symbol] = Symbol(1, 0, line)
    
    def insert_new(self, symbol):
        if symbol in self.entries:
            self.entries[symbol].new_count += 1
        else:
            self.entries[symbol] = Symbol(0, 1, 0)
    
    def __getitem__(self, symbol):
        return self.entries[symbol]


def diff(old : List[Any], new : List[Any]):
    
    symbol_table = SymbolTable()

    mapping = {}
    reverse_mapping = {}

    # Add virtual symbols
    # old.insert(0, '<start>')
    # old.append('<end>')
    # new.insert(0, '<start>')
    # new.append('<end>')

    # Pass 1
    for symbol in new:
        symbol_table.insert_new(symbol)

    # Pass 2
    for line, symbol in enumerate(old):
        symbol_table.insert_old(symbol, line)
    
    # Pass 3
    for line, symbol in enumerate(new):
        entry: Symbol = symbol_table[symbol]
        if entry.old_count == 1 and entry.new_count == 1:
            mapping[entry.olno] = line
            reverse_mapping[line] = entry.olno
    
    print(f'found {len(mapping)} direct mappings!')
    print(f'There are {sum(1 for s in symbol_table.entries.values() if s.old_count > 1 or s.new_count > 1)} non-unique symbols')
    print(f'There are {sum(1 for s in symbol_table.entries.values() if s.old_count * s.new_count == 0)} one-sided symbols')
    print('printing top 10 symbols')
    i = 0
    for symbol in reversed(sorted(symbol_table.entries.keys(), key=lambda s: max(symbol_table[s].old_count, symbol_table[s].new_count))):
        if i == 10:
            break
        i += 1
        print(symbol_table[symbol].old_count, symbol_table[symbol].new_count, symbol)
    
    # TODO: add some leeway for movement (allow for jumps - but only if jumping over unmapped symbols)

    # Pass 4
    for line, symbol in list(enumerate(new))[1:]:
        if line - 1 not in reverse_mapping:
            continue

        maybe_old_line = reverse_mapping[line - 1] + 1

        if maybe_old_line >= len(old) or maybe_old_line in mapping:
            continue

        if old[maybe_old_line] == symbol:
            mapping[maybe_old_line] = line
            reverse_mapping[line] = maybe_old_line

    # Pass 5
    for line, symbol in list(reversed(list(enumerate(new))))[:1]:
        if line + 1 not in reverse_mapping:
            continue

        maybe_old_line = reverse_mapping[line + 1] - 1

        if maybe_old_line in mapping:
            continue

        if old[maybe_old_line] == symbol:
            mapping[maybe_old_line] = line
            reverse_mapping[line] = maybe_old_line
    
    # Remove virtual symbols
    # mapping.pop(0)
    # mapping.pop(len(old) - 1)
    # reverse_mapping.pop(0)
    # reverse_mapping.pop(len(new) - 1)
    
    return mapping, reverse_mapping