from enum import IntEnum
class dwarf_variable_data_type(IntEnum):
    """
    variable type mapping from dwarf_reader/include/variable_type.h
    """
    VAR_TYPE_STRUCT = 0
    VAR_TYPE_UNION = 1
    VAR_TYPE_POINTER = 2
    VAR_TYPE_CLASS = 3
    VAR_TYPE_UNHANDLED = 4