import os
import time

import PPSSPPDebugger
import asyncio
from typing import Callable, List, Dict, Union, Tuple, Any, NamedTuple, Set, Optional
import FrozenKeysDict
# import copy
import struct
from collections import Counter
from pathlib import Path
import hashlib
import parse
import websockets
import json

# from collections import namedtuple
# import csv

const_overlay_base_address = 0x8ABB180
const_overlay_code_start = 0x08ABB200
const_ol_azito_bin_size = 1091840
const_ol_mission_bin_size = 893312
const_ol_title_bin_size = 144384


def load_file_by_path(path: str) -> bytes:
    # Reads the file with given path in binary mode and returns the bytes object
    with open(path, "rb") as source:
        return source.read()


def read_string_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    # If length is -1, reads bytes one by one in utf-8 encoding until the zero byte is read
    # (NOTE: the zero byte is not included in the resulting string!)
    # If length is not -1, calls bytes.decode("utf-8")
    # (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    res = ""
    if length == -1:
        address = offset
        one_byte = data[address:address + 1]
        val = int.from_bytes(one_byte, "big")
        char = one_byte.decode("utf-8")
        while val != 0:
            res += char
            address += 1
            one_byte = data[address:address + 1]
            val = int.from_bytes(one_byte, "big")
            char = one_byte.decode("utf-8")
    else:
        raw = data[offset:offset + length]
        res = raw.decode("utf-8")
    return res


def read_shift_jis_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    # If length is -1, reads groups of 2 bytes in shift-jis encoding until the zero byte is read
    # (NOTE: the zero byte is not included in the resulting string!)
    # If length is not -1, calls bytes.decode("shift-jis")
    # (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    res = ""
    if length == -1:
        address = offset
        two_bytes = data[address:address + 2]
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("shift-jis")
        while val != 0:
            res += char
            address += 2
            two_bytes = data[address:address + 2]
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("shift-jis")
    else:
        raw = data[offset:offset + length]
        res = raw.decode("shift-jis")
    return res
    pass


def read_wstring_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
    """
    :param data: bytes object
    :param offset: offset
    :param length: [optional] length of the range measured in characters
    :return: wide string in the utf-16 encoding
    """
    # If length is -1, reads groups of 2 bytes in utf - 16 encoding until the zero byte is read
    # (NOTE: the zero byte is not included in the resulting string!)
    # If length is not -1, calls bytes.decode("utf-16")
    # (NOTE: in this case the zero byte is not trimmed if it ends up in the range!)
    res = ""
    if length == -1:
        address = offset
        two_bytes = data[address:address + 2]
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("utf-16")
        while val != 0:
            res += char
            address += 2
            two_bytes = data[address:address + 2]
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("utf-16")
    else:
        raw = data[offset:offset + 2 * length]
        res = raw.decode("utf-16")
    return res
    pass


def read_int_from_bytes(data: bytes, offset: int, byteorder: str) -> int:
    four_bytes = data[offset:offset + 4]
    val = int.from_bytes(four_bytes, byteorder)
    return val


def read_custom_int_from_bytes(data: bytes, offset: int, sizeof: int, byteorder: str) -> int:
    value_bytes = data[offset:offset + sizeof]
    val = int.from_bytes(value_bytes, byteorder)
    return val


def read_float_from_bytes(data: bytes, offset: int) -> float:
    four_bytes = data[offset:offset + 4]
    val = struct.unpack("f", four_bytes)[0]
    return val


def is_PAC_msg_table(data: bytes) -> bool:
    if len(data) % 4 != 0:
        return False
    i = 0
    offset = 0
    while offset < len(data):
        if i != read_int_from_bytes(data, offset, "little"):
            return False
        i += 1
        offset += 4
    return True


def binary_search(array: List, val: int) -> int:
    """
    This is the lower bound binary search:
     - if array contains val, returns its index\n
     - if val is bigger than every array element, returns the last index\n
     - if array[i] < val < array[i+1], returns i\n
     - if val is less than every array element, returns -1
    :param array: a list to conduct the search in
    :param val: the value to search for
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if array[mid] < val:
            lo = mid
        else:
            hi = mid

    # if hi == len(array) => hi was never assigned to =>
    # => for every array element x statement "val > x" holds =>
    # => val is bigger than any element in array =>
    # => we return the last index == lo
    if hi == len(array):
        return lo
    # else there has been at least one assignment to hi =>
    # there is at least one k such that val <= array[k] =>
    # in the end val <= array[hi]

    # it's useless to compare array[lo] and val as array[lo] is always less than val
    # if element is found, we just return the index
    if array[hi] == val:
        return hi
    # else either lo == -1 (val is less than every array element)
    # or array[lo] < val < array[hi] => we return lo
    return lo


def binary_search_lambda(array: List, val: int, key: Callable[[Any], int]) -> int:
    """
    This is the lower bound binary search:
     - if array contains val, returns its index\n
     - if val is bigger than every array element, returns the last index\n
     - if array[i] < val < array[i+1], returns i\n
     - if val is less than every array element, returns -1
    :param array: a list to conduct the search in
    :param val: the value to search for
    :param key: the lambda function used when comparing array[mid] and val
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if key(array[mid]) < val:
            lo = mid
        else:
            hi = mid

    # if hi == len(array) => hi was never assigned to =>
    # => for every array element x statement "val > x" holds =>
    # => val is bigger than any element in array =>
    # => we return the last index == lo
    if hi == len(array):
        return lo
    # else there has been at least one assignment to hi =>
    # there is at least one k such that val <= array[k] =>
    # in the end val <= array[hi]

    # it's useless to compare array[lo] and val as array[lo] is always less than val
    # if element is found, we just return the index
    if key(array[hi]) == val:
        return hi
    # else either lo == -1 (val is less than every array element)
    # or array[lo] < val < array[hi] => we return lo
    return lo


def contains_bsearch(array: List, val: int) -> bool:
    """
    This binary search does the same thing as the operator "in", but faster - O(log(n))\n
    :param array: a sorted list to conduct the search in
    :param val: the value to search for
    :return: boolean value: does the array contain val?
    """
    if not array:
        raise ValueError("List must not be empty!")
    lo = -1
    hi = len(array)
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if array[mid] < val:
            lo = mid
        else:
            hi = mid
    # if val in array, then its index is hi
    if hi == len(array):
        return False
    return array[hi] == val


def analyze_instruction_set(file_path: str):
    stats = Counter()
    print(file_path[file_path.rfind("\\") + 1:])
    with open(file_path, encoding="utf-8") as source:
        for line in source:
            words = line.strip().split(";")
            # A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;address;
            # param_1_type;param_1_name;param_2_type;param_2_name...
            arg_types_info = words[10::2]
            for arg_type in arg_types_info:
                if arg_type.startswith("uint32_t_T"):
                    stats["uint32_t_T"] += 1
                elif arg_type.startswith("uint16_t_T"):
                    stats["uint16_t_T"] += 1
                elif arg_type == "uint32_t_P":
                    stats["uint32_t_P"] += 1
                elif arg_type.startswith("uintX_t_T"):
                    stats["uintX_t_T"] += 1
                elif arg_type.startswith("uintXC_t_T"):
                    stats["uintXC_t_T"] += 1
                elif arg_type.startswith("COUNT_"):
                    # I don't want to implement this now
                    stats["COUNT"] += 1
                elif arg_type.startswith("CONTINOUS_"):
                    stats["CONTINOUS"] += 1
                elif arg_type == "uintX_t":
                    stats["uintX_t"] += 1
                elif arg_type == "string":
                    stats["string"] += 1
                else:
                    print(f"Unknown type {arg_type}")
                    stats[arg_type] += 1

    return stats


def read_PAC_string_argument(data: bytes, offset: int) -> Tuple[str, int]:
    original_offset = offset
    while data[offset] != 0:
        offset += 1
    length = offset - original_offset + 1
    return read_shift_jis_from_bytes(data, original_offset, length), length


def is_PAC_instruction(data: bytes, offset: int) -> bool:
    return data[offset] == 0x25 and data[offset + 3] <= 0x23


def is_left_out_PAC_args(data: bytes) -> bool:
    # if len(data) % 4 != 0:
    if len(data) % 8 != 0:
        return False
    # NB! So far this function returns false negative for args that only take up 4 bytes
    potential_args = [data[4 * i: 4 * i + 4] for i in range(0, len(data) // 4, 2)]
    for arg in potential_args:
        val = int.from_bytes(arg, "little")
        if val > 64 or val & (val - 1) != 0:  # val is not a power of 2
            return False
    return True


def unpack_int_from_bytes(int_bytes: bytes) -> int:
    return int.from_bytes(int_bytes, "little")


class Memory_entity:
    def __init__(self):
        self.memory_location: int = 0
        self.size: int = 0
        self.raw_data: bytes = b""

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)

    def __str__(self):  # unfinished
        return f"Memory entity: size = {self.size} bytes"


class Padding_bytes(Memory_entity):
    def __init__(self, word_length):
        Memory_entity.__init__(self)
        self.machine_word_length = word_length
        self.zeroes_only = True

    def initialize_by_raw_data(self, raw: bytes):
        Memory_entity.initialize_by_raw_data(self, raw)
        for byte in raw:
            if byte != 0:
                self.zeroes_only = False
                return

    def __str__(self):  # unfinished
        return f"Padding bytes: count = {self.size}, machine word length = {self.machine_word_length}"


class Patapon_file(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.name: str = ""

    def __str__(self):
        return "Patapon file" + (f" ({self.name})" if self.name != "" else "") + f", size={self.size} bytes"


class MSG_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.msg_count: int = 0
        self.magic: int = 0
        self.computed: bool = False
        self.packed: bool = True
        self.strings: List[str] = []

    def initialize_by_raw_data(self, raw):
        Memory_entity.initialize_by_raw_data(self, raw)
        self.msg_count = int.from_bytes(self.raw_data[0:4], "little")
        self.magic = int.from_bytes(self.raw_data[4:8], "little")

    def compute_items(self, packed: bool = False):
        self.packed = packed
        if packed:
            first = unpack_int_from_bytes(self.raw_data[8:12])
            for i in range(self.msg_count - 1):
                # first is precomputed
                second = unpack_int_from_bytes(self.raw_data[12 + 4 * i:16 + 4 * i])
                self.strings.append(
                    read_wstring_from_bytes(self.raw_data, first, (second - first) // 2).replace("\x00", "")
                )
                first = second
            # now first = the last offset
            self.strings.append(
                read_wstring_from_bytes(self.raw_data, first, self.size - first).replace("\x00", "")
            )
            return
        for i in range(self.msg_count):
            self.strings.append(
                read_wstring_from_bytes(self.raw_data, unpack_int_from_bytes(self.raw_data[8 + 4 * i:12 + 4 * i]))
            )

    def __getitem__(self, index: int) -> str:
        # given that we don't compute strings array when loading
        if self.raw_data == b"":
            raise RuntimeError("MSG file is not initialized")
        if index >= self.msg_count:
            raise IndexError(f"{index} is not a correct index")
        if self.computed:
            return self.strings[index]
        offset_bytes = self.raw_data[8 + 4 * index: 12 + 4 * index]
        offset = int.from_bytes(offset_bytes, "little")
        return read_wstring_from_bytes(self.raw_data, offset)
        pass


# address;A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;
# param_1_type;param_1_name;param_2_type;param_2_name...
# raw_size(hex) == 0 <=> size unknown

class PAC_instruction_param(NamedTuple):
    type: str
    name: str


class PAC_variables(NamedTuple):
    var_0x4: Set[int]
    var_0x8: Set[int]
    var_0x20: Set[int]
    var_0x40: Set[int]


class PAC_instruction_template:
    def __init__(self, instr_info: List[str], args_info: List[str]):
        # A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;address;
        # raw_size, ext_name and param_amount are unused so far
        # raw_size(hex) == 0 <=> size unknown

        self.function_address: int = int(instr_info[9], 16)
        self.signature: int = int("".join(instr_info[0:4]), 16)
        self.name: str = instr_info[5]
        self.description: str = instr_info[7]

        # param_1_type;param_1_name;param_2_type;param_2_name...

        # Let's make a list of PAC_instruction_param
        pairs = zip(args_info[0::2], args_info[1::2])
        self.PAC_params = [PAC_instruction_param(*i) for i in pairs]
        # how can we freeze this list?
        pass


class PAC_instruction(Memory_entity):

    def __init__(self, raw: bytes, offset: int, template: PAC_instruction_template):
        Memory_entity.__init__(self)

        self.function_address = template.function_address
        self.signature = template.signature
        self.instr_class = (self.signature >> 16) % 256
        self.instr_index = self.signature % 65536
        self.name = template.name
        self.description = template.description
        self.cut_off = False

        self.PAC_params: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
        params_dict: Dict[PAC_instruction_param, Any] = {}
        self.ordered_PAC_params: List[Tuple[PAC_instruction_param, Any]] = []

        original_offset = offset
        offset += 4  # skip the signature

        # TO DO: make sure that every entry in the dict will be distinct
        # Solution: use better input file )))))

        # NB! Anything but uintX_t, uintX_t_T, uintXC_t_T, uint32_t_T, uint32_t_P string
        # COUNT, ENTITY_ID and EQUIP_ID should not be used for now!

        for index, param in enumerate(template.PAC_params):
            # wait, is "index" unused? Looks like it is...
            if param.type == "uintX_t":  # unfinished
                # skip padding if needed
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
            elif param.type.startswith("uintX_t_T"):  # unfinished
                # skip padding if needed
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)

                # arg_type = read_int_from_bytes(raw, offset, "little")
                arg_type = raw[offset]
                offset += 4

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    # it means we're done
                    offset -= 4
                    break

                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 4
            elif param.type.startswith("uintXC_t_T"):  # unfinished
                sizeof = 4 - (offset % 4)

                # arg_type = read_custom_int_from_bytes(raw, offset, sizeof, "little")
                arg_type = raw[offset]
                offset += sizeof
                # undefined_param: PAC_instruction_param

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    raise RuntimeError("Cannot init PAC_instruction: param.type is uintXC_t_T, but values is None!")
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))
                offset += 4
            elif param.type.startswith("uint32_t_T"):
                # arg_type = read_int_from_bytes(raw, offset, "little")
                arg_type = raw[offset]
                offset += 4
                # undefined_param: PAC_instruction_param

                values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                if values is None:
                    # it means we're done
                    offset -= 4
                    break
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 4
            elif param.type.startswith("uint16_t_T"):
                # arg_type = read_custom_int_from_bytes(raw, offset, 2, "little")
                arg_type = raw[offset]
                offset += 2
                values = self.argument_switch_case(raw, offset, arg_type, 2, param)
                # so far in this scenario "values" can't be None, but I'll throw a check just in case
                if values is None:
                    raise RuntimeError("Cannot init PAC_instruction: sizeof == 2, but values is None!")
                undefined_param, val = values

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))  # replace with "values"?
                offset += 2
                pass
            elif param.type == "float":
                val = read_float_from_bytes(raw, offset)
                params_dict[param] = val
                offset += 4
            elif param.type == "string":
                val, length = read_PAC_string_argument(raw, offset)

                # This is a test
                val = val.replace("\x00", "")
                # Test part end

                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += length
            elif param.type.startswith("COUNT_"):  # unfinished
                # # count = read_int_from_bytes(raw, offset, "little")
                # # count = read_custom_int_from_bytes(raw, offset, 1, "little")
                # count = raw[offset]  # why is this a Union[int, bytes]?
                # offset += 4
                # for i in range(count):
                #     val = read_int_from_bytes(raw, offset, "little")
                #     count_param = PAC_instruction_param(f"count_{i}", "Unknown")
                #     params_dict[count_param] = val
                #     self.ordered_PAC_params.append((count_param, val))
                #     offset += 4
                res, new_offset = self.read_count_argument(raw, offset, param)
                for count_param, val in res:
                    params_dict[count_param] = val
                    self.ordered_PAC_params.append((count_param, val))
                    offset = new_offset
                if self.cut_off:
                    # we've reached the new instruction
                    break
                pass
            elif param.type == "uint32_t" or param.type == "uint32_t_P" or param.type == "uint32_t_P_ret":
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type.startswith("CONTINOUS_"):  # unfinished
                # TO DO: fix the typo in the file
                remains = len(raw) - offset
                integer_count = remains // 4
                for i in range(integer_count):
                    val = read_int_from_bytes(raw, offset, "little")
                    continuous_param = PAC_instruction_param(f"continuous_{i}", "Unknown")
                    params_dict[continuous_param] = val
                    offset += 4
                pass
            elif param.type == "ENTITY_ID":
                offset += 4
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type == "EQUIP_ID":
                offset += 4
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            elif param.type == "KEYBIND_ID":
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
                pass
            else:
                pass

        self.PAC_params.initialize_from_dict(params_dict)
        # We are done now, so let's initialize raw data
        self.initialize_by_raw_data(raw[original_offset:offset])
        pass

    def argument_switch_case(self, raw: bytes, offset: int, arg_type: int, sizeof: int, param: PAC_instruction_param):
        """
        This is a switch-case code for parsing uint_something_T arguments like 02 00 00 00 FF FF FF FF. \n
        None is returned <=> arg_type is broken and there is a valid PAC signature at offset - sizeof

            :param raw: bytes object
            :param offset: offset
            :param arg_type: 0x1, 0x2, 0x4, 0x10, etc.
            :param sizeof: number of bytes this argument takes
            :param param: info from instruction template
            :returns: PAC_instruction_param for the dict and the arg value or None if the operation was unsuccessful
        """
        undefined_param: PAC_instruction_param
        # Weird, only param.name is used here.

        if arg_type == 0x40:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x40 variable", param.name)
        elif arg_type == 0x20:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x20 variable", param.name)
        elif arg_type == 0x10:  # float
            if sizeof == 2:
                raise ValueError("argument_switch_case error: can't decode 2-byte float value!")
            val = read_float_from_bytes(raw, offset)
            undefined_param = PAC_instruction_param("float", param.name)
        elif arg_type == 0x8:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x8 variable", param.name)
        elif arg_type == 0x4:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x4 variable", param.name)
        elif arg_type == 0x2:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("uint32_t", param.name)
        elif arg_type == 0x1:
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("0x1 value", param.name)
        else:
            # Let's check if the thing that we've just read is a valid signature
            if sizeof != 2 and is_PAC_instruction(raw, offset - sizeof):  # is it ok to put sizeof here?
                # Also maybe turn this check into a bit mask?
                # TO DO: properly implement a check here
                self.cut_off = True
                return None
            val = read_custom_int_from_bytes(raw, offset, sizeof, "little")
            undefined_param = PAC_instruction_param("Unknown", param.name)
        return undefined_param, val

    def read_count_argument(self, raw: bytes, offset: int, param: PAC_instruction_param):
        """
        :param raw: bytes object
        :param offset: offset
        :param param: info from instruction template
        :returns: a list of tuples in form (count_param, val) and the offset after the end of the count args range
        """
        # COUNT_uint32t_uint32tP
        count_info, args_info = param.type.split("_")[1:]
        res: List[Tuple[PAC_instruction_param, int]] = []

        if count_info == "byte":
            count = raw[offset]
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4
        elif count_info == "uint32t":
            arg_type = raw[offset]
            if arg_type != 0x2 and arg_type != 0x1:
                raise RuntimeError(f"Cannot parse {param.type} argument at offset {offset:X}")
            offset += 4
            count = read_int_from_bytes(raw, offset, "little")
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4
        elif count_info == "uint32tP":
            count = read_int_from_bytes(raw, offset, "little")
            offset += 4

            if args_info == "uint32t":
                for i in range(count):
                    arg_type = raw[offset]
                    offset += 4
                    values = self.argument_switch_case(raw, offset, arg_type, 4, param)
                    if values is None:
                        offset -= 4
                        break
                    undefined_param, val = values
                    count_param = PAC_instruction_param(f"count_{count_info} {undefined_param.type} {i}", param.name)
                    res.append((count_param, val))
                    offset += 4
            elif args_info == "uint32tP":
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{count_info}_{i}", "Unknown")
                    res.append((count_param, val))
                    offset += 4
        return res, offset

    def __str__(self):  # unfinished
        ans = f"{hex(self.signature)} ({self.name})"
        return ans
        # for pac_param, value in self.ordered_PAC_params:
        #     pass

    def __repr__(self):
        return f"{hex(self.signature)} ({self.name})"

    def get_used_pac_vars(self) -> PAC_variables:
        args = self.ordered_PAC_params
        used = PAC_variables(set(), set(), set(), set())
        for arg in args:
            arg_type = arg[0].type
            if arg_type.startswith("0x4 "):
                used.var_0x4.add(arg[1])
            elif arg_type.startswith("0x8 "):
                used.var_0x8.add(arg[1])
            elif arg_type.startswith("0x20 "):
                used.var_0x20.add(arg[1])
            elif arg_type.startswith("0x40 "):
                used.var_0x40.add(arg[1])
        return used


class Unknown_PAC_instruction(Memory_entity):
    def __init__(self, raw: bytes):
        Memory_entity.__init__(self)
        self.signature = int.from_bytes(raw[0:4], "big")
        self.instr_class = (self.signature >> 16) % 256
        self.instr_index = self.signature % 65536
        self.initialize_by_raw_data(raw)
        pass

    def __str__(self):
        return f"{hex(self.signature)}"

    def __repr__(self):
        return f"{hex(self.signature)}"


class Left_out_PAC_arguments(Memory_entity):
    def __init__(self, raw: bytes, offset: int):
        Memory_entity.__init__(self)
        self.raw_data = raw[offset:]
        self.size = len(self.raw_data)
        self.supposed_instruction = raw
        self.supposed_size = len(self.supposed_instruction)


class PAC_message_table(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.msg_count: int = 0

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)
        self.msg_count = self.size // 4


class Switch_case_table(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        # self.number_of_branches = 0
        self.branches: List[int] = []

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)
        # self.number_of_branches = self.size // 4
        branches = [raw[4 * i: 4 * i + 4] for i in range(self.size // 4)]
        self.branches = list(map(unpack_int_from_bytes, branches))
        pass

    def __str__(self):
        return f"Switch-case table: size = {self.size} bytes, branches count = {len(self.branches)}"


# Maybe use dataclasses here?
class PAC_transition(NamedTuple):
    save_address: bool
    fallthrough: bool
    potential: bool


class PAC_Edge:
    __slots__ = ("entry", "exit", "properties")

    def __init__(self):
        self.entry = EntryPoint()
        self.exit = ExitPoint()
        # self.save_address = False
        self.properties = PAC_transition(False, True, False)

    def __repr__(self):
        return f"Edge from 0x{self.exit.position:X} to 0x{self.entry.position:X}"

    def __str__(self):
        return f"Edge from 0x{self.exit.position:X} to 0x{self.entry.position:X}"


class EntryPoint:
    def __init__(self):
        self.where_from: List[PAC_Edge] = []
        self.position: int = 0
        self.instruction: Optional[PAC_instruction] = None
        self.code_block: Optional[ContiguousCodeBlock] = None

    def __repr__(self):
        ans = f"Entry point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans

    def __str__(self):
        ans = f"Entry point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans


class ExitPoint:
    def __init__(self):
        self.where_to: List[PAC_Edge] = []
        self.position: int = 0
        self.instruction: Optional[PAC_instruction] = None
        self.code_block: Optional[ContiguousCodeBlock] = None

    def __repr__(self):
        ans = f"Exit point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans

    def __str__(self):
        ans = f"Exit point: file offset = 0x{self.position:X}"
        if self.instruction is not None:
            ans += f"; 0x{self.instruction.signature:X} ({self.instruction.name})"
        return ans


# unused
class RawDataBlock:
    pass


class ContiguousCodeBlock:
    def __init__(self):
        self.size: int = 0
        self.start: int = 0
        self.instructions: Dict[int, PAC_instruction] = {}  # int is absolute file offset
        self.instructions_offsets: List[int] = []
        self.ordered_instructions: List[PAC_instruction] = []
        # self.entry_points: List[EntryPoint] = []
        self.entry_points: Dict[int, EntryPoint] = {}
        self.exit_point: ExitPoint = ExitPoint()

        self.is_split: bool = False
        self.is_source: bool = True

    def __repr__(self):
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def __str__(self):
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def accept_jump_to(self, to: int, exit_point: ExitPoint, transition: PAC_transition) -> bool:
        """
        Makes the block create a connection going from the exitpoint to the offset 'to'\n
        :param to: PAC offset which belongs to this block or precedes it
        :param exit_point: some other block's exitpoint
        :param transition: properties of this transition
        :return: True on success
        """
        # valid_start = contains_bsearch(self.instructions_offsets, to)
        if not contains_bsearch(self.instructions_offsets, to):
            # This means the same as "if to not in self.instructions_offsets"

            # We only accept this when the offset is pointing to the part that goes before the block
            if to < self.instructions_offsets[0]:
                edge = PAC_Edge()
                edge.entry = self.entry_points[self.start]
                edge.exit = exit_point
                edge.properties = transition

                edge.entry.where_from.append(edge)
                edge.exit.where_to.append(edge)

                self.is_source = False
                return True
            # Report back the issue
            return False

        # In this case to is a valid instruction start => self.instructions[to] is valid
        edge = PAC_Edge()
        edge.exit = exit_point
        edge.properties = transition

        if to not in self.entry_points.keys():
            # Let's make a new entry point here...
            entry_point = EntryPoint()
            # ... initialize it...
            entry_point.code_block = self
            entry_point.instruction = self.instructions[to]
            entry_point.position = to

            edge.entry = entry_point
            edge.entry.where_from.append(edge)
            # ...and add to the dictionary.
            edge.exit.where_to.append(edge)
            self.entry_points[to] = entry_point
        else:
            # There is already one there so let's modify it
            edge.entry = self.entry_points[to]
            edge.entry.where_from.append(edge)
            edge.exit.where_to.append(edge)

        self.is_source = False
        return True

    def to_dot_str(self):
        return "\\n".join([instr.name + f" (0x{offset:X})" for offset, instr in self.instructions.items()])

    def get_entry_point(self) -> EntryPoint:
        return next(iter(self.entry_points.values()))


class PAC_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.instructions_count: int = 0
        self.unknown_instructions_count: int = 0
        self.cut_instructions_count: int = 0

        # Dictionary order is insertion order as of Python 3.7!
        self.cut_instructions: Dict[int, PAC_instruction] = {}
        self.raw_entities: Dict[int, Memory_entity] = {}
        self.padding_bytes: Dict[int, Padding_bytes] = {}
        self.switch_case_tables: Dict[int, Switch_case_table] = {}
        self.left_out_PAC_arguments: Dict[int, Left_out_PAC_arguments] = {}
        # self.contains_msg_table: bool = False
        self.msg_tables: Dict[int, PAC_message_table] = {}

        # self.temp_instructions: Dict[int, Dict[int, PAC_instruction]] = {}
        self.instructions: Dict[int, Dict[int, PAC_instruction]] = {}

        self.unknown_instructions: Dict[int, Dict[int, Unknown_PAC_instruction]] = {}
        # self.unknown_instructions: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()  # value type == ?

        self.ordered_instructions: Dict[int, PAC_instruction] = {}
        self.entities_offsets: List[int] = []
        self.entities: Dict[int, Union[Memory_entity, Padding_bytes, Switch_case_table, PAC_message_table,
                                       Left_out_PAC_arguments, Unknown_PAC_instruction, PAC_instruction]] = {}

    def get_entity_by_offset(self, offset: int) -> Tuple[int, Union[
            Memory_entity, Padding_bytes, Switch_case_table, PAC_message_table, Left_out_PAC_arguments,
            Unknown_PAC_instruction, PAC_instruction
        ]
    ]:
        starting_offset = self.entities_offsets[binary_search(self.entities_offsets, offset)]
        return starting_offset, self.entities[starting_offset]

    def dump_data_to_directory(self, dir_path: str, attempt_shift_jis_decoding=False):
        # no checks regarding the directory
        raw_entity: Memory_entity
        base_path = Path(dir_path + "Untitled" if self.name == "" else dir_path + self.name)
        base_path.mkdir(exist_ok=True, parents=True)
        for location, raw_entity in self.raw_entities.items():
            with (base_path / str(location)).open("wb") as file:
                file.write(raw_entity.raw_data)
        if attempt_shift_jis_decoding and self.raw_entities:
            base_path = base_path / "shift_jis"
            base_path.mkdir(exist_ok=True, parents=True)
            for location, raw_entity in self.raw_entities.items():
                try:
                    with (base_path / (str(location) + ".sjis")).open("wb") as file:
                        data = read_shift_jis_from_bytes(raw_entity.raw_data, 0, raw_entity.size)
                        file.write(data.encode("utf-8"))
                except Exception as e:
                    (base_path / (str(location) + ".sjis")).unlink(missing_ok=True)

    def getInstructions(self, signature: int) -> Dict[int, PAC_instruction]:
        if signature not in self.instructions:
            return {}
        return self.instructions[signature]  # can we not search for it again?


class CPU_breakpoint:
    def __init__(self):
        self.address: int = 0x0
        self.enabled: bool = False
        self.log: bool = False
        self.condition: str = ""
        self.logFormat: str = ""


class Memory_breakpoint:
    def __init__(self):
        self.address: int = 0x0
        self.size: int = 0
        self.enabled: bool = False
        self.log: bool = False
        self.read: bool = True
        self.write: bool = True
        self.change: bool = True
        self.logFormat: str = ""


class ELF_function(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.name = ""

    def __str__(self):
        return f"{self.name}, {self.memory_location:#x}, size = {self.size} bytes"


class MIPS_code_state:
    def __init__(self):
        self.PC: int = 0
        self.previous_PC: int = -1
        self.asm_line: str = ""
        self.instruction: str = ""
        self.args: str = ""
        self.opcode: int = 0
        self.function: str = ""
        self.previous_function: str = ""

    def __str__(self):
        return f"PC = {self.PC:#x}, {self.asm_line} ({self.function})"


class PAC_analysis_results:
    def __init__(self):
        pass


def defaultMayBeInstruction(signature: int) -> bool:
    if signature % 256 > 0x24:
        return False
    signature //= 256
    return signature % 256 != 0


class PAC_parser:
    def __init__(self):
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.jump_table_next_to_switch = True
        self.cmd_inxJmp_signature = 0x0
        self.find_unknown_instructions = True
        self.PAC_signature_to_name: Dict[int, str] = {}  # maybe not needed...
        self.templates: Dict[int, PAC_instruction_template] = {}
        self.instruction_heuristic: Callable[[int], bool] = defaultMayBeInstruction

        self.file: PAC_file = PAC_file()
        self.cur_offset = 0
        self.last_offset = 0
        self.last_was_instruction = False
        self.cur_signature = 0x0

    def mayBeInstruction(self, signature: int):
        return self.instruction_heuristic(signature)

    def setTemplates(self, PAC_instruction_templates: Dict[int, PAC_instruction_template]):
        self.templates = PAC_instruction_templates

    def findNextInstruction(self) -> bool:
        """
        Tries to advance cur_offset to the next instruction or unknown instruction\n
        :return: True on success (if the file suffix contains instructions or unknown instructions)
        """
        percent = 0x25
        while True:
            # TO DO: implement alignment settings for better parsing
            # TO DO: maybe request that self.cur_offset < self.file.size - 4 and play with it to omit checking?
            while self.cur_offset < self.file.size and self.file.raw_data[self.cur_offset] != percent:
                self.cur_offset += 1
            # Now let's make a check...
            if self.cur_offset + 3 < self.file.size:
                # We have enough bytes
                if self.find_unknown_instructions:
                    # Here we use some sort of heuristic
                    if self.mayBeInstruction(struct.unpack_from(">i", self.file.raw_data, self.cur_offset)[0]):
                        return True
                    else:
                        self.cur_offset += 1
                else:
                    # Here we test if the signature is known
                    if struct.unpack_from(">i", self.file.raw_data, self.cur_offset)[0] in self.templates:
                        return True
                    else:
                        self.cur_offset += 1
            else:
                # We don't have enough bytes
                return False

    def processMessageTable(self, raw: bytes):
        msg_table = PAC_message_table()
        msg_table.initialize_by_raw_data(raw)
        self.file.msg_tables[self.last_offset] = msg_table
        self.file.entities[self.last_offset] = msg_table

    def processLeftOutArgs(self, raw: bytes):
        instr_offset = self.file.entities_offsets[-1]
        instr_bytes = self.file.ordered_instructions[instr_offset].raw_data
        args = Left_out_PAC_arguments(instr_bytes + raw, self.last_offset - instr_offset)
        self.file.left_out_PAC_arguments[self.last_offset] = args
        self.file.entities[self.last_offset] = args

    def processMemoryEntity(self, raw: bytes):
        entity = Memory_entity()
        entity.initialize_by_raw_data(raw)
        self.file.raw_entities[self.last_offset] = entity
        self.file.entities[self.last_offset] = entity

    def processRawData(self):
        """
        Attempts to create a raw entity (either MSG table, left out PAC arguments or Memory entity) \n
        from the range [self.cur_offset; self.last_offset) and advances self.last_offset
        :return: Does not return anything
        """
        if self.cur_offset == self.last_offset:
            return

        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        if is_PAC_msg_table(raw):
            self.processMessageTable(raw)
        elif self.last_was_instruction and is_left_out_PAC_args(raw):
            self.processLeftOutArgs(raw)
        else:
            self.processMemoryEntity(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.last_offset = self.cur_offset
        self.last_was_instruction = False

    def processInstruction(self):
        # self.cur_signature must be set before calling this
        self.file.entities_offsets.append(self.cur_offset)
        template = self.templates[self.cur_signature]
        instruction = PAC_instruction(self.file.raw_data, self.cur_offset, template)

        if self.cur_signature not in self.file.instructions:
            self.file.instructions[self.cur_signature] = {}
        self.file.instructions[self.cur_signature][self.cur_offset] = instruction

        self.file.entities[self.cur_offset] = instruction
        self.file.ordered_instructions[self.cur_offset] = instruction

        if instruction.cut_off:
            self.file.cut_instructions[self.cur_offset] = instruction
            self.file.cut_instructions_count += 1

        self.cur_offset += instruction.size
        self.last_offset += instruction.size

        # Special cmd_inxJmp case:
        if self.jump_table_next_to_switch and self.cur_signature == self.cmd_inxJmp_signature:
            self.findNextInstruction()
            self.processAddressTable()

        if template.PAC_params and template.PAC_params[-1].type == "string":
            self.fixAlignment()

        self.last_was_instruction = True

    def processUnknownInstruction(self):
        # assumes self.last_offset == self.cur_offset
        self.cur_offset += 4
        res = self.findNextInstruction()

        # Unknown instruction will be from self.last_offset to self.cur_offset
        if not res:
            # No more instructions => the whole file suffix is an unknown instruction
            self.cur_offset = self.file.size

        raw = self.file.raw_data[self.last_offset:self.cur_offset]

        if self.cur_signature not in self.file.unknown_instructions:
            self.file.unknown_instructions[self.cur_signature] = {}

        unknown_instruction = Unknown_PAC_instruction(raw)
        self.file.unknown_instructions[self.cur_signature][self.last_offset] = unknown_instruction
        self.file.entities[self.last_offset] = unknown_instruction
        self.file.entities_offsets.append(self.last_offset)
        self.file.unknown_instructions_count += 1
        self.last_offset = self.cur_offset
        pass

    def fixAlignment(self):
        if self.cur_offset % 4 != 0:
            padding = Padding_bytes(4)
            padding_bytes_length = 4 - (self.cur_offset % 4)
            padding_raw = self.file.raw_data[self.cur_offset:self.cur_offset + padding_bytes_length]
            padding.initialize_by_raw_data(padding_raw)
            self.file.padding_bytes[self.cur_offset] = padding

            self.file.entities[self.cur_offset] = padding
            self.file.entities_offsets.append(self.cur_offset)
            self.cur_offset += padding_bytes_length
            self.last_offset += padding_bytes_length
            pass

    def processAddressTable(self):
        if self.cur_offset == self.last_offset:
            return
        raw = self.file.raw_data[self.last_offset:self.cur_offset]
        table = Switch_case_table()
        table.initialize_by_raw_data(raw)

        self.file.entities_offsets.append(self.last_offset)
        self.file.entities[self.last_offset] = table
        self.file.switch_case_tables[self.last_offset] = table
        self.last_offset = self.cur_offset

    def parse(self):
        if self.file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")

        while self.cur_offset < self.file.size:
            res = self.findNextInstruction()
            if res:
                self.processRawData()
                # now self.last_offset == self.cur_offset
                signature = struct.unpack_from(">i", self.file.raw_data, self.cur_offset)[0]
                self.cur_signature = signature

                # self.find_unknown_instructions == False => the else clause is never executed
                if signature in self.templates:
                    self.processInstruction()
                else:
                    self.processUnknownInstruction()
            else:
                # No more instructions => self.file.raw_data[self.last_offset:] is a raw entity
                self.cur_offset = self.file.size
                self.processRawData()
        pass

    def reset(self, file: PAC_file):
        self.file = file
        self.cur_offset = 0
        self.last_offset = 0
        self.last_was_instruction = False
        self.cur_signature = 0x0


def get_first_difference(path_1: Path, path_2: Path) -> Tuple[int, Tuple[int, int]]:
    """
    If the first value is -1, the files are identical; else the value is the first difference offset

    In this case, the second tuple contains the values of bytes at this offset

    :param path_1: first file path
    :param path_2: second file path
    :return: a tuple of an int and another tuple of two ints
    """
    source_1 = path_1.open(mode="rb").read()
    source_2 = path_2.open(mode="rb").read()
    # diff = difflib.Differ()
    # res = diff.compare(source_1, source_2)
    data = zip(source_1, source_2)
    for i, (a, b) in enumerate(data):
        if a != b:
            # found first difference
            return i, (a, b)
    return -1, (0, 0)


class MemoryAccess(NamedTuple):
    size: int
    info: str
    actual_start: int
    pc: int


class MemAccessInfo(NamedTuple):
    type: str
    size: int
    info: str
    address: int
    alias: str
    pc: int
    fun_name: str


def verify_ranges_intersections(sorted_ranges: List[Tuple[int, int]]) -> bool:
    for i in range(len(sorted_ranges) - 1):
        start, size = sorted_ranges[i]
        if size <= 0 or start + size > sorted_ranges[i+1][0]:
            return False
    return sorted_ranges[-1][1] > 0


class FunctionMemoryAccesses:
    def __init__(self, name: str):
        self.name = name
        # self.PCs: Set[int] = set()
        self.accesses: Set[MemoryAccess] = set()


class MemoryAccessesStats:
    """
    Information about all memory accesses on the range
    """
    def __init__(self, address: int, size: int):
        self.address = address
        self.size = size
        # offset -> (function name -> all its accesses)
        self.writes: Dict[int, Dict[str, FunctionMemoryAccesses]] = {}
        self.reads: Dict[int, Dict[str, FunctionMemoryAccesses]] = {}


def create_pattern_file(path: Path, writes: bool, access_stats: MemoryAccessesStats):
    with open(path, mode="w") as output:
        # We are going to use either "reads" or "writes" depending on the "writes" argument
        if writes:
            dictionary = access_stats.writes
        else:
            dictionary = access_stats.reads
        for offset, func_accesses in dictionary.items():
            true_offset = offset
            if offset < 0:
                offset = 0  # I sure hope true_offset doesn't change here...

            # let's make a dict from size to a set of (who, info, pc)
            data_regrouped: Dict[int, Set[Tuple[str, str, int]]] = {}
            for func_name, accesses in func_accesses.items():
                for access in accesses.accesses:
                    if access.size not in data_regrouped:
                        data_regrouped[access.size] = set()
                    data_regrouped[access.size].add((func_name, access.info, access.pc))

            # let's prepare a label for this offset
            for size, accesses_info in data_regrouped.items():
                # let's make a string with the info about how off the access is
                size //= 8
                true_size = size
                out_of_range_comment = ""

                if true_offset < 0 or true_offset + size > access_stats.size:
                    # either the offset has been adjusted or the access is too big for our range
                    if true_offset < 0:
                        # account for the shift of the left border:
                        size += true_offset
                    # account for the shift of the right border
                    size = min(size, access_stats.size)
                    out_of_range_comment = f"true_offset={hex(true_offset)}, true_size={true_size}, "

                base_line = f"u8 offset_0x{offset:X}[{size}]  @ 0x{offset:X} "
                base_line += "[[comment(\""
                # in case the access is actually only partially in our range...
                base_line += out_of_range_comment

                # let's write a comment now!
                comment = ""
                for who, info, pc in accesses_info:
                    comment += f"({who}, {info}, PC={pc:X}), "
                base_line += comment.rstrip(", ")
                base_line += f"\")]];\n"
                pass
            output.write(base_line)


class PataponDebugger:
    def __init__(self):
        self.debugger = PPSSPPDebugger.PPSSPP_Debugger()
        # self.MSG_files: List[MSG_file] = []
        self.MSG_files: Dict[int, MSG_file] = {}
        self.memory_breakpoints: List[Memory_breakpoint] = []
        self.cpu_breakpoints: List[CPU_breakpoint] = []
        self.cpu_breakpoints_handlers: Dict[int, Callable[[dict], None]] = {}
        self.error = PPSSPPDebugger.const_error_event

        # this should be either removed or rethought...
        # self.PAC_name_to_signature: Dict[str, int] = {}
        self.PAC_signature_to_name: Dict[int, str] = {}

        self.PAC_instruction_templates: Dict[int, PAC_instruction_template] = {}
        self.PAC_instructions: Dict[int, PAC_instruction] = {}  # now unused?
        self.jump_table_next_to_switch = True
        self.inxJmp_signature: int = 0x0
        self.unknown_PAC_signatures: Set = set()
        self.Eboot_PAC_functions: Dict[int, ELF_function] = {}
        # self.ordered_PAC_functions: List[ELF_function] = []
        self.Eboot_PAC_function_offsets: List[int] = []

        self.magic_to_MSG_type: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
        data: Dict[int, str] = {
            0: "azito.msg, classselect.msg or any mission msg file",
            1: "itemmsg.msg",
            2: "unitnamemsg.msg",
            3: "system.msg",
            4: "titlemsg.msg",
            5: "errormessage.msg",
            6: "unused",
            7: "unused",
            8: "worldmapmsg.msg",
            9: "tipsmsg.msg",
            10: "chatmsg.msg",
            11: "dlc_worldmap.msg"
        }
        self.magic_to_MSG_type.initialize_from_dict(data)

        self.current_overlay: str = ""

        self.size_to_PAC: Dict[int, Tuple[bool, str]] = {}
        self.hash_to_PAC: Dict[str, str] = {}

    def read_instruction_set(self, file_path: str):
        # the user expects this operation to change the set
        self.PAC_instruction_templates.clear()
        with open(file_path, encoding="utf-8") as source:
            for line in source:
                words = line.strip().split(";")
                # A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;address;
                # param_1_type;param_1_name;param_2_type;param_2_name...
                instr_info = words[0:10]
                args_info = words[10:]

                # instruction = PAC_instruction(instr_info, args_info)

                template = PAC_instruction_template(instr_info, args_info)
                self.PAC_instruction_templates[template.signature] = template
                self.PAC_signature_to_name[template.signature] = template.name

                address = int(instr_info[-1], 16)
                if True or address < const_overlay_base_address:
                    PAC_function = ELF_function()
                    PAC_function.name = instr_info[5]
                    PAC_function.memory_location = address
                    if address in self.Eboot_PAC_functions.keys():
                        print(f"{address:#x} has already been mentioned in the instruction file!")
                    self.Eboot_PAC_functions[address] = PAC_function
                    # self.ordered_PAC_functions.append(PAC_function)
                    self.Eboot_PAC_function_offsets.append(address)

                # self.PAC_instructions[instruction.signature] = instruction
                # self.PAC_name_to_signature[instruction.name] = instruction.signature
                pass
        # self.ordered_PAC_functions.sort(key=lambda x: x.memory_location)
        self.Eboot_PAC_function_offsets.sort()

    def initialize_PAC_functions(self):  # so far in testing
        pass

    def prepare_PACs_info(self, directory: Path):
        sizes: Dict[int, List[str]] = {}
        for file in directory.glob("*.pac"):
            # we only want to look at the files
            if not file.is_file():
                continue
            size = file.stat().st_size
            if size not in sizes:
                sizes[size] = []
            sizes[size].append(file.name)
        # now let's see...
        for size, names in sizes.items():
            if len(names) == 1:
                self.size_to_PAC[size] = (True, names[0])
                continue
            # if not, we'll have to compute hashes
            for name in names:
                data = (directory / name).open("rb").read()
                hashed = hashlib.md5(data).hexdigest()
                self.hash_to_PAC[hashed] = name
            self.size_to_PAC[size] = (False, "")

    def dump_memory(self, address: int, size: int) -> bytes:
        base_address = self.debugger.PPSSPP_base_address
        return self.debugger.memory.read_bytes(base_address + address, size)
        pass

    def dump_memory_to_file(self, address: int, size: int, save_as: str):
        base_address = self.debugger.PPSSPP_base_address
        raw_data: bytes = self.debugger.memory.read_bytes(base_address + address, size)
        with open(save_as, "wb") as dest:
            dest.write(raw_data)
        pass

    def get_register(self, register: str) -> int:
        response = asyncio.run(self.debugger.cpu_getReg(register))
        return response["uintValue"]

    def get_register_float(self, register: str) -> float:
        response = asyncio.run(self.debugger.cpu_getReg(register))
        return float(response["floatValue"])

    def get_registers(self, registers: List[str]) -> List[str]:
        pass

    #

    def add_cpu_breakpoint(self, handler: Callable[[dict], None], address: int,
                           enabled=True, log=False, condition="", logFormat=""):
        # 1) add it to the collection
        # 2) be able to check if there is a breakpoint with given address
        # 3) accept requests to remove a breakpoint by address efficiently
        pass

    def listen_for_breakpoints_once(self):
        response = asyncio.run(self.debugger.block_until_event("cpu.stepping", self.error))
        PC = response["pc"]
        if PC in self.cpu_breakpoints_handlers.keys():
            # the stepping occurred due to breakpoint that we have set up
            self.cpu_breakpoints_handlers[PC](response)
        # if not, let's.... ah... I see...

    def grab_MSG_from_memory(self, address: int, size: int, magic: int, name: str):
        # self.MSG_files.append()
        file = MSG_file()
        file.initialize_by_raw_data(self.dump_memory(address, size))
        file.compute_items()
        file.memory_location = address
        file.name = name
        self.MSG_files[magic] = file
        pass

    def add_MSG(self, file: MSG_file):
        self.MSG_files[file.magic] = file

    def grab_PAC_from_memory(self, address: int, size: int, name: str):
        file = PAC_file()
        file.initialize_by_raw_data(self.dump_memory(address, size))
        file.memory_location = address
        file.name = name
        # self.PAC_files.append(...) or self.PAC_files[name] = ...
        pass

    def add_PAC(self, address, size):
        pass

    def run_until_jalr_t9(self, delta_t: float, jump_address: int = None):
        # Should be executed after the CPU has begun stepping
        jalr_t9_signature = 0x0320F809  # stored backwards in memory (little-endian)
        if jump_address is None:
            while True:
                ret = asyncio.run(self.debugger.cpu_stepInto())  # cpu.stepping
                PC = ret["pc"]
                opcode = self.debugger.memory_read_int(PC)
                opcode %= 2 ** 32
                if opcode == jalr_t9_signature:
                    print(f"jalr t9 found at {PC:#x}")
                # ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
                # name = ret["lines"][0]["name"]
                # params = ret["lines"][0]["params"]
                # if name == "jalr" and params == "t9":
                #     print(f"jalr t9 found at {hex(PC)}")  # the next instruction may modify t9
                time.sleep(delta_t)
        else:
            while True:
                ret = asyncio.run(self.debugger.cpu_stepInto())  # cpu.stepping
                PC = ret["pc"]
                # opcode = self.debugger.memory_read_int(PC)
                # if opcode == jalr_t9_signature:
                #     print(f"jalr t9 found at {PC}")
                ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
                name = ret["lines"][0]["name"]
                params = ret["lines"][0]["params"]
                if name == "jalr" and params == "t9":
                    print(f"jalr t9 found at {hex(PC)}")  # the next instruction may modify t9
                    ret = asyncio.run(self.debugger.cpu_stepInto())
                    ret = asyncio.run(self.debugger.cpu_getReg("t9"))
                    t9 = ret["uintValue"]
                    print(f"t9 == {hex(t9)}")
                    if t9 == jump_address:
                        print("It matches the requested jump address")
                time.sleep(delta_t)

    def run_until_jr_t9(self, delta_t: float, jump_address: int = None):
        # the code must be improved later, but so far I can just paste the code from above and fix it

        # Should be executed after the CPU has begun stepping
        jr_t9_signature = 0x03200008  # stored backwards in memory (little-endian)
        if jump_address is None:
            while True:
                ret = asyncio.run(self.debugger.cpu_stepInto())  # cpu.stepping
                PC = ret["pc"]
                opcode = self.debugger.memory_read_int(PC)
                opcode %= 2 ** 32
                if opcode == jr_t9_signature:
                    print(f"jr t9 found at {PC}")
                # ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
                # name = ret["lines"][0]["name"]
                # params = ret["lines"][0]["params"]
                # if name == "jr" and params == "t9":
                #     print(f"jr t9 found at {hex(PC)}")  # the next instruction may modify t9
                time.sleep(delta_t)
        else:
            while True:
                ret = asyncio.run(self.debugger.cpu_stepInto())  # cpu.stepping
                PC = ret["pc"]
                # opcode = self.debugger.memory_read_int(PC)
                # if opcode == jalr_t9_signature:
                #     print(f"jalr t9 found at {PC}")
                ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
                name = ret["lines"][0]["name"]
                params = ret["lines"][0]["params"]
                if name == "jalr" and params == "t9":
                    print(f"jalr t9 found at {hex(PC)}")  # the next instruction may modify t9
                    ret = asyncio.run(self.debugger.cpu_stepInto())
                    ret = asyncio.run(self.debugger.cpu_getReg("t9"))
                    t9 = ret["uintValue"]
                    print(f"t9 == {hex(t9)}")
                    if t9 == jump_address:
                        print("It matches the requested jump address")
                time.sleep(delta_t)

    def find_asm_in_range(self, start: int, end: int, opcode: int):
        # start_time = time.monotonic()
        maxint_plus_one = 2 ** 32
        findings = []
        for address in range(start, end, 4):
            cur_opcode = self.debugger.memory_read_int(address)
            cur_opcode %= maxint_plus_one
            if cur_opcode == opcode:
                findings.append(address)
        return findings
        # end_time = time.monotonic()
        # diff_time = end_time - start_time
        # return diff_time

    def follow_MIPS(self, last_PC: int, until_PC_is: int, delta_t: float,
                    file_path: Optional[Path] = None, max_count: int = -1):
        ret = asyncio.run(self.debugger.cpu_getReg("pc"))
        PC = ret["uintValue"]
        previous_PC = last_PC
        previous_function = ""
        code_states: List[MIPS_code_state] = []
        count = 0
        while PC != until_PC_is:
            if max_count != -1 and count >= max_count:  # may be optimized
                break
            ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
            disasm_info = ret["lines"][0]
            name = disasm_info["name"]
            params = disasm_info["params"]
            opcode = self.debugger.memory_read_int(PC) % (2 ** 32)
            func = disasm_info["function"]

            state = MIPS_code_state()
            state.previous_PC = previous_PC
            state.PC = PC
            state.opcode = opcode
            state.args = params
            state.instruction = name
            state.asm_line = f"{name} {params}"
            state.function = func
            state.previous_function = previous_function
            code_states.append(state)

            ret = asyncio.run(self.debugger.cpu_stepInto())
            previous_PC = PC
            previous_function = func
            PC = ret["pc"]
            count += 1
            time.sleep(delta_t)
        if file_path is None:
            return code_states
        if not code_states:
            with open(file_path, "w", encoding="utf-8") as output:
                pass
            return code_states

        with open(file_path, "w", encoding="utf-8") as output:
            state = code_states[0]
            output.write(f"Start at PC={state.PC:x}, {state.asm_line} ({state.function})\n")

            prev_function = state.function
            for state in code_states[1:]:
                if state.previous_PC + 4 != state.PC:
                    output.write(f"Jumped to {state.PC:x}")
                    if prev_function != state.function:
                        output.write(f" ({state.function})")
                    output.write("\n")
                output.write(f"PC={state.PC:x}, {state.asm_line}\n")
                prev_function = state.function
                pass
        return code_states

    def follow_MIPS_func_names(self, until_in_range: range, delta_t: float, file_path: Optional[Path] = None,
                               max_count: int = -1):
        ret = asyncio.run(self.debugger.cpu_getReg("pc"))
        PC = ret["uintValue"]
        previous_function = "Random name"
        func_list: List[str] = []
        count = 0
        while PC not in until_in_range:
            if max_count != -1 and count >= max_count:  # may be optimized
                break
            ret = asyncio.run(self.debugger.memory_disasm(PC, 1, None))
            func = ret["lines"][0]["function"]

            if func == "":
                # hle.func.scan hasn't been run beforehand
                if previous_function != "":
                    func_list.append("Unknown function")
            else:
                if previous_function != func:
                    func_list.append(func)

            ret = asyncio.run(self.debugger.cpu_stepInto())
            previous_function = func
            PC = ret["pc"]
            count += 1
            time.sleep(delta_t)

        if file_path is None:
            return func_list
        if not func_list:
            with open(file_path, "w", encoding="utf-8") as output:
                pass
            return func_list
        with open(file_path, "w", encoding="utf-8") as output:
            for func_name in func_list:
                output.write(func_name)
                output.write("\n")
        return func_list

    def recognize_title_bin(self):
        # if OL_Title.bin is loaded, scan for funcs
        if self.debugger.memory_read_string(const_overlay_base_address + 0x20) == "OL_Title.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_title_bin_size, True)

    def recognize_azito_bin(self):
        # if OL_Azito.bin is loaded, scan for funcs
        if self.debugger.memory_read_string(const_overlay_base_address + 0x20) == "OL_Azito.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_azito_bin_size, True)

    def recognize_mission_bin(self):
        # if OL_Mission.bin is loaded, scan for funcs
        if self.debugger.memory_read_string(const_overlay_base_address + 0x20) == "OL_Mission.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_mission_bin_size, True)

    def recognize_current_overlay(self):
        filename = self.debugger.memory_read_string(const_overlay_base_address + 0x20)
        if filename == "OL_Title.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_title_bin_size, True)
            self.current_overlay = filename
        elif filename == "OL_Azito.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_azito_bin_size, True)
            self.current_overlay = filename
        elif filename == "OL_Mission.bin":
            self.debugger.hle_func_scan(const_overlay_code_start, const_ol_mission_bin_size, True)
            self.current_overlay = filename
        else:
            self.current_overlay = ""

    def identify_PAC(self, address: int) -> str:
        alloc_info_address = self.debugger.memory_read_int(address - 4)
        file_end = self.debugger.memory_read_int(alloc_info_address)
        size = file_end - address
        if size not in self.size_to_PAC:
            print(f"Fatal error: unrecognized PAC file at address 0x{address:X}!")
            exit()
        unique, name = self.size_to_PAC[size]
        if not unique:
            # compute the hash
            data = self.dump_memory(address, size)
            hashed = hashlib.md5(data).hexdigest()
            if hashed not in self.hash_to_PAC:
                print(f"Fatal error: unrecognized PAC file at address 0x{address:X}!")
                exit()
            name = self.hash_to_PAC[hashed]
        # now the name is correct!
        return name

    def log_struct_accesses(self, address: int, size: int):
        error = PPSSPPDebugger.const_error_event
        # CHK Read32(CPU) at 08f08700 ((08f08700)), PC=0892b64c (z_un_0892b644)
        parser = parse.compile("CHK {:l}{:d}({:w}) at {:x} (({:w})), PC={:x} ({:w})")
        # test = parser.parse("CHK Read32(CPU) at 08f08700 ((08f08700)), PC=0892b64c (z_un_0892b644)")

        # let's place a memory bp on the range
        asyncio.run(self.debugger.memory_breakpoint_add(address, size, enabled=False, log=True))
        # now let's prepare a dict...
        accesses: Dict[int, Set[MemAccessInfo]] = {}
        got_log = False

        # now the actual action
        while True:
            try:
                # ret = asyncio.run(self.debugger.block_until_event("cpu.stepping", PPSSPPDebugger.const_error_event))
                # # how do we know if the stepping occurred due to a memory bp?
                # reason = ret["reason"]
                # if reason != "memory.breakpoint":
                #     asyncio.run(self.debugger.cpu_resume())
                #     continue
                # # print("Reason is memory.breakpoint")
                # code_addresses.add(ret["pc"])
                # asyncio.run(self.debugger.cpu_resume())

                # if not got_log:
                #     event = "log"
                # else:
                #     event = "cpu.stepping"
                # ret = asyncio.run(self.debugger.block_until_event(event, error))
                ret = asyncio.run(self.debugger.block_until_any({"log"}, error))
                if ret["event"] == "log":
                    # we can access the field "message" to get the log and parse it
                    log_message = ret["message"].rstrip()
                    print(log_message)
                    parsed = parser.parse(log_message)
                    if parsed is None:
                        continue

                    mem_access_info = MemAccessInfo(*parsed.fixed)
                    addr = mem_access_info.address
                    # TO DO: identify the range which this access belongs to
                    # But for now let's suppose that we only have one watchpoint...
                    # accesses[addr] = mem_access_info
                    if addr not in accesses:
                        accesses[addr] = set()
                    accesses[addr].add(mem_access_info)
                else:
                    # Do something here... maybe even nothing later...
                    asyncio.run(self.debugger.cpu_resume())
            except KeyboardInterrupt:
                print("Finishing!")
                # print(", ".join([f"0x{i:X}" for i in code_addresses]))
                for addr, access_list in accesses.items():
                    print(f"0x{addr-address:X}")
                    lines = [f"{acc.type}{acc.size} by {acc.fun_name} (PC=0x{acc.pc:X})" for acc in access_list]
                    print("\n".join(lines))
                break
            except Exception as e:
                print("Exception!")
                print(e)

    def AccessLogger(self, ranges: Set[Tuple[int, int]], path: Path, addr_to_name: Optional[Dict[str, str]] = None):
        error = PPSSPPDebugger.const_error_event
        # CHK Read32(CPU) at 08f08700 ((08f08700)), PC=0892b64c (z_un_0892b644)
        # CHK Write1155072(IoRead/disc0:/PSP_GAME/USRDIR/Overlay/OL_Title.bin offset 0x00000000) at 08abb180

        sorted_ranges = sorted(ranges)
        if not verify_ranges_intersections(sorted_ranges):
            print("Ranges intersect, cannot start AccessLogger!")
            return None

        parser = parse.compile("CHK {:l}{:d}({}) at {:x} (({:w})), PC={:x} ({:w})")

        for address, size in ranges:
            asyncio.run(self.debugger.memory_breakpoint_add(address, size, enabled=False, log=True))
        # now let's prepare a dict...
        accesses: Dict[int, Set[MemAccessInfo]] = {}

        async def AsyncLogger():
            async with websockets.connect(self.debugger.connection_URI, ping_timeout=None) as ws:
                while True:
                    response = json.loads(await ws.recv())
                    if response["event"] != "log":
                        continue
                    log_message = response["message"].rstrip()
                    # print(log_message)
                    parsed = parser.parse(log_message)
                    if parsed is None:
                        continue
                    mem_access_info = MemAccessInfo(*parsed.fixed)
                    addr = mem_access_info.address
                    if addr not in accesses:
                        accesses[addr] = set()
                    accesses[addr].add(mem_access_info)

        try:
            asyncio.run(AsyncLogger())
        except (KeyboardInterrupt, Exception) as e:
            print("Intercepted exception:", end=" ")
            print(e)
            print("Finishing!")

            accesses_info: Dict[int, MemoryAccessesStats] = \
                {address: MemoryAccessesStats(address, size) for address, size in sorted_ranges}

            access_set: Set[MemAccessInfo]
            for address, access_set in sorted(accesses.items()):
                # let's see which range is this...
                index = binary_search_lambda(sorted_ranges, address, key=lambda tup: tup[0])

                # what if this is -1?
                if index == -1:
                    # someone accessed the first range, but the start address lies outside of it
                    range_start = sorted_ranges[0][0]
                    offset = address - range_start
                else:
                    range_start, range_size = sorted_ranges[index]
                    offset = address - range_start
                    if offset >= range_size:
                        # this is not the range that was accessed
                        range_start = sorted_ranges[index + 1][0]
                        offset = address - range_start

                # range_start = sorted_ranges[index][0]
                # offset = address - range_start
                # print(f"0x{offset:X}")

                # We get the range which the accesses RAM part belongs to
                access_stats = accesses_info[range_start]

                for access_info in access_set:
                    # We are going to write to either "reads" or "writes" depending on the "type" field
                    if access_info.type == "Read":
                        dictionary = access_stats.reads
                    else:
                        dictionary = access_stats.writes
                    # This dictionary is "offset inside the range -> (dict 'function name -> all its accesses')"
                    if offset not in dictionary:
                        dictionary[offset] = {}

                    # Make a replacement if needed
                    func_name = access_info.fun_name
                    if access_info.fun_name.startswith("z_un_"):
                        if access_info.fun_name[5:] in addr_to_name:
                            func_name = addr_to_name[access_info.fun_name[5:]]

                    if func_name not in dictionary[offset]:
                        dictionary[offset][func_name] = FunctionMemoryAccesses(func_name)
                    memory_access = MemoryAccess(access_info.size, access_info.info, offset, access_info.pc)
                    dictionary[offset][func_name].accesses.add(memory_access)

            print("accesses_info filled!")
            for address, access_stats in accesses_info.items():
                reads_path = path / f"{access_stats.address:X}_reads.hexpat"
                writes_path = path / f"{access_stats.address:X}_writes.hexpat"
                create_pattern_file(reads_path, False, access_stats)
                create_pattern_file(writes_path, True, access_stats)
