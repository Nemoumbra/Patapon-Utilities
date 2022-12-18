import time

import PPSSPPDebugger
import asyncio
from typing import Callable, List, Dict, Union, Tuple, Any, NamedTuple, Set, Optional
import FrozenKeysDict
# import copy
import struct
from collections import Counter
from pathlib import Path

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
     - if val is in array, returns its index\n
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


def contains_bsearch(array: List, val: int) -> bool:
    """
    This binary search does the same thing as the operator "in", but faster - O(log(n))\n
    :param array: a list to conduct the search in
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


def read_PAC_var_argument(data: bytes, offset: int, sizeof: int = 4) -> Tuple[str, Union[int, float]]:
    pass


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


# class PAC_params:
#     def __int__(self):
#         count = 0


# PAC_instruction_param = namedtuple("type", "name")

class PAC_instruction_param(NamedTuple):
    type: str
    name: str


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
    # def __init__(self, instr_info: List[str], args_info: List[str]):
    #     Memory_entity.__init__(self)
    #
    #     # address;A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;
    #     # raw_size, ext_name and param_amount are unused so far
    #     # raw_size(hex) == 0 <=> size unknown
    #
    #     self.function_address: int = int(instr_info[0], 16)
    #     self.signature: int = int("".join(instr_info[1:5]), 16)
    #     self.name: str = instr_info[6]
    #     self.description: str = instr_info[8]
    #     # param_1_type;param_1_name;param_2_type;param_2_name...
    #     self.PAC_params: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
    #     # Let's make a list of PAC_instruction_param
    #     zipped = zip(args_info[0::2], args_info[1::2])
    #     to_namedtuple = [PAC_instruction_param(*i) for i in zipped]
    #     args: Dict[PAC_instruction_param, Any] = dict.fromkeys(to_namedtuple)
    #
    #     self.PAC_params.initialize_from_dict(args)
    #     pass
    #     # What I want: self.PAC_params[i].type, self.PAC_params[i].name and self.PAC_params[i].value

    # def initialize_by_raw_data(self, raw: bytes):
    #     # should be called to make a non-template instruction
    #     pass

    # Value types:
    # 0 - uint32_t
    # 1 - float
    # 2 - string
    # 100 - uint32_t_P
    # 10xx - uint32_t_Tx
    # 20xx - Vx
    # * /

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

    # outdated
    def initialize_from_template(self, raw: bytes, offset: int, template: PAC_instruction_template):
        self.function_address = template.function_address
        self.signature = template.signature
        self.name = template.name
        self.description = template.description

        self.PAC_params: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
        params_dict: Dict[PAC_instruction_param, Any] = {}

        original_offset = offset
        offset += 4  # skip the signature

        # TO DO: make sure that every entry in the dict will be distinct
        for param in template.PAC_params:
            if param.type == "uintX_t":  # unfinished
                pass
            elif param.type.startswith("uintX_t_T"):  # unfinished
                pass
            elif param.type.startswith("uint32_t_T"):
                arg_type = read_int_from_bytes(raw, offset, "little")
                offset += 4
                undefined_param: PAC_instruction_param

                if arg_type == 0x40:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x40 variable", "pointer")
                elif arg_type == 0x20:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x20 variable", "pointer")
                elif arg_type == 0x10:  # float
                    val = read_float_from_bytes(raw, offset)
                    undefined_param = PAC_instruction_param("float", "pointer")
                elif arg_type == 0x8:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x8 variable", "pointer")
                elif arg_type == 0x4:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x4 variable", "pointer")
                elif arg_type == 0x2:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("uint32_t", "pointer")
                elif arg_type == 0x1:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x1 value", "pointer")
                else:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("Unknown", "pointer")

                self.PAC_params[undefined_param] = val
                offset += 4
            elif param.type == "float":
                val = read_float_from_bytes(raw, offset)
                params_dict[param] = val
                offset += 4
            elif param.type == "string":
                val = read_string_from_bytes(raw, offset)
                self.PAC_params[param] = val
                length = len(val)
                offset += length + 2  # right...?
            elif param.type.startswith("COUNT_"):  # unfinished
                count = read_int_from_bytes(raw, offset, "little")
                offset += 4
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{i}", "Unknown")
                    self.PAC_params[count_param] = val
                    offset += 4
                pass
            elif param.type == "uint32_t" or param.type == "uint32_t_P" or param.type == "uint32_t_P_ret":
                val = read_int_from_bytes(raw, offset, "little")
                self.PAC_params[param] = val
                offset += 4
                pass
            elif param.type.startswith("CONTINOUS_"):  # unfinished
                # TO DO: fix the typo in the file
                remains = len(raw) - offset
                integer_count = remains // 4
                for i in range(integer_count):
                    val = read_int_from_bytes(raw, offset, "little")
                    continuous_param = PAC_instruction_param(f"continuous_{i}", "Unknown")
                    self.PAC_params[continuous_param] = val
                    offset += 4
                pass
            elif param.type == "ENTITY_ID":
                val = read_int_from_bytes(raw, offset, "little")
                self.PAC_params[param] = val
                offset += 4
                pass
            elif param.type == "EQUIP_ID":
                val = read_int_from_bytes(raw, offset, "little")
                self.PAC_params[param] = val
                offset += 4
                pass
            elif param.type == "KEYBIND_ID":
                val = read_int_from_bytes(raw, offset, "little")
                self.PAC_params[param] = val
                offset += 4
                pass
            else:
                pass
        self.PAC_params.initialize_from_dict(params_dict)
        # we are done now, so let's initialize raw data
        self.initialize_by_raw_data(raw[original_offset:offset])

    def __str__(self):  # unfinished
        ans = f"{hex(self.signature)} ({self.name})"
        return ans
        # for pac_param, value in self.ordered_PAC_params:
        #     pass

    def __repr__(self):
        return f"{hex(self.signature)} ({self.name})"


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


class used_PAC_variables(NamedTuple):
    var_0x4: Set[int]
    var_0x8: Set[int]
    var_0x20: Set[int]
    var_0x40: Set[int]


def get_used_pac_vars(instruction: PAC_instruction) -> used_PAC_variables:
    args = instruction.ordered_PAC_params
    used = used_PAC_variables(set(), set(), set(), set())
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


class EntryPoint:
    def __init__(self):
        self.where_from: List[ExitPoint] = []
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
        self.where_to: List[EntryPoint] = []
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

    def __repr__(self):
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def __str__(self):
        return f"Code block (number of instructions = {len(self.instructions)}, size = {self.size} bytes)"

    def add_jump_to(self, to: int, exit_point: ExitPoint) -> bool:
        # valid_start = contains_bsearch(self.instructions_offsets, to)
        if not contains_bsearch(self.instructions_offsets, to):
            # This means the same as "if to not in self.instructions_offsets"
            if to < self.instructions_offsets[0]:
                self.entry_points[self.start].where_from.append(exit_point)
                exit_point.where_to.append(self.entry_points[self.start])
                return True
            # Angrily stare and report back
            return False

        # Else to is a valid instruction start => self.instructions[to] is valid
        if to not in self.entry_points.keys():
            # Let's make a new entry point here...
            entry_point = EntryPoint()
            # ... initialize it...
            entry_point.code_block = self
            entry_point.instruction = self.instructions[to]
            entry_point.position = to
            entry_point.where_from.append(exit_point)
            # ...and add to the dictionary!
            exit_point.where_to.append(entry_point)
            self.entry_points[to] = entry_point
        else:
            # There is already one there so let's modify it
            self.entry_points[to].where_from.append(exit_point)
            exit_point.where_to.append(self.entry_points[to])
        return True


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

    def get_entity_by_offset(self, offset: int) -> Tuple[int, Union[Memory_entity, Padding_bytes,
                                                                    Switch_case_table, PAC_message_table, Left_out_PAC_arguments,
                                                                    Unknown_PAC_instruction, PAC_instruction]]:
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
    return True


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

    def acceptTemplates(self, PAC_instruction_templates: Dict[int, PAC_instruction_template]):
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
                    if self.mayBeInstruction(struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0]):
                        return True
                    else:
                        self.cur_offset += 1
                else:
                    # Here we test if the signature is known
                    if struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0] in self.templates:
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
        args = Left_out_PAC_arguments(self.file.raw_data[instr_offset:], self.last_offset - instr_offset)
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

        # Special cmd_inxJmp case:
        if self.jump_table_next_to_switch and self.cur_signature == self.cmd_inxJmp_signature:
            res = self.findNextInstruction()
            self.processAddressTable()

        if template.PAC_params and template.PAC_params[-1].type == "string":
            self.fixAlignment()

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
        self.file.unknown_instructions_count += 1
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

    def parse(self):
        if self.file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")

        while self.cur_offset < self.file.size:
            res = self.findNextInstruction()
            if res:
                self.processRawData()
                # now self.last_offset == self.cur_offset
                signature = struct.unpack_from("<i", self.file.raw_data, self.cur_offset)[0]
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

    def parse_PAC_file(self, file: PAC_file):
        # if not self.PAC_instruction_templates:
        #     raise RuntimeError("Instruction set has not been read beforehand!")
        if file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")
        # let's start!
        # signature_to_dict: Dict[int, Dict[int, PAC_instruction]] = {}
        # unk_signature_to_dict: Dict[int, Dict[int, Unknown_PAC_instruction]] = {}
        offset = 0
        previous_offset = 0
        percent = 0x25
        message_table_found = False
        while offset < file.size:
            previous_offset = offset
            # find 0x25 == %
            # if offset > 0x2C0B4:
            #     print("weird part")
            instruction_found = False
            while not instruction_found:
                while offset < file.size and file.raw_data[offset] != percent:
                    offset += 1
                # maybe this is not a real instruction...?
                if offset + 3 < file.size:
                    # well, there is enough bytes, but we're not satisfied yet
                    last_bytes = file.raw_data[offset + 2:offset + 4]
                    if last_bytes[0] != 0 and last_bytes[1] <= 0x23:
                        # fine...
                        instruction_found = True
                    else:
                        offset += 1
                else:
                    # file ends with something like a cut instruction =>
                    # we need to make it a raw entity and break
                    raw = file.raw_data[previous_offset:]

                    # if not message_table_found and is_PAC_msg_table(raw):
                    if is_PAC_msg_table(raw):
                        msg_table = PAC_message_table()
                        msg_table.initialize_by_raw_data(raw)
                        file.msg_tables[previous_offset] = msg_table
                        file.entities[previous_offset] = msg_table
                        # message_table_found = True
                    elif is_left_out_PAC_args(raw) and file.entities_offsets and \
                            isinstance(file.entities[file.entities_offsets[-1]], PAC_instruction):
                        # if the last entity was a PAC instruction
                        instr_offset = file.entities_offsets[-1]
                        args = Left_out_PAC_arguments(file.raw_data[instr_offset:],
                                                      previous_offset - instr_offset)
                        file.left_out_PAC_arguments[previous_offset] = args
                        file.entities[previous_offset] = args
                    else:
                        entity = Memory_entity()
                        entity.initialize_by_raw_data(raw)
                        file.raw_entities[previous_offset] = entity
                        file.entities[previous_offset] = entity
                    file.entities_offsets.append(previous_offset)
                    break
                    # by breaking we leave instruction_found == False
                    pass
            # how many bytes have we skipped?
            if not instruction_found:
                break
            skipped_count = offset - previous_offset  # maybe we can dispose of the skipped_count variable...
            if skipped_count != 0:
                # This means that there is an unknown memory entity starting at previous_offset
                # with size == skipped_bytes
                raw = file.raw_data[previous_offset:offset]
                # if not message_table_found and is_PAC_msg_table(raw):
                if is_PAC_msg_table(raw):
                    msg_table = PAC_message_table()
                    msg_table.initialize_by_raw_data(raw)
                    file.msg_tables[previous_offset] = msg_table
                    file.entities[previous_offset] = msg_table
                    # message_table_found = True
                elif is_left_out_PAC_args(raw) and file.entities_offsets and \
                        isinstance(file.entities[file.entities_offsets[-1]], PAC_instruction):
                    # if the last entity was a PAC instruction
                    instr_offset = file.entities_offsets[-1]
                    args = Left_out_PAC_arguments(file.raw_data[instr_offset:offset], previous_offset - instr_offset)
                    file.left_out_PAC_arguments[previous_offset] = args
                    file.entities[previous_offset] = args
                else:
                    entity = Memory_entity()
                    entity.initialize_by_raw_data(raw)
                    file.raw_entities[previous_offset] = entity
                    file.entities[previous_offset] = entity
                file.entities_offsets.append(previous_offset)
                pass
            # maybe the file ends with raw data?
            if offset == file.size:
                # we are done
                break

            # now read the signature
            # maybe we should make a check before trying to access 4 continuous bytes...?

            signature = read_int_from_bytes(file.raw_data, offset, "big")

            # if signature == 0x25004200:
            #     print("cmd_memset")
            file.entities_offsets.append(offset)
            if signature not in self.PAC_instruction_templates.keys():
                # Unknown instruction
                # The tool assumes the whole section between this and the next % is related to this instruction
                self.unknown_PAC_signatures.add(signature)
                instruction_found = False
                next_instr_offset = offset + 4
                while not instruction_found:
                    while next_instr_offset < file.size and file.raw_data[next_instr_offset] != percent:
                        next_instr_offset += 1
                    # maybe this is not a real instruction...?
                    if next_instr_offset + 3 < file.size:
                        # well, there is enough bytes, but we're not satisfied yet
                        last_bytes = file.raw_data[next_instr_offset + 2:next_instr_offset + 4]
                        if last_bytes[0] != 0 and last_bytes[1] <= 0x23:
                            # fine...
                            instruction_found = True
                        else:
                            next_instr_offset += 1
                    else:
                        # we need to make the whole file suffix a part of this unknown instruction
                        raw = file.raw_data[offset:]
                        unknown_instruction = Unknown_PAC_instruction(raw)
                        if signature not in file.unknown_instructions:
                            file.unknown_instructions[signature] = {}
                        file.unknown_instructions[signature][offset] = unknown_instruction
                        file.entities[offset] = unknown_instruction
                        file.unknown_instructions_count += 1
                        break
                        # by breaking we leave instruction_found == False
                        pass
                if not instruction_found:
                    break

                skipped_count = next_instr_offset - offset
                raw = file.raw_data[offset:next_instr_offset]
                unknown_instruction = Unknown_PAC_instruction(raw)
                if signature not in file.unknown_instructions:
                    file.unknown_instructions[signature] = {}
                file.unknown_instructions[signature][offset] = unknown_instruction
                file.entities[offset] = unknown_instruction

                # The following code is no longer necessary
                # if next_instr_offset == file.size:
                #     # This instruction is the last thing in the file so we can break
                #     break
                offset += skipped_count  # maybe offset = next_instr_offset ?
                file.unknown_instructions_count += 1
            else:
                # this instruction is known to the tool
                template = self.PAC_instruction_templates[signature]
                instruction = PAC_instruction(file.raw_data, offset, template)
                # add it to the dictionary

                # if signature == 0x25000700:
                #     print("cmd_mov")

                if signature not in file.instructions:
                    file.instructions[signature] = {}
                file.instructions[signature][offset] = instruction
                file.entities[offset] = instruction
                file.ordered_instructions[offset] = instruction
                if instruction.cut_off:
                    file.cut_instructions[offset] = instruction
                    file.cut_instructions_count += 1
                offset += instruction.size
                file.instructions_count += 1

                if template.PAC_params and template.PAC_params[-1].type == "string":
                    # alignment might be broken
                    if offset % 4 != 0:
                        padding = Padding_bytes(4)
                        padding_bytes_length = 4 - (offset % 4)
                        padding_raw = file.raw_data[offset:offset + padding_bytes_length]
                        padding.initialize_by_raw_data(padding_raw)
                        file.padding_bytes[offset] = padding
                        file.entities[offset] = padding
                        file.entities_offsets.append(offset)
                        offset += padding_bytes_length
                        pass
                    pass

                if self.jump_table_next_to_switch and instruction.signature == self.inxJmp_signature:
                    previous_offset = offset
                    instruction_found = False
                    while not instruction_found:
                        while offset < file.size and file.raw_data[offset] != percent:
                            offset += 1
                        # maybe this is a part of the table?
                        if offset + 3 < file.size:
                            # well, there is enough bytes, but we're not satisfied yet
                            last_bytes = file.raw_data[offset + 2:offset + 4]
                            if last_bytes[0] != 0 and last_bytes[1] <= 0x23:
                                # fine...
                                instruction_found = True
                            else:
                                offset += 1
                        else:
                            # file ends with something like a cut instruction =>
                            # we need to make it a raw entity and break
                            # This is quite contradictory to what we believe is happening, but why not?
                            raw = file.raw_data[previous_offset:]
                            entity = Memory_entity()
                            entity.initialize_by_raw_data(raw)
                            file.raw_entities[previous_offset] = entity
                            file.entities_offsets.append(previous_offset)
                            file.entities[previous_offset] = entity
                            break
                            # by breaking we leave instruction_found == False
                            pass
                    if not instruction_found:
                        break
                    # Else we have found the switch-case table
                    table = Switch_case_table()
                    table.initialize_by_raw_data(file.raw_data[previous_offset:offset])
                    file.entities_offsets.append(previous_offset)
                    file.entities[previous_offset] = table
                    file.switch_case_tables[previous_offset] = table
                pass

        # We need to make a map <signature, map <location, PAC_instruction>>
        # Prepare dict and initialize FrozenKeysDict with it:
        # file.instructions.initialize_from_dict(signature_to_dict)
        # file.unknown_instructions.initialize_from_dict(file.temp_unknown_instructions)

        pass

    def initialize_PAC_functions(self):  # so far in testing
        pass

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
