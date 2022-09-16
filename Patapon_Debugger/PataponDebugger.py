import PPSSPPDebugger
import asyncio
from typing import Callable, List, Dict, Union, Tuple, Any, NamedTuple, Set
import FrozenKeysDict
# import copy
import struct
from collections import Counter
from pathlib import Path


# from collections import namedtuple
# import csv


def load_file_by_path(path: str) -> bytes:
    with open(path, "rb") as source:
        return source.read()


def read_string_from_bytes(data: bytes, offset: int, length: int = -1) -> str:
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
    i = 0
    offset = 0
    while offset < len(data):
        if i != read_int_from_bytes(data, offset, "little"):
            return False
        i += 1
        offset += 4
    return True


def binary_search(array: List, val: int) -> int:
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
    if array[hi] == val:
        return hi
    return lo


def analyze_instruction_set(file_path: str):
    stats = Counter()
    with open(file_path, encoding="utf-8") as source:
        for line in source:
            words = line.strip().split(";")
            # A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;address;
            # param_1_type;param_1_name;param_2_type;param_2_name...
            arg_types_info = words[10::2]
            for arg_type in arg_types_info:
                if arg_type.startswith("uint32_t_T"):
                    stats["uint32_t_T"] += 1
                elif arg_type.startswith("uintX_t_T"):
                    stats["uintX_t_T"] += 1
                elif arg_type.startswith("COUNT_"):
                    stats["COUNT_"] += 1
                elif arg_type.startswith("CONTINOUS_"):
                    stats["CONTINOUS_"] += 1
                else:
                    stats[arg_type] += 1

    return stats


def read_PAC_string_argument(data: bytes, offset: int) -> Tuple[str, int]:
    original_offset = offset
    while data[offset] != 0:
        offset += 1
    length = offset - original_offset + 1
    return read_shift_jis_from_bytes(data, original_offset, length), length


def is_PAC_instruction(data: bytes, offset: int) -> bool:
    return data[offset] == 0x25 and data[offset + 2] != 0 and data[offset + 3] <= 0x23


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


class MSG_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.msg_count: int = 0
        self.magic: int = 0

    def initialize_by_raw_data(self, raw):
        Memory_entity.initialize_by_raw_data(self, raw)
        self.msg_count = int.from_bytes(self.raw_data[0:4], "little")
        self.magic = int.from_bytes(self.raw_data[4:8], "little")

    def __getitem__(self, index: int) -> str:
        # given that we don't compute strings array when loading
        if self.raw_data == b"":
            raise RuntimeError("MSG file is not initialized")
        if index >= self.msg_count:
            raise IndexError(f"{index} is not a correct index")

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

    # def compute_size(self):
    #     key: PAC_instruction_param
    #     # 0x8913aa0;25;17;2d;00;0;callMessageWindow;callMessageWindow;(description);17;
    #     # uint32_t_T1;Pointer;
    #     # V1;Offset;
    #     # uint32_t_T2;Pointer;
    #     # V2;Offset;
    #     # uint32_t_T3;Pointer;
    #     # V3;Offset;
    #     # uint32_t_T4;Pointer;
    #     # V4;Offset;
    #     # uint32_t_T5;Pointer;
    #     # V5;Offset;
    #     # uint32_t_T6;Pointer;
    #     # V6;Offset;
    #     # uint32_t_T7;Pointer;
    #     # V7;Offset;
    #     # uint32_t_P;Jump destination;
    #     # uint32_t_T8;Pointer;
    #     # V8;Offset
    #
    #     # Removing unnecessary data:
    #     # uint32_t_T1;
    #     # V1;  this is uint32_t
    #
    #     # uint32_t_T2;
    #     # V2;  this is uint32_t
    #
    #     # uint32_t_T3;
    #     # V3;  this is float
    #
    #     # uint32_t_T4;
    #     # V4;  this is float
    #
    #     # uint32_t_T5;
    #     # V5;  this is float
    #
    #     # uint32_t_T6;
    #     # V6;  this is uint32_t
    #
    #     # uint32_t_T7;
    #     # V7;  this is uint32_t
    #
    #     # uint32_t_P;  this is uint32_t
    #
    #     # uint32_t_T8;
    #     # V8;  this is uint32_t
    #
    #     for key in self.PAC_params.keys():
    #         print(key.type)
    #         pass
    #     pass

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

        # NB! Anything but uintX_t, uint32_t_T, string, COUNT, ENTITY_ID and EQUIP_ID should not be used for now!
        for index, param in enumerate(template.PAC_params):
            if param.type == "uintX_t":  # unfinished
                # if offset % 4 == 0:
                #     val = read_int_from_bytes(raw, offset, "little")
                #     # make new PAC_param ?
                #     params_dict[param] = val
                #     offset += 4
                # else:
                #     # offset & (~3) == offset rounded down to the closest number divisible by 4
                #     val = read_custom_int_from_bytes(raw, offset, 4 - (offset % 4), "little")
                #     pass
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)
                val = read_int_from_bytes(raw, offset, "little")
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += 4
            elif param.type.startswith("uintX_t_T"):  # unfinished
                sizeof = 4 - (offset % 4)
                arg_type = read_custom_int_from_bytes(raw, offset, sizeof, "little")
                offset += sizeof

                if arg_type == 0x40:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x40 variable", "Pointer")
                elif arg_type == 0x20:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x20 variable", "Pointer")
                elif arg_type == 0x10:  # float
                    val = read_float_from_bytes(raw, offset)
                    undefined_param = PAC_instruction_param("float", "Pointer")
                elif arg_type == 0x8:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x8 variable", "Pointer")
                elif arg_type == 0x4:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x4 variable", "Pointer")
                elif arg_type == 0x2:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("uint32_t", "Pointer")
                elif arg_type == 0x1:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x1 value", "Pointer")
                else:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("Unknown", "Pointer")

                params_dict[undefined_param] = val
                offset += 4
            elif param.type.startswith("uint32_t_T"):
                arg_type = read_int_from_bytes(raw, offset, "little")
                offset += 4
                undefined_param: PAC_instruction_param

                if arg_type == 0x40:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x40 variable", param.name)
                elif arg_type == 0x20:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x20 variable", param.name)
                elif arg_type == 0x10:  # float
                    val = read_float_from_bytes(raw, offset)
                    undefined_param = PAC_instruction_param("float", param.name)
                elif arg_type == 0x8:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x8 variable", param.name)
                elif arg_type == 0x4:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x4 variable", param.name)
                elif arg_type == 0x2:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("uint32_t", param.name)
                elif arg_type == 0x1:
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("0x1 value", param.name)
                else:
                    if is_PAC_instruction(raw, offset - 4):
                        self.cut_off = True
                        offset -= 4
                        break
                    val = read_int_from_bytes(raw, offset, "little")
                    undefined_param = PAC_instruction_param("Unknown", param.name)

                params_dict[undefined_param] = val
                self.ordered_PAC_params.append((undefined_param, val))
                offset += 4
            elif param.type == "float":
                val = read_float_from_bytes(raw, offset)
                params_dict[param] = val
                offset += 4
            elif param.type == "string":
                # val = read_string_from_bytes(raw, offset)
                # val = read_shift_jis_from_bytes(raw, offset)
                val, length = read_PAC_string_argument(raw, offset)
                params_dict[param] = val
                self.ordered_PAC_params.append((param, val))
                offset += length
            elif param.type.startswith("COUNT_"):  # unfinished
                count = read_int_from_bytes(raw, offset, "little")
                offset += 4
                for i in range(count):
                    val = read_int_from_bytes(raw, offset, "little")
                    count_param = PAC_instruction_param(f"count_{i}", "Unknown")
                    params_dict[count_param] = val
                    self.ordered_PAC_params.append((count_param, val))
                    offset += 4
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
        ans = f"{hex(self.signature)}:{self.name}("
        for pac_param, value in self.ordered_PAC_params:
            pass
    # def initialize(self, raw: bytes, offset: int):
    #     original_offset = offset
    #     offset += 4  # skip the signature
    #     key: PAC_instruction_param
    #     # skip_next_key = False
    #     for key in self.PAC_params.keys():
    #
    #         if key.type == "uintX_t":  # unfinished
    #             pass
    #         elif key.type.startswith("uintX_t_T"):  # unfinished
    #             pass
    #         elif key.type.startswith("uint32_t_T"):
    #             # skip_next_key = True
    #             arg_type = read_int_from_bytes(raw, offset, "little")
    #             offset += 4
    #             if arg_type == 0x10:  # float
    #                 val = read_float_from_bytes(raw, offset)
    #             else:
    #                 val = read_int_from_bytes(raw, offset, "little")
    #             self.PAC_params[key] = val
    #             offset += 4
    #         elif key.type == "float":
    #             val = read_float_from_bytes(raw, offset)
    #             self.PAC_params[key] = val
    #             offset += 4
    #         elif key.type == "string":
    #             val = read_string_from_bytes(raw, offset)
    #             self.PAC_params[key] = val
    #             length = len(val)
    #             offset += length + 2
    #         elif key.type.startswith("COUNT_"):  # unfinished
    #             pass
    #         elif key.type == "uint32_t" or key.type == "uint32_t_P" or key.type == "uint32_t_P_ret":
    #             val = read_int_from_bytes(raw, offset, "little")
    #             self.PAC_params[key] = val
    #             offset += 4
    #             pass
    #         elif key.type.startswith("CONTINOUS_"):  # unfinished
    #             pass
    #         else:
    #             pass
    #     # now we are done, let's initialize raw data
    #     self.initialize_by_raw_data(raw[original_offset:offset])


class Unknown_PAC_instruction(Memory_entity):
    def __init__(self, raw: bytes):
        Memory_entity.__init__(self)
        self.signature = int.from_bytes(raw[0:4], "big")
        self.initialize_by_raw_data(raw)
        pass


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


class PAC_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.instructions_count: int = 0
        self.unknown_instructions_count: int = 0
        self.cut_instructions_count: int = 0
        self.cut_instructions: Dict[int, PAC_instruction] = {}
        self.raw_entities: Dict[int, Memory_entity] = {}
        self.padding_bytes: Dict[int, Padding_bytes] = {}
        self.switch_case_tables: Dict[int, Switch_case_table] = {}
        self.left_out_PAC_arguments: Dict[int, Left_out_PAC_arguments] = {}
        # self.contains_msg_table: bool = False
        self.msg_tables: Dict[int, PAC_message_table] = {}
        self.instructions: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
        self.unknown_instructions: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()  # value type == ?
        self.entities_offsets: List[int] = []
        self.entities: Dict[int, Union[Memory_entity, Padding_bytes, Switch_case_table, PAC_message_table,
                                       Left_out_PAC_arguments, Unknown_PAC_instruction, PAC_instruction]] = {}

    def get_entity_by_offset(self, offset: int) -> Union[Memory_entity, Padding_bytes,
                                                         Switch_case_table, PAC_message_table, Left_out_PAC_arguments,
                                                         Unknown_PAC_instruction, PAC_instruction]:
        starting_offset = self.entities_offsets[binary_search(self.entities_offsets, offset)]
        return self.entities[starting_offset]

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
        self.PAC_name_to_signature: Dict[str, int] = {}

        self.PAC_instruction_templates: Dict[int, PAC_instruction_template] = {}
        self.PAC_instructions: Dict[int, PAC_instruction] = {}
        self.jump_table_next_to_switch = True
        self.unknown_PAC_signatures: Set = set()

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

    def read_instruction_set(self, file_path: str):
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

                # self.PAC_instructions[instruction.signature] = instruction
                # self.PAC_name_to_signature[instruction.name] = instruction.signature
                pass

    def parse_PAC_file(self, file: PAC_file):
        if not self.PAC_instruction_templates:
            raise RuntimeError("Instruction set has not been read beforehand!")
        if file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")
        # let's start!
        signature_to_dict: Dict[int, Dict[int, PAC_instruction]] = {}
        unk_signature_to_dict: Dict[int, Dict[int, Unknown_PAC_instruction]] = {}
        offset = 0
        previous_offset = 0
        percent = 0x25
        message_table_found = False
        while offset < file.size:
            previous_offset = offset
            # find 0x25 == %
            instruction_found = False
            while not instruction_found:
                while offset < file.size and file.raw_data[offset] != percent:
                    offset += 1
                # maybe this is not a real instruction...?
                if offset + 3 < file.size:
                    # well, there is enough bytes, but we're not satisfied yet
                    last_bytes = file.raw_data[offset+2:offset+4]
                    if last_bytes[0] != 0 and last_bytes[1] <= 0x23:
                        # fine...
                        instruction_found = True
                    else:
                        offset += 1
                else:
                    # file ends with something like a cut instruction =>
                    # we need to make it a raw entity and break
                    raw = file.raw_data[previous_offset:]

                    if not message_table_found and is_PAC_msg_table(raw):
                        msg_table = PAC_message_table()
                        msg_table.initialize_by_raw_data(raw)
                        file.msg_tables[previous_offset] = msg_table
                        file.entities[previous_offset] = msg_table
                        message_table_found = True
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
                if not message_table_found and is_PAC_msg_table(raw):
                    msg_table = PAC_message_table()
                    msg_table.initialize_by_raw_data(raw)
                    file.msg_tables[previous_offset] = msg_table
                    file.entities[previous_offset] = msg_table
                    message_table_found = True
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
                        if signature not in unk_signature_to_dict:
                            unk_signature_to_dict[signature] = {}
                        unk_signature_to_dict[signature][offset] = unknown_instruction
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
                if signature not in unk_signature_to_dict:
                    unk_signature_to_dict[signature] = {}
                unk_signature_to_dict[signature][offset] = unknown_instruction
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

                if signature not in signature_to_dict:
                    signature_to_dict[signature] = {}
                signature_to_dict[signature][offset] = instruction
                file.entities[offset] = instruction
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

                if self.jump_table_next_to_switch and instruction.signature == 0x25002f00:
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
        file.instructions.initialize_from_dict(signature_to_dict)
        file.unknown_instructions.initialize_from_dict(unk_signature_to_dict)

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
        file.memory_location = address
        file.name = name
        self.MSG_files[magic] = file
        pass

    def add_MSG(self, file: MSG_file):
        self.MSG_files[file.magic] = file

    def add_PAC(self, address, size):
        pass

    def run_until_jalr_t9(self, jump_address: int):
        # Should be executed after the CPU has begun stepping
        jalr_t9_signature = 0x0320F809  # stored backwards in memory (le)
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

    def run_until_jr_t9(self, jump_address: int):
        pass
