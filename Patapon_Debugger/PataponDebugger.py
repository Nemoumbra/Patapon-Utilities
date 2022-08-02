import PPSSPPDebugger
import asyncio
from typing import Callable, List, Dict, Union, Tuple, Any, NamedTuple
import FrozenKeysDict
import copy
# from collections import namedtuple
# import csv


def load_file_by_path(path: str) -> bytes:
    with open(path, "rb") as source:
        return source.read()


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


class Memory_entity:
    def __init__(self):
        self.memory_location: int = 0
        self.size: int = 0
        self.raw_data: bytes = b""

    def initialize_by_raw_data(self, raw: bytes):
        self.raw_data = raw
        self.size = len(raw)


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


class PAC_instruction:
    def __init__(self, instr_info: List[str], args_info: List[str]):
        # address;A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;
        # raw_size, ext_name and param_amount are unused so far
        # raw_size(hex) == 0 <=> size unknown
        self.function_address: int = int(instr_info[0], 16)
        self.signature: int = int("".join(instr_info[1:5]), 16)
        self.name: str = instr_info[6]
        self.description: str = instr_info[8]
        # param_1_type;param_1_name;param_2_type;param_2_name...
        self.PAC_params: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()
        # Let's make a list of PAC_instruction_param
        zipped = zip(args_info[0::2], args_info[1::2])
        to_namedtuple = [PAC_instruction_param(*i) for i in zipped]
        args: Dict[PAC_instruction_param, Any] = dict.fromkeys(to_namedtuple)

        self.PAC_params.initialize_from_dict(args)
        pass
        # What I want: self.PAC_params[i].type, self.PAC_params[i].name and self.PAC_params[i].value


class PAC_message_table(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.msg_count: int = 0


class PAC_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.instructions_count: int = 0
        self.contains_msg_table: bool = False
        self.msg_table: PAC_message_table = PAC_message_table()
        self.instructions: FrozenKeysDict = FrozenKeysDict.FrozenKeysDict()


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
        self.PAC_name_to_signature: Dict[str, int] = {}
        self.PAC_instructions: Dict[int, PAC_instruction] = {}

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
                # address;A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;
                # param_1_type;param_1_name;param_2_type;param_2_name...
                instr_info = words[0:10]
                args_info = words[10:]

                instruction = PAC_instruction(instr_info, args_info)

                self.PAC_instructions[instruction.signature] = instruction
                self.PAC_name_to_signature[instruction.name] = instruction.signature
                pass

    def parse_PAC_file(self, file: PAC_file):
        if not self.PAC_instructions:
            raise RuntimeError("Instruction set has not been read beforehand!")
        if file.raw_data == b"":
            raise RuntimeError("PAC file raw data is empty!")
        # let's start!
        offset = 0
        previous_offset = 0
        percent = 0x25
        while offset < file.size:
            previous_offset = offset

            # find 0x25 == %
            while file.raw_data[offset] != percent and offset < file.size:
                offset += 1
            # how many bytes have we skipped?
            skipped_count = offset - previous_offset
            if skipped_count != 0:
                # This means that there is an unknown memory entity starting at previous_offset
                # with size == skipped_bytes
                # TO DO : save this entity to the special list
                pass
            # maybe the file ends with raw data?
            if offset == file.size:
                # we are done
                break
            # now read the signature
            signature = read_int_from_bytes(file.raw_data, offset, "big")
            if signature not in self.PAC_instructions.keys():
                # Unknown instruction
                # The tool assumes the whole section between this and the next % is related to this instruction
                pass
            else:
                instruction = copy.deepcopy(self.PAC_instructions[signature])
                # this instruction is known to the tool
                pass

        pass

    def dump_memory(self, address: int, size: int):
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

