import PPSSPPDebugger
import asyncio
from typing import Callable, List, Dict, Union, Tuple, Any, NamedTuple
import FrozenKeysDict
# from collections import namedtuple
# import csv


class Memory_entity:
    def __init__(self):
        self.memory_location = 0
        self.size = 0


class Patapon_file(Memory_entity):
    def __init__(self):
        Memory_entity.__init__(self)
        self.name = ""


class MSG_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.msg_count = 0
        self.magic = 0

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
        self.msg_count = 0


class PAC_file(Patapon_file):
    def __init__(self):
        Patapon_file.__init__(self)
        self.instructions_count = 0
        self.contains_msg_table = False
        self.msg_table = PAC_message_table()


class CPU_breakpoint:
    def __init__(self):
        self.address = 0x0
        self.enabled = False
        self.log = False
        self.condition = ""
        self.logFormat = ""


class Memory_breakpoint:
    def __init__(self):
        self.address = 0x0
        self.size = 0
        self.enabled = False
        self.log = False
        self.read = True
        self.write = True
        self.change = True
        self.logFormat = ""


class PataponDebugger:
    def __init__(self):
        self.debugger = PPSSPPDebugger.PPSSPP_Debugger()
        self.MSG_files: List[MSG_file] = []
        self.memory_breakpoints: List[Memory_breakpoint] = []
        self.cpu_breakpoints: List[CPU_breakpoint] = []
        self.cpu_breakpoints_handlers: Dict[int, Callable[[dict], None]] = {}
        self.error = PPSSPPDebugger.const_error_event
        self.PAC_name_to_signature: Dict[str, int] = {}
        self.PAC_instructions: Dict[int, PAC_instruction] = {}

    def read_instruction_set(self, file_path: str):
        with open(file_path, encoding="utf-8") as source:
            for line in source:
                words = line.split(";")
                # address;A;B;C;D;raw_size(hex);function_name;extended_name;function_desc;param_amount;
                # param_1_type;param_1_name;param_2_type;param_2_name...
                instr_info = words[0:10]
                args_info = words[10:]

                instruction = PAC_instruction(instr_info, args_info)

                self.PAC_instructions[instruction.signature] = instruction
                self.PAC_name_to_signature[instruction.name] = instruction.signature
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

    def add_MSG(self, address, size, magic, name):
        # self.MSG_files.append()
        pass


