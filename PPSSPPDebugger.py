import enum
from pymem import Pymem
import asyncio
import websockets
import requests
import json
import ipaddress


class PPSSPP_version(enum.Enum):
    _32_bit = 0
    _64_bit = 1


class DebuggerRequest(enum.Enum):
    memory_base = 0
    memory_disasm = 1
    cpu_searchDisasm = 2
    cpu_assemble = 3
    cpu_stepping = 4
    cpu_resume = 5
    cpu_status = 6
    cpu_getAllRegs = 7
    cpu_getReg = 8
    cpu_setReg = 9
    cpu_evaluate = 10
    cpu_breakpoint_add = 11
    cpu_breakpoint_update = 12
    cpu_breakpoint_remove = 13
    cpu_breakpoint_list = 14
    memory_breakpoint_add = 15
    memory_breakpoint_update = 16
    memory_breakpoint_remove = 17
    memory_breakpoint_list = 18
    gpu_buffer_screenshot = 19
    gpu_buffer_renderColor = 20
    gpu_buffer_renderDepth = 21
    gpu_buffer_renderStencil = 22
    gpu_buffer_texture = 23
    gpu_buffer_clut = 24
    gpu_record_dump = 25
    gpu_stats_get = 26
    gpu_stats_feed = 27
    game_reset = 28
    game_status = 29
    version = 30
    hle_thread_list = 31
    hle_thread_wake = 32
    hle_thread_stop = 33
    hle_func_list = 34
    hle_func_add = 35
    hle_func_remove = 36
    hle_func_rename = 37
    hle_module_list = 38
    hle_backtrace = 39
    input_analog = 40
    input_buttons_send = 41
    input_buttons_press = 42
    input_analog_send = 43
    log = 44
    memory_mapping = 45
    memory_info_config = 46
    memory_info_set = 47
    memory_info_list = 48
    memory_info_search = 49
    memory_read_u8 = 50
    memory_read_u16 = 51
    memory_read_u32 = 52
    memory_read = 53
    memory_readString = 54
    memory_write_u8 = 55
    memory_write_u16 = 56
    memory_write_u32 = 57
    memory_write = 58
    replay_begin = 59
    replay_abort = 60
    replay_flush = 61
    replay_execute = 62
    replay_status = 63
    replay_time_get = 64
    replay_time_set = 65
    cpu_stepInto = 66
    cpu_stepOver = 67
    cpu_stepOut = 68
    cpu_runUntil = 69
    cpu_nextHLE = 70


const_32_bit_process_name = "PPSSPPWindows.exe"
const_64_bit_process_name = "PPSSPPWindows64.exe"
const_PPSSPP_match_list_url = "http://report.ppsspp.org/match/list"


def get_IPV4_from_server(ppsspp_match_url):  # is not noexcept
    r = requests.get(ppsspp_match_url)
    r_json = r.json()
    if not r_json:
        # print("Error! Server returned \"[]\", cannot proceed")
        # exit()
        raise RuntimeError("Error! Server returned \"[]\"")

    for obj in r_json:
        if 'ip' in obj:
            try:
                if isinstance(ipaddress.ip_address(obj['ip']), ipaddress.IPv4Address):
                    return obj
            except ValueError:
                pass
    # print("Error! No IPV4 in server's response, cannot proceed")
    raise RuntimeError("Error! Server did not return a valid IPv4 address")


def make_event_request_string(**kwargs):
    return json.dumps(kwargs)


# This will be a class that will be used to make calls to PPSSPP
class PPSSPP_Debugger:
    connection_URI = ""
    version = PPSSPP_version._32_bit
    process = ""
    memory = None

    def __init__(self):
        pass

    def initialize_Pymem(self, version):  # should be surrounded by try except
        self.version = version
        if version == PPSSPP_version._32_bit:
            self.process = const_32_bit_process_name
        else:
            self.process = const_64_bit_process_name
        self.memory = Pymem(self.process)

    def initialize_URI(self):  # # should be surrounded by try except
        listing = get_IPV4_from_server(const_PPSSPP_match_list_url)
        self.connection_URI = f"ws://{listing['ip']}:{listing['p']}/debugger"

    async def memory_base(self):
        request = make_event_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            if "addressHex" not in response:
                raise RuntimeError()
            return response["addressHex"]

    async def memory_disasm(self):
        request = make_event_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_searchDisasm(self):
        request = make_event_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_assemble(self):
        request = make_event_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_stepping(self):
        request = make_event_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

