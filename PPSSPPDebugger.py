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


def make_request_string(**kwargs):
    return json.dumps(kwargs)


# This will be a class that will be used to make calls to PPSSPP
class PPSSPP_Debugger:
    connection_URI = ""
    emulator_version = PPSSPP_version._32_bit
    process = ""
    memory = None

    def __init__(self):
        pass

    def initialize_Pymem(self, version):  # should be surrounded by try except
        self.emulator_version = version
        if version == PPSSPP_version._32_bit:
            self.process = const_32_bit_process_name
        else:
            self.process = const_64_bit_process_name
        self.memory = Pymem(self.process)

    def initialize_URI(self):  # # should be surrounded by try except
        listing = get_IPV4_from_server(const_PPSSPP_match_list_url)
        self.connection_URI = f"ws://{listing['ip']}:{listing['p']}/debugger"

    async def memory_base(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            if "addressHex" not in response:
                raise RuntimeError()
            return response["addressHex"]

    async def memory_disasm(self, address, count, end, thread="", displaySymbols=True):  # unfinished
        # end is the address after the last one that needs to be disassembled
        # I have no idea how displaySymbols works
        if thread == "":
            if count == "":
                request = make_request_string(event="memory.disasm", address=address, end=end,
                                              displaySymbols=displaySymbols)
            else:
                request = make_request_string(event="memory.disasm", address=address, count=count,
                                              displaySymbols=displaySymbols)
                # Test:
                # request = make_request_string(event="memory.disasm", address=address, count=count)
        else:
            if count == "":
                request = make_request_string(event="memory.disasm", thread=thread, address=address, end=end,
                                              displaySymbols=displaySymbols)
            else:
                request = make_request_string(event="memory.disasm", thread=thread, address=address, count=count,
                                              displaySymbols=displaySymbols)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def cpu_searchDisasm(self, address, match, thread="", end="", displaySymbols=True):  # unfinished
        # for some reason PPSSPP does not recognise this event
        if thread == "":
            request = make_request_string(event="cpu.searchDisasm", address=address, end=end, match=match,
                                          displaySymbols=displaySymbols)
        else:
            request = make_request_string(event="cpu.searchDisasm", thread=thread, address=address, end=end,
                                          match=match, displaySymbols=displaySymbols)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def cpu_assemble(self, address, code):  # unfinished
        # doesn't work either
        request = make_request_string(event="cpu.assemble", address=address, code=code)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def cpu_stepping(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_resume(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_status(self):  # unfinished
        request = make_request_string(event="cpu.status")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def cpu_getAllRegs(self, thread=""):  # unfinished
        if thread == "":
            request = make_request_string(event="cpu.getAllRegs")
        else:
            request = make_request_string(event="cpu.getAllRegs", thread=thread)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response

    async def cpu_getReg(self, name, thread="", category="", register=""):  # unfinished
        if thread == "":
            if name == "":
                request = make_request_string(event="cpu.getReg", category=category, register=register)
            else:
                request = make_request_string(event="cpu.getReg", name=name)
        else:
            if name == "":
                request = make_request_string(event="cpu.getReg", thread=thread, category=category, register=register)
            else:
                request = make_request_string(event="cpu.getReg", thread=thread, name=name)

        # But how do we implement a call by category and register index?
        # Maybe we should add an optional pair of parameters for this method and
        # prompt users to use an empty string as name when they use the second way to call it?

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error occurs, raise exception
            return response

    async def cpu_setReg(self, name, value, thread="", category="", register=""):  # unfinished
        if thread == "":
            if name == "":
                request = make_request_string(event="cpu.setReg", category=category,
                                              register=register, value=value)
            else:
                request = make_request_string(event="cpu.setReg", name=name, value=value)
        else:
            if name == "":
                request = make_request_string(event="cpu.setReg", thread=thread, category=category,
                                              register=register, value=value)
            else:
                request = make_request_string(event="cpu.setReg", thread=thread, name=name, value=value)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def cpu_evaluate(self, expression, thread=""):  # unfinished
        # don't use curly brackets to access a register
        # now [address, size] works smoothly all of a sudden!
        # even [reg_name, size] works!
        if thread == "":
            request = make_request_string(event="cpu.evaluate", expression=expression)
        else:
            request = make_request_string(event="cpu.evaluate", thread=thread, expression=expression)

        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def cpu_breakpoint_add(self, address, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.add", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def cpu_breakpoint_update(self, address, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.update", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def cpu_breakpoint_remove(self, address):  # unfinished
        request = make_request_string(event="cpu.breakpoint.remove", address=address)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def cpu_breakpoint_list(self):  # unfinished
        request = make_request_string(event="cpu.breakpoint.list")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def memory_breakpoint_add(self, address, size, enabled=True, log=False, read=True,
                                    write=True, change=False, logFormat=""):  # unfinished
        # if either of read, write or change parameters is present, others must also be included
        request = make_request_string(event="memory.breakpoint.add", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def memory_breakpoint_update(self, address, size, enabled=True, log=False, read=True,
                                    write=True, change=False, logFormat=""):  # unfinished
        request = make_request_string(event="memory.breakpoint.update", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def memory_breakpoint_remove(self, address, size):  # unfinished
        request = make_request_string(event="memory.breakpoint.remove", address=address, size=size)
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def memory_breakpoint_list(self):  # unfinished
        request = make_request_string(event="memory.breakpoint.list")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def gpu_buffer_screenshot(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_buffer_renderColor(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_buffer_renderDepth(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_buffer_renderStencil(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_buffer_texture(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_buffer_clut(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_record_dump(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_stats_get(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def gpu_stats_feed(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def game_reset(self):  # unfinished
        # game must be running
        # doesn't work on v1.11.3, crashes v1.12.3
        request = make_request_string(event="game.reset")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            # if error, raise exception

    async def game_status(self):  # unfinished
        # "paused" = screen where you can load states
        request = make_request_string(event="game.status")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
            # if error, raise exception

    async def version(self):  # unfinished
        request = make_request_string(event="version")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            return response
        # if error, raise exception

    async def hle_thread_list(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_thread_wake(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_thread_stop(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_func_list(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_func_add(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_func_remove(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_func_rename(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_module_list(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def hle_backtrace(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def input_analog(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def input_buttons_send(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def input_buttons_press(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def input_analog_send(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def log(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_mapping(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_info_config(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_info_set(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_info_list(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_info_search(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_read_u8(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_read_u16(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_read_u32(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_read(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_readString(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_write_u8(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_write_u16(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_write_u32(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def memory_write(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_begin(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_abort(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_flush(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_execute(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_status(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_time_get(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def replay_time_set(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_stepInto(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_stepOver(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_stepOut(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_runUntil(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_nextHLE(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
