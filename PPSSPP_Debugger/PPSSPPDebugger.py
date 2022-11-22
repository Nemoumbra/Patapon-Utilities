import base64
import codecs
import enum
from pymem import Pymem
import asyncio
import websockets
import requests
import json
import ipaddress
from typing import Union, Optional, Set


class PPSSPP_bitness(enum.Enum):
    bitness_32 = 0
    bitness_64 = 1


class DebuggerRequest(enum.Enum):
    memory_base = 0  # needs exception support
    memory_disasm = 1  # needs exception support
    memory_searchDisasm = 2  # needs exception support
    memory_assemble = 3  # needs exception support
    cpu_stepping = 4  # needs exception support
    cpu_resume = 5  # needs exception support
    cpu_status = 6  # needs exception support
    cpu_getAllRegs = 7  # needs exception support
    cpu_getReg = 8  # needs exception support
    cpu_setReg = 9  # needs exception support
    cpu_evaluate = 10  # needs exception support
    cpu_breakpoint_add = 11  # needs exception support
    cpu_breakpoint_update = 12  # needs exception support
    cpu_breakpoint_remove = 13  # needs exception support
    cpu_breakpoint_list = 14  # needs exception support
    memory_breakpoint_add = 15  # needs exception support
    memory_breakpoint_update = 16  # needs exception support
    memory_breakpoint_remove = 17  # needs exception support
    memory_breakpoint_list = 18  # needs exception support

    # GPU section
    gpu_buffer_screenshot = 19
    gpu_buffer_renderColor = 20
    gpu_buffer_renderDepth = 21
    gpu_buffer_renderStencil = 22
    gpu_buffer_texture = 23
    gpu_buffer_clut = 24
    gpu_record_dump = 25
    gpu_stats_get = 26
    gpu_stats_feed = 27

    game_reset = 28  # broken
    game_status = 29  # needs exception support
    version = 30  # needs exception support

    # HLE section
    hle_thread_list = 31  # needs exception support
    hle_thread_wake = 32
    hle_thread_stop = 33
    hle_func_list = 34  # needs exception support
    hle_func_add = 35  # needs exception support
    hle_func_remove = 36  # needs exception support
    hle_func_rename = 37
    hle_func_scan = 69   # needs exception support
    hle_module_list = 38  # needs exception support
    hle_backtrace = 39  # needs exception support

    # Input section
    input_buttons_send = 40
    input_buttons_press = 41
    input_analog_send = 42

    # Memory access section
    memory_mapping = 43
    memory_info_config = 44
    memory_info_set = 45
    memory_info_list = 46
    memory_info_search = 47
    memory_read_u8 = 48  # needs exception support
    memory_read_u16 = 49  # needs exception support
    memory_read_u32 = 50  # needs exception support
    memory_read = 51  # needs exception support
    memory_readString = 52  # needs exception support
    memory_write_u8 = 53  # needs exception support
    memory_write_u16 = 54  # needs exception support
    memory_write_u32 = 55  # needs exception support

    memory_write = 56  # needs exception support
    # (this function is objectively hard to use)

    # Replay section
    replay_begin = 57
    replay_abort = 58
    replay_flush = 59
    replay_execute = 60
    replay_status = 61
    replay_time_get = 62
    replay_time_set = 63

    cpu_stepInto = 64  # needs exception support
    cpu_stepOver = 65  # needs exception support
    cpu_stepOut = 66  # needs exception support
    cpu_runUntil = 67
    cpu_nextHLE = 68


const_32_bit_process_name = "PPSSPPWindows.exe"
const_64_bit_process_name = "PPSSPPWindows64.exe"
const_PPSSPP_match_list_url = "http://report.ppsspp.org/match/list"
const_PPSSPP_connection_base = "ws://{0}:{1}/debugger"
const_error_event = "error"


def make_request_string(**kwargs):
    return json.dumps(kwargs)


async def test_localhost_URI(port: int) -> str:
    request = make_request_string(event="memory.base")
    connection_URI = const_PPSSPP_connection_base.format("127.0.0.1", port)
    print(f"Connecting to {connection_URI}...")
    async with websockets.connect(connection_URI) as ws:
        await ws.send(request)
        response = json.loads(await ws.recv())
    return connection_URI


def get_IPV4_from_server(ppsspp_match_url) -> str:
    print(f"Connecting to \"{ppsspp_match_url}\"...")
    resp: requests.Response
    try:
        resp = requests.get(ppsspp_match_url, timeout=3)
    except requests.Timeout:
        print(f"Connection timed out!")
        # Maybe this is where we retry for some time
        raise RuntimeError("Cannot connect to server")
    resp_json = resp.json()
    if not resp_json:
        raise RuntimeError("Error! Server returned \"[]\"")
    for entry in resp_json:
        if "ip" in entry:
            try:
                if isinstance(ipaddress.ip_address(entry["ip"]), ipaddress.IPv4Address):
                    return const_PPSSPP_connection_base.format(entry["ip"], entry["p"])
            except ValueError:
                pass
    raise RuntimeError("Error! Server did not return a valid IPv4 address")


def prepare_URI(ppsspp_match_url: str, port=-1) -> str:
    # we try to check localhost URI
    if port != -1:
        try:
            return asyncio.run(test_localhost_URI(port))
        except Exception:
            print(f"Unable to use {port = }")
    # if we fail, we try to reach out to server
    return get_IPV4_from_server(ppsspp_match_url)


# This will be a class that will be used to make calls to PPSSPP
class PPSSPP_Debugger:
    connection_URI = ""
    emulator_version = PPSSPP_bitness.bitness_32
    process = ""
    memory = None
    PPSSPP_base_address = 0

    def __init__(self):
        pass

    def initialize_Pymem(self, version):  # should be surrounded by try except
        self.emulator_version = version
        if version == PPSSPP_bitness.bitness_32:
            self.process = const_32_bit_process_name
        else:
            self.process = const_64_bit_process_name
        self.memory = Pymem(self.process)

    def initialize_URI(self, port=-1):  # should be surrounded by try except
        URI = prepare_URI(const_PPSSPP_match_list_url, port)
        self.connection_URI = URI

    def initialize_debugger(self):
        response = asyncio.run(self.memory_base())
        address = int(response["addressHex"], 16)
        # the result may be zero if the game is not started
        if address == 0:
            raise RuntimeError("PPSSPP base address initialization error")
        self.PPSSPP_base_address = address

    async def block_until_event(self, receive_event: str, error_event: str) -> dict:
        async with websockets.connect(self.connection_URI) as ws:
            response = json.loads(await ws.recv())
            while response["event"] != receive_event and response["event"] != error_event:
                response = json.loads(await ws.recv())
            return response

    async def block_until_any(self, receive_events: Set[str], error_event: str) -> dict:
        async with websockets.connect(self.connection_URI) as ws:
            response = json.loads(await ws.recv())
            while response["event"] not in receive_events and response["event"] != error_event:
                response = json.loads(await ws.recv())
            return response

    async def send_request_receive_answer(self, request: str, receive_event: str, error_event: str) -> dict:
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            while response["event"] != receive_event and response["event"] != error_event:
                response = json.loads(await ws.recv())
            return response

    async def send_request_receive_any(self, request: str, receive_events: Set[str], error_event: str) -> dict:
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            while response["event"] not in receive_events and response["event"] != error_event:
                response = json.loads(await ws.recv())
            return response

    # Debugger events

    async def memory_base(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_disasm(self, address: int, count: int, end, thread="", displaySymbols=True):  # unfinished
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

        return await self.send_request_receive_answer(request, "memory.disasm", const_error_event)

    async def memory_searchDisasm(self, address: int, match: str, thread="", end="", displaySymbols=True):  # unfinished
        if thread == "":
            request = make_request_string(event="memory.searchDisasm", address=address, end=end, match=match,
                                          displaySymbols=displaySymbols)
        else:
            request = make_request_string(event="memory.searchDisasm", thread=thread, address=address, end=end,
                                          match=match, displaySymbols=displaySymbols)

        return await self.send_request_receive_answer(request, "memory.searchDisasm", const_error_event)

    async def memory_assemble(self, address: int, code: str):  # unfinished
        # doesn't work either
        request = make_request_string(event="memory.assemble", address=address, code=code)

        return await self.send_request_receive_answer(request, "memory.assemble", const_error_event)

    async def cpu_stepping(self):  # unfinished
        request = make_request_string(event="cpu.stepping")

        return await self.send_request_receive_answer(request, "cpu.stepping", const_error_event)

    async def cpu_resume(self):  # unfinished
        request = make_request_string(event="cpu.resume")

        return await self.send_request_receive_answer(request, "cpu.resume", const_error_event)

    async def cpu_status(self):  # unfinished
        request = make_request_string(event="cpu.status")

        return await self.send_request_receive_answer(request, "cpu.status", const_error_event)

    async def cpu_getAllRegs(self, thread=""):  # unfinished
        if thread == "":
            request = make_request_string(event="cpu.getAllRegs")
        else:
            request = make_request_string(event="cpu.getAllRegs", thread=thread)

        return await self.send_request_receive_answer(request, "cpu.getAllRegs", const_error_event)

    async def cpu_getReg(self, name: str, thread="", category="", register=""):  # unfinished
        # But how do we implement a call by category and register index?
        # Maybe we should add an optional pair of parameters for this method and
        # prompt users to use an empty string as name when they use the second way to call it?

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

        return await self.send_request_receive_answer(request, "cpu.getReg", const_error_event)

    async def cpu_setReg(self, name: str, value: Union[int, str], thread="", category="", register=""):  # unfinished
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

        return await self.send_request_receive_answer(request, "cpu.setReg", const_error_event)

    async def cpu_evaluate(self, expression: str, thread=""):  # unfinished
        # don't use curly brackets to access a register
        # now [address, size] works smoothly all of a sudden!
        # even [reg_name, size] works! ... Maybe...
        if thread == "":
            request = make_request_string(event="cpu.evaluate", expression=expression)
        else:
            request = make_request_string(event="cpu.evaluate", thread=thread, expression=expression)

        return await self.send_request_receive_answer(request, "cpu.evaluate", const_error_event)

    async def cpu_breakpoint_add(self, address: int, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.add", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.add", const_error_event)

    async def cpu_breakpoint_update(self, address: int, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.update", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.update", const_error_event)

    async def cpu_breakpoint_remove(self, address: int):  # unfinished
        request = make_request_string(event="cpu.breakpoint.remove", address=address)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.remove", const_error_event)

    async def cpu_breakpoint_list(self):  # unfinished
        request = make_request_string(event="cpu.breakpoint.list")

        return await self.send_request_receive_answer(request, "cpu.breakpoint.list", const_error_event)

    async def memory_breakpoint_add(self, address: int, size: int, enabled=True, log=False, read=True,
                                    write=True, change=False, logFormat=""):  # unfinished
        # if either of read, write or change parameters is present, others must also be included
        request = make_request_string(event="memory.breakpoint.add", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "memory.breakpoint.add", const_error_event)

    async def memory_breakpoint_update(self, address: int, size: int, enabled=True, log=False, read=True,
                                       write=True, change=False, logFormat=""):  # unfinished
        request = make_request_string(event="memory.breakpoint.update", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "memory.breakpoint.update", const_error_event)

    async def memory_breakpoint_remove(self, address: int, size: int):  # unfinished
        request = make_request_string(event="memory.breakpoint.remove", address=address, size=size)

        return await self.send_request_receive_answer(request, "memory.breakpoint.remove", const_error_event)

    async def memory_breakpoint_list(self):  # unfinished
        request = make_request_string(event="memory.breakpoint.list")

        return await self.send_request_receive_answer(request, "memory.breakpoint.list", const_error_event)

    # GPU section

    async def gpu_buffer_screenshot(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_buffer_renderColor(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_buffer_renderDepth(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_buffer_renderStencil(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_buffer_texture(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_buffer_clut(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_record_dump(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_stats_get(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def gpu_stats_feed(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    # GPU section end

    async def game_reset(self, break_=False):  # unfinished
        # game must be running
        # doesn't work on v1.11.3, crashes v1.12.3
        request = make_request_string(event="game.reset")

        return await self.send_request_receive_answer(request, "game.reset", const_error_event)

    async def game_status(self):  # unfinished
        # "paused" = screen where you can load states
        request = make_request_string(event="game.status")

        return await self.send_request_receive_answer(request, "game.status", const_error_event)

    async def version(self):  # unfinished
        request = make_request_string(event="version")

        return await self.send_request_receive_answer(request, "version", const_error_event)

    # HLE section

    async def hle_thread_list(self):  # unfinished
        request = make_request_string(event="hle.thread.list")
        return await self.send_request_receive_answer(request, "hle.thread.list", const_error_event)

    async def hle_thread_wake(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def hle_thread_stop(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def hle_func_list(self):  # unfinished
        request = make_request_string(event="hle.func.list")
        return await self.send_request_receive_answer(request, "hle.func.list", const_error_event)

    async def hle_func_add(self, address: int, size: int = -1, name: Optional[str] = None):  # unfinished
        if size == -1:
            if name is None:
                request = make_request_string(event="hle.func.add", address=address)
            else:
                request = make_request_string(event="hle.func.add", address=address, name=name)
        else:
            if name is None:
                request = make_request_string(event="hle.func.add", address=address, size=size)
            else:
                request = make_request_string(event="hle.func.add", address=address, size=size, name=name)

        return await self.send_request_receive_answer(request, "hle.func.add", const_error_event)

    async def hle_func_remove(self, address: int):  # unfinished
        request = make_request_string(event="hle.func.remove", address=address)
        return await self.send_request_receive_answer(request, "hle.func.remove", const_error_event)

    async def hle_func_removeRange(self, address: int, size: int):  # unfinished
        request = make_request_string(event="hle.func.removeRange", address=address, size=size)
        return await self.send_request_receive_answer(request, "hle.func.removeRange", const_error_event)

    async def hle_func_rename(self, address: int, name: str):  # unfinished
        request = make_request_string(event="hle.func.rename", address=address, name=name)
        return await self.send_request_receive_answer(request, "hle.func.rename", const_error_event)

    async def hle_func_scan(self, address: int, size: int, recreate: bool = False):  # unfinished
        request = make_request_string(event="hle.func.scan", address=address, size=size, recreate=recreate)
        return await self.send_request_receive_answer(request, "hle.func.scan", const_error_event)

    async def hle_module_list(self):  # unfinished
        request = make_request_string(event="hle.module.list")
        return await self.send_request_receive_answer(request, "hle.module.list", const_error_event)

    async def hle_backtrace(self, thread=""):  # unfinished
        if thread == "":
            request = make_request_string(event="hle.backtrace")
        else:
            request = make_request_string(event="hle.backtrace", thread=thread)
        return await self.send_request_receive_answer(request, "hle.backtrace", const_error_event)

    # HLE section end

    # Input section

    async def input_buttons_send(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def input_buttons_press(self, button: str, duration=1):  # unfinished
        request = make_request_string(event="input.buttons.press", button=button, duration=duration)
        return await self.send_request_receive_answer(request, "input.buttons.press", const_error_event)

    async def input_analog_send(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    # Input section end

    # Memory access section

    async def memory_mapping(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_info_config(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_info_set(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_info_list(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_info_search(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def memory_read_u8(self, address: int):  # unfinished
        request = make_request_string(event="memory.read_u8", address=address)
        return await self.send_request_receive_answer(request, "memory.read_u8", const_error_event)

    async def memory_read_u16(self, address: int):  # unfinished
        request = make_request_string(event="memory.read_u16", address=address)
        return await self.send_request_receive_answer(request, "memory.read_u16", const_error_event)

    async def memory_read_u32(self, address: int):  # unfinished
        request = make_request_string(event="memory.read_u32", address=address)
        return await self.send_request_receive_answer(request, "memory.read_u32", const_error_event)

    async def memory_read(self, address: int, size: int, replacements=False):  # unfinished
        # What should the default parameter be equal to? TO DO: check PPSSPP code!
        # I also didn't quite understand what it does exactly...
        request = make_request_string(event="memory.read", address=address, size=size, replacements=replacements)
        return await self.send_request_receive_answer(request, "memory.read", const_error_event)

    async def memory_readString(self, address: int, type="utf-8"):  # unfinished
        request = make_request_string(event="memory.readString", address=address, type=type)
        return await self.send_request_receive_answer(request, "memory.readString", const_error_event)

    async def memory_write_u8(self, address: int, value: int):  # unfinished
        request = make_request_string(event="memory.write_u8", address=address, value=value)
        return await self.send_request_receive_answer(request, "memory.write_u8", const_error_event)

    async def memory_write_u16(self, address: int, value: int):  # unfinished
        request = make_request_string(event="memory.write_u16", address=address, value=value)
        return await self.send_request_receive_answer(request, "memory.write_u16", const_error_event)

    async def memory_write_u32(self, address: int, value: int):  # unfinished
        request = make_request_string(event="memory.write_u32", address=address, value=value)
        return await self.send_request_receive_answer(request, "memory.write_u32", const_error_event)

    async def memory_write(self, address: int, base64: str):  # unfinished
        # This bad because the base64 object is a string for it to be normally put into JSON
        request = make_request_string(event="memory.write", address=address, base64=base64)
        return await self.send_request_receive_answer(request, "memory.write", const_error_event)

    # Memory section end

    # Replay section

    async def replay_begin(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_abort(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_flush(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_execute(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_status(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_time_get(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def replay_time_set(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    # Replay section end

    async def cpu_stepInto(self, thread=""):  # unfinished
        if thread == "":
            request = make_request_string(event="cpu.stepInto")
        else:
            request = make_request_string(event="cpu.stepInto", thread=thread)

        return await self.send_request_receive_answer(request, "cpu.stepping", const_error_event)

    async def cpu_stepOver(self, thread=""):  # unfinished
        # PC == jal instruction => skips the next instruction, use stepInto and then stepOver to check it
        # After playing with stepInto and stepOver I broke PPSSPP v1.11.3. Exercise caution.
        if thread == "":
            request = make_request_string(event="cpu.stepOver")
        else:
            request = make_request_string(event="cpu.stepOver", thread=thread)

        return await self.send_request_receive_answer(request, "cpu.stepping", const_error_event)

    async def cpu_stepOut(self, thread=""):  # unfinished
        if thread == "":
            request = make_request_string(event="cpu.stepOut")
        else:
            request = make_request_string(event="cpu.stepOut", thread=thread)

        return await self.send_request_receive_answer(request, "cpu.stepping", const_error_event)

    async def cpu_runUntil(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def cpu_nextHLE(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

    async def cpu_startLogging(self, filename: Optional[str] = None):
        if filename is not None:
            request = make_request_string(event="cpu.startLogging", filename=filename)
        else:
            request = make_request_string(event="cpu.startLogging")
        return await self.send_request_receive_answer(request, "cpu.startLogging", const_error_event)

    async def cpu_flushLogs(self):
        request = make_request_string(event="cpu.flushLogs")
        return await self.send_request_receive_answer(request, "cpu.flushLogs", const_error_event)

    # High-level functions
    async def memory_write_bytes(self, address: int, byte_str: bytes):
        # The order of bytes in byte_str is the same as in the memory!
        return await self.memory_write(address, base64.b64encode(byte_str).decode("utf-8"))

    def memory_read_byte(self, address: int) -> int:
        # value = self.memory.read_char(self.PPSSPP_base_address + address)  # throws
        value = self.memory.read_bytes(self.PPSSPP_base_address + address, 1)
        return int.from_bytes(value, "little")

    def memory_read_short(self, address: int) -> int:
        value = self.memory.read_short(self.PPSSPP_base_address + address)
        return value

    def memory_read_int(self, address: int) -> int:
        value = self.memory.read_int(self.PPSSPP_base_address + address)
        return value

    def memory_write_byte(self, address: int, value: int):
        self.memory.write_bytes(self.PPSSPP_base_address + address, value.to_bytes(1, "little"), 1)

    def memory_write_short(self, address: int, value: int):
        value = self.memory.write_short(self.PPSSPP_base_address + address, value)

    def memory_write_int(self, address: int, value: int):
        value = self.memory.write_int(self.PPSSPP_base_address + address, value)

    def memory_read_string(self, address: int) -> str:
        res = ""
        base = self.PPSSPP_base_address
        val = int.from_bytes(self.memory.read_bytes(base + address, 1), "big")
        char = self.memory.read_char(base + address)
        while val != 0:
            res += char
            address += 1
            val = int.from_bytes(self.memory.read_bytes(base + address, 1), "big")
            char = self.memory.read_char(base + address)
        return res

    def memory_read_wstring(self, address: int) -> str:
        res = ""
        base = self.PPSSPP_base_address
        two_bytes = self.memory.read_bytes(base + address, 2)
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("utf-16")
        while val != 0:
            res += char
            address += 2
            two_bytes = self.memory.read_bytes(base + address, 2)
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("utf-16")
        return res

    def memory_read_shift_jis_string(self, address: int) -> str:
        res = ""
        base = self.PPSSPP_base_address
        two_bytes = self.memory.read_bytes(base + address, 2)
        val = int.from_bytes(two_bytes, "big")
        char = two_bytes.decode("shift-jis")
        while val != 0:
            res += char
            address += 2
            two_bytes = self.memory.read_bytes(base + address, 2)
            val = int.from_bytes(two_bytes, "big")
            char = two_bytes.decode("shift-jis")
        return res

    def memory_write_string(self, address: int, value: str):
        self.memory.write_string(self.PPSSPP_base_address + address, value)

    def memory_write_wstring(self, address: int, value: str):
        base = self.PPSSPP_base_address
        str_bytes = value.encode("utf-16le")
        self.memory.write_bytes(base + address, str_bytes, len(str_bytes))
        # for char in value:
        #     two_bytes = char.encode("utf-16le")
        #     # ok, str.encode adds BOM to the start, that's bad
        #     self.memory.write_bytes(base + address, two_bytes, 2)
        #     address += 2
        pass

    def memory_write_shift_jis_string(self, address: int, value: str):
        base = self.PPSSPP_base_address
        str_bytes = value.encode("shift-jis")
        self.memory.write_bytes(base + address, str_bytes, len(str_bytes))
        pass

