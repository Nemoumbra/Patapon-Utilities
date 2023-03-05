import base64
import codecs
import enum
from pymem import Pymem
import asyncio
import websockets
import requests
import json
import ipaddress
from typing import Union, Optional, Set, Dict, Tuple, Any


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
    hle_func_rename = 37  # needs exception support
    hle_func_scan = 69   # needs exception support
    hle_module_list = 38  # needs exception support
    hle_backtrace = 39  # needs exception support

    # Input section
    input_buttons_send = 40  # needs exception support
    input_buttons_press = 41  # needs exception support
    input_analog_send = 42

    memory_mapping = 43  # needs exception support
    memory_info_config = 44  # needs exception support
    memory_info_set = 45  # needs exception support
    memory_info_list = 46  # needs exception support
    memory_info_search = 47

    # Memory access section
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


# Technically speaking, there are 4 process names
const_32_bit_process_name = "PPSSPPWindows.exe"
# const_64_bit_process_name = "PPSSPPWindows64.exe"
const_64_bit_process_name = "PPSSPPDebug64.exe"
const_PPSSPP_match_list_url = "http://report.ppsspp.org/match/list"
const_PPSSPP_connection_base = "ws://{0}:{1}/debugger"
const_error_event = "error"


class API_args:
    def __init__(self, event: str):
        self._args: dict = {"event": event}

    def add(self, name: Optional[str] = None, value: Optional[Any] = None, /, **kwargs):
        if (name is not None) and (value is not None):
            self._args[name] = value
        self._args.update(kwargs)

    def __str__(self):
        return json.dumps(self._args)


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
                # If the constructor fails, we don't reach the return statement
                pass
    raise RuntimeError("Error! Server did not return a valid IPv4 address")


def prepare_URI(ppsspp_match_url: str, port=-1) -> str:
    # we try to check localhost URI
    if port != -1:
        try:
            ret = asyncio.run(test_localhost_URI(port))
            print("Success!")
            return ret
        except Exception:
            print(f"Unable to use {port = }")
    # If we fail, we try to reach out to the server
    ret = get_IPV4_from_server(ppsspp_match_url)
    print("Using server URI:", ret)
    return ret


# This will be a class that will be used to make calls to PPSSPP
class PPSSPP_Debugger:
    connection_URI = ""
    emulator_version = PPSSPP_bitness.bitness_32
    process = ""
    memory = None
    PPSSPP_base_address = 0

    def __init__(self):
        pass

    def initialize_Pymem(self, version):  # should be surrounded by try except or not
        self.emulator_version = version
        if version == PPSSPP_bitness.bitness_32:
            self.process = const_32_bit_process_name
        else:
            self.process = const_64_bit_process_name
        try:
            self.memory = Pymem(self.process)
        except Exception as e:
            print("Pymem initialization error:", e)

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
        event = "memory.base"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_disasm(self, address: int, count: int, end, thread="", displaySymbols=True):  # unfinished
        # end is the address after the last one that needs to be disassembled
        # I have no idea how displaySymbols works
        event = "memory.disasm"
        args = API_args(event)
        args.add(address=address, displaySymbols=displaySymbols)
        if count == "":
            args.add(end=end)
        else:
            args.add(count=count)

        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_searchDisasm(self, address: int, match: str, thread="", end="", displaySymbols=True):  # unfinished
        event = "memory.searchDisasm"
        args = API_args(event)
        args.add(address=address, end=end, match=match, displaySymbols=displaySymbols)

        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_assemble(self, address: int, code: str):  # unfinished
        event = "memory.assemble"
        args = API_args(event)
        args.add(address=address, code=code)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_stepping(self):  # unfinished
        event = "cpu.stepping"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_resume(self):  # unfinished
        event = "cpu.resume"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_status(self):  # unfinished
        event = "cpu.status"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getAllRegs(self, thread=""):  # unfinished
        event = "cpu.getAllRegs"
        args = API_args(event)
        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getReg(self, name: str, thread="", category="", register=""):  # unfinished
        # But how do we implement a call by category and register index?
        # Maybe we should add an optional pair of parameters for this method and
        # prompt users to use an empty string as name when they use the second way to call it?
        event = "cpu.getReg"
        args = API_args(event)

        if thread != "":
            args.add(thread=thread)
        if name != "":
            args.add(name=name)
        else:
            args.add(category=category, register=register)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_setReg(self, name: str, value: Union[int, str], thread="", category="", register=""):  # unfinished
        event = "cpu.setReg"
        args = API_args(event)

        args.add(value=value)
        if thread != "":
            args.add(thread=thread)
        if name != "":
            args.add(name=name)
        else:
            args.add(category=category, register=register)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_evaluate(self, expression: str, thread=""):  # unfinished
        # don't use curly brackets to access a register
        # now [address, size] works smoothly all of a sudden!
        # even [reg_name, size] works! ... Maybe...
        event = "cpu.evaluate"
        args = API_args(event)

        args.add(expression=expression)
        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_breakpoint_add(self, address: int, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        event = "cpu.breakpoint.add"
        args = API_args(event)
        args.add(address=address, enabled=enabled, log=log, condition=condition, logFormat=logFormat)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_breakpoint_update(self, address: int, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        event = "cpu.breakpoint.update"
        args = API_args(event)
        args.add(address=address, enabled=enabled, log=log, condition=condition, logFormat=logFormat)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_breakpoint_remove(self, address: int):  # unfinished
        event = "cpu.breakpoint.remove"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_breakpoint_list(self):  # unfinished
        event = "cpu.breakpoint.list"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_breakpoint_add(self, address: int, size: int, enabled=True, log=False, read=True,
                                    write=True, change=False, logFormat=""):  # unfinished
        # If either of read, write or change parameters is present, others must also be included
        event = "memory.breakpoint.add"
        args = API_args(event)
        args.add(address=address, size=size, enabled=enabled, log=log, read=read, write=write,
                 change=change, logFormat=logFormat)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_breakpoint_update(self, address: int, size: int, enabled=True, log=False, read=True,
                                       write=True, change=False, logFormat=""):  # unfinished
        event = "memory.breakpoint.update"
        args = API_args(event)
        args.add(address=address, size=size, enabled=enabled, log=log, read=read, write=write,
                 change=change, logFormat=logFormat)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_breakpoint_remove(self, address: int, size: int):  # unfinished
        event = "memory.breakpoint.remove"
        args = API_args(event)
        args.add(address=address, size=size)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_breakpoint_list(self):  # unfinished
        event = "memory.breakpoint.list"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # GPU section

    async def gpu_buffer_screenshot(self, type: str, alpha: Optional[bool] = None):  # unfinished
        event = "gpu.buffer.screenshot"
        args = API_args(event)
        args.add(type=type)
        if alpha is not None:
            args.add(alpha=alpha)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_buffer_renderColor(self, type: str, alpha: Optional[bool] = None):  # unfinished
        event = "gpu.buffer.renderColor"
        args = API_args(event)
        args.add(type=type)
        if alpha is not None:
            args.add(alpha=alpha)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_buffer_renderDepth(self, type: str, alpha: Optional[bool] = None):  # unfinished
        event = "gpu.buffer.renderDepth"
        args = API_args(event)
        args.add(type=type)
        if alpha is not None:
            args.add(alpha=alpha)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_buffer_renderStencil(self, type: str, alpha: Optional[bool] = None):  # unfinished
        event = "gpu.buffer.renderStencil"
        args = API_args(event)
        args.add(type=type)
        if alpha is not None:
            args.add(alpha=alpha)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_buffer_texture(self, type: str, alpha: Optional[bool] = None, level: int = 0):  # unfinished
        event = "gpu.buffer.texture"
        args = API_args(event)
        args.add(type=type, level=level)
        if alpha is not None:
            args.add(alpha=alpha)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_buffer_clut(self, type: str, alpha: Optional[bool] = None, stackWidth: Optional[int] = None):  # unfinished
        event = "gpu.buffer.clut"
        args = API_args(event)
        args.add(type=type)
        if alpha is not None:
            args.add(alpha=alpha)
        if stackWidth is not None:
            args.add(stackWidth=stackWidth)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_record_dump(self):  # unfinished
        event = "gpu.record.dump"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_stats_get(self):  # unfinished
        event = "gpu.stats.get"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def gpu_stats_feed(self, enable: bool = True):  # unfinished
        event = "gpu.stats.feed"
        args = API_args(event)
        args.add(enable=enable)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # GPU section end

    async def game_reset(self, break_=False):  # unfinished
        # Game must be running
        # Doesn't work on v1.11.3, crashes v1.12.3
        event = "game.reset"
        args = API_args(event)
        args.add("break", break_)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def game_status(self):  # unfinished
        # "paused" = screen where you can load states
        event = "game.status"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def version(self):  # unfinished
        event = "version"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # HLE section

    async def hle_thread_list(self):  # unfinished
        event = "hle.thread.list"
        args = API_args(event)
        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_thread_wake(self, thread: int):  # unfinished
        event = "hle.thread.wake"
        args = API_args(event)
        args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_thread_stop(self, thread: int):  # unfinished
        event = "hle.thread.stop"
        args = API_args(event)
        args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_list(self):  # unfinished
        event = "hle.func.list"
        args = API_args(event)
        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_add(self, address: int, size: int = -1, name: Optional[str] = None):  # unfinished
        event = "hle.func.add"
        args = API_args(event)
        args.add(address=address)
        if size != -1:
            args.add(size=size)
        if name is not None:
            args.add(name=name)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_remove(self, address: int):  # unfinished
        event = "hle.func.remove"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_removeRange(self, address: int, size: int):  # unfinished
        event = "hle.func.removeRange"
        args = API_args(event)
        args.add(address=address, size=size)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_rename(self, address: int, name: str):  # unfinished
        event = "hle.func.rename"
        args = API_args(event)
        args.add(address=address, name=name)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_func_scan(self, address: int, size: int, recreate: bool = False):  # unfinished
        event = "hle.func.scan"
        args = API_args(event)
        args.add(address=address, size=size, recreate=recreate)
        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_module_list(self):  # unfinished
        event = "hle.module.list"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def hle_backtrace(self, thread=""):  # unfinished
        event = "hle.backtrace"
        args = API_args(event)
        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # HLE section end

    # Input section

    async def input_buttons_send(self, **kwargs):  # unfinished
        event = "input.buttons.send"
        args = API_args(event)
        args.add(buttons=kwargs)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def input_buttons_press(self, button: str, duration=1):  # unfinished
        event = "input.buttons.press"
        args = API_args(event)
        args.add(button=button, duration=duration)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def input_analog_send(self, x: float, y: float, stick: Optional[str] = "left"):  # unfinished
        if abs(x) > 1 or abs(y) > 1:
            raise AssertionError("Arguments 'x' and 'y' must be from -1.0 to 1.0")

        event = "input.analog.send"
        args = API_args(event)
        args.add(x=x, y=y, stick=stick)
        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # Input section end

    # Memory access section

    async def memory_mapping(self):  # unfinished
        event = "memory.mapping"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_info_config(self, detailed: Optional[bool] = None):  # unfinished
        event = "memory.info.config"
        args = API_args(event)
        if detailed is not None:
            args.add(detailed=detailed)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_info_set(self, address: int, size: int, type: str, tag: str, pc: Optional[int] = None):
        event = "memory.info.set"
        args = API_args(event)
        args.add(address=address, size=size, type=type)

        if pc is not None:
            args.add(pc=pc)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_info_list(self, address: int, size: int, type: str):  # unfinished
        event = "memory.info.list"
        args = API_args(event)
        args.add(address=address, size=size, type=type)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_info_search(self, match: str, address: Optional[int] = None, end: Optional[int] = None,
                                 type: Optional[str] = None):  # unfinished
        event = "memory.info.search"
        args = API_args(event)
        args.add(match=match)
        if type is not None:
            args.add(type=type)

        if address is None and end is None:
            raise AssertionError("Both parameters 'address' and 'end' are omitted")

        if address is not None:
            args.add(address=address)

        if end is not None:
            args.add(end=end)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_read_u8(self, address: int):  # unfinished
        event = "memory.read_u8"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_read_u16(self, address: int):  # unfinished
        event = "memory.read_u16"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_read_u32(self, address: int):  # unfinished
        event = "memory.read_u32"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_read(self, address: int, size: int, replacements=False):  # unfinished
        # What should the default parameter be equal to? TO DO: check PPSSPP code!
        # I also didn't quite understand what it does exactly...
        event = "memory.read"
        args = API_args(event)
        args.add(address=address, size=size, replacements=replacements)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_readString(self, address: int, type="utf-8"):  # unfinished
        event = "memory.readString"
        args = API_args(event)
        args.add(address=address, type=type)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_write_u8(self, address: int, value: int):  # unfinished
        event = "memory.write_u8"
        args = API_args(event)
        args.add(address=address, value=value)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_write_u16(self, address: int, value: int):  # unfinished
        event = "memory.write_u16"
        args = API_args(event)
        args.add(address=address, value=value)
        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_write_u32(self, address: int, value: int):  # unfinished
        event = "memory.write_u32"
        args = API_args(event)
        args.add(address=address, value=value)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def memory_write(self, address: int, base64: str):  # unfinished
        # This bad because the base64 object is a string for it to be normally put into JSON
        event = "memory.write"
        args = API_args(event)
        args.add(address=address, base64=base64)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # Memory section end

    # Replay section

    async def replay_begin(self):  # unfinished
        event = "replay.begin"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_abort(self):  # unfinished
        event = "replay.abort"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_flush(self):  # unfinished
        event = "replay.flush"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_execute(self, version: int, base64: str):  # unfinished
        event = "replay.execute"
        args = API_args(event)
        args.add(version=version, base64=base64)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_status(self):  # unfinished
        event = "replay.status"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_time_get(self):  # unfinished
        event = "replay.time.get"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def replay_time_set(self, value: int):  # unfinished
        event = "replay.time.set"
        args = API_args(event)
        args.add(value=value)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    # Replay section end

    async def cpu_stepInto(self, thread=""):  # unfinished
        await_event = "cpu.stepping"
        event = "cpu.stepInto"
        args = API_args(event)
        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, await_event, const_error_event)

    async def cpu_stepOver(self, thread=""):  # unfinished
        # PC == jal instruction => skips the next instruction, use stepInto and then stepOver to check it
        # After playing with stepInto and stepOver I broke PPSSPP v1.11.3. Exercise caution.
        await_event = "cpu.stepping"
        event = "cpu.stepOver"
        args = API_args(event)
        if thread != "":
            args.add(thread=thread)

        request = str(args)
        return await self.send_request_receive_answer(request, await_event, const_error_event)

    async def cpu_stepOut(self, thread=""):  # unfinished
        await_event = "cpu.stepping"
        event = "cpu.stepOut"
        args = API_args(event)
        if thread != "":
            args.add(thread=thread)
        request = str(args)

        return await self.send_request_receive_answer(request, await_event, const_error_event)

    async def cpu_runUntil(self, address: int):  # unfinished
        event = "cpu.runUntil"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_nextHLE(self):  # unfinished
        event = "cpu.nextHLE"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_startLogging(self, filename: Optional[str] = None):
        event = "cpu.startLogging"
        args = API_args(event)
        if filename is not None:
            args.add(filename=filename)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_flushLogs(self, filename: Optional[str] = None):
        event = "cpu.flushLogs"
        args = API_args(event)
        if filename is not None:
            args.add(filename=filename)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getLoggingSettings(self):
        event = "cpu.getLoggingSettings"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getLoggingForbiddenRanges(self):
        event = "cpu.getLoggingForbiddenRanges"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_loggerForbidRange(self, start: int, size: int):
        event = "cpu.loggerForbidRange"
        args = API_args(event)
        args.add(start=start, size=size)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_loggerAllowRange(self, start: int, size: int):
        event = "cpu.loggerAllowRange"
        args = API_args(event)
        args.add(start=start, size=size)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_loggerUpdateInfo(self, address: int, log_info: Optional[str] = None):
        event = "cpu.loggerUpdateInfo"
        args = API_args(event)
        args.add(address=address)

        if log_info is not None:
            args.add(log_info=log_info)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getLoggerInfo(self):
        event = "cpu.getLoggerInfo"
        args = API_args(event)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_getLoggerInfoAt(self, address: int):
        event = "cpu.getLoggerInfoAt"
        args = API_args(event)
        args.add(address=address)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

    async def cpu_updateLoggerSettings(self, mode=None, maxCount=None, flushWhenFull=None,
                                       ignoreForbiddenWhenRecording=None, lastLinesCount=None):
        if mode is None and maxCount is None and flushWhenFull is None and \
                ignoreForbiddenWhenRecording is None and lastLinesCount is None:
            raise AssertionError("At least one parameter must be not None")

        event = "cpu.updateLoggerSettings"
        args = API_args(event)
        if mode is not None:
            args.add(mode=mode)
        if maxCount is not None:
            args.add(maxCount=maxCount)
        if flushWhenFull is not None:
            args.add(flushWhenFull=flushWhenFull)
        if ignoreForbiddenWhenRecording is not None:
            args.add(ignoreForbiddenWhenRecording=ignoreForbiddenWhenRecording)
        if lastLinesCount is not None:
            args.add(lastLinesCount=lastLinesCount)

        request = str(args)
        return await self.send_request_receive_answer(request, event, const_error_event)

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

