import enum
from pymem import Pymem
import asyncio
import websockets
import requests
import json
import ipaddress


class PPSSPP_bitness(enum.Enum):
    bitness_32 = 0
    bitness_64 = 1


class DebuggerRequest(enum.Enum):
    memory_base = 0  # needs exception support
    memory_disasm = 1  # needs exception support
    cpu_searchDisasm = 2  # broken
    cpu_assemble = 3  # broken
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
    hle_thread_list = 31
    hle_thread_wake = 32
    hle_thread_stop = 33
    hle_func_list = 34
    hle_func_add = 35
    hle_func_remove = 36
    hle_func_rename = 37
    hle_module_list = 38
    hle_backtrace = 39

    # Input section
    input_analog = 40
    input_buttons_send = 41
    input_buttons_press = 42
    input_analog_send = 43

    # Memory access section
    memory_mapping = 44
    memory_info_config = 45
    memory_info_set = 46
    memory_info_list = 47
    memory_info_search = 48
    memory_read_u8 = 49
    memory_read_u16 = 50
    memory_read_u32 = 51
    memory_read = 52
    memory_readString = 53
    memory_write_u8 = 54
    memory_write_u16 = 55
    memory_write_u32 = 56
    memory_write = 57

    # Replay section
    replay_begin = 58
    replay_abort = 59
    replay_flush = 60
    replay_execute = 61
    replay_status = 62
    replay_time_get = 63
    replay_time_set = 64

    cpu_stepInto = 65  # needs exception support
    cpu_stepOver = 66  # needs exception support
    cpu_stepOut = 67  # needs exception support
    cpu_runUntil = 68
    cpu_nextHLE = 69


const_32_bit_process_name = "PPSSPPWindows.exe"
const_64_bit_process_name = "PPSSPPWindows64.exe"
const_PPSSPP_match_list_url = "http://report.ppsspp.org/match/list"
const_error_event = "error"


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
    emulator_version = PPSSPP_bitness.bitness_32
    process = ""
    memory = None

    def __init__(self):
        pass

    def initialize_Pymem(self, version):  # should be surrounded by try except
        self.emulator_version = version
        if version == PPSSPP_bitness.bitness_32:
            self.process = const_32_bit_process_name
        else:
            self.process = const_64_bit_process_name
        self.memory = Pymem(self.process)

    def initialize_URI(self):  # # should be surrounded by try except
        listing = get_IPV4_from_server(const_PPSSPP_match_list_url)
        self.connection_URI = f"ws://{listing['ip']}:{listing['p']}/debugger"

    def block_until_event(self):
        pass

    async def send_request_receive_answer(self, request, receive_event, error_event):
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
            while response["event"] != receive_event and response["event"] != error_event:
                response = json.loads(await ws.recv())
            return response

    # Debugger events

    async def memory_base(self):  # unfinished
        request = make_request_string(event="memory.base")
        return await self.send_request_receive_answer(request, "memory.base", const_error_event)

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

        return await self.send_request_receive_answer(request, "memory.disasm", const_error_event)

    async def cpu_searchDisasm(self, address, match, thread="", end="", displaySymbols=True):  # unfinished
        # for some reason PPSSPP does not recognise this event
        if thread == "":
            request = make_request_string(event="cpu.searchDisasm", address=address, end=end, match=match,
                                          displaySymbols=displaySymbols)
        else:
            request = make_request_string(event="cpu.searchDisasm", thread=thread, address=address, end=end,
                                          match=match, displaySymbols=displaySymbols)

        return await self.send_request_receive_answer(request, "cpu.searchDisasm", const_error_event)

    async def cpu_assemble(self, address, code):  # unfinished
        # doesn't work either
        request = make_request_string(event="cpu.assemble", address=address, code=code)

        return await self.send_request_receive_answer(request, "cpu.assemble", const_error_event)

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

    async def cpu_getReg(self, name, thread="", category="", register=""):  # unfinished
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

        return await self.send_request_receive_answer(request, "cpu.setReg", const_error_event)

    async def cpu_evaluate(self, expression, thread=""):  # unfinished
        # don't use curly brackets to access a register
        # now [address, size] works smoothly all of a sudden!
        # even [reg_name, size] works! ... Maybe...
        if thread == "":
            request = make_request_string(event="cpu.evaluate", expression=expression)
        else:
            request = make_request_string(event="cpu.evaluate", thread=thread, expression=expression)

        return await self.send_request_receive_answer(request, "cpu.evaluate", const_error_event)

    async def cpu_breakpoint_add(self, address, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.add", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.add", const_error_event)

    async def cpu_breakpoint_update(self, address, enabled=True, log=False, condition="", logFormat=""):  # unfinished
        request = make_request_string(event="cpu.breakpoint.update", address=address, enabled=enabled,
                                      log=log, condition=condition, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.update", const_error_event)

    async def cpu_breakpoint_remove(self, address):  # unfinished
        request = make_request_string(event="cpu.breakpoint.remove", address=address)

        return await self.send_request_receive_answer(request, "cpu.breakpoint.remove", const_error_event)

    async def cpu_breakpoint_list(self):  # unfinished
        request = make_request_string(event="cpu.breakpoint.list")

        return await self.send_request_receive_answer(request, "cpu.breakpoint.list", const_error_event)

    async def memory_breakpoint_add(self, address, size, enabled=True, log=False, read=True,
                                    write=True, change=False, logFormat=""):  # unfinished
        # if either of read, write or change parameters is present, others must also be included
        request = make_request_string(event="memory.breakpoint.add", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "memory.breakpoint.add", const_error_event)

    async def memory_breakpoint_update(self, address, size, enabled=True, log=False, read=True,
                                       write=True, change=False, logFormat=""):  # unfinished
        request = make_request_string(event="memory.breakpoint.update", address=address, size=size, enabled=enabled,
                                      log=log, read=read, write=write, change=change, logFormat=logFormat)

        return await self.send_request_receive_answer(request, "memory.breakpoint.update", const_error_event)

    async def memory_breakpoint_remove(self, address, size):  # unfinished
        request = make_request_string(event="memory.breakpoint.remove", address=address, size=size)

        return await self.send_request_receive_answer(request, "memory.breakpoint.remove", const_error_event)

    async def memory_breakpoint_list(self):  # unfinished
        request = make_request_string(event="memory.breakpoint.list")

        return await self.send_request_receive_answer(request, "memory.breakpoint.list", const_error_event)

    # GPU section

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

    # GPU section end

    async def game_reset(self):  # unfinished
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

    # HLE section end

    # Input section

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

    # Input section end

    # Memory access section

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

    # Memory section end

    # Replay section

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
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())

    async def cpu_nextHLE(self):  # unfinished
        request = make_request_string(event="memory.base")
        async with websockets.connect(self.connection_URI) as ws:
            await ws.send(request)
            response = json.loads(await ws.recv())
