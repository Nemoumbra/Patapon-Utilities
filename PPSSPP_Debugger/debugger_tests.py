import base64
import debugger
import asyncio
import pymem


def test_debugger():
    test = debugger.PPSSPP_Debugger()
    error_event = debugger.const_error_event
    try:
        test.initialize_URI()
    except Exception as e:
        print("initialize_URI exception")
        print(e)

    try:
        # Regular events tests

        # ret = asyncio.run(test.memory_base())  # 0
        # ret = asyncio.run(test.cpu_getReg(name="v1"))  # 8
        # ret = asyncio.run(test.cpu_getAllRegs())  # 7
        # ret = asyncio.run(test.cpu_breakpoint_add(address=0x8913aa0, enabled=False))  # 11
        # ret = asyncio.run(test.cpu_breakpoint_update(address=0x8913aa0, enabled=True))  # 12
        # ret = asyncio.run(test.cpu_breakpoint_remove(address=0x8913aa0))  # 13
        # ret = asyncio.run(test.cpu_status())  # 6
        # ret = asyncio.run(test.cpu_setReg("v1", 2))  # 9
        # ret = asyncio.run(test.cpu_breakpoint_list())  # 14
        # ret = asyncio.run(test.memory_breakpoint_add(0x08AABD94, 1))  # 15
        # ret = asyncio.run(test.memory_breakpoint_update(0x08AABD94, 1, enabled=False))  # 16
        # ret = asyncio.run(test.memory_breakpoint_remove(0x08AABD94, 1))  # 17
        # ret = asyncio.run(test.memory_breakpoint_list())  # 18
        # ret = asyncio.run(test.memory_disasm(0x0884f66c, count=10, end=""))  # 1
        # ret = asyncio.run(test.memory_disasm(0x0884f66c, count="", end=0x0884f698))  # 1

        # broken:
        # ret = asyncio.run(test.cpu_searchDisasm(0x0884f66c, "nop", end=0x0884f698))  # 2
        # ret = asyncio.run(test.cpu_assemble(0x8913aa0, "nop"))  # 3

        # ret = asyncio.run(test.cpu_evaluate("1 + v1"))  # 10
        # ret = asyncio.run(test.cpu_evaluate("[0x08AABD94, 4]"))  # 10

        # Actually, I don't know anymore... maybe this works, but only sometimes, lol
        # ret = asyncio.run(test.cpu_evaluate("[v1, 4]"))  # 10

        # broken
        # ret = asyncio.run(test.game_reset())  # 28

        # ret = asyncio.run(test.game_status())  # 29
        # ret = asyncio.run(test.version())  # 30
        # ret = asyncio.run(test.cpu_stepping())  # 4
        # ret = asyncio.run(test.cpu_resume())  # 5
        # ret = asyncio.run(test.cpu_stepInto())  # 65
        # ret = asyncio.run(test.cpu_stepOver())  # 66
        # ret = asyncio.run(test.cpu_stepOut())  # 67, PC = 0884F66C
        # ret = asyncio.run(test.memory_read_u8(0x08AABD94))
        # ret = asyncio.run(test.memory_read_u16(0x08AABD94))
        # ret = asyncio.run(test.memory_read_u32(0x08AABD94))  # very often the result is 08D97980 (80 79 D9 08)
        # ret = asyncio.run(test.memory_read(0x08AABD94, 4))
        # ret = base64.b64decode(ret["base64"])
        # ret = asyncio.run(test.memory_readString(0x092059B4)) # 0x092059B4 - R.e.t.u.r.n. .f.i.r.e.!...
        # ret = base64.b64decode(ret["base64"])  # if type == "base64"
        # ret = asyncio.run(test.memory_write_u8(0x08AABD94, 0xFE))  # (80 79 D9 08) -> (FE 79 D9 08)
        # ret = asyncio.run(test.memory_write_u16(0x08AABD94, 0x1234))  # (80 79 D9 08) -> (34 12 D9 08)
        # ret = asyncio.run(test.memory_write_u32(0x08AABD94, 0xFEFF5678))  # (80 79 D9 08) -> (78 56 FF FE)
        # ret = asyncio.run(test.memory_write(0x08AABD94, base64.b64encode(b"\x12\x13\x14\x15").decode("utf-8")))
        # Use test.memory_write_bytes instead of this one (in the high-level section).

        pass

        # High-level functions:

        # ret = asyncio.run(test.cpu_breakpoint_add(address=0x8913aa0))
        # ret = asyncio.run(test.block_until_event("cpu.stepping", error_event))
        # ret = asyncio.run(test.memory_write_bytes(0x08AABD94, b"\x80y\xD9\x08"))

        # Pymem functions
        # test.initialize_Pymem(debugger.PPSSPP_bitness.bitness_64)
        # test.initialize_debugger()
        # ret = test.memory_read_byte(0x08AABD94)
        # ret = test.memory_read_short(0x08AABD94)
        # ret = test.memory_read_int(0x08AABD94)
        pass
    except pymem.exception.MemoryReadError as e:
        print(e)
    except UnicodeDecodeError as e:
        print(e)
    except Exception as e:
        print(e)
