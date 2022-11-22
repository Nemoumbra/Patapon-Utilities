import base64
import PPSSPPDebugger
import asyncio
import pymem
import time


def test_debugger():
    test = PPSSPPDebugger.PPSSPP_Debugger()
    print("PPSSPP_Debugger initialized")
    error_event = PPSSPPDebugger.const_error_event
    try:
        test.initialize_URI(49249)
        # print("Preparations done, checking if PPSSPP is running...")
        # PPSSPPDebugger.test_localhost_URI(test.connection_URI.)
    except Exception as e:
        print(e)
        exit()

    try:
        # Regular events tests

        # TO DO: change numbers in accordance with the new DebuggerRequest version

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

        # ret = asyncio.run(test.memory_searchDisasm(0x0884f66c, "jr ra", end=0x0884f688))  # 2
        # 0x0884f698
        # ret = asyncio.run(test.memory_assemble(0x8913aa0, "addiu sp,sp,-0x40"))  # 3
        # original is 0x27BDFFC0 - 	addiu sp,sp,-0x40

        # ret = asyncio.run(test.cpu_evaluate("1 + v1"))  # 10
        # ret = asyncio.run(test.cpu_evaluate("[0x08AABD94, 4]"))  # 10

        # Actually, I don't know anymore... maybe this works, but only sometimes, lol
        # ret = asyncio.run(test.cpu_evaluate("[v1, 4]"))  # 10

        # semi-broken
        # print("\"version\"")
        # start_time = time.monotonic()
        # ret = asyncio.run(test.version())
        # end_time = time.monotonic()
        # diff_time = end_time - start_time
        # print(f"It took {diff_time} seconds to perform this operation")
        # print("Version: {0}".format(ret["version"]))
        #
        # print("\"game.reset\"")
        # start_time = time.monotonic()
        # ret = asyncio.run(test.game_reset())  # 28
        # end_time = time.monotonic()
        # diff_time = end_time - start_time
        # print(f"It took {diff_time} seconds to perform this operation")
        # print("Response: ", ret)

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

        # ret = asyncio.run(test.hle_thread_list())
        # ret = asyncio.run(test.hle_func_list())
        # ret = asyncio.run(test.hle_module_list())
        # ret = asyncio.run(test.hle_backtrace())  # Set up a memory bp at 0x09494FC2 in hideout

        # ret = asyncio.run(test.hle_func_scan(0x0884f66c, 1))
        # ret = asyncio.run(test.hle_func_scan(0x0884f66c, 40))
        # ret = asyncio.run(test.hle_func_scan(0x0884f66c, 100))
        # ret = asyncio.run(test.hle_func_scan(0x8ABB180, 100))
        # ret = asyncio.run(test.hle_func_scan(0x8ac0b20, 0x08AC0C10 - 0x8ac0b20 + 4))
        # 0x8ac0b20 - setTitleTimmingScript start, 0x08AC0C10 == last instruction address
        # ret = asyncio.run(test.hle_func_scan(0x8ABB180, 893312))
        # 0x8ABB180 == overlay start

        # ret = asyncio.run(test.hle_func_scan(0x08ABB200, 144384))
        # ret = asyncio.run(test.hle_func_remove(0x8ac0b20))
        # ret = asyncio.run(test.hle_func_add(0x8ac0b20, 0x08AC0C10 - 0x8ac0b20 + 4, "setTitleTimmingScript"))
        # 08AC0C10 is the last instruction address (delay-slot of jr ra)
        # ret = asyncio.run(test.hle_func_rename(0x8ac0b20, "z_un_08AC0B20"))

        # ret = asyncio.run(test.hle_func_removeRange(0x08AC0B14, 0x120))
        # ret = asyncio.run(test.hle_func_scan(0x8ABB200, 893312))
        # ret = asyncio.run(test.hle_func_removeRange(0x08AC0B14, 0x120))
        # ret = asyncio.run(test.hle_func_removeRange(0x8ABB200, 893312))

        # ret = asyncio.run(test.hle_func_scan(0x8ABB200, 144384, True))
        # ret = asyncio.run(test.hle_func_scan(0x8ABB200, 1091840, True))
        # ret = asyncio.run(test.hle_func_sca0x08AC0A34n(0x8ABB200, 893312, True))
        # ret = asyncio.run(test.hle_func_scan(0x08AC0A34, 0x08AC0C3C - 0x08AC0A34, True))

        # When Start is pressed, the stepping will begin
        # ret = asyncio.run(test.input_buttons_press("cross"))

        # ret = asyncio.run(test.memory_disasm(0x08879988, 4, None))
        # ret = asyncio.run(test.cpu_stepping())
        # ret = asyncio.run(test.cpu_startLogging())
        ret = asyncio.run(test.cpu_startLogging("MSG_loader.txt"))
        ret = asyncio.run(test.cpu_resume())
        ret = asyncio.run(test.block_until_event("cpu.stepping", PPSSPPDebugger.const_error_event))
        ret = asyncio.run(test.cpu_flushLogs())
        pass

        # High-level functions:

        # ret = asyncio.run(test.cpu_breakpoint_add(address=0x8913aa0))
        # ret = asyncio.run(test.block_until_event("cpu.stepping", error_event))
        # ret = asyncio.run(test.memory_write_bytes(0x08AABD94, b"\x80y\xD9\x08"))

        # Pymem functions

        # The next two lines must not be commented out during testing
        # test.initialize_Pymem(PPSSPPDebugger.PPSSPP_bitness.bitness_64)
        # test.initialize_debugger()

        # ret = test.memory_read_byte(0x08AABD94)
        # ret = test.memory_read_short(0x08AABD94)
        # ret = test.memory_read_int(0x08AABD94)
        # test.memory_write_byte(0x08AABD94, 0x11)
        # test.memory_write_short(0x08AABD94, 0x2233)
        # test.memory_write_int(0x08AABD94, 0x44556677)

        # ret = test.memory_read_string(0x099A5FB4)
        # 0x099A5FB4 is a start of Field of angry giants name => correct answer is F
        # ret = test.memory_read_wstring(0x099A5FB4)  # Now correct answer is Field of Angry Giants
        # ret = test.memory_read_wstring(0x99ADC8A)
        # 0x99ADC8A is a start of the same wstring, but on Russian => answer is Поле Злых великанов
        # ret = test.memory_write_string(0x099A5FB4, "Test")
        # ret = test.memory_write_wstring(0x099A5FB4, "АБВГДЕЁЖЗИЙКЛМНОПРСТУ")
        pass
    except pymem.exception.MemoryReadError as e:
        print(e)
    except pymem.exception.MemoryWriteError as e:
        print(e)
    except UnicodeDecodeError as e:
        print(e)
    except Exception as e:
        print(e)
        exit()
    print("Tests finished!")
    exit()
