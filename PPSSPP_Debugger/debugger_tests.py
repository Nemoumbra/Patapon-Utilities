import debugger
import asyncio


def test_debugger():
    test = debugger.PPSSPP_Debugger()
    try:
        test.initialize_URI()
    except Exception as e:
        print("initialize_URI exception")
        print(e)

    try:
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
        pass
    except Exception as e:
        # print()
        print(e)
