from subprocess import check_output
from pymem import Pymem
import time
import tkinter
from tkinter import messagebox
import math
import struct
import numpy
import asyncio
import websockets
import requests
import json
from datetime import datetime
import ipaddress


def get_IPV4_from_server(ppsspp_match_api):
    r = requests.get(ppsspp_match_api)
    r_json = r.json()
    if not r_json:
        print("Error! Server returned \"[]\", cannot proceed")
        exit()

    for obj in r_json:
        if 'ip' in obj:
            try:
                if isinstance(ipaddress.ip_address(obj['ip']), ipaddress.IPv4Address):
                    return obj
            except ValueError:
                pass
    print("Error! No IPV4 in server's response, cannot proceed")
    exit()


def load_item_names(file_path):
    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
            lines = [line.rstrip() for line in lines]
            return lines
    except Exception as e:
        print("Error! Failed to load data from ", file_path, ", cannot proceed", sep='')
        print("Exception details:", e)
        exit()


def load_pac_funcs_raw(file_path):
    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
            lines = [line.rstrip() for line in lines]
            return lines
    except Exception as e:
        print("Error! Failed to load data from ", file_path, ", cannot proceed", sep='')
        print("Exception details:", e)
        exit()


def pac_funcs_from_raw(raw):
    pac_functions = []  # return value
    cur_class = 0
    pac_buffer = []
    for x in raw:
        pac_func = x.split(',')
        try:
            if int(pac_func[0], 16) == cur_class:
                pac_buffer.append(pac_func[3])
            else:
                cur_class = int(pac_func[0], 16)
                pac_functions.append(pac_buffer)
                pac_buffer = [pac_func[3]]
        except Exception as e:
            print("Error!")
            print(e)
            print("Cannot proceed")
            exit()
    return pac_functions


process = "PPSSPPWindows.exe"
# open the process
try:
    pm = Pymem(process)
except:
    print("Cannot find process", process)
    exit()


PPSSPP_MATCH_API = "http://report.ppsspp.org/match/list"
# PPSSPP_SUB_PROTOCOL = "debugger.ppsspp.org"
# PPSSPP_DEFAULT_PATH = "/debugger"

listing = get_IPV4_from_server(PPSSPP_MATCH_API)


async def get_base_address_hex():
    # print("get_address_hex called")
    connection_uri = f"ws://{listing['ip']}:{listing['p']}/debugger"
    print(connection_uri)
    async with websockets.connect(connection_uri) as websocket:
        await websocket.send(json.dumps({"event": "memory.base"}))
        r = json.loads(await websocket.recv())
        return r["addressHex"]


async def pac_ptr_lookup(pac_ptr_id):
    async with websockets.connect(
            f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        pac_ptr = 0x0  # address to the pac data table
        game_addr = 0x0  # pointer for the function that grabs the pac ptr address
        ptr_table_addr = 0x0883C528  # pointer for the switch case going over 0x40 0x20 etc

        if pac_ptr_id == 0x4 or pac_ptr_id == 0x8:
            game_addr = 0x088374FC
        if pac_ptr_id == 0x20 or pac_ptr_id == 0x40:
            game_addr = 0x0883750C
        # print("function starts")

        while True:
            print("check if pac_ptr is 0x4 or 0x8")
            await websocket.send(json.dumps(
                {"event": "cpu.breakpoint.add", "address": ptr_table_addr, "condition": "a0==" + str(hex(pac_ptr_id))}))
            r = json.loads(await websocket.recv())

            if r["event"] == "cpu.breakpoint.add":
                print("breakpoint 1 planted successfully")

                r = json.loads(await websocket.recv())

                print("waiting for steppings 1")
                while r["event"] != "cpu.stepping":
                    r = json.loads(await websocket.recv())

                print("cool. now get the registry a0")
                await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a0"}))
                pac_check = json.loads(await websocket.recv())

                print("printing pac_check:")
                print(pac_check)

                print("remove breakpoint 1 now")
                await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": ptr_table_addr}))

                print("verify correct event")
                if pac_check["event"] == "cpu.getReg":
                    print("pac_ptr is now " + str(pac_check["uintValue"]))
                    pac_ptr = pac_check["uintValue"]

                print("check if pac_ptr is 0x4 or 0x8 but inside the function")
                if pac_ptr == pac_ptr_id:
                    print("add bp2")
                    await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": game_addr}))
                    r = json.loads(await websocket.recv())

                    print("resume cpu")
                    await websocket.send(json.dumps({"event": "cpu.resume"}))

                    r = json.loads(await websocket.recv())

                    print("wait for stepping")
                    while r["event"] != "cpu.stepping":
                        r = json.loads(await websocket.recv())

                    print("stepping received, now read the register v0")
                    await websocket.send(json.dumps({"event": "cpu.getReg", "name": "v0"}))
                    addr = json.loads(await websocket.recv())

                    print("cleanup. remove breakpoint 2 now")
                    await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": game_addr}))

                    print("resume cpu")
                    await websocket.send(json.dumps({"event": "cpu.resume"}))

                    print(str(pac_check["uintValue"]) + " address is " + str(addr["uintValue"]))
                    return addr["uintValue"]
                else:
                    # print("pac_ptr incorrect. resume cpu and start over")
                    await websocket.send(json.dumps({"event": "cpu.resume"}))

        #print("function returns")
        #return pac_ptr


async def bnd_listener():
    async with websockets.connect(
            f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        # print("check if pac_ptr is 0x4 or 0x8")
        await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": 0x088774D0}))
        r = json.loads(await websocket.recv())

        while True:
            # print("breakpoint 1 planted successfully")

            r = json.loads(await websocket.recv())

            # print("waiting for steppings 1")
            while r["event"] != "cpu.stepping":
                r = json.loads(await websocket.recv())

            # print("cool. now get the registry a0")
            await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a0"}))
            name_ptr = json.loads(await websocket.recv())

            bnd_name = name_ptr["uintValue"]

            # await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": 0x088774D0}))
            await websocket.send(json.dumps({"event": "cpu.resume"}))

            print(get_string(bnd_name))


async def item_listener():
    async with websockets.connect(
            f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        # print("check if pac_ptr is 0x4 or 0x8")
        await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": 0x08901A9C}))
        r = json.loads(await websocket.recv())

        while True:
            # print("breakpoint 1 planted successfully")

            r = json.loads(await websocket.recv())

            # print("waiting for steppings 1")
            while r["event"] != "cpu.stepping":
                print("prediction: " + guess_next_item())
                r = json.loads(await websocket.recv())

            # print("cool. now get the registry a0")
            await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a1"}))
            name_ptr = json.loads(await websocket.recv())

            item_id = name_ptr["uintValue"]

            # await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": 0x088774D0}))
            await websocket.send(json.dumps({"event": "cpu.resume"}))

            print("Real dropped item: " + get_item_from_id(item_id))


# pac pointer addresses
_0x4_addr = 0x0
_0x8_addr = 0x0
_0x20_addr = 0x0
_0x40_addr = 0x0

breakpoint_warning_str = ("This button is used to scan the game for memory regions that contain important game data."
                           "Some pointer addresses are only accessible while the player is in the mission.\n"
                           "Make sure to go to any mission before clicking \"Yes\", otherwise the p3-helper instance will make your PPSSPP unusable.")
pointers_loaded_str = ("Pointers loaded successfully :)\n"
                      "They will be persistent through all save datas.\n"
                       "Be careful when using savestates: you may have savestates that have different memory regions. "
                       "When you are loading a savestate, go to a mission and press the \"load addresses\" button again to update them.")


def test_bp():
    if messagebox.askyesno('p3-helper warning', breakpoint_warning_str):
        global _0x4_addr
        global _0x8_addr
        global _0x20_addr
        global _0x40_addr

        _0x4_addr = asyncio.run(pac_ptr_lookup(0x4))
        _0x8_addr = asyncio.run(pac_ptr_lookup(0x8))
        _0x20_addr = asyncio.run(pac_ptr_lookup(0x20))
        _0x40_addr = asyncio.run(pac_ptr_lookup(0x40))

        print("[RESULT] Found 0x4 address: " + str(hex(_0x4_addr)))
        print("[RESULT] Found 0x8 address: " + str(hex(_0x8_addr)))
        print("[RESULT] Found 0x20 address: " + str(hex(_0x20_addr)))
        print("[RESULT] Found 0x40 address: " + str(hex(_0x40_addr)))

        messagebox.showinfo('p3-helper', pointers_loaded_str)


def pac_logger_bp():
    if messagebox.askyesno('p3-helper warning', 'This will run pac logger'):
        pac = asyncio.run(pac_get_instruction())

        messagebox.showinfo('p3-helper', 'Pac instruction found')


def listen_for_bnds():
    while True:
        asyncio.run(bnd_listener())


def listen_for_items():
    while True:
        asyncio.run(item_listener())


base = -1
# get PPSSPP base address from a node.js script (connection to PPSSPP debugger)
try:
    base = int(asyncio.run(get_base_address_hex()), 16)
except Exception as e:
    print("Error:", e)
    exit()
print("PPSSPP base pointer: " + str(hex(base)))

# offsets
# _0x4_addr = 0x9A3AEC0
# _0x8_addr = 0x8D39BE0
flag_addr = 0x08D960A0
ptr_global = 0x8B7D088
ptr_application = 0x8B4C8D4

item_names_path = r'p2_item_table.dat'
pac_funcs_raw_path = r'p3_ins_table.dat'

# load data into data tables
item_names = load_item_names(item_names_path)
pac_funcs_raw = load_pac_funcs_raw(pac_funcs_raw_path)  # p3_ins_table.dat
pac_funcs = pac_funcs_from_raw(pac_funcs_raw)

print(pac_funcs)
print(pac_funcs[3][7])


def get_uint32(offset):
    global base
    return pm.read_int(base + offset)


def get_string(offset):
    global base
    o = offset
    t = ""
    b = pm.read_bytes(base + o, 1)
    i = int.from_bytes(b, "big")
    c = pm.read_char(base + o)
    while i != 0:
        t += c
        o += 1
        b = pm.read_bytes(base + o, 1)
        c = pm.read_char(base + o)
        i = int.from_bytes(b, "big")
    return t


def get_string_16(offset):
    global base
    o = offset
    t = ""
    b = pm.read_bytes(base + o, 1)
    i = int.from_bytes(b, "big")
    u = 0
    c = pm.read_char(base + o)
    while u < 3:
        if i != 0:
            t += c
        o += 1
        b = pm.read_bytes(base + o, 1)
        c = pm.read_char(base + o)
        i = int.from_bytes(b, "big")
        if i == 0:
            u += 1
        else:
            u = 0
    return t


# get a pointer
def get_pointer(pointer, offset):
    global base
    global _0x4_addr
    global _0x8_addr
    global _0x20_addr
    global _0x40_addr

    if _0x4_addr != 0x0:
        if pointer == 0x4:
            # print(base + _0x4_addr + offset*4)
            return get_uint32(_0x4_addr + offset * 4)
    else:
        return 0x0

    if _0x8_addr != 0x0:
        if pointer == 0x8:
            # print(base + _0x8_addr + offset*4)
            return get_uint32(_0x8_addr + offset * 4)
    else:
        return 0x0

    if _0x20_addr != 0x0:
        if pointer == 0x20:
            # print(base + _0x8_addr + offset*4)
            return get_uint32(_0x20_addr + offset * 4)
    else:
        return 0x0

    if _0x40_addr != 0x0:
        if pointer == 0x40:
            # print(base + _0x8_addr + offset*4)
            return get_uint32(_0x40_addr + offset * 4)
    else:
        return 0x0


def get_flag(flag_id):
    offset = math.floor(float(flag_id) / float(8))
    byte = pm.read_bytes(base + flag_addr + offset, 1)
    binary = str(bin(int.from_bytes(byte, "big")))[2:]
    while len(binary) != 8:
        binary = "0" + binary
    return binary[::-1][flag_id % 8]


# convert item id to name
def get_item_from_id(item):
    if item < 0:
        amount = ""
        if item == -1:
            return "NO ITEM (loot stops here)"
        if item == -2:
            amount = "(little)"
        if item == -3:
            amount = "(moderate)"
        if item == -4:
            amount = "(a lot)"
        if item <= -5:
            amount = "(huge)"

        return "Ka-ching " + amount
    else:
        return item_names[item]


# create window
root = tkinter.Tk()
root.title("p3-helper v1.0.1 by owocek")
root.geometry("1200x480")

global state
state = 0

global page
page = 0

global display
display = 0

global refresh_rate
refresh_rate = 100


def switch_iteminfo():
    pass
#     global state
#     state = 0
#     global page
#     page = 0
#
#     lb_itemdrop.place(relx=0.0, rely=0.15)
#     lb_misid.place(relx=0.0, rely=0.185)
#
#     lb_0x4.place(relx=-1.0, rely=-1.0)
#
#     for x in range(0, 150):
#         lbs[x].place(relx=-1, rely=-1)
#
#     for x in range(0, 80):
#         lbs[x].place(relx=-1, rely=-1)
#
#     for x in range(0, 20):
#         xpos = float(x % 4) / float(4)
#         ypos = math.floor(float(x) / float(4)) / float(24)
#         t1_loot[x].place(relx=xpos, rely=0.34 + ypos)
#
#     lb_t1.place(relx=0.0, rely=0.3)


def switch_item0x4():
    pass
#     global state
#     state = 1
#     global page
#     page = 0
#
#     lb_itemdrop.place(relx=-1.0, rely=-1.0)
#     lb_misid.place(relx=-1.0, rely=-1.0)
#
#     lb_0x4.place(relx=0.0, rely=0.15)
#
#     for x in range(0, 150):
#         lbs[x].place(relx=-1, rely=-1)
#
#     for x in range(0, 80):
#         xpos = float(x % 8) / float(8)
#         ypos = math.floor(float(x) / float(8)) / float(16)
#         lbs[x].place(relx=xpos, rely=0.22 + ypos)
#
#     for x in range(0, 20):
#         t1_loot[x].place(relx=-1, rely=-1)
#
#     lb_t1.place(relx=-1, rely=-1)


def switch_item0x8():
    pass
#     switch_item0x4()  # its the same thing
#
#     global state
#     state = 2
#     global page
#     page = 0


def switch_item0x20():
    pass
#     switch_item0x4()  # its the same thing
#
#     global state
#     state = 4
#     global page
#     page = 0


def switch_item0x40():
    pass
#     switch_item0x4()  # its the same thing
#
#     global state
#     state = 5
#     global page
#     page = 0


def switch_flags():
    pass
#     switch_item0x4()
#
#     global state
#     state = 3
#     global page
#     page = 0
#
#     for x in range(0, 150):
#         xpos = float(x % 10) / float(10)
#         ypos = math.floor(float(x) / float(10)) / float(24)
#         lbs[x].place(relx=xpos, rely=0.22 + ypos)


def btn_toint():
    global display
    display = 0


def btn_tohex():
    global display
    display = 1


def btn_tofloat():
    global display
    display = 2


def btn_next():
    global page
    page += 1


def btn_prev():
    global page
    if page > 0:
        page -= 1


def get_state():
    global state
    return state


def get_page():
    global page
    return page


def get_display():
    global display
    return display


def get_refresh_rate():
    global refresh_rate
    return refresh_rate


def btn_rr_increase():
    global refresh_rate
    refresh_rate += 10


def btn_rr_decrease():
    global refresh_rate
    if refresh_rate >= 20:
        refresh_rate -= 10


async def pac_get_instruction():
    async with websockets.connect(
            f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        pac_reader_ptr = 0x0883C1B0
        pac_reader_id_ptr = 0x0883C1B8
        s3_ptr = 0x0
        pac_addr = 0x0
        pac_base = 0x25
        pac_class = 0x0
        pac_id = 0x0
        global pac_funcs

        await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": 0x0883C1BC}))
        r = json.loads(await websocket.recv())

        while True:
            while r["event"] != "cpu.stepping":
                r = json.loads(await websocket.recv())

            await websocket.send(json.dumps({"event": "cpu.getReg", "name": "s3"}))
            pac_check = json.loads(await websocket.recv())
            await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a0"}))
            pac_check2 = json.loads(await websocket.recv())

            if pac_check["event"] == "cpu.getReg":
                s3_ptr = pac_check["uintValue"]
            if pac_check2["event"] == "cpu.getReg":
                pac_addr = pac_check2["uintValue"]

            pac_class = get_uint32(s3_ptr + 0x104)
            pac_id = get_uint32(s3_ptr + 0x108)

            await websocket.send(json.dumps({"event": "cpu.resume"}))
            r = json.loads(await websocket.recv())

            # Getting the current date and time
            dt = datetime.now()

            tm = "[" + str(dt) + "]"

            if pac_id <= (len(pac_funcs[pac_class]) - 1):
                print(tm + " [PAC] " + hex(pac_addr) + ": " + hex(pac_base) + " " + hex(pac_class) + " " + hex(
                    pac_id) + " " + pac_funcs[pac_class][pac_id])
            else:
                print(tm + " [PAC] " + hex(pac_addr) + ": " + hex(pac_base) + " " + hex(pac_class) + " " + hex(
                    pac_id) + " UNK_" + str(hex(pac_class)) + "_" + str(hex(pac_id)))
            # print(pac_funcs)

        #print("function returns")
        #return 0

global lb_itemdrop
global lb_refresh
global lb_misid
global lb_0x4
global lbs

def prepare_window():
    btn_1 = tkinter.Button(root, text="level info", command=switch_iteminfo)
    btn_2 = tkinter.Button(root, text="0x4", command=switch_item0x4)
    btn_3 = tkinter.Button(root, text="0x8", command=switch_item0x8)
    btn_4 = tkinter.Button(root, text="flags", command=switch_flags)
    btn_5 = tkinter.Button(root, text="int", command=btn_toint)
    btn_6 = tkinter.Button(root, text="hex", command=btn_tohex)
    btn_7 = tkinter.Button(root, text="load addresses", command=test_bp)
    btn_12 = tkinter.Button(root, text="pac logger", command=pac_logger_bp)
    btn_11 = tkinter.Button(root, text="item listener", command=listen_for_items)
    btn_8 = tkinter.Button(root, text="0x20", command=switch_item0x20)
    btn_9 = tkinter.Button(root, text="0x40", command=switch_item0x40)
    btn_10 = tkinter.Button(root, text="float", command=btn_tofloat)
    btn_rplus = tkinter.Button(root, text="+", command=btn_rr_increase)
    btn_rminus = tkinter.Button(root, text="-", command=btn_rr_decrease)
    btn_nextpage = tkinter.Button(root, text=">>>", command=btn_next)
    btn_prevpage = tkinter.Button(root, text="<<<", command=btn_prev)

    btn_1.place(relx=0.01, rely=0.02)
    btn_2.place(relx=0.075, rely=0.02)
    btn_3.place(relx=0.10, rely=0.02)
    btn_4.place(relx=0.185, rely=0.02)
    btn_5.place(relx=0.905, rely=0.02)
    btn_6.place(relx=0.93, rely=0.02)
    btn_7.place(relx=0.80, rely=0.02)
    btn_11.place(relx=0.80, rely=0.09)
    btn_12.place(relx=0.80, rely=0.16)
    btn_8.place(relx=0.125, rely=0.02)
    btn_9.place(relx=0.155, rely=0.02)
    btn_10.place(relx=0.96, rely=0.02)
    btn_rplus.place(relx=0.33, rely=0.02)
    btn_rminus.place(relx=0.35, rely=0.02)
    btn_nextpage.place(relx=0.70, rely=0.9)
    btn_prevpage.place(relx=0.30, rely=0.9)

    global lb_itemdrop
    lb_itemdrop = tkinter.Label(text="Latest item drop:")
    lb_itemdrop.place(relx=0.0, rely=0.15)

    global lb_misid
    lb_misid = tkinter.Label(text="Mission ID:")
    lb_misid.place(relx=0.0, rely=0.185)

    global lb_0x4
    lb_0x4 = tkinter.Label(text="0x4 registers:\n")

    global lb_refresh
    lb_refresh = tkinter.Label(text="Refresh rate: 100ms")
    lb_refresh.place(relx=0.23, rely=0.024)

    global lbs
    lbs = []
    t1_loot = []

    for x in range(0, 150):
        # print(x)
        lb = tkinter.Label(text=str(hex(x)) + ":")
        # lb.place(relx = float(1.0)/float(8 - x%8 + 1), rely = math.floor(float(x)/float(8)))
        # print(float(1.0)/float(x%8 + 1))
        # print(math.floor(float(x)/float(8)))
        lbs.append(lb)


# btn_1 = tkinter.Button(root, text="level info", command=switch_iteminfo)
# btn_2 = tkinter.Button(root, text="0x4", command=switch_item0x4)
# btn_3 = tkinter.Button(root, text="0x8", command=switch_item0x8)
# btn_4 = tkinter.Button(root, text="flags", command=switch_flags)
# btn_5 = tkinter.Button(root, text="int", command=btn_toint)
# btn_6 = tkinter.Button(root, text="hex", command=btn_tohex)
# btn_7 = tkinter.Button(root, text="load addresses", command=test_bp)
# btn_12 = tkinter.Button(root, text="pac logger", command=pac_logger_bp)
# btn_11 = tkinter.Button(root, text="item listener", command=listen_for_items)
# btn_8 = tkinter.Button(root, text="0x20", command=switch_item0x20)
# btn_9 = tkinter.Button(root, text="0x40", command=switch_item0x40)
# btn_10 = tkinter.Button(root, text="float", command=btn_tofloat)
# btn_rplus = tkinter.Button(root, text="+", command=btn_rr_increase)
# btn_rminus = tkinter.Button(root, text="-", command=btn_rr_decrease)
# btn_nextpage = tkinter.Button(root, text=">>>", command=btn_next)
# btn_prevpage = tkinter.Button(root, text="<<<", command=btn_prev)
#
# btn_1.place(relx=0.01, rely=0.02)
# btn_2.place(relx=0.075, rely=0.02)
# btn_3.place(relx=0.10, rely=0.02)
# btn_4.place(relx=0.185, rely=0.02)
# btn_5.place(relx=0.905, rely=0.02)
# btn_6.place(relx=0.93, rely=0.02)
# btn_7.place(relx=0.80, rely=0.02)
# btn_11.place(relx=0.80, rely=0.09)
# btn_12.place(relx=0.80, rely=0.16)
# btn_8.place(relx=0.125, rely=0.02)
# btn_9.place(relx=0.155, rely=0.02)
# btn_10.place(relx=0.96, rely=0.02)
# btn_rplus.place(relx=0.33, rely=0.02)
# btn_rminus.place(relx=0.35, rely=0.02)
# btn_nextpage.place(relx=0.70, rely=0.9)
# btn_prevpage.place(relx=0.30, rely=0.9)
#
# lb_itemdrop = tkinter.Label(text="Latest item drop:")
# lb_itemdrop.place(relx=0.0, rely=0.15)
#
# lb_misid = tkinter.Label(text="Mission ID:")
# lb_misid.place(relx=0.0, rely=0.185)
#
# lb_0x4 = tkinter.Label(text="0x4 registers:\n")
#
# lb_refresh = tkinter.Label(text="Refresh rate: 100ms")
# lb_refresh.place(relx=0.23, rely=0.024)
#
# lbs = []
# t1_loot = []
#
# for x in range(0, 150):
#     # print(x)
#     lb = tkinter.Label(text=str(hex(x)) + ":")
#     # lb.place(relx = float(1.0)/float(8 - x%8 + 1), rely = math.floor(float(x)/float(8)))
#     # print(float(1.0)/float(x%8 + 1))
#     # print(math.floor(float(x)/float(8)))
#     lbs.append(lb)
prepare_window()


def p2helper_loop():
    # print("Mission ID: "+str(get_mission_id()))
    # print("Mission name: "+get_mission_name())
    state = get_state()
    page = get_page()
    display = get_display()
    refresh_rate = get_refresh_rate()
    lb_refresh['text'] = "Refresh rate: " + str(refresh_rate) + "ms"
    if state == 0:
        # lb_itemdrop['text'] = "Latest item drop: "+get_item_from_id(get_pointer(0x8, 0x155))
        # lb_itemdrop['text'] = guess_next_item() + "              Abnormal " + guess_next_item_high()
        lb_misid['text'] = "Mission ID: " + str(get_pointer(0x8, 0x154))

    elif state == 1:
        text = "0x4 registers:\n"
        lb_0x4['text'] = text
        for x in range(0, 80):
            if display == 0:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(get_pointer(0x4, x + (page * 80)))
            if display == 1:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(hex(get_pointer(0x4, x + (page * 80))))
            if display == 2:
                q = get_pointer(0x4, x + (page * 80))
                b8 = struct.pack('i', q)
                dec, = struct.unpack('f', b8)
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(dec)
    elif state == 2:
        text = "0x8 registers:\n"
        lb_0x4['text'] = text
        for x in range(0, 80):
            if display == 0:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(get_pointer(0x8, x + (page * 80)))
            if display == 1:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(hex(get_pointer(0x8, x + (page * 80))))
            if display == 2:
                q = get_pointer(0x8, x + (page * 80))
                b8 = struct.pack('i', q)
                dec, = struct.unpack('f', b8)
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(dec)
    elif state == 3:
        text = "flags (true/false)\n"
        lb_0x4['text'] = text
        for x in range(0, 150):
            lbs[x]['text'] = str(hex(x + (page * 150))) + ": " + str(get_flag(x + (page * 150)))
    elif state == 4:
        text = "0x20 registers:\n"
        lb_0x4['text'] = text
        for x in range(0, 80):
            if display == 0:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(get_pointer(0x20, x + (page * 80)))
            if display == 1:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(hex(get_pointer(0x20, x + (page * 80))))
            if display == 2:
                q = get_pointer(0x20, x + (page * 80))
                b8 = struct.pack('i', q)
                dec, = struct.unpack('f', b8)
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(dec)
    elif state == 5:
        text = "0x40 registers:\n"
        lb_0x4['text'] = text
        for x in range(0, 80):
            if display == 0:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(get_pointer(0x40, x + (page * 80)))
            if display == 1:
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(hex(get_pointer(0x40, x + (page * 80))))
            if display == 2:
                q = get_pointer(0x40, x + (page * 80))
                b8 = struct.pack('i', q)
                dec, = struct.unpack('f', b8)
                lbs[x]['text'] = str(hex(x + (page * 80))) + ": " + str(dec)

    root.after(refresh_rate, p2helper_loop)


root.after(1, p2helper_loop)

root.mainloop()
