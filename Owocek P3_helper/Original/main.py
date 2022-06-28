
# globals:

# pac pointer addresses
_0x4_addr = 0x0
_0x8_addr = 0x0
_0x20_addr = 0x0
_0x40_addr = 0x0


async def get_address_hex():
    async with websockets.connect(
        f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        await websocket.send(json.dumps({"event": "memory.base"}))
        r = json.loads(await websocket.recv())
        return r["addressHex"]
        
async def pac_ptr_lookup(pac_ptr_id):
    async with websockets.connect(
        f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
        pac_ptr = 0x0 # address to the pac data table 
        game_addr = 0x0 # pointer for the function that grabs the pac ptr address
        ptr_table_addr = 0x0883C528 # pointer for the switch case going over 0x40 0x20 etc
        
        if pac_ptr_id == 0x4 or pac_ptr_id == 0x8:
            game_addr = 0x088374FC
        if pac_ptr_id == 0x20 or pac_ptr_id == 0x40:
            game_addr = 0x0883750C
        #print("function starts")
        
        while True:
            print("check if pac_ptr is 0x4 or 0x8")
            await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": ptr_table_addr, "condition": "a0=="+str(hex(pac_ptr_id))}))
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
                    print("pac_ptr is now "+str(pac_check["uintValue"]))
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
                    
                    print(str(pac_check["uintValue"])+" address is "+str(addr["uintValue"]))
                    return addr["uintValue"]
                else:
                    #print("pac_ptr incorrect. resume cpu and start over")
                    await websocket.send(json.dumps({"event": "cpu.resume"}))
                    
        print("function returns")
        return pac_ptr
        
async def bnd_listener():
    async with websockets.connect(
        f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
            #print("check if pac_ptr is 0x4 or 0x8")
            await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": 0x088774D0}))
            r = json.loads(await websocket.recv())
            
            while True:
                #print("breakpoint 1 planted successfully")
                
                r = json.loads(await websocket.recv())
                
                #print("waiting for steppings 1")
                while r["event"] != "cpu.stepping":
                    r = json.loads(await websocket.recv())
                    
                #print("cool. now get the registry a0")
                await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a0"}))
                name_ptr = json.loads(await websocket.recv())
                
                bnd_name = name_ptr["uintValue"]
                
                #await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": 0x088774D0}))
                await websocket.send(json.dumps({"event": "cpu.resume"}))
                
                print(get_string(bnd_name))
                
async def item_listener():
    async with websockets.connect(
        f"ws://{listing['ip']}:{listing['p']}/debugger"
    ) as websocket:
            #print("check if pac_ptr is 0x4 or 0x8")
            await websocket.send(json.dumps({"event": "cpu.breakpoint.add", "address": 0x08901A9C}))
            r = json.loads(await websocket.recv())
            
            while True:
                #print("breakpoint 1 planted successfully")
                
                r = json.loads(await websocket.recv())
                
                #print("waiting for steppings 1")
                while r["event"] != "cpu.stepping":
                    print("prediction: "+guess_next_item())
                    r = json.loads(await websocket.recv())
                    
                #print("cool. now get the registry a0")
                await websocket.send(json.dumps({"event": "cpu.getReg", "name": "a1"}))
                name_ptr = json.loads(await websocket.recv())
                
                item_id = name_ptr["uintValue"]
                
                #await websocket.send(json.dumps({"event": "cpu.breakpoint.remove", "address": 0x088774D0}))
                await websocket.send(json.dumps({"event": "cpu.resume"}))
                
                print("Real dropped item: "+get_item_from_id(item_id))


def test_bp():
    if messagebox.askyesno('p3-helper warning', 'This button is used to scan the game for memory regions that contain important game data. Some pointer addresses are only accessible while the player is in the mission.\nMake sure to go to any mission before clicking "Yes", otherwise the p3-helper instance will make your PPSSPP unusable.'):
        global _0x4_addr
        global _0x8_addr
        global _0x20_addr
        global _0x40_addr
        
        _0x4_addr = asyncio.run(pac_ptr_lookup(0x4))
        _0x8_addr = asyncio.run(pac_ptr_lookup(0x8))
        _0x20_addr = asyncio.run(pac_ptr_lookup(0x20))
        _0x40_addr = asyncio.run(pac_ptr_lookup(0x40))
        
        print("[RESULT] Found 0x4 address: "+str(hex(_0x4_addr)))
        print("[RESULT] Found 0x8 address: "+str(hex(_0x8_addr)))
        print("[RESULT] Found 0x20 address: "+str(hex(_0x20_addr)))
        print("[RESULT] Found 0x40 address: "+str(hex(_0x40_addr)))
        
        messagebox.showinfo('p3-helper', 'Pointers loaded successfully :)\nThey will be persistent through all save datas.\nBe careful when using savestates: you may have savestates that have different memory regions. When you are loading a savestate, go to a mission and press the "load addresses" button again to update them.')


def pac_logger_bp():
    if messagebox.askyesno('p3-helper warning', 'this will run pac logger'):
        
        pac = asyncio.run(pac_get_instruction())
        
        messagebox.showinfo('p3-helper', 'pac instruction found')

def listen_for_bnds():
    while True:
        asyncio.run(bnd_listener())
def listen_for_items():
    while True:
        asyncio.run(item_listener())
