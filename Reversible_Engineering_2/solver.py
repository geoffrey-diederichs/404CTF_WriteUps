import gdb

INPUT_OFFSET = 570
CHECK_INPUT_OFFSET = 463

def gdb_exec(command: str) -> str:
    return gdb.execute(command, from_tty=False, to_string=True)

def find_entry() -> str:
    info = gdb_exec("info file")
    for i in info.split("\n"):
        if "Entry point:" in i:
            return i.split(" ")[2]
    return ""

def set_breaks(entry_addr: str) -> None:
    new_char_addr = hex(int(entry_addr, 16)+INPUT_OFFSET)
    gdb_exec(f"break *{new_char_addr}")
    new_char_addr = hex(int(entry_addr, 16)+CHECK_INPUT_OFFSET)
    gdb_exec(f"break *{new_char_addr}") 

def set_input(x:str) -> None:
    gdb_exec(f"set var $rax=\"{x}\"")

def get_reg(register: str) -> str:
    output = gdb_exec(f"x/2gx ${register}")
    output = output.split("\n")[0].split("\t")
    full_out = [ "_" for i in range(16) ]

    out = output[1][2:]
    for i in range(int(len(out)/2)):
        full_out[7-i] = hex(int(out[(i*2):(i*2)+2], 16))

    out = output[2][2:]
    for i in range(int(len(out)/2)):
        full_out[15-i] = hex(int(out[(i*2):(i*2)+2], 16))
    
    return full_out


def crack_key(ite: int) -> (str, int):
    key = [ " " for i in range(16) ]
    while " " in key:                        
        gdb_exec("restart "+str(ite))
        if ite > 1:
            gdb_exec("delete checkpoint "+str(ite-1))
        output = gdb_exec("checkpoint")
        output = gdb_exec("continue")
        my_in = get_reg("rdx")
 
        gdb_exec("si")
        for i in range(19):
            output = gdb_exec("ni")
        enc_in = get_reg("rdi")
        enc_pass = get_reg("rsi")
 
        for i in range(16):
            for k in range(16):
                if enc_in[i] == enc_pass[k]:
                    key[k] = my_in[i]
 
        key_str = ""
        for i in key:
            if i == " ":
                key_str += "_" 
            else:
                key_str += chr(int(i, 16))
        print(key_str)
         
        ite += 1
    
    return key_str, ite

def solve_one_key() -> str:
    gdb_exec("checkpoint")
    key, ite = crack_key(1)
    gdb_exec("restart 0")
    gdb_exec("delete checkpoint "+str(ite-1))
    gdb_exec("delete checkpoint "+str(ite))
    gdb_exec("continue")
    gdb_exec("continue")

    return key

if __name__ == "__main__":
    gdb_exec("file crackme.bin")
    gdb_exec("break printf")
    gdb_exec("run")

    entry_addr = find_entry()
    gdb_exec("delete break")
    set_breaks(entry_addr)
    output = gdb_exec("continue")
   
    key1 = solve_one_key()
    key2 = solve_one_key()
    key3 = solve_one_key()

    print(key1, key2, key3)
    
    """

    gdb_exec("checkpoint")
    key1, ite = crack_key(1)
    gdb_exec("restart 0")
    gdb_exec("delete checkpoint "+str(ite-1))
    gdb_exec("delete checkpoint "+str(ite))
    gdb_exec("continue")
    gdb_exec("continue")
    
    gdb_exec("checkpoint")
    key2, ite = crack_key(1)
    gdb_("restart 0")


    print(key1, key2)

    gdb_exec("continue")
    """
