import gdb
import socket

HOST = "challenges.404ctf.fr"
PORT = 31999

ENCODED_PASS_OFFSET = 349 
MEMSET_OFFSET = 394
CHARACTERS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

def gdb_exec(command: str) -> str:
    return gdb.execute(command, from_tty=False, to_string=True)

def find_entry() -> str:
    info = gdb_exec("info file")
    for i in info.split("\n"):
        if "Entry point:" in i:
            return i.split(" ")[2]
    return ""

def find_encoded_pass(entry_addr: str) -> [hex]:
    pass_addr = hex(int(entry_addr, 16)+ENCODED_PASS_OFFSET)
    gdb_exec(f"break *{pass_addr}")
    gdb_exec("run "+"A"*16)
    full_pass = [ "_" for i in range(16) ]
    
    enc_pass = gdb_exec("print $rax")
    enc_pass = enc_pass.split(" ")[2][2:18]
    for i in range(int(len(enc_pass)/2)):
        full_pass[7-i] = hex(int(enc_pass[(i*2):(i*2)+2], 16))

    enc_pass = gdb_exec("print $rdx")
    enc_pass = enc_pass.split(" ")[2][2:18]
    for i in range(int(len(enc_pass)/2)):
         full_pass[15-i] = hex(int(enc_pass[(i*2):(i*2)+2], 16))

    gdb_exec("delete breakpoints")
    return full_pass

def set_break(entry_addr: str) -> None:
    new_char_addr = hex(int(entry_addr, 16)+MEMSET_OFFSET)
    gdb_exec(f"break *{new_char_addr}")

def encode(x: [chr]) -> [hex]:
    argument = ""
    for i in x:
        argument += i
    gdb_exec("run "+argument)
    enc_x_raw = gdb_exec("x/2gx $rdi")
    full_enc_x = [ "_" for i in range(16) ]

    enc_x = enc_x_raw.split("\t")[1][2:18]
    for i in range(int(len(enc_x)/2)):
        full_enc_x[7-i] = hex(int(enc_x[(i*2):(i*2)+2], 16))
    
    enc_x = enc_x_raw.split("\t")[2][2:18]
    for i in range(int(len(enc_x)/2)):
        full_enc_x[15-i] = hex(int(enc_x[(i*2):(i*2)+2], 16))
    
    return full_enc_x

def find_pass(enc_pass: [hex]) -> str:
    password = [ "_" for i in range(16) ]
    for i in range(4):
        charac = CHARACTERS[i*16:16+i*16]
        if i == 3:
            charac.append("A")
            charac.append("A")
        encoded = encode(charac)
        for k in range(16):
            for j in range(16):
                if enc_pass[k] == encoded[j]:
                    password[k] = charac[j]
    return "".join(password)

def send_password(password: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = s.recv(1024)
        print(data.decode("utf-8"), end="")
        with open("token.txt", "r") as f:
            token = f.read()
            print(" >", token)
            s.send(token.encode()+b"\n")
        data = s.recv(1024)
        print(data.decode("utf-8"), end="")
        print(" >", password)
        s.send(password.encode()+b"\n")
        data = s.recv(1024)
        print(data.decode("utf-8"), end="")


if __name__ == "__main__":
    gdb_exec("file crackme.bin")
    gdb_exec("run")
    entry_addr = find_entry()
    enc_pass = find_encoded_pass(entry_addr)
    set_break(entry_addr)
    password = find_pass(enc_pass)

    send_password(password)
