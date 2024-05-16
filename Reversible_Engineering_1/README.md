# Revers(ibl)e Engineering [1/2]

Here is a translated version of the challenge's description we were given :

```md
After a challenging year marked by competitions, you decide to return to your hometown. You are filled with emotion as you spot the dojo of your childhood and decide to visit it. Your former sensei is there, smiling.

"Clairvoyance is the most formidable weapon of a fighter. To anticipate each movement before it is made, that is the true mastery of combat. Rise to my challenge and prove your worth."

Retrieve a zip archive with netcat containing a crackme and a token, send back the token with the solution to the crackme to a second server, receive a flag... Easy. Small detail: you have twenty seconds to do all this, and the binary changes with each attempt.

Connection:
nc challenges.404ctf.fr 31998 > chall.zip
nc challenges.404ctf.fr 31999

Author: @Izipak (_hdrien)
```

Let's try to download one of those archives :

```console
$ nc challenges.404ctf.fr 31998 > chall.zip && unzip chall.zip && ls -l                                      
Archive:  chall.zip
 extracting: crackme.bin             
 extracting: token.txt               
total 36
-rw-r--r-- 1 coucou coucou 14742 Apr 24 10:13 chall.zip
-rw------- 1 coucou coucou 14496 Apr 24 08:13 crackme.bin
-rw------- 1 coucou coucou    32 Apr 24 08:13 token.txt

$ cat token.txt 
393aaf57eb0b625ab20cfa65327101f0

$ file crackme.bin
crackme.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=68dd82947dbeb975ddc70502cb740514ff8716a2, for GNU/Linux 3.2.0, stripped

$ checksec crackme.bin 
[*] '/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

$ chmod +x crackme.bin && ./crackme.bin 
J'ai besoin d'un argument!

$ ./crackme.bin A               
L'argument doit comporter 16 caractères.

$ ./crackme.bin AAAAAAAAAAAAAAAA
Dommage... Essaie encore!
```

`crackme.bin` asks for a 16 characters long input, then shuts down as it doesn't seem to be the correct password.  
Let's try to send a solution :

```console
$ nc challenges.404ctf.fr 31998 > chall.zip && unzip chall.zip && cat token.txt && printf '\n' && nc challenges.404ctf.fr 31999
Archive:  chall.zip
 extracting: crackme.bin             
 extracting: token.txt               
d5c35f615fa524da3326d295ea7585b6
Token ? 
d5c35f615fa524da3326d295ea7585b6
Alors, la solution ? 
test
Nope...
```
  
You can access these two examples of archives sent by the server : [archive 1](./chall_example1), [archive 2](./chall_example2).  
  
Let's analyse [the first crackme](./chall_example1/crackme.bin).

## Static analysis

Using Ghidra, we can find these functions :

```C
undefined8 main(int param_1,long user_input)
{
  int win_condition;
  undefined8 uVar1;
  size_t user_input_len;
  void *encoded_input;
  undefined8 encoded_pass_1;
  undefined8 encoded_pass_2;
  int input_len;
  
  if (param_1 < 2) {
    puts("J\'ai besoin d\'un argument!");
    uVar1 = 1;
  }
  else {
    user_input_len = strlen(*(char **)(user_input + 8));
    input_len = (int)user_input_len;
    if (input_len == 16) {
      encoded_pass_1 = 0xa9dab58698ccb89d;
      encoded_pass_2 = 0xbbd949da83d394c9;
      encoded_input = (void *)encode_input(*(undefined8 *)(user_input + 8));
      win_condition = memcmp(encoded_input,&encoded_pass_1,16);
      if (win_condition == 0) {
        puts("GG!");
        uVar1 = 0;
      }
      else {
        puts("Dommage... Essaie encore!");
        uVar1 = 1;
      }
    }
    else {
      puts(&DAT_00102028);
      uVar1 = 1;
    }
  }
  return uVar1;
}
```
```C
void * encode_input(long input)
{
  byte bVar1;
  byte bVar2;
  void *pvVar3;
  int local_c;
  
  pvVar3 = malloc(0x10);
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    bVar1 = *(byte *)(input + local_c);
    bVar1 = bVar1 ^ (byte)((bVar1 >> 2 & 1) << 4) ^ (bVar1 >> 5) * '\x02' & 2;
    bVar1 = bVar1 ^ (byte)(((uint)bVar1 & (int)(uint)bVar1 >> 3 & 1U) << 7);
    bVar1 = bVar1 ^ (bVar1 >> 7 & (byte)((int)(uint)bVar1 >> 2) & 1) * '\x02';
    bVar1 = bVar1 ^ ((char)bVar1 >> 7) * -2 & 2U;
    bVar1 = bVar1 ^ (byte)((int)(uint)bVar1 >> 5) & 1 & (byte)((int)(uint)bVar1 >> 1) ^ 0x40;
    bVar2 = bVar1 ^ bVar1 >> 1 & 1;
    bVar1 = bVar2 ^ (byte)((int)(uint)bVar2 >> 5) & 1 & (byte)((int)(uint)bVar2 >> 2) ^
            (byte)((bVar1 >> 5 & 1) << 4);
    bVar1 = bVar1 ^ (byte)((bVar1 & 1) << 2);
    bVar1 = bVar1 ^ (byte)((int)(uint)bVar1 >> 1) & 1 & (byte)((int)(uint)bVar1 >> 6) ^ 0x21;
    bVar1 = bVar1 ^ bVar1 >> 5 & 1 ^ 0x80;
    bVar1 = bVar1 ^ (byte)(((int)(uint)bVar1 >> 2 & (int)(uint)bVar1 >> 1 & 1U) << 3) ^
            (bVar1 >> 7) << 3;
    *(byte *)((long)local_c + (long)pvVar3) =
         bVar1 ^ (byte)(((int)(uint)bVar1 >> 3 & (int)(uint)bVar1 >> 4 & 1U) << 2) ^ 5;
  }
  return pvVar3;
}
```

The binary is stripped of any symbols, but I've modified some of the function and variable names to make this more understandable.

As we can see in the code above, the `main` function starts by checking if our input (stored as `user_input`) is indeed 16 characters long :

```C
    user_input_len = strlen(*(char **)(user_input + 8));
    input_len = (int)user_input_len;
    if (input_len == 16) {
```

If that's the case, it will pass it to the `encode_input` function. This function will encode our input, and return it as `encoded_input`. Finally, the encoded password stored under `encoded_pass_1` and `encoded_pass_2` will be compared to `encoded_input` :

```C
      encoded_pass_1 = 0xa9dab58698ccb89d;
      encoded_pass_2 = 0xbbd949da83d394c9;
      encoded_input = (void *)encode_input(*(undefined8 *)(user_input + 8));
      win_condition = memcmp(encoded_input,&encoded_pass_1,16);
```

A detail to understand in the previous snippet of code, is that the `memcmp` function is given a pointer towards `encoded_pass_1`, but is being told that the string to compare is 16 bytes long. Since both `encoded_pass_1` and `encoded_pass_2` are 8 bytes long, and they're stored right next to each other on the stack (being declared one right after the other), `memcmp` will indeed compare our encoded input to both these variables.  
 
Next, the program will tell us if we gave the right password depending on the `memcmp` return value :

```C
      if (win_condition == 0) {
        puts("GG!");
        uVar1 = 0;
      }
      else {
        puts("Dommage... Essaie encore!");
        uVar1 = 1;
      }
```

In other words, the password will be a 16 characters long input that once encoded by `encode_input` corresponds to `encoded_pass_1` and `encoded_pass_2`.  
  
Let's analyse [this second crackme](./chall_example2/crackme.bin) to try and find differences between the two programs. Using Ghidra, we can find :

```C
      encoded_pass_1 = 0x19182d3d0fd0973e;
      encoded_pass_2 = 0x30272025ded09705;
```

```C
void * encode_input(long param_1)
{
  byte bVar1;
  byte bVar2;
  void *pvVar3;
  int local_c;

  pvVar3 = malloc(0x10);
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    bVar1 = *(byte *)(param_1 + local_c) ^ (*(byte *)(param_1 + local_c) >> 4) << 7 ^ 0x80;
    bVar1 = bVar1 ^ (bVar1 >> 7) << 2;
    bVar1 = bVar1 ^ (byte)(((int)(uint)bVar1 >> 2 & (int)(uint)bVar1 >> 1 & 1U) << 7);
    bVar1 = bVar1 ^ (bVar1 >> 6) * '\x02' & 2 ^ 0x80;
    bVar2 = bVar1 ^ (byte)(((uint)(bVar1 >> 7) & (int)(uint)bVar1 >> 4 & 1U) << 2) ^
            (byte)((bVar1 >> 6 & 1) << 4);
    bVar2 = bVar2 ^ (byte)((bVar2 >> 1 & 1) << 2);
    bVar2 = bVar2 ^ (byte)(((uint)(bVar1 >> 7) & (int)(uint)bVar2 >> 5 & 1U) << 2);
    bVar1 = bVar2 ^ (byte)(((int)(uint)bVar2 >> 4 & (int)(uint)bVar2 >> 1 & 1U) << 6) ^ 6;
    bVar1 = bVar1 ^ ((byte)((int)(uint)bVar1 >> 6) & (byte)((int)(uint)bVar1 >> 3) & 1) * '\x02' ^
            0xc0;
    bVar1 = bVar1 ^ (bVar1 & (byte)((int)(uint)bVar1 >> 2) & 1) * '\x02';
    *(byte *)((long)local_c + (long)pvVar3) =
         bVar1 ^ ((byte)((int)(uint)bVar1 >> 5) & (byte)((int)(uint)bVar1 >> 6) & 1) * '\x02' ^ 1;
  }
  return pvVar3;
}
```

As we can see, it seems that both the encoded password and encoding function are randomly generated for each crackme. But since we've identified both the encoded password, and the snippet of code encoding our password, we can simply bruteforce the crackme.

To do so, we'll need to test every characters possible to find their encoded version and cross reference our results with the encoded password. We'll also need to script this procedure since this needs to be done in less than 20 seconds.
  
Let's try all this on [the first crackme](./chall_example1/crackme.bin) using GDB and Python.

## Dynamic analysis

We can execute any GDB command from a Python script, and get the output of that command as a string to parse. For example, here is a script retrieving the entry point of a program :

```python
import gdb

output = gdb.execute("info file", from_tty=False, to_string=True)
for i in output.split("\n"):
    if "Entry point" in i:
        print("This is the entry point : ", i.split(" ")[2])
```

```console
$ gdb -q crackme.bin -x example.py
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
Reading symbols from crackme.bin...
(No debugging symbols found in crackme.bin)
This is the entry point :  0x1080
```

Let's try, step by step, to test a few characters. We'll code a script  executing the same commands we do, and then put it all together to crack this binary.

First, the binary being stripped and PIE being activated, we'll need to calculate the address of the instructions we want to put breakpoints at based on the entry point and offsets we'll determine. Let's start by retrieving the entry point :

```gdb
gef➤  info file
Symbols from "/home/coucou/Documents/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin".
Local exec file:
	`/home/coucou/Documents/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin', 
        file type elf64-x86-64.
	Entry point: 0x1080'
[...]

gef➤  run
Starting program: /home/coucou/Documents/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
J'ai besoin d'un argument!
[Inferior 1 (process 49546) exited with code 01]

gef➤  info file
Symbols from "/home/coucou/Documents/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin".
Local exec file:
	`/home/coucou/Documents/404CTF_WriteUps/Reversible_Engineering_1/chall_example1/crackme.bin', 
        file type elf64-x86-64.
	Entry point: 0x555555555080'
[...]
```

Once we've ran the program once, the addresses won't be modified inside GDB anymore.

We've already coded this first part earlier to show how Python works with GDB, so let's directly jump to the next step : extracting the encoded password. Those should be in memory when they're being defined in the `main` function :

```C
encoded_pass_1 = 0xa9dab58698ccb89d;
encoded_pass_2 = 0xbbd949da83d394c9;
```

Let's try and find these instructions in GDB :

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551c7                  jmp    0x55555555523d
   0x5555555551c9                  movabs rax, 0xa9dab58698ccb89d
   0x5555555551d3                  movabs rdx, 0xbbd949da83d394c9
 → 0x5555555551dd                  mov    QWORD PTR [rbp-0x20], rax
   0x5555555551e1                  mov    QWORD PTR [rbp-0x18], rdx
   0x5555555551e5                  mov    rax, QWORD PTR [rbp-0x30]
   0x5555555551e9                  add    rax, 0x8
   0x5555555551ed                  mov    rax, QWORD PTR [rax]
   0x5555555551f0                  mov    rdi, rax
```
```gdb
gef➤  print $rax
$1 = 0xa9dab58698ccb89d

gef➤  print $rdx
$3 = 0xbbd949da83d394c9
```

We can see that the encoded password is stored in the register. Now let's calculate the offset between this instruction and the entry point :

```python3
>>> 0x5555555551dd - 0x555555555080
349
```

Using all of this, we can code this script extracting the encoded password :

```python
import gdb

ENCODED_PASS_OFFSET = 349 

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

if __name__ == "__main__":
    gdb_exec("file crackme.bin")
    gdb_exec("run")
    entry_addr = find_entry()
    enc_pass = find_encoded_pass(entry_addr)

    print(enc_pass)
```

```console
$ gdb -q -x test.py
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
J'ai besoin d'un argument!
[Inferior 1 (process 50339) exited with code 01]

Breakpoint 1, 0x00005555555551dd in ?? ()

['0x9d', '0xb8', '0xcc', '0x98', '0x86', '0xb5', '0xda', '0xa9', '0xc9', '0x94', '0xd3', '0x83', '0xda', '0x49', '0xd9', '0xbb']
```

Now, we'll need to input characters, and extract their encoded versions. The encoded input should be in memory during the `memcmp` call :

```C
win_condition = memcmp(encoded_input,&encoded_pass_1,16);
```

Let's try and find this instruction in GDB :

```gdb
gef➤  r $(python3 -c 'import sys; sys.stdout.buffer.write(b"ABCDEFGHIJQLMNOP")')
```

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555551ff                  mov    edx, 0x10
   0x555555555204                  mov    rsi, rax
   0x555555555207                  mov    rdi, rcx
●→ 0x55555555520a                  call   0x555555555050 <memcmp@plt>
   ↳  0x555555555050 <memcmp@plt+0000> jmp    QWORD PTR [rip+0x2fba]        # 0x555555558010 <memcmp@got.plt>
      0x555555555056 <memcmp@plt+0006> push   0x2
      0x55555555505b <memcmp@plt+000b> jmp    0x555555555020
      0x555555555060 <malloc@plt+0000> jmp    QWORD PTR [rip+0x2fb2]        # 0x555555558018 <malloc@got.plt>
      0x555555555066 <malloc@plt+0006> push   0x3
      0x55555555506b <malloc@plt+000b> jmp    0x555555555020
───────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
memcmp@plt (
   $rdi = 0x00005555555592a0 → 0xa5b3bab8bdafa2a8,
   $rsi = 0x00007fffffffd960 → 0xa9dab58698ccb89d,
   $rdx = 0x0000000000000010,
   $rcx = 0x00005555555592a0 → 0xa5b3bab8bdafa2a8
)
```

```gdb
gef➤  x/2gx $rdi
0x5555555592a0:	0xa5b3bab8bdafa2a8	0xb933b638b1bcaa2f
```

Our encoded password seems to be stored inside `rdi`. Since we are working on a little endian system, we can deduce that the character `A` is being encoded to `0xa8`, `B` to `0xa2`, etc. Let's calculate the offset between this instruction and the entry point :

```python
>>> 0x55555555520a - 0x555555555080
394
```

Using all of this, we can add these functions to our script to input 16 characters and extract their encoded version :

```python
MEMSET_OFFSET = 394

def set_break(entry_addr: str) -> None:
    new_char_addr = hex(int(entry_addr, 16)+MEMSET_OFFSET)
    gdb_exec(f"break *{new_char_addr}")

def encode(x: [chr]) -> [int]:
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

if __name__ == "__main__":
    gdb_exec("file crackme.bin")
    gdb_exec("run")
    entry_addr = find_entry()
    enc_pass = find_encoded_pass(entry_addr)
    set_break(entry_addr)
    encoded = encode("ABCDEFGHIJQLMNOP")

    print(encoded)
```

```console
$ gdb -q -x test.py
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
J'ai besoin d'un argument!
[Inferior 1 (process 51348) exited with code 01]

Breakpoint 1, 0x00005555555551dd in ?? ()

Breakpoint 2, 0x000055555555520a in ?? ()

['0xa8', '0xa2', '0xaf', '0xbd', '0xb8', '0xba', '0xb3', '0xa5', '0x2f', '0xaa', '0xbc', '0xb1', '0x38', '0xb6', '0x33', '0xb9']
```

Those values match the one we got earlier : our script is indeed working ! Let's add the final touch to it, and crack this binary.

## Exploit

To finish our script, we'll need to repeat the operation we did previously, checking new characters every time, and comparing their encoded version to the encoded password to find the solution. This function should do the trick :

```python
CHARACTERS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

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

if __name__ == "__main__":
    gdb_exec("file crackme.bin")
    gdb_exec("run")
    entry_addr = find_entry()
    enc_pass = find_encoded_pass(entry_addr)
    set_break(entry_addr)
    password = find_pass(enc_pass)

    print(password)
```

```console
$ gdb -q -x solver.py 

cE2bxX4T3j5q496S
```

```console
$ ./crackme.bin cE2bxX4T3j5q496S
GG!
```

We got the solution ! Now all that remains, is sending it back to the servers immediately using Python. [This script](./solver.py) puts it all together and should give us the flag in a few seconds :

```console
$ nc challenges.404ctf.fr 31998 > chall.zip && unzip chall.zip && chmod +x crackme.bin && gdb -q -x solver.py

Token ? 
 > 7bdbab98c126b915d314e52aeb63b33b
Alors, la solution ? 
 > M2GW4OQsS0MiLsYm
GG. Voila ton flag!
404CTF{e9d749db81e9f8caf745a5547da13579}
```

We get the flag !