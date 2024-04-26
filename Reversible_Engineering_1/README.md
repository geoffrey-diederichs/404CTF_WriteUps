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
  
You can access those two examples of archives sent by the server : [archive 1](./chall_example1), [archive 2](./chall_example2).  
  
Let's analyse [the first crackme](./chall_example1/crackme.bin).

## Static analysis

Using Ghidra, we can find those functions :

```C
undefined8 FUN_00101169(int param_1,long param_2)
{
  int iVar1;
  undefined8 uVar2;
  size_t sVar3;
  void *__s1;
  undefined8 local_28;
  undefined8 local_20;
  int local_c;
  
  if (param_1 < 2) {
    puts("J\'ai besoin d\'un argument!");
    uVar2 = 1;
  }
  else {
    sVar3 = strlen(*(char **)(param_2 + 8));
    local_c = (int)sVar3;
    if (local_c == 16) {
      local_28 = 0xa9dab58698ccb89d;
      local_20 = 0xbbd949da83d394c9;
      __s1 = (void *)FUN_0010123f(*(undefined8 *)(param_2 + 8));
      iVar1 = memcmp(__s1,&local_28,16);
      if (iVar1 == 0) {
        puts("GG!");
        uVar2 = 0;
      }
      else {
        puts("Dommage... Essaie encore!");
        uVar2 = 1;
      }
    }
    else {
      puts(&DAT_00102028);
      uVar2 = 1;
    }
  }
  return uVar2;
}

void * FUN_0010123f(long param_1)
{
  byte bVar1;
  byte bVar2;
  void *pvVar3;
  int local_c;
  
  pvVar3 = malloc(0x10);
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    bVar1 = *(byte *)(param_1 + local_c);
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

Our entry is passed as `param_2` to the `FUN_00101169` function. This function will check if the entry is indeed 16 characters long :

```C
    sVar3 = strlen(*(char **)(param_2 + 8));
    local_c = (int)sVar3;
    if (local_c == 16) {
```

If that's the case, it will pass it to the `FUN_0010123f` function. This function will encode `param_2` and return it. Finally, `FUN_00101169` will compare the encoded entry to `local_28` and `local_20` :

```C
      local_28 = 0xa9dab58698ccb89d;
      local_20 = 0xbbd949da83d394c9;
      __s1 = (void *)FUN_0010123f(*(undefined8 *)(param_2 + 8));
      iVar1 = memcmp(__s1,&local_28,16);
```

A detail to understand in the previous snippet of code, is that the `memcmp` function is given a pointer towards `local_28`, but is being told that the string to compare is 16 bytes long. Since both `local_28` and `local_20` are 8 bytes long, and they're stored right next to each other on the stack (being declared one right after the other), `memcmp` will indeed compare our encoded input to both those variables.  
 
Next, the program will tell us if we gave the right password depending on the `memcmp` return value :

```C
      if (iVar1 == 0) {
        puts("GG!");
        uVar2 = 0;
      }
      else {
        puts("Dommage... Essaie encore!");
        uVar2 = 1;
      }
```

In other words, the password will be a 16 characters long input that once encoded by `FUN_0010123f` corresponds to `local_28` and `local_20`. From now on, we'll call `FUN_0010123f` the encoding function, and the two variables `local_28`, `local_20` the encoded password.  
  
Let's analyse [this second crackme](./chall_example2/crackme.bin) to try and find differences between the two programs. Using Ghidra we find those two differences :

```C
      local_28 = 0x19182d3d0fd0973e;
      local_20 = 0x30272025ded09705;
```

```C
void * FUN_0010123f(long param_1)
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

As we can see, it seems that both the encoded password and encoding function are randomly generated for each crackme. There is either a pattern to be found to easily reverse the encoding function and find the password, or we'll need to brute force it.  
  
Let's dynamically analyse [the first crackme](./chall_example1/crackme.bin) to find out which case scenario we're in.

## Dynamic analysis

Using GDB let's have a deeper look into what `FUN_0010123f` returns. We'll add a breakpoint after the `memcmp` call to find our encoded entry in the register :

```gdb
gef➤  x/i 0x55555555520a
=> 0x55555555520a:	call   0x555555555050 <memcmp@plt>

gef➤  break *0x55555555520a
Breakpoint 1 at 0x55555555520a

gef➤  run $(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*16)')
```

Once the breakpoint's reached :

```gdb
───────────────────────────────────────────────────────────────────── code:x86:64 ────
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
───────────────────────────────────────────────────────────── arguments (guessed) ────
memcmp@plt (
   $rdi = 0x00005555555592a0 → 0xa8a8a8a8a8a8a8a8,
   $rsi = 0x00007fffffffd8f0 → 0xa9dab58698ccb89d,
   $rdx = 0x0000000000000010,
   $rcx = 0x00005555555592a0 → 0xa8a8a8a8a8a8a8a8
)
```

By analysing the `memcmp` call's arguments, we can deduce that `rdi` contains our encoded entry. Let's take a look at it :

```gdb
gef➤  x/2gx $rdi
0x5555555592a0:	0xa8a8a8a8a8a8a8a8	0xa8a8a8a8a8a8a8a8
```

We can see that the `0x41` bytes (`A` in ascii) we injected got encoded to `0xa8`. If our encoded password contained a`0xa8`, we would have found one the password's character.  
  
We can now repeat this process on different bytes to try and find a pattern, but sadly none seem to emerge : we'll have to brute force the algorithm by testing every byte one by one until we find the password.
  
Since the encoding function seems to be generated randomly, we'll need to script this procedure.

## Exploit

To do so, we'll use Python. We can execute any GDB command from a Python script, and get the output of that command as a string to parse. For example, here is a script retrieving the entry point of a program :

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

[This script](./solver.py) solve the given `crackme.bin`, by :
- Retrieving the entry point of the program, from which the addresses where we'll need to add breakpoints to analyse memory will be calculated.
- Retrieving the encoded password in memory.
- Encoding bytes by passing them to the program as arguments, and retrieve them once encoded by inspecting memory during the `memcmp` call.
- Comparing our encoded bytes to the encoded password to deduce the password.
- Connecting to the server to send it both our token and password.

This script is also optimized enough to find the password in less than a few seconds.  
To do so, instead of encoding one byte at a time like we did in the dynamic analysis, the script encodes 16 bytes at a time since the program takes an input of 16 bytes. Also, after craking a few passwords, we can notice that they almost always consist of alphanumerical characters. That's why this script only works with those characters to considerably reduce the number of bytes we have to encode.  
  
Finally let's run it :

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
