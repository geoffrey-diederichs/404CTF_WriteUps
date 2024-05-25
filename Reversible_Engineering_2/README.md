# Revers(ibl)e Engineering [2/2]

Here is a translated version of the challenge's description we were given :

```md
It is recommended to finish Revers(ibl)e Engineering [1/2] before attempting this challenge.
Due to the nature of the generated binaries, you may want to run them in a VM.

'I see that my teaching has borne fruit, let's increase the level. When anticipating during a fight becomes impossible, only the one who can dance on the edge of the unpredictable can triumph in this ballet of the unknown.'

Same principle as the previous challenge, but this time you have ten minutes. Lucky you! However, the crackmes are for single use only. Not very eco-friendly, I know..
nc challenges.404ctf.fr 31990 > chall.zip
nc challenges.404ctf.fr 31991

Author : @Izipak (_hdrien)
```

You can access these two examples of binaries sent by the server : [binary 1](./chall_example1/crackme.bin), [binary 2](./chall_example2/crackme.bin).

Let's try and run one of these binaries :

```console
$ ./crackme.bin
Veuillez fournir votre clé de vérification.
Clé : AAAAA
Mauvaise clé, dommage..

$ ./crackme.bin

```

The program is asking us a for a key, and it just seems to freeze without doing anything when we execute the program a second time. As mentionned in the description above, we probably can only run it once.

Let's analyze [this binary](./chall_example1/crackme.bin) to try and understand what's going on.

## Static analysis

Using Ghidra, we can find these functions :

```C
undefined8 main(void)
{
  int win_condition;
  long lVar1;
  undefined8 *puVar2;
  undefined message [128];
  undefined user_input [16];
  undefined password [16];
  undefined8 shellcode [33];
  int connection_success_2;
  int connection_success;
  
  puVar2 = shellcode;
  for (lVar1 = 0x20; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  connection_success = download_shellcode(shellcode);
  if (connection_success < 0) {
    printf("Une erreur est survenue lors de la verification :(");
    exit(1);
  }
  while( true ) {
    connection_success_2 = download_password_message(password,message);
    if (connection_success_2 < 0) {
      printf("Une erreur est survenue lors de la verification :(");
      exit(1);
    }
    if (connection_success_2 == 1337) break;
    get_input(message,user_input);
    win_condition = check_input(shellcode,password,user_input);
    if (win_condition != 0) {
      puts(&LOOSE);
      exit(1);
    }
  }
  puts(&WIN);
  return 0;
}
```
```C
void get_input(undefined8 message,undefined8 *user_input)
{
  undefined8 buffer;
  undefined8 local_20;
  
  printf("%s",message);
  fgets((char *)&buffer,32,stdin);
  *user_input = buffer;
  user_input[1] = local_20;
  return;
}
```
```C
bool check_input(undefined8 shellcode,undefined8 password,void *user_input)
{
  int win_condition;
  void *encoded_password;
  
  encode_input(shellcode,user_input);
  encoded_password = (void *)encode_password(password);
  win_condition = memcmp(user_input,encoded_password,16);
  return win_condition != 0;
}
```
```C
void encode_input(long shellcode,undefined8 user_input)
{
  code *pcVar1;
  int local_c;
  
  local_c = 0;
  while (pcVar1 = *(code **)(shellcode + (long)local_c * 8), pcVar1 != (code *)0x0) {
    (*pcVar1)(user_input);
    local_c = local_c + 1;
  }
  return;
}
```
```C
void * encode_password(long password)
{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  void *pvVar4;
  int local_c;
  
  pvVar4 = malloc(0x10);
  for (local_c = 0; local_c < 0x10; local_c = local_c + 1) {
    bVar1 = *(byte *)(password + local_c);
    bVar2 = bVar1 ^ (byte)((bVar1 >> 2 & 1) << 5);
    bVar2 = bVar2 ^ (byte)(((int)(uint)bVar2 >> 5 & (int)(uint)bVar2 >> 2 & 1U) << 4);
    bVar2 = bVar2 ^ (byte)(((uint)(bVar1 >> 7) & bVar2 & 1) << 3);
    bVar2 = bVar2 ^ bVar2 * '\x02' & 2 ^ (bVar1 >> 7) << 5 ^ 0x10;
    bVar2 = bVar2 ^ (byte)(((uint)(bVar1 >> 7) & (int)(uint)bVar2 >> 5 & 1U) << 4) ^
            (bVar1 >> 7) << 5;
    bVar2 = bVar2 ^ bVar2 * '\x02' & 2 ^ 1 ^ (bVar1 >> 7) << 4 ^ (bVar1 >> 7) << 3 ^
            (byte)((bVar2 >> 5 & 1) << 3);
    bVar2 = bVar2 ^ (byte)(((int)(uint)bVar2 >> 4 & (int)(uint)bVar2 >> 2 & 1U) << 6) ^ 0x10;
    bVar2 = bVar2 ^ (byte)(((int)(uint)bVar2 >> 2 & bVar2 & 1) << 6);
    bVar3 = bVar2 ^ 0x10;
    bVar3 = bVar3 ^ (byte)((bVar3 >> 4 & 1) << 2);
    bVar3 = bVar3 ^ bVar1 >> 7 & (byte)((int)(uint)bVar3 >> 1);
    bVar2 = bVar3 ^ (byte)(((int)(uint)bVar3 >> 1 & (int)(uint)bVar3 >> 4 & 1U) << 2) ^
            (byte)((bVar2 >> 5 & 1) << 3);
    bVar2 = bVar2 ^ (byte)(((int)(uint)bVar2 >> 1 & (int)(uint)bVar2 >> 4 & 1U) << 2) ^ 0x20;
    *(byte *)((long)local_c + (long)pvVar4) = bVar2 ^ (byte)((int)(uint)bVar2 >> 3) & bVar1 >> 7;
  }
  return pvVar4;
}
```

The binary is stripped of any symbols, but I've modified some of the function and variable names to make this more understandable. I also didn't put the source code of the `download_shellcode` and `download_password_message` functions in this write-up as that won't be useful to crack this binary. But it is important to know that these functions are used by the program to connect back to the servers and download data. Moreover, we can deduce that this is why the program can only be executed once (the servers will send us the required data once, on the second attempt they won't respond). And we should execute this on a VM since the communication with the server aren't secured : we are directly executing a shellcode they send us without any verifications.

As you can see in the code above, the `main` function starts by trying to download a shellcode :

```C
  connection_success = download_shellcode(shellcode);
```

If successful, we enter a while loop in which we download the password to crack, and a message printed out later on :

```C
  while( true ) {
    connection_success_2 = download_password_message(password,message);
```

If successful, it will call the `get_input` function that will print out the downloaded message before taking an input of 32 bytes :

```C
  printf("%s",message);
  fgets((char *)&buffer,32,stdin);
```

This input, along with the downloaded password and shellcode will then be passed on to the `check_input` function which will encode both the input and password before comparing them :

```C
  encode_input(shellcode,user_input);
  encoded_password = (void *)encode_password(password);
  win_condition = memcmp(user_input,encoded_password,16);
```

We can see in the source code of these functions that our input is encoded using the given shellcode, while the password is encoded by some obfuscated arithmetic operations. Depending on the return code of the `memcmp` function, the program will either exit or keep running the while loop :

```C
  win_condition = memcmp(user_input,encoded_password,16);
  return win_condition != 0;
```
```C
    win_condition = check_input(shellcode,password,user_input);
    if (win_condition != 0) {
      puts(&LOOSE);
      exit(1);
    }
```

By analyzing [the other binary](./chall_example2/crackme.bin), we can see that just like [the previous challenge](../Reversible_Engineering_1/) `encode_password`, the password to crack, and the shellcode used by `encode_input` all changed. 

To crack the password, we'll need to input characters, and extract their encoded version to cross check them with the encoded password. This challenge is pretty similar to [the previous one](../Reversible_Engineering_1/), but in this case we can't run it over and over again trying out different passwords each time since the servers will only give us the required data once. We'll need to take a snapshot of the program after it received everything from the server, and come back to it once the input has been processed. To do so, we'll use [checkpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Checkpoint_002fRestart.html) in GDB.

We'll need to put a checkpoint when the input is given, send our characters to be encoded, then extract their encoded versions during the `memcmp` call and cross reference them with the `encoded_password`.

## Exploit

For this write up, we won't be able to go into as much details [as the previous one](../Reversible_Engineering_1/) since the servers are down. But you can still find [this script](./solver.py) solving the binaries :

```md
$ cat token.txt 
b59db5ce88ebee1563521008f7896836

$ nc challenges.404ctf.fr 31991
Token ? 
b59db5ce88ebee1563521008f7896836
Alors, la solution ? 
MLpocSzoM65ZqEbc9jey96L3SgMpEKVa8LuhzMEEXdhUDcCx
GG. Voila ton flag!
404CTF{4df8110da3b4c5c1e87e564418fab97f}
```

The key differences between this script and the previous one being the use of checkpoints, that there are three keys to solve (after you've solved a key the servers sends you a new one), and that the inputs are given manually so the script has to also extract the `user_input` to determine what the encoded bytes correspond to.
