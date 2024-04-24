# Revers(ibl)e Engineering [1/2]

## Sujet

```md
Après une année éprouvante marquée par les compétitions, vous décidez de rentrer dans votre village natal. C'est avec beaucoup d'émotion que vous apercevez le dojo de votre enfance et décidez de vous y rendre. Votre ancienne sensei vous y attend, le sourire aux lèvres.

"La clairvoyance est l'arme la plus redoutable du combattant. Anticiper chaque mouvement avant qu'il ne soit lancé, voilà la véritable maîtrise du combat. Relève mon défi et prouve ta valeur."

Récupérer une archive zip avec netcat contenant un crackme et un token, renvoyer le token avec la solution du crackme à un deuxième serveur, recevoir un flag... Facile. Petit détail : vous avez vingt secondes pour faire tout ça, et le binaire change à chaque essai.

Connexion :
nc challenges.404ctf.fr 31998 > chall.zip
nc challenges.404ctf.fr 31999
 
Auteur: @Izipak (_hdrien)
```

Essayons de récupérer une archive :

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

Tentons d'envoyer un flag :

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

Il va donc falloir télécharger une archive sur le premier service, résoudre le crackme qu'il contient, puis envoyer le token suivie de la solution au second service le tout en moins de 20 secondes.
  
Vous pouvez accéder à ces deux exemples d'archives : [archive 1](./chall_example1), [archive 2](./chall_example2).
  
Commençons pas analyser [le premier crackme](./chall_example1/crackme.bin).

## Analyse statique

En utilisant Ghidra, on retrouve ces deux fonctions :

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

Notre entrée est stocké dans la variable `param_2` passé à la fonction `FUN_00101169`
en argument. Cette fonction va ensuite vérifier que notre entrée fasse 16 charactères :

```C
    sVar3 = strlen(*(char **)(param_2 + 8));
    local_c = (int)sVar3;
    if (local_c == 16) {
```

Si c'est bien le cas, elle va ensuite l'envoyer à la fonction `FUN_0010123f`. Cette fonction va réaliser des opérations arithmétiques pour encoder `param_2`. Le résultat sera renvoyé à `FUN_00101169` qui le comparera à `local_28` et `local_20` :

```C
      local_28 = 0xa9dab58698ccb89d;
      local_20 = 0xbbd949da83d394c9;
      __s1 = (void *)FUN_0010123f(*(undefined8 *)(param_2 + 8));
      iVar1 = memcmp(__s1,&local_28,16);
```

Une nuance à bien comprendre dans ce code est que dans cette ligne `iVar1 = memcmp(__s1,&local_28,16);`, `memcmp` va évaluer 16 bytes à partir du pointeur vers `local_28`. Or `local_28` et `local_20` font chacuns 8 bytes et sont écrit à la suite dans la stack, autrement dit le code compare bien notre entrée à ces deux variables.  
  
Le programme nous indique ensuite si notre entrée une fois encodé correspond bien à ces deux variables :

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

Autrement dit, la solution de ce crackme est une suite de charactères qui une fois encodé par `FUN_0010123f` correspond à `local_28` et `local_20`.
  
Analyson maintenant [ce deuxième crackme](./chall_example2/crackme.bin) pour identifier les différences entre les crackmes qui nous sont envoyés. En utilisant Ghidra, on 
trouve ces deux différences :

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

Les variables `local_28` et `local_20` ainsi que l'algorithme d'encodage utilisé par la fonction `FUN_0010123f` semblent être généré aléatoirement pour chaque nouveau crackme.  
  
Il semble difficile de comprendre la fonction `FUN_0010123f` pour trouver un algoritme l'inversant, et cette fonction étant généré aléatoirement il serait impossible de le faire en 20 secondes pour envoyer la solution à temps. Essayons d'analyser dynamiquement le programme.

## Analyse dynamique

Utilisons GDB pour analyser ce que la fonction `FUN_0010123f` nous renvoie. Ajoutons un breakpoint au niveau de l'appel de `memcmp` et retrouvons notre entrée encodé dans le registre :

```gdb
gef➤  x/i 0x55555555520a
=> 0x55555555520a:	call   0x555555555050 <memcmp@plt>

gef➤  break *0x55555555520a
Breakpoint 1 at 0x55555555520a

gef➤  run $(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*16)')
```

Une fois le breakpoint atteint :

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

En analysant les arguments de `memcmp`, on déduit que `rdi` contient notre entrée encodée. Affichons la :

```gdb
gef➤  x/2gx $rdi
0x5555555592a0:	0xa8a8a8a8a8a8a8a8	0xa8a8a8a8a8a8a8a8
```

On en déduit que le byte `0x41` (`A` en ascii), correspond à `0xa8` une fois encodé. En procédant de cette manière nous pouvons encoder plusieurs caractères, mais malheureusement aucun pattern ne semble émerger : il va faloir encoder tous les bytes possibles pour ensuite cracker la solution (`local_28` et `local_20`).
  
Seulement `FUN_0010123f` étant généré aléatoirement à chaque crackme, il va falloir automatiser le processus pour cracker la solution en moins de 20 secondes. Essayons de scripter la démarche réalisé lors de cette analyse dynamqiue.

## Exploit

Pour se faire, nous allons utiliser un script python. Nous pouvons exécuter n'importe quelle commande GDB et récuperer le résultat de cette commande avec python, par exemple voici un script récupérant le point d'entrée du programme donné :

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

Dans ce script, il a fallu :
- Récupérer le point d'entrée du programme à partir duquel les adresses utilisées pour interrompre l'exécution du programme sont calculées. 
- Interrompre le programme à un moment bien précis lors duquel la solution encodée est enregistré dans la mémoire pour pouvoir la récupérer.
- Encoder des bytes en les injectant, puis interrompre le programme au moment de l'appel de `memcmp` pour récupérer l'entrée encodée dans la mémoire.
- Comparer les caratères encodés à la solution encodé pour en déduire le mot de passe.
- Ouvrir le fichier `token.txt` pour récuperer le token.
- Se connecter en TCP pour envoyer le token suivie du mot de passe.

Il faut ensuite optimiser ce programme pour qu'il crack le solution en moins de 20 secondes. Pour se faire, au lieu d'encoder 1 byte à la fois comme précedemment dans la solution dynamqiue, nous allons encoder 16 bytes à la fois (la taille maximum des entrées possibles). Et après avoir cracker quelques crackme, nous pouvons remarquer que les mots de passes sont uniquement constitués de caractères alphanumériques réduisant énormément les bytes à encoder. Ce qui nous donne [ce script](./solver.py) qui crack le mot de passe et envoie la solution en quelques secondes :

```console
$ nc challenges.404ctf.fr 31998 > chall.zip && unzip chall.zip && chmod +x crackme.bin && gdb -q -x solver.py

Token ? 
 > 7bdbab98c126b915d314e52aeb63b33b
Alors, la solution ? 
 > M2GW4OQsS0MiLsYm
GG. Voila ton flag!
404CTF{e9d749db81e9f8caf745a5547da13579}
```
