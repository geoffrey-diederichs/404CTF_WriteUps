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
  
Commençons pas analyser [ce crackme](./chall_example1/crackme.bin).

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

## Solution

```console
$ nc challenges.404ctf.fr 31998 > chall.zip && unzip chall.zip && chmod +x crackme.bin && gdb -q -x solver.py

Token ? 
 > 7bdbab98c126b915d314e52aeb63b33b
Alors, la solution ? 
 > M2GW4OQsS0MiLsYm
GG. Voila ton flag!
404CTF{e9d749db81e9f8caf745a5547da13579}
```
