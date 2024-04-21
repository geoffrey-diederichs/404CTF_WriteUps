# Échauffement

## Sujet

```md
Un bon échauffement permet non seulement d'éviter des blessures, mais aussi de conditionner son corps et son esprit au combat qui va suivre. Ce crackme devrait constituer un exercice adéquat.

 
Auteur: @Izipak (_hdrien)
```

[Ce fichier](./echauffement.bin) est fournit. Testons le :

```console
$ ./echauffement.bin 
Vous ne devinerez jamais le mot de passe secret ! Mais allez-y, essayez..
test
C'est bien ce que je pensais, vous ne connaissez pas le mot de passe..
```

Il demande une entrée avant de s'interrompre. Essayons de trouver le mot de passe.

# Analyse statique

Avec Ghidra nous trouvons les fonctions suivantes :

```C
undefined8 main(void)
{
  int iVar1;
  char local_48 [64];
  
  puts("Vous ne devinerez jamais le mot de passe secret ! Mais allez-y, essayez..");
  fgets(local_48,64,stdin);
  iVar1 = secret_func_dont_look_here(local_48);
  if (iVar1 == 0) {
    puts(&DAT_001020c8);
  }
  else {
    puts("C\'est bien ce que je pensais, vous ne connaissez pas le mot de passe..");
  }
  return 0;
}
```

```C
undefined4 secret_func_dont_look_here(long param_1)
{
  size_t sVar1;
  undefined4 local_10;
  int local_c;
  
  sVar1 = strlen(secret_data);
  local_10 = 0;
  for (local_c = 0; local_c < (int)sVar1; local_c = local_c + 1) {
    if ((char)(*(char *)(param_1 + local_c) * 2 - (char)local_c) != secret_data[local_c]) {
      local_10 = 1;
    }
  }
  return local_10;
}
```

La fonction main récupère notre entrée et l'envoie à `secret_func_dont_look_here` qui la compare à une variable `secret_data`. En retrouvant cette variable dans la mémoire, nous trouvons un pointeur qui nous redirige ici :

```md
                             DAT_00102008                                    XREF[3]:     secret_func_dont_look_here:00101
                                                                                          secret_func_dont_look_here:00101
                                                                                          00104040(*)  
        00102008 68              ??         68h    h
        00102009 5f              ??         5Fh    _
        0010200a 66              ??         66h    f
        0010200b 83              ??         83h
        0010200c a4              ??         A4h
        0010200d 87              ??         87h
        0010200e f0              ??         F0h
        0010200f d1              ??         D1h
        00102010 b6              ??         B6h
        00102011 c1              ??         C1h
        00102012 bc              ??         BCh
        00102013 c5              ??         C5h
        00102014 5c              ??         5Ch    \
        00102015 dd              ??         DDh
        00102016 be              ??         BEh
        00102017 bd              ??         BDh
        00102018 56              ??         56h    V
        00102019 c9              ??         C9h
        0010201a 54              ??         54h    T
        0010201b c9              ??         C9h
        0010201c d4              ??         D4h
        0010201d a9              ??         A9h
        0010201e 50              ??         50h    P
        0010201f cf              ??         CFh
        00102020 d0              ??         D0h
        00102021 a5              ??         A5h
        00102022 ce              ??         CEh
        00102023 4b              ??         4Bh    K
        00102024 c8              ??         C8h
        00102025 bd              ??         BDh
        00102026 44              ??         44h    D
        00102027 bd              ??         BDh
        00102028 aa              ??         AAh
        00102029 d9              ??         D9h
        0010202a 00              ??         00h
        0010202b 00              ??         00h
        0010202c 00              ??         00h
        0010202d 00              ??         00h
        0010202e 00              ??         00h
        0010202f 00              ??         00h
```

Avec un peu de traitement de donné on extrait la variable `secret_data` en hexadecimal :

```python
['68', '5f', '66', '83', 'a4', '87', 'f0', 'd1', 'b6', 'c1', 'bc', 'c5', '5c', 'dd', 'be', 'bd', '56', 'c9', '54', 'c9', 'd4', 'a9', '50', 'cf', 'd0', 'a5', 'ce', '4b', 'c8', 'bd', '44', 'bd', 'aa', 'd9', '00', '00', '00', '00', '00', '00']
```

Notre entrée est comparé à cette variable dans cette boucle :

```C
  for (local_c = 0; local_c < (int)sVar1; local_c = local_c + 1) {
    if ((char)(*(char *)(param_1 + local_c) * 2 - (char)local_c) != secret_data[local_c]) {
      local_10 = 1;
    }
  }
```

Essayons d'inverser cette algorithme.

## Analyse dynamique

En inversant l'opération mathématique effectué dans cette ligne `if ((char)(*(char *)(param_1 + local_c) * 2 - (char)local_c) != secret_data[local_c])`, essayons de calculer le premier charatère du mot de passe :

```python
>>> hex(int((0x68+0)/2))
'0x34'
```

`0x68` étant le premier charactère de `secret_data`. Vérifions sur GDB que nous avons le bon charactère :

```gdb
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5593398d11a9 <secret_func_dont_look_here+0054> add    rax, rdx
   0x5593398d11ac <secret_func_dont_look_here+0057> movzx  eax, BYTE PTR [rax]
   0x5593398d11af <secret_func_dont_look_here+005a> cmp    BYTE PTR [rbp-0xd], al
 → 0x5593398d11b2 <secret_func_dont_look_here+005d> je     0x5593398d11bb <secret_func_dont_look_here+102>	TAKEN [Reason: Z]
   ↳  0x5593398d11bb <secret_func_dont_look_here+0066> add    DWORD PTR [rbp-0x4], 0x1
      0x5593398d11bf <secret_func_dont_look_here+006a> mov    eax, DWORD PTR [rbp-0x4]
      0x5593398d11c2 <secret_func_dont_look_here+006d> cmp    eax, DWORD PTR [rbp-0xc]
      0x5593398d11c5 <secret_func_dont_look_here+0070> jl     0x5593398d1183 <secret_func_dont_look_here+46>
      0x5593398d11c7 <secret_func_dont_look_here+0072> mov    eax, DWORD PTR [rbp-0x8]
      0x5593398d11ca <secret_func_dont_look_here+0075> leave  
```

En analysant le code, on comprend que ce jmp est réalisé lorsque la condition est validé. Nous avons le bon algorithme pour reverse le mot de passe. Automatisons le.

## Exploit

En utilisant [ce script](./exploit.py) qui reprend la formule mathématique appliqué dans l'analyse dynamique, et l'applique sur la variable `secret_data` retrouvé dans l'analyse statique, on obtient :

```python
$ python3 exploit.py                                                 
[+] Starting local process './echauffement.bin': pid 18899
[*] Switching to interactive mode
[*] Process './echauffement.bin' stopped with exit code 0 (pid 18899)
Vous ne devinerez jamais le mot de passe secret ! Mais allez-y, essayez..
Wow, impressionnant ! Vous avez réussi !
[*] Got EOF while reading in interactive
$ 
Flag :  404CTF{l_ech4uff3m3nt_3st_t3rm1ne}\x11\x11\x12\x12\x13\x13
```

Le flag est donc : `404CTF{l_ech4uff3m3nt_3st_t3rm1ne}`.
