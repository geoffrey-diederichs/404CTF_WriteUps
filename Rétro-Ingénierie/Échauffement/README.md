# Échauffement

## Sujet

```md
Un bon échauffement permet non seulement d'éviter des blessures, mais aussi de conditionner son corps et son esprit au combat qui va suivre. Ce crackme devrait constituer un exercice adéquat.

 
Auteur: @Izipak (_hdrien)
```

[Ce fichier](./echauffement.bin) est fournit.

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


