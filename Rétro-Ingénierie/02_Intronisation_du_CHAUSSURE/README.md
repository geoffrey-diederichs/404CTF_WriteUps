# Intronisation du CHAUSSURE

## Sujet

```md
Montrez votre valeur

Le CHAUSSURE, cette fameuse entité pionnière dans le domaine du sport de combat a ouvert un tournoi pour tous les chat-diateurs qui souhaiteraient se mesurer au reste du monde. Les présélections commencent et un premier défi a été publié par le CHAUSSURE. Ce dernier semble très cryptique, à vous d'en déceler les secrets!
 
Auteur : @Narcisse
```

[Ce programme](./intronisation) est fournit. Essayons le :

```console
$ ./intronisation
Bienvenue, rétro-ingénieur en herbe!
Montre moi que tu es à la hauteur :
>>> test
Mauvaise réponse...
```

Ce programme demande une entrée puis s'interrompt. Analysons le.

## Analyse statique

En utilisant Ghidra, on trouve ces fonctions :

```C
void processEntry entry(void)
{
  size_t sVar1;
  char local_28;
  char local_27;
  char local_26;
  char local_25;
  char local_24;
  char local_23;
  char local_22;
  char local_21;
  char local_20;
  char local_1f;
  char local_1e;
  char local_1d;
  char local_1c;
  
  syscall();
  syscall();
  sVar1 = _strlen(&local_28);
  if (((((sVar1 == 14) && (local_27 == 't')) && (local_21 == 'r')) &&
      ((((local_1e == '1' && (local_1d == 's')) &&
        ((local_23 == 'n' && ((local_24 == '1' && (local_26 == 'u')))))) && (local_28 == '5')))) &&
     ((((local_1f == 'n' && (local_1c == '3')) && (local_20 == '0')) &&
      ((local_25 == 'p' && (local_22 == 't')))))) {
    syscall();
  }
  else {
    syscall();
  }
  syscall();
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```

On comprend très rapidement que l'entrée de l'utilisateur est évalué dans cette condition :

```C
  if (((((sVar1 == 14) && (local_27 == 't')) && (local_21 == 'r')) &&
      ((((local_1e == '1' && (local_1d == 's')) &&
        ((local_23 == 'n' && ((local_24 == '1' && (local_26 == 'u')))))) && (local_28 == '5')))) &&
     ((((local_1f == 'n' && (local_1c == '3')) && (local_20 == '0')) &&
      ((local_25 == 'p' && (local_22 == 't')))))) {
```

La variable `sVar1` semble contenir la longeur de notre entrée : `sVar1 = _strlen(&local_28);`. Il faudrait donc que notre mot passe fasse 14 charactères d'après cette condition : `sVar1 == 14`.    
En remettant les charactères dans l'ordre (par rapport à celui dans lequel ils sont initialisés), on obtient : `5tup1ntr0n1s3`. Ce qui fait 13 charactères (si la fonction utilisé par le programme récupère le `\n` nous n'aurons pas à rajouter de charactères). Essayons :

```console
$ ./intronisation               
Bienvenue, rétro-ingénieur en herbe!
Montre moi que tu es à la hauteur :
>>> 5tup1ntr0n1s3
Bravo !!!
```

Nous avons donc le flag : `404CTF{5tup1ntr0n1s3}`.
