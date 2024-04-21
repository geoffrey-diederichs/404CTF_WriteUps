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
