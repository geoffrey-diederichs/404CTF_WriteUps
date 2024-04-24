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

Il va donc faloir télécharger une archive sur le premier service, résoudre le crackme qu'il contient, puis envoyer le token suivie de la solution au second service.
  
Vous pouvez accéder à ces deux exemples d'archives : [archive 1](./chall_example1), [archive 2](./chall_example2).
  
Commençons pas analyser [ce crackme](./chall_example1/crackme.bin).



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
