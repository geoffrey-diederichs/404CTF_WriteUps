```gdb
gef➤  set follow-fork-mode child
gef➤  set detach-on-fork off
gef➤  set env LD_PRELOAD=./ptrace.so

gef➤  set {char}0x5555555562c9=0x75
```

```console
$ python3 -c 'import sys; sys.stdout.buffer.write(b"fi3r_n4n0comb4ttant")' | ./nanocombattant
=================================================================================
Bienvenue dans l'arène ! Pour rentrer, saisissez le mot de passe du CHAUSSURE :  
_____                                                                       _____
(   ) ≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈  (   )
 |||                                                                         ||| 
 |||          ~Qu'est-ce que tu peux faire contre le 404 CROU~               ||| 
 |||            ~on a la méthode et les XOR qui rendent fou~                 ||| 
 |||                                                                         ||| 
(___) ≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈≈  (___)

              >>> Bienvenue dans l'arène frère d'arme !
```
