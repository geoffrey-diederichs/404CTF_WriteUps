# Revers(ibl)e Engineering [1/2]

Here is a translated version of the challenge's description we were given :

```md
After a challenging year marked by competitions, you decide to return to your hometown. You are filled with emotion as you spot the dojo of your childhood and decide to visit it. Your former sensei is there, smiling.

"Clairvoyance is the most formidable weapon of a fighter. To anticipate each movement before it is made, that is the true mastery of combat. Rise to my challenge and prove your worth."

Retrieve a zip archive with netcat containing a crackme and a token, send back the token with the solution to the crackme to a second server, receive a flag... Easy. Small detail: you have twenty seconds to do all this, and the binary changes with each attempt.

Connection:
nc challenges.404ctf.fr 31998 > chall.zip
nc challenges.404ctf.fr 31999

Author: @Izipak (_hdrien)
```

Let's try to download one of those archives :

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

`crackme.bin` asks for a 16 characters long input, then shuts down as it doesn't seem the be the correct password.  
Let's try to send a solution :

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

As we can see, we'll need to download an archive, solve the crackme, and then send back the token followed by the solution in under 20 seconds.  
  
You can access those two examples of archives sent by the servers : [archive 1](./chall_example1), [archive 2](./chall_example2).  
  
Let's analyse [the first crackme](./chall_example1/crackme.bin).
