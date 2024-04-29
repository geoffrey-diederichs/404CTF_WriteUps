# Jean Pile

Here's a translated version of the subject :

```md
Annual 404 Race Canteen

Welcome everyone to the annual 404CTF race: it's D-Day, and a restaurant has been made available on-site for the participants. It is owned by someone named Jean Pile, and one thing is clear, his choices for the menu are very strange :

1 chicken, 2 chicken, 3 chicken...

How will you manage to extract information about the other contestants from him ?

Objective : read flag.txt
Please note that ASLR is activated.

Autor : @Narcisse
```

Let's test the program :

```console
$ ./jean_pile 
Bienvenue dans la cantine de la fameuse course annuelle du 404 ctf !
                                              _                    
                                   .-.  .--''` )                  
                                _ |  |/`   .-'`                   
                               ( `\      /`                       
                               _)   _.  -'._                       
                             /`  .'     .-.-;                      
                             `).'      /  \  \                   
                            (`,        \_o/_o/__                  
                             /           .-''`  ``'-.              
                             {         /` ,___.--''`             
                             {   ;     '-. \ \                  
           _   _             {   |'-....-`'.\_\                =============menu=============
          / './ '.           \   \          `"`                |                            |
       _  \   \  |            \   \                            |          1 pouler          |
      ( '-.J     \_..----.._ __)   `\--..__                    |          2 pouler          |
     .-`                    `        `\    ''--...--.          |          3 pouler          |
    (_,.--`/`         .-             `\       .__ _)           |                            |
            |          (                 }    .__ _)           ==============================
            \_,         '.               }_  - _.'                
               \_,         '.            } `'--'                  
                  '._.     ,_)          /                          
                     |    /           .'                           
                      \   |    _   .-'                            
                       \__/;--.||-'                               
                        _||   _||__   __                           
                 _ __.-` "`)(` `"  ```._)                        
                (_`,-   ,-'  `''-.   '-._)                         
               (  (    /          '.__.'                           
                `"`'--'"                                         

Voulez-vous commander un plat ou plus ?
>>> 1
Choisissez un plat.
>> 1
Merci à vous bonne soirée!
```

The program is asking for user inputs, let's see if it those are vulnerable to a buffer overflow.

## Static analysis

Using Ghidra, we can find this function :

```C
void service(void)
{
  char *pcVar1;
  char local_38 [40];
  int local_10;
  int local_c;
  
  puts("Voulez-vous commander un plat ou plus ?");
  printf(">>> ");
  fflush(stdin);
  __isoc99_scanf("%d",&local_10);
  getchar();
  if (local_10 == 1) {
    puts("Choisissez un plat.");
    printf(">> ");
    pcVar1 = fgets(local_38,200,stdin);
    if (pcVar1 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    for (local_c = 0; local_c < 200; local_c = local_c + 1) {
      if (local_38[local_c] == '\n') {
        local_38[local_c] = '\0';
      }
    }
  }
  else {
    puts("Choisissez un plat.");
    printf(">> ");
    pcVar1 = fgets(local_38,200,stdin);
    if (pcVar1 == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    for (local_c = 0; local_c < 200; local_c = local_c + 1) {
      if (local_38[local_c] == '\n') {
        local_38[local_c] = '\0';
      }
    }
    puts("Un nouveau serveur revient vers vous pour la suite de votre commande au plus vite.");
    service();
  }
  return;
}
```

This is the function used to get the user input, in which we can this spot this line of code :
`pcVar1 = fgets(local_38,200,stdin);`. The program is asking for an input of 200 bytes even tho `local_38` is only 40 bytes long : this is a buffer overflow.

There does not seem to be a win function, and as stated in the subject of the challenge ASLR is activated : we'll have to bypass by executing a ret2lib.

## Dynamic analysis


