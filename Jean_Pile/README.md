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
