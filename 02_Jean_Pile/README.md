# Jean Pile

## Analyse statique

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
  __isoc99_scanf(&DAT_004014a5,&local_10);
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
