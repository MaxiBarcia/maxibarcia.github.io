HTB nos proporciona una direccion ip del laboratorio a vulnerar con la herramienta metasploit. 


![msf](/assets/images/posts/htb/metasploit1.png){: .align-center}

luego de buscar el nombre de la aplicacion web se procede a buscar un exploit `search elfinder` se procede a configurar como se aprecia en los comandos ingresados.

![msf](/assets/images/posts/htb/msf2.png){: .align-center}


y se procede a ejectuar en modo jobs `exploit -j` generando asi una session nueva.
![msf](/assets/images/posts/htb/msf3.png){: .align-center}
enumeramos las sessiones yse ve como se creo la session 1, ingresamos y podemos encontrar que ya estamo scomo www-data.
asi podemos ver como crear el exploit -j minimizandolo a la session 1 y asi poder utilizar el `job`

----------
### Esclando privilegios. 

Lo primero es `background` o Ctrl + Z -> (y)  y ponernos a buscar en este caso vulnerabilidad de sudo y para ello lo buscamos como 
```json
msf6> grep baron search sudo
msf6> use 63 (ya sabia que este servia)
msf6> set SESSION 1
msf6> exploit

```
![msf](/assets/images/posts/htb/msf4.png){: .align-center}


root!