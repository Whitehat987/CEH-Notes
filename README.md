Udemy - Notes
1. Wireshark
Explanation
Keywords to Notice: pcapng, hostname, Plain text format

Firstly, We will login to the Host Ethical hacker-1, then we will navigate to Documents Folder to access the moviescopemm.pcapng file by opening it in Wireshark Application.

Secondly, Since the credentials are in plain text we get the Plain text data by Right Clicking the IP Address of moviescope.com website and Selecting Follow -> TCP Stream

Note: There will be huge data to analyze but a simple search trick will help, in search box enter user and keep clicking Find Next button until your find the username and password value.
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
2. Windows server 2016(s.txt)

Keywords to Notice: server 2016, SECRET.txt, backdoor, Path

Firstly, Since we already have the IP Address and Credential for Server 2016 we can easily login to the Sever and navigate to that folder.

Secondly, As the file SECRET.txt is hidden, Open up Powershell Terminal and type ls -force and cat SECRET.txt

----------------------------------------------------------------------------------
3.Security Assesment Find OS name

Keywords to Notice: SQL injection, MySQL, Website

Firstly, after a complete Subnet scan with Nmap we can get the OS version and all services running on all the live machines.

Secondly, usually MySQL services runs on 3306 port number, so search it and determine the OS name and enter the text box
-----------------------------------------------------------------------------------------------------------------------
4.FTP server

Keywords to Notice: FTP, flag.txt

Firstly, The username list and password list files are stored on Desktop with Folder name “Wordlist”

Secondly, By using Hydra tool we can attack and get the credentials.

Command: hydra -L wordlist/userlist.txt -P wordlist/passlist.txt ftp://192.168.0.100


Thirdly, After getting the credentials, open Terminal(Parrot OS) , type FTP and Press Enter

Input Username and Password.

After successful login, type ls to view the files list, now to copy the “flag.txt” to local machine type

ftp> get flag.txt ~/Desktop/filepath/flag_data.txt

After getting the file, exit the FTP console and cat ~/Desktop/filepath/flag_data.txt

Note: If any error related to flag_data.txt, then first create a file with this name flag_data.txt and then run the above get command
-------------------------------------------------------------------------------------------------------------------
5.Wordpress password

Keywords to Notice: WordPress, james, ip address

Firstly, We have the URL for WordPress site and username, so we can easily crack WordPress login credentials by using wpscan tool

Second, using wpscan we will specify the username and password wordlist to crack.
-----------------------------------------------------------------------------------------------
6.Login Windows Server and Enumerate a User

Keywords to Notice: IP address, Domain user accounts,

There can be two approaches

1. Login to the Windows Server directly via the credentials and access the Local Users and Groups from the Server manager’s Tools Menu

2. Use ADExplorer and enter the credentials and view the details

Lastly, compare the usernames present in the question and enter the answer which is not present

--------------------------------------------------------------------------------------------------------
7.Employee Want to Delete File (Windows server 2016)

Keywords to Notice: document, Computer Name, Desktop

Firstly, after a complete Subnet scan with Nmap we can get the hostname, OS running on all the live machines.

Secondly, Identify which machine host windows Server 2016

Lastly, Login into to that devices via RDP by entering the Windows Server 2016 IP address with the given Credentials.

Browse the Desktop, locate and open the Text file to get the document number
--------------------------------------------------------------------------------------------------------------------------------------------------
8.VeraCrypt volume file

Keywords to Notice: Ethical Hacker-1, VeraCrypt, password, secret

Open the VeraCrypt tool -> Select File -> Mount -> Enter the Password(test) -> OK

Browse the File Explorer and check the newly add Disk, open the file present in it and answer
---------------------------------------------------------------------------------------------------
9.Android using ADB

Keywords to Notice: Android, SD Card, file

Firstly, After the initial Scan through Nmap we can determine the IP Address of a Android device, so we to connect the device using ADB command and retrieve the file

Secondly, Enter the below commands and connect to the Android and access the file

adb connect 192.168.0.4:5555
adb devices -l
adb shell
cd SD Card
ls 
cat file.txt
---------------------------------------------------------------------------------------------------
10.Dos Attack(Wire-shark)

Keywords to Notice: DOS.pcapng, IP Address, Document Folder

Firstly, We will login to the Host Ethical hacker-1, then we will navigate to Documents Folder to access the DOS.pcapng file by opening it in Wireshark Application

Secondly, In Wireshark go to Statistics and Select Conversations, IPv4 and click sort by packets

Now check the Packets numbers sent from A->B and B->A , the highest the number the going from one ip to another ip, will the IP Address which is doing DOS attack.

-----------------------------------------------------------------------------------------------------
11. DVWA Md5 Hash

Keywords to Notice: DVWA, MD5, type command, decrypt, file path, credentials

Here there are two method:

1. Upload a php shell file and take reverse shell and traverse through the folders to get hash.txt file and view the hash

2. Go to Command Injection after login to DVWA website by keeping the Security as Low.

Enter this command |type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt

This will show the hash, copy that hash and open https://hashes.com/en/decrypt/hash

website in another tab and paste to get the decrypted content

---------------------------------------------------------------------------------------------------
12. .Hex File Cryptool

Keywords to Notice: DES(ECB) Algorithm, FTP, Flag1.txt, Cry-DES (ECB)-FTP-lP.hex

Firstly, The question is all about the CrypTool, open the file in this tool and go to Encrypt/Decrypt Menu and select Symmetric(modern) -> DES(ECB) -> Decrypt. Now you can see the content of the file i.e, password.

Secondly, After getting the credentials, open Terminal (Parrot OS), type FTP and Press Enter

Input Username and Password.

After successful login, type ls to view the files list, now to copy the “flag1.txt” to local machine type

ftp> get flag1.txt ~/Desktop/filepath/flag_data1.txt

After getting the file, exit the FTP console and cat ~/Desktop/filepath/flag_data1.txt

Note: If any error related to flag_data1.txt, then first create a file with this name flag_data1.txt and then run the above get command
----------------------------------------------------------------------------------------------------
13. Remote Desktop Connection Open on Which Machine(NMAP)

Keywords to Notice: Windows remote Desktop, Nmap, IP Address

Firstly, we have to run a full Nmap Scan on the subnet, to get all the ports and services running on all machines.

Secondly, search for port 389(RDP port) in the output of Nmap and find the IP address which as this 389-port open.

------------------------------------------------------------------------------------------------------
14. SQl Injection(SQL Map)

Keywords to Notice: URL, Kety, SQL DSSS, Cookie, Ethical Hacker-2

Two ways.

1. Login to www.moviescope.com using credentials and browse to profile of the logged in user, and use IDOR vulnerability by changing the ID value until you see, Kety profile details

2. Use SqlMap tool to dump the entire database to get the details
---------------------------------------------------------------------------
15.  EncodedFile.txt(BcTextEncoder)

Keywords to Notice: Ethical Hacker-1, password, EncodedFile.txt

Firstly, Login to Ethical Hacker-1 machine, Browse the Admin Desktop and locate the EncodedFile.txt, Since we are pretty sure the we cant use snow.exe tool as it is encoded we use BCTextEncoder tool to decode the file.

Secondly, Locate the BCTextEncoder software in CEH tool shared drive, Open the EncodedFile.txt file and enter the password magic123 to decode
-----------------------------------------------------------------------------
16. Cheack MD5 Hashes(Hashcal)
Keywords to Notice: MD5 hashes, Imp folder, Path

In this case we have to compare one file hash with another and determine if there is change in it, we can HashCalc or MD5 Calculator.

Firstly, Open the File which contains the hash value and now open HashCalc tool to open the file which we need to verify the integrity.

Compare the Hash value, if there is change, then the file is been tampered or if both are same then the files are not tampered.
------------------------------------------------------------------------------
17. Perform Ddos Attack

Keywords to Notice: multiple sources, DDOS.pcapng, DDOS Attack

Firstly, Login to Ethical Hacker-2 machine and Open the file DDOS.pcapng from Wireshark

Secondly, In Wireshark go to Statistics and Select Conversations, sort by packets

Now we can see the number of IPv4 Address based on number of Packets transfer, count the unique IP Address with huge amount of Packet transfer
-----------------------------------------------------------------------------------
18. Cryptool Info

Keywords to Notice: Ethical Hacker-1, key-value, Cry-RC4- Accountno.hex

The question is all about the CrypTool, open the file in this tool and go to Encrypt/Decrypt Menu and select Symmetric(modern) -> RC4 -> KEY 14 -> Decrypt. Now you can see the content of the file.

Note: As the Encryption algorithm name is present in Filename, so they have not mentioned in the question.

------------------------------------------------------------------------------------
19.Cheack Website Method(Get POST )

Keywords to Notice: Method, OWASP , SQL Injection

There are two paths to solve this problem.

1. Here we must remember the HTTP Methods (GET, POST, PUT, DELETE etc) which are used in communication on Internet. Also, mostly parameter is passed using GET and POST methods. So, without using the OWASP tool on can guess it would be POST or GET method.

2. Run the OWASP tool, enter the web app URL and click on Attack button, wait till the attack completes and click the Spider section and analyze the request method used in it.

-------------------------------------------------------------------------------------
20.steganography(Snow)
Keywords to Notice: machine name, Path, Snow, password, steganography

Firstly, In this case EthicalHacker-1 machine is the attacker windows machine we know it because it will be given in the Details section In the exam.

Secondly, Since the file path is already given, we can easily navigate to file.

Lastly, open Terminal/PowerShell in the folder and use the SNOW.exe tool to decrypt the file by specifying the password

Command: SNOW.EXE -C -p test Confidential.txt
-------------------------------------------------------------------------------------

21.SMTP port Found IP

Keywords to Notice: Simple Mail Transfer Protocol, IP Address

Firstly, Run a full Nmap subnet Scan, to get all the ports/services and OS running on all machines.

Secondly, search for port 25(SMTP port) in the output of Nmap and find the IP address which as this 25-port open.
---------------------------------------------------------------------------------------
22. Windows server 2019 

Firstly, after a complete Subnet scan with Nmap we can get the hostname, OS running on all the live machines.

Secondly, Identify which machine host windows Server 2019

Lastly, Login into to that device via RDP by entering the Windows Server 2019 IP address with the given Credentials in the question.

Browse the Desktop folder, locate and open the Text file to get the document number.
------------------------------------------------------------------------------------------
23. OS version Of Mysql server Host

Keywords to Notice: SQL injection, MySQL, Website

Firstly, after a complete Subnet scan with Nmap we can get the OS version and all services running on all the live machines.

Secondly, usually MySQL services runs on 3306 port number, so search it and determine the OS name and the MYSQL version.
--------------------------------------------------------------------------------------------
24. Enumerate the Local User of the suspicious account

Keywords to Notice: IP address, local user account

Firstly, Login to the Windows machine via the given credentials and access the Local Users and Groups from Run Window(Win + R) and typing lusrmgr.msc

Compare the usernames present in the question and enter the answer which is NOT present

----------------------------------------------------------------------------------------------
25. stegnography  Snow 

Keywords to Notice: machine name, FilePath, password, steganography

Firstly, In this case EthicalHacker2 machine is the windows machine, login to the machine via the given credentials

Secondly, Since the file path is already given, we can easily navigate to file.

Lastly, open Terminal/PowerShell in the folder and use the SNOW.exe tool to decrypt the file by specifying the password

Command: SNOW.EXE -C -p secret123 whistleblower.txt
-----------------------------------------------------------------------------------------------
26. Wireshark Find .txt file in FTP

Firstly, We will login to the Host EthicalHacker2, then we will navigate to Documents Folder to access the FTPTraffic.pcapng file by opening it in Wireshark Application.

Secondly, Since the credentials are in plain text , type FTP in search bar this will show only FTP Protocol traffic. Right Clicking the IP Address of FTP traffic and Selecting Follow -> TCP Stream
-------------------------------------------------------------------------------------------------
27. Dos Attack(Wireshark)

Keywords to Notice: ServiceDown.pcapng, IP Address, Document Folder

Firstly, We will login to the Host Ethical hacker-1, then we will navigate to Documents Folder to access the ServiceDown.pcapng file by opening it in Wireshark Application

Secondly, In Wireshark go to Statistics and Select Conversations, IPv4 and click sort by packets

Now check the Packets numbers sent from A->B and B->A , the highest the number the going from one ip to another ip, will the IP Address which is doing the attack

--------------------------------------------------------------------------------------------------
28.Ddos Attack(Wireshark)

Keywords to Notice: multiple sources, DDOS.pcapng, DDOS Attack

Firstly, Login to Ethical Hacker-2 machine and Open the file DDOS.pcapng from Wireshark

Secondly, In Wireshark go to Statistics and Select Conversations, sort by packets

Now we can see the number of IPv4 Address based on number of Packets transfer, count the unique IP Address with huge amount of Packet transfer
------------------------------------------------------------------------------------------------------
29. SSH Brutforce using Hydra

Keywords to Notice: SSH, flag.txt

Firstly, The username list and password list files are stored on Desktop with Folder name “Wordlist”

Secondly, By using Hydra tool we can attack and get the credentials.

Command: hydra -L wordlist/userlist.txt -P wordlist/passlist.txt 192.168.0.100 ssh

Thirdly, After getting the credentials, open Putty or Terminal( ssh username@IPAddress) enter the credentials obtained.

After successful login, type locate flag.txt to find the file and its location, after getting the filepath.
cat /path/flag.txt
------------------------------------------------------------------------------------------------
30. Wordpress Scan(Brutforce Wpscan)

Keywords to Notice: WordPress, ross, ip address

Firstly, We have the URL for WordPress site and username, so we can easily crack WordPress login credentials by using WPSCAN tool

Second, using wpscan we will specify the username and password wordlist to crack.

wpscan --url http://172.16.0.27:8080/wordpress -u ross -P ~/Desktop/wordlists/password.txt
-----------------------------------------------------------------------------------------------------

31. LLMNR/NBT technique to get the password

eywords to Notice: LLMNR/NBT, hostname

Firstly, Since the EthicalHacker3 machine is auto logged in, open your parrot terminal and start the Responder tool. responder -I eth0 ↵

Secondly, Go back to EthicalHacker3 and open Run (Win+R) , type and path Eg://1.1.1.12 and press Enter.

Thirdly, Switch to Parrot machine terminal where you can see the Hash value of that machine request.

Lastly, To crack that hash, use JohntheRipper

john SMB<filename> ↵

EthicalHacker3 IP Address can be obtained from Intial Subnet scan or in exam the IP address will be provided for the same.

---------------------------------------------------------------------------------------------------------
32. DVWA crack Hash 

Keywords to Notice: DVWA, MD5, ls command, decrypt, file path, credentials



Here there are two method:

1. Upload a php shell file and take reverse shell and traverse through the folders to get hash.txt file and view the hash

2. Go to Command Injection tab after logging in to DVWA website by keeping the Security as Low.

Enter this command |ls var/www/html /DVWA/hackable/uploads/passcode.txt

This will show the hash, copy that hash and open https://hashes.com/en/decrypt/hash

website in another tab and paste to get the decrypted content
--------------------------------------------------------------------------------------------------------
33.Covert TCP
https://www.youtube.com/watch?v=bDcz4qIpiQ4&ab_channel=InfoVault
Traverse though each line in Wireshark and concentrate on Identification field, keep an eye on Hex value and ANSI value.
---------------------------------------------------------------------------------------------------------

34.IDOR Vulnerability

Keywords to Notice: website URL, Donna, IDOR,

Two ways.

Login to www.vulweb.com using credentials and browse to profile of the logged in user, and use IDOR vulnerability by changing the emp ID parameter in url until you see Donna profile details.

Use SqlMap tool to dump the entire database to get the details
--------------------------------------------------------------------------------------------------------------------
35.Cry-DES (ECB)-TELNET-lP.hex (Cryptool)

Keywords to Notice: DES(ECB) Algorithm, TELNET, Flag1.txt, Cry-DES (ECB)-TELNET-lP.hex

Firstly, The question is all about the CrypTool, open the file in this tool and go to Encrypt/Decrypt Menu and select Symmetric(modern) -> DES(ECB) -> Decrypt. Now you can see the content of the file i.e, password.

Secondly, After getting the credentials, open Terminal (Parrot OS), type TELNET IP-address and Press Enter

Input Username and Password.

After successful login, type dir to view the files

telnet@win$ dir

telnet@win$ type flag1.txt

After getting the file, type command to view the file details

------------------------------------------------------------------------------------------------------------------
36. Decode the file present in the Ethical Hacker-1(BCTextencoder)

Keywords to Notice: Ethical Hacker-1, password, EncodedFile.txt



Firstly, Login to Ethical Hacker-1 machine, Browse the Admin Desktop and locate the EncodedFile.txt, Since we are pretty sure the we cant use snow.exe tool as it is encoded we use BCTextEncoder tool to decode the file.

Secondly, Locate the BCTextEncoder software in CEH tool shared drive, Open the EncodedFile.txt file and enter the password magic123 to decode

-----------------------------------------------------------------------------------------------------------------------------
37.How many Live host are present in the network?(Netdiscover,Nmap)

Keywords to Notice: live host

We can either use Nmap tool or netdiscover command to get the number of live host in a network

Nmap: nmap -sP 192.168.2.1/24

Netdiscover :  netdiscover -r 192.168.29.1/24
