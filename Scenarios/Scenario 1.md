# Scenario 1 - Web Site Defacement

Below is the scenario verbatum from Splunk's site:

> Today is Alice's first day at the Wayne Enterprise Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprise's IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

Gcpd poison ivy memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html



## Questions:
1. What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

2. What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

3. What content management system is imreallynotbatman.com likely using?

4. What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

5. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

6. What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

7. What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

8. What is the name of the executable uploaded by Po1s0n1vy?

9. What is the MD5 hash of the executable uploaded?

10. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

11. What special hex code is associated with the customized malware discussed in question 111?

12. What was the first brute force password used?

13. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

14. What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

15. What was the average password length used in the password brute forcing attempt?

16. How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

17. How many unique passwords were attempted in the brute force attempt?



## Starting to Investigate

I was searching online for a good methodology on how to start looking into an alert and saw several posts on a simple query that lets you familiarize yourself with the dataset.
```
| metadata type=sourcetypes index="botsv1" 
```
![metadata](/Scenarios/Screenshots/metadata.png)

Now we can get an idea of what sourcetypes we are working with, along with how many logs are in each.



### 1
I started by using the index="botvs1" and searching for imreallynotbatman.com to get an idea of traffic and any interesting fields data that stands out. 
```
index="botsv1" imreallynotbatman.com
```
Right off the bat (see what I did there =P), I see src_ip has three IP's with 40.80.148.42 showing 47,649 hits.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_src_ip.png">
</p>



### 2
To answer 2, I continued to use the last query and could see from the output that src_header has some interesting data. Clicking on src_header, I am able to figure out that Po1s0n1vy used Acunetix.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_acunetix.png">
</p>



### 3
3 took me a second. Personally in my career, I have helped a web team and only have seen NGINX and WordPress. After a quick Google of common CMS tools, I saw Joomla. As you would have it, Joomla shows up on the src_header option from the last question. 



### 4
Looking at the Suricata logs with the source IP as the web server, I was poking through the interesting fields and came across http.http_content_type. This showed one image. 
<p align="center">
    <img src="/Scenarios/Screenshots/s1_jpeg.png">
</p>
I then expanded the raw text option and found the jpeg file name. This data also helps point us to the next question. It pays to sometimes read a ahead so you have an idea of the next few questions =P
<p align="center">
    <img src="/Scenarios/Screenshots/s1_batmanjpeg.png">
</p>



### 5
From number 4's image of the jpeg, we can see the image came from prankglassinebracket.jumpingcrab.com. NOt sure if it's an easter egg or not but the port is 1337 or LEET. 



### 6
Number 4 also shows the IP as the dest_IP: 23.22.63.114



### 7
Knowing that you have to POST form data to a web server, we can craft a query to see what IP's have been hitting the server.
```
index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
| stats count by src_ip
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_bruteforce_ip.png">
</p>



### 8
For this one, I just added .exe to the search field and only had two hits. I did not know what shtml was so after looking it up, I could rule it out; giving me 3791.exe
<p align="center">
    <img src="/Scenarios/Screenshots/s1_exe.png">
</p>



### 9
I was having no luck just looking in fields and raw data. I switched between sysmon logs and suricata. Just searching the index for the file name and piping it to stats value(md5) gave me what I needed.Also noticed that when looking up the 23.22.63.114 IP on threatminer.org that is had three md5 hashes. The middle one being the md5 hash that sysmon logs showed.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_md5hash.png">
</p>



### 10
This on uses OSINT to find. When we scanned the attacker's IP in VirusTotal, we can see the MirandaTateScreensaver.scr.exe file under "Communicating Files (4)". VirusTotal provides us with the SHA256 hash.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_sha256.png">
</p>



### 11
hex code



### 12
Take the query from 7 and remove the stats option and add:
```
| table _time form_data
| reverse
```
You can disregard reverse if you want to just click on _time's sort option.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_firstpw.png">
</p>



### 13
Searching around for Coldplay songs that had six letters and then looking at the list of passwords used. There are 214 passwords that are six letters long. We can use a search and check against a list from whatever source you found the list of songs. I did not use "Fix You" because of the space.
```
| eval pwlen=len(userpassword)
| search pwlen=6
| where userpassword  in ("clocks", "oceans", "sparks", "shiver", "yellow")
| table userpassword
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_coldplay.png">
</p>
<p align="center">
    <img src="/Scenarios/Screenshots/s1_yellow.png">
</p>


### 14
This one wasn't hard but I need more experience using rex expressions. We can continue working off the query from 7 and 12.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats count by userpassword
```
We can see from the count that "batman" is the only password used twice hinting that it is the correct password.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_correctpw.png">
</p>



### 15
This one was a bit tricky for me. I had to do a lot of searching for way to average as well as figure out the syntax.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| eval pwlen=len(userpassword)
| stats avg(pwlen) AS avglen
| eval avglen=round(avglen,0)
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_pwlength.png">
</p>



### 16
Working off of the query from 17, lets change out the last portion to utilize search and transaction. This will only look at the times batman is used and check the time it took between uses. Round to two decimal places.
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| search userpassword=batman
| transaction userpassword
| table duration
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_pwtime.png">
</p>



### 17
Still using the rex expression, we can use stats to count by unique (or distinc count) passwords.
You can see that there are 413 total but remember one of the passwords was used twice once it was figured out. 
```
| rex field=form_data "passwd=(?<userpassword>\w+)"
| stats dc by userpassword
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_uniquepw.png">
</p>