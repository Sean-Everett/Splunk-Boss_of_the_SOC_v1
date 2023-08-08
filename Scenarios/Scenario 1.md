# Scenario 1 - Web Site Defacement

Below is the scenario verbatum from Splunk's site:

> Today is Alice's first day at the Wayne Enterprise Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprise's IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

Gcpd poison ivy memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html



## Questions:
101. What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

102. What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

103. What content management system is imreallynotbatman.com likely using?

104. What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

105. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

106. What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

108. What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

109. What is the name of the executable uploaded by Po1s0n1vy?

110. What is the MD5 hash of the executable uploaded?

111. GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

112. What special hex code is associated with the customized malware discussed in question 111?

114. What was the first brute force password used?

115. One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

116. What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

117. What was the average password length used in the password brute forcing attempt?

118. How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

119. How many unique passwords were attempted in the brute force attempt?



## Starting to Investigate

I was searching online for a good methodology on how to start looking into an alert and saw several posts on a simple query that lets you familiarize yourself with the dataset.
```
| metadata type=sourcetypes index="botsv1" 
```
![metadata](/Scenarios/Screenshots/metadata.png)

Now we can get an idea of what sourcetypes we are working with, along with how many logs are in each.



### 101
I started by using the index="botvs1" and searching for imreallynotbatman.com to get an idea of traffic ad any interesting fields data that stands out. 
```
index="botsv1" imreallynotbatman.com
```
Right of the bat, I see src_ip has three IP's with 40.80.148.42 showing 47,649 hits.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_src_ip.png">
</p>



### 102
To answer 102, I continued to use the last query and could see from the output that src_header has some interesting data. Clicking on src_header, I am able to figure out that Po1s0n1vy used Acunetix.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_acunetix.png">
</p>



### 103
103 took me a second. Personally in my career, I have helped a web team and only have seen NGINX and WordPress. After a quick Google of common CMS tools, I saw Joomla. As you would have it, Joomla shows up on the src_header option from the last question. 



### 104
I shouldn't say we cannot find the file that defaced the website, but before the can do that, Po1s0n1vy has to have access to the web server. We will have to come back to this one shortly.



### 105



### 106



### 107
Knowing that you have to POST form data to a web server, we can craft a query to see what IP's have been hitting the server.
```
index="botsv1" sourcetype="stream:http" http_method="POST" dest_ip="192.168.250.70" form_data=*username*passwd*
| stats count by src_ip
```
<p align="center">
    <img src="/Scenarios/Screenshots/s1_bruteforce_ip.png">
</p>



### 108



### 109



### 110



### 111



### 112
Take the query from 107 and remove the stats option and add:
```
| table _time form_data
| reverse
```
You can disregard reverse if you want to just click on time's filter option.
<p align="center">
    <img src="/Scenarios/Screenshots/s1_firstpw.png">
</p>



### 113



### 114



### 115



### 116



### 117