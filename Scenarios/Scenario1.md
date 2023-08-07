# Scenario 1 - Website Defacement

Below is the scenario verbatum from Splunk's site:

> Today is Alice's first day at the Wayne Enterprise Security Operations Center. Lucius sits Alice down and gives her first assignment: A memo from Gotham City Police Department (GCPD). Apparently GCPD has found evidence online (http://pastebin.com/Gw6dWjS9) that the website www.imreallynotbatman.com hosted on Wayne Enterprise's IP address space has been compromised. The group has multiple objectives... but a key aspect of their modus operandi is to deface websites in order to embarrass their victim. Lucius has asked Alice to determine if www.imreallynotbatman.com. (the personal blog of Wayne Corporations CEO) was really compromised.

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Splunk quick reference guide: https://www.splunk.com/pdfs/solution-guides/splunk-quick-reference-guide.pdf

Gcpd poison ivy memo: https://botscontent.netlify.app/v1/gcpd-poisonivy-memo.html

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html

### Questions:
101 - What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

102 - What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name.

103 - What content management system is imreallynotbatman.com likely using?

104 - What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with extension?

105 - This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

106 - What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

108 - What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

109 - What is the name of the executable uploaded by Po1s0n1vy?

110 - What is the MD5 hash of the executable uploaded?

111 - GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the Po1s0n1vy APT group, if initial compromise fails, is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to Po1s0n1vys initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.

112 - What special hex code is associated with the customized malware discussed in question 111?

114 - What was the first brute force password used?

115 - One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. We are looking for a six character word on this one. Which is it?

116 - What was the correct password for admin access to the content management system running "imreallynotbatman.com"?

117 - What was the average password length used in the password brute forcing attempt?

118 - How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login?

119 - How many unique passwords were attempted in the brute force attempt?