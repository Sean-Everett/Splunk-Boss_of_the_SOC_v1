# Scenario 2 - Rasomware



Below is the scenario 2 from Splunk's site:

>After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

>Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

Ransomware screen shot: https://botscontent.netlify.app/v1/cerber-sshot.png

Ransomware warning: https://botscontent.netlify.app/v1/cerber-sample-voice.mp3

Bots v1 sourcetype summary: https://botscontent.netlify.app/v1/bots_sourcetypes.html

Alices journal: https://botscontent.netlify.app/v1/alice-journal.html

Mission document: https://botscontent.netlify.app/v1/mission_document.html



## Questions:
1. What was the most likely IPv4 address of we8105desk on 24AUG2016?

2. Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

3. What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

4. What was the first suspicious domain visited by we8105desk on 24AUG2016?

5. During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?

6. What is the name of the USB key inserted by Bob Smith?

7. Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

8. How many distinct PDFs did the ransomware encrypt on the remote file server?

9. The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

10. The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

11. The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

12. Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?



## Starting the Investigate

Feeling more confident from scenario 1, lets move on to part 2!

### 1
Starting out, we know we need to look for "we8105desk" on August 24th 2016. You can set the date using the query or use the tool bar's built in feature.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_date.png">
</p>
Below, I will also provide a few images that will helps us here. On the left will be Windows EventID's and the right will be Sysmon EventID's:
<div id="event ids" align="center">
    <table>
	    <tr>
    	    <td style="padding:10px">
        	    <img src="/Scenarios/Screenshots/s2_winevents.png">
      	    </td>
            <td style="padding:10px">
            	<img src="/Scenarios/Screenshots/s2_sysmonids.png">
            </td>
        </tr>
    </table>
</div>
I was not certain is users are logging in locally or via RDP so I searched for both 4624 and 3. 4624 was mainly showing a process id. Got what I was looking for using EventID=3.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_sourceip.png">
</p>



### 2
The question lets you know to go straight to suricata logs. Added cerber and checked the interesting fields for signature id and was able to use stats.
```
index=botsv1 sourcetype=suricata cerber
| stats count by alert.signature_id
```
<p align="center">
    <img src="/Scenarios/Screenshots/s2_lowsigid.png">
</p>



### 3
From my network experience, I know that DNS uses A records and will point something human readable to an IP address. We got the source IP from question 1. Without adding "cerber" or "cerber*", there were 46 results. You could also add to the query to disregard well known domains to narrow it down if cerber wasn't part of the dns record.
```
NOT (query{}=*.microsoft.com OR query{}=*.google.com OR query{}=*.waynecorpinc.com)
```
<p align="center">
    <img src="/Scenarios/Screenshots/s2_fqdn.png">
</p>
As you can see, it lowered the results down to 36; which I could take down even farther by adding the ".local" but just want to show how you can filter out results.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_fqdn2.png">
</p>



### 4
For question 4, I added a few more options to help filter out some more DNS entries. 
<p align="center">
    <img src="/Scenarios/Screenshots/s2_sus.png">
</p>



### 5
To start, I just used vbs in the query and checked the source fields.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbs1.png">
</p>
I thought this was the way to go but wasted some time. Later, finally looked at the Sysmon logs with the following:

```
index=botsv1 source=WinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk vbs
```

I can see a few things that stand out.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbscl.png">
</p>
Since the question is asking about it launching from ".exe" and asking about length, I (against everything in me) disregarded the "decrypt my files" and tried to find the length of the other command.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_vbslen.png">
</p>



### 6
After some research, Windows Registry uses friendlyname for USB's. Used that to generate a query and looked around in the fields. Data showed MIRANDA_PRI.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_usb.png">
</p>



### 7
I had a few options on this one. I decided to search for the destination port of 445(smb) since it's for fileshares. Setting the host and looking for the destination, I was able to find the IP and server name.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_smbip.png">
</p>
<p align="center">
    <img src="/Scenarios/Screenshots/s2_smbsvr.png">
</p>



### 8
I wasted a bit of time on this one. I searched for the host being "we9041srv" and "pdf". It had some hits but being able to figure out how many files were encrypted was tricky. There wasn't anything that was out right saying encrypted. Finally saw accesses and files were deleted. Poking around more, I found relative target name.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_pdfs.png">
</p>



### 9
We know that Bob is using "we8105desk" and that script ran using the command line. If we look back at question 1, I shared an image of Event ID's and 1 is "Process Create". Sort by time so we have the initial process and parent ID's.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_pid.png">
</p>



### 10
The Sysmon Event ID list on question 1 shows Event ID 2 is for file creation. From the question, we are looking for .txt files in Bob's Windows profile. In the fields we can see TargetFileName. We can break that down into how many text files are seen.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_txt.png">
</p>



### 11
Looking at the Fortigate UTM, we can see the messages it gave from Bob's traffic. The single instance that stood out to me was "File is infected". 
<p align="center">
    <img src="/Scenarios/Screenshots/s2_msg.png">
</p>
Isolating that event, we can see the URL along with the file that was downloaded.
<p align="center">
    <img src="/Scenarios/Screenshots/s2_mhtr.png">
</p>



### 12
From my studies of Comptia Security+, we know that you can hide data in an image without ruining the image. This process is called Steganography.