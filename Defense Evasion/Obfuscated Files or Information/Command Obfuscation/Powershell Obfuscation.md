## Usecase
	Powershell Obfuscation

## Background
	Usecase ini berkaitan dengan Teknik MITRE berikut : 
	1027.010 Obfuscated Files or Information: Command Obfuscation


Ada beberapa teknik yang digunakan untuk mendeteksi Powershell Obfuscation
	
	1. Potential PowerShell Obfuscation Via Reversed Commands
<details>
	
![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/2c6c55c8-1491-4eff-82a7-72982f4a61c1)
![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/15a1b34d-ae78-4f98-a846-dd2ce1d9ab0f)
</details>

	2. Potential PowerShell Obfuscation Via WCHAR
 	Detects suspicious encoded character syntax often used for defense evasion.
<details>
	
![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/9b967158-de75-4441-b76b-6eb2b68cf63e)
![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/d0725a83-f6d2-42e9-954c-95a97712eada)
</details>

	3. Powershell Obfuscation and Escape Characters
 	Looks for the execution of PowerShell with unusually high counts of characters like ^, +, $, and %. 
	Inspired by the 2022 Red Canary Threat Detection report.
<details>

![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/274404cf-c7db-4714-920e-04fd2608ad17)
</details>

	Usecase akan memonitor jika dalam command powershell ditemukan sedikitnya 5 karakter - ^, +, $, and %
<details>
 
![image](https://github.com/harboot/JTI-SIEM-Playbook/assets/1296040/68fa03db-7557-43b7-b7d7-c162d3229395)
</details>


## Detection
<details>

'''
Process name Is:
	Powershell

Command Is: 
Hctac
kaerb
dnammoc
ekovn 
ekovni
eliFd
rahc
etirw
golon
tninon
eddih
tpircS
ssecorp
llehsrewop
esnopser
daolnwod
tneilCbeW
tneilc
hcaerof
ptth
elifotevas
46esab
htaPpmeTteG
tcejbO
maerts
retupmoc
char\)\s+0x
char\]\s+0x	
'^([^^+$%]*[\^+$%]){5,}[^^+$%]*$'
'''
</details>

## Procedure
	- Periksa aktivitas parent process (aplikasi) yang menjalankan perintah powershell, baik sesudah maupun sebelum alert ke trigger.
	- Jalankan full scan antivirus. 

## Reference
	- https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf
	- https://redcanary.com/threat-detection-report/techniques/powershell/

