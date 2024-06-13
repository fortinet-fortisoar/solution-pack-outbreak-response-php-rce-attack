# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

FortiGuard Labs has observed increased exploitation attempts targeting the new PHP vulnerability on over 25,000 unique IPS devices. The TellYouThePass ransomware gang has been leveraging CVE-2024-4577, a remote code execution vulnerability in PHP to deliver web shells and deploy ransomware on targeted systems. 

 The **Outbreak Response - PHP RCE Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.1.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/php-rce-attack) contains information about the outbreak alert **Outbreak Response - PHP RCE Attack**. 

## Background: 

CVE-2024-4577 is a critical argument injection vulnerability in PHP that can be exploited to achieve remote code execution (RCE). Censys has observed about 458,800 instances of potentially vulnerable PHP servers as of June 9, 2024.

TellYouThePass ransomware was previously associated with Log4Shell exploitation, targeting Windows and Linux, and has been active since 2019. 

 

## Announced: 

Researchers at watchTowr released a proof-of-concept (PoC) script for CVE-2024-4577 on their GitHub page.
Fortinet customers remain protected through the IPS signature to detect and block the attack attempts targeting the vulnerability. FortiGuard Labs recommends users apply the most recent patch from the vendor to fully mitigate any risks.  

## Latest Developments: 

June 10, 2024: Imperva Threat Research reported on attacker activity leveraging the new PHP vulnerability.
https://www.imperva.com/blog/update-cve-2024-4577-quickly-weaponized-to-distribute-tellyouthepass-ransomware/

June 7, 2024: Researchers at watchTowr released a proof-of-concept (PoC) script for CVE-2024-4577 on their GitHub page.
https://github.com/watchtowrlabs/CVE-2024-4577

June 6, 2024: Patched versions were released by PHP to address this vulnerability.
https://www.php.net/ 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|