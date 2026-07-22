# CVE Repository

*A curated archive of proof-of-concept exploits and technical write-ups for analyzed CVEs, organized by affected product.*

This repository documents vulnerabilities (CVEs) that have been researched and reproduced across a range of products. Each entry contains a technical write-up and, where applicable, a proof-of-concept (PoC) script. All material is provided for educational purposes and authorized security research only. Entries are organized by product and listed alphabetically so a specific exploit is easy to locate.

## Disclaimer

The exploits, proof-of-concept code, and technical write-ups in this repository were developed and are published **strictly for educational purposes and authorized security research**, including learning, defensive testing, and coordinated vulnerability disclosure.

You must have **explicit, written authorization** to test any system that you do not own. Using this material against systems without permission may be illegal and is entirely your own responsibility.

The author provides this material "as is", without warranty of any kind, and **accepts no liability** for any misuse, damage, or unlawful activity carried out with it. By accessing or using anything in this repository, you agree that you alone are responsible for your actions and for complying with all applicable laws and regulations.

## Repository Structure

Each vulnerability lives in its own folder, following the convention `<Product>/<CLASS> - <CVE-ID>/`: a `README.md` write-up plus an optional proof-of-concept script (not always present).

```
<Product>/<CLASS> - <CVE-ID>/
|-- README.md      # technical write-up and reproduction steps
`-- <poc>          # optional proof-of-concept script (not always present)
```

- `<Product>` - the affected product (e.g. `Linux Kernel`, `Keycloak`).
- `<CLASS>` - the vulnerability class (e.g. `RCE`, `SQLi`, `LPE`, `PathTraversal`, `CWE###`).
- `<CVE-ID>` - the CVE identifier, or an advisory / GHSA id where no CVE was assigned.

## Vulnerabilities by Product

### Adminer
- [FileRead - CVE-2020-35572](./Adminer/FileRead%20-%20CVE-2020-35572)

### Adobe ColdFusion
- [RCE - CVE-2009-2265](./Adobe%20ColdFusion/RCE%20-%20CVE-2009-2265)

### ADV190005
- [HTTP/2 Settings Flood - adv190005.py](./ADV190005/adv190005.py)

### Apache ActiveMQ
- [RCE - CVE-2023-46604](./Apache%20ActiveMQ/RCE%20-%20CVE-2023-46604)

### Apache OFBiz
- [RCE - CVE-2023-51467](./Apache%20OFBiz/RCE%20-%20CVE-2023-51467)

### Apache Struts2
- [PathTraversal - CVE-2024-53677](./Apache%20Struts2/PathTraversal%20-%20CVE-2024-53677)

### apport
- [LPE - CVE-2023-1326](./apport/LPE%20-%20CVE-2023-1326)

### below
- [LPE - CVE-2025-27591](./below/LPE%20-%20CVE-2025-27591)

### Bludit
- [RCE - CVE-2019-16113](./Bludit/RCE%20-%20CVE-2019-16113)

### Cacti
- [RCE - CVE-2025-24367](./Cacti/RCE%20-%20CVE-2025-24367)

### Camaleon CMS
- [AuthBypass - CVE-2025-2304](./Camaleon%20CMS/AuthBypass%20-%20CVE-2025-2304)

### ClamAV
- [XXE - CVE-2023-20052](./ClamAV/XXE%20-%20CVE-2023-20052)

### CMS Made Simple
- [SQLi - CVE-2019-9053](./CMS%20Made%20Simple/SQLi%20-%20CVE-2019-9053)

### CPython
- [PathTraversal - CVE-2025-4517](./CPython/PathTraversal%20-%20CVE-2025-4517)

### CrushFTP
- [AuthBypass - CVE-2025-31161](./CrushFTP/AuthBypass%20-%20CVE-2025-31161)

### CUPS
- [RCE - CVE-2024-47176](./CUPS/RCE%20-%20CVE-2024-47176)

### CVE-2023-44487
- [HTTP/2 Rapid Reset - CVE-2023-44487.py](./CVE-2023-44487/CVE-2023-44487.py)

### Docker Desktop
- [SSRF - CVE-2025-9074](./Docker%20Desktop/SSRF%20-%20CVE-2025-9074)

### Dolibarr
- [RCE - CVE-2023-30253](./Dolibarr/RCE%20-%20CVE-2023-30253)

### Drupal
- [RCE - CVE-2018-7600](./Drupal/RCE%20-%20CVE-2018-7600)

### Druva inSync
- [LPE - CVE-2020-5752](./Druva%20inSync/LPE%20-%20CVE-2020-5752)

### Enlightenment
- [LPE - CVE-2022-37706](./Enlightenment/LPE%20-%20CVE-2022-37706)

### Erlang OTP SSH
- [RCE - CVE-2025-32433](./Erlang%20OTP%20SSH/RCE%20-%20CVE-2025-32433)

### esm.sh
- [LFI - CVE-2025-59341](./esm.sh/LFI%20-%20CVE-2025-59341)

### FreePBX
- [SQLi - CVE-2025-57819](./FreePBX/SQLi%20-%20CVE-2025-57819)
- [PathTraversal - CVE-2025-61678](./FreePBX/PathTraversal%20-%20CVE-2025-61678)

### Ghost CMS
- [PathTraversal - CVE-2023-40028](./Ghost%20CMS/PathTraversal%20-%20CVE-2023-40028)

### GlobalProtect
- [RXSS - CVE-2025-0133](./GlobalProtect/RXSS%20-%20CVE-2025-0133)

### GLPI
- [SQLi - CVE-2025-24799](./GLPI/SQLi%20-%20CVE-2025-24799)

### GNU Bash
- [RCE - CVE-2014-6271](./GNU%20Bash/RCE%20-%20CVE-2014-6271)

### Grafana
- [RCE - CVE-2024-9264](./Grafana/RCE%20-%20CVE-2024-9264)
- [PathTraversal - CVE-2021-43798](./Grafana/PathTraversal%20-%20CVE-2021-43798)

### HFS (HttpFileServer)
- [RCE - CVE-2014-6287](./HFS%20(HttpFileServer)/RCE%20-%20CVE-2014-6287)

### ImageMagick
- [RCE - CVE-2024-41817](./ImageMagick/RCE%20-%20CVE-2024-41817)

### ISPConfig
- [RCE - CVE-2023-46818](./ISPConfig/RCE%20-%20CVE-2023-46818)

### Jenkins
- [CWE200 - CVE-2025-59474](./Jenkins/CWE200%20-%20CVE-2025-59474)

### JetBrains TeamCity
- [AuthBypass - CVE-2023-42793](./JetBrains%20TeamCity/AuthBypass%20-%20CVE-2023-42793)

### Joomla
- [AuthBypass - CVE-2023-23752](./Joomla/AuthBypass%20-%20CVE-2023-23752)

### js2py
- [RCE - CVE-2024-28397](./js2py/RCE%20-%20CVE-2024-28397)

### Keycloak
- [CWE200 - CVE-2020-27838](./Keycloak/CWE200%20-%20CVE-2020-27838)
- [RXSS - CVE-2021-20323](./Keycloak/RXSS%20-%20CVE-2021-20323)
- [SSRF - CVE-2020-10770](./Keycloak/SSRF%20-%20CVE-2020-10770)

### Langflow
- [RCE - CVE-2026-33017](./Langflow/RCE%20-%20CVE-2026-33017)

### Laravel
- [RCE - CVE-2018-15133](./Laravel/RCE%20-%20CVE-2018-15133)

### laravel-admin
- [RCE - CVE-2023-24249](./laravel-admin/RCE%20-%20CVE-2023-24249)

### LimeSurvey
- [RCE - CVE-2021-44967](./LimeSurvey/RCE%20-%20CVE-2021-44967)

### Linux Kernel
- [LPE - CVE-2017-16995](./Linux%20Kernel/LPE%20-%20CVE-2017-16995)
- [CWE665 - CVE-2022-0847](./Linux%20Kernel/CWE665%20-%20CVE-2022-0847)
- [LPE - CVE-2023-0386](./Linux%20Kernel/LPE%20-%20CVE-2023-0386)
- [LPE - CVE-2021-3493](./Linux%20Kernel/LPE%20-%20CVE-2021-3493)

### Magento
- [RCE - CVE-2015-1398](./Magento/RCE%20-%20CVE-2015-1398)
- [SQLi - CVE-2015-1397](./Magento/SQLi%20-%20CVE-2015-1397)

### MCPJam Inspector
- [RCE - CVE-2026-23744](./MCPJam%20Inspector/RCE%20-%20CVE-2026-23744)

### Metabase
- [RCE - CVE-2023-38646](./Metabase/RCE%20-%20CVE-2023-38646)

### Microsoft AD CS
- [PrivEsc - CVE-2024-49019](./Microsoft%20AD%20CS/PrivEsc%20-%20CVE-2024-49019)

### Microsoft IIS
- [RCE - CVE-2017-7269](./Microsoft%20IIS/RCE%20-%20CVE-2017-7269)

### Microsoft Windows AFD
- [LPE - CVE-2011-1249](./Microsoft%20Windows%20AFD/LPE%20-%20CVE-2011-1249)

### Microsoft Windows File Explorer
- [AuthBypass - CVE-2025-24071](./Microsoft%20Windows%20File%20Explorer/AuthBypass%20-%20CVE-2025-24071)

### Microsoft Windows Secondary Logon
- [LPE - CVE-2016-0099](./Microsoft%20Windows%20Secondary%20Logon/LPE%20-%20CVE-2016-0099)

### Microsoft Windows Server Service
- [RCE - CVE-2008-4250](./Microsoft%20Windows%20Server%20Service/RCE%20-%20CVE-2008-4250)

### Microsoft Windows SMBv1
- [RCE - CVE-2017-0144](./Microsoft%20Windows%20SMBv1/RCE%20-%20CVE-2017-0144)

### motionEye
- [RCE - CVE-2025-60787](./motionEye/RCE%20-%20CVE-2025-60787)

### needrestart
- [LPE - CVE-2024-48990](./needrestart/LPE%20-%20CVE-2024-48990)

### Next.js
- [RCE - CVE-2025-55182](./Next.js/RCE%20-%20CVE-2025-55182)

### Nginx-UI
- [AuthBypass - CVE-2026-27944](./Nginx-UI/AuthBypass%20-%20CVE-2026-27944)

### Nibbleblog
- [RCE - CVE-2015-6967](./Nibbleblog/RCE%20-%20CVE-2015-6967)

### Nostromo (nhttpd)
- [RCE - CVE-2019-16278](./Nostromo%20(nhttpd)/RCE%20-%20CVE-2019-16278)

### OpenNetAdmin
- [RCE - CVE-2019-25065](./OpenNetAdmin/RCE%20-%20CVE-2019-25065)

### OpenSSL
- [InfoDisclosure - CVE-2014-0160](./OpenSSL/InfoDisclosure%20-%20CVE-2014-0160)

### OpenSTAManager
- [RCE - CVE-2025-69212](./OpenSTAManager/RCE%20-%20CVE-2025-69212)

### pac4j
- [AuthBypass - CVE-2026-29000](./pac4j/AuthBypass%20-%20CVE-2026-29000)

### Paessler PRTG Network Monitor
- [RCE - CVE-2018-9276](./Paessler%20PRTG%20Network%20Monitor/RCE%20-%20CVE-2018-9276)

### PDF24 Creator
- [LPE - CVE-2023-49147](./PDF24%20Creator/LPE%20-%20CVE-2023-49147)

### PDF.js
- [RCE - CVE-2024-4367](./PDF.js/RCE%20-%20CVE-2024-4367)

### pdfminer.six
- [RCE - CVE-2025-64512](./pdfminer.six/RCE%20-%20CVE-2025-64512)

### PHP
- [RCE - ADV20210328-PHP-GIT-BACKDOOR](./PHP/RCE%20-%20ADV20210328-PHP-GIT-BACKDOOR)

### polkit
- [LPE - CVE-2021-4034](./polkit/LPE%20-%20CVE-2021-4034)

### PrivateBin
- [LFI - CVE-2025-64714](./PrivateBin/LFI%20-%20CVE-2025-64714)

### Roundcube Webmail
- [RCE - CVE-2025-49113](./Roundcube%20Webmail/RCE%20-%20CVE-2025-49113)

### Samba
- [RCE - CVE-2026-4480](./Samba/RCE%20-%20CVE-2026-4480)
- [RCE - CVE-2007-2447](./Samba/RCE%20-%20CVE-2007-2447)

### snapd
- [LPE - CVE-2026-3888](./snapd/LPE%20-%20CVE-2026-3888)

### sudo
- [LPE - CVE-2025-32462](./sudo/LPE%20-%20CVE-2025-32462)
- [AuthBypass - CVE-2019-14287](./sudo/AuthBypass%20-%20CVE-2019-14287)

### TensorFlow
- [RCE - CVE-2024-3660](./TensorFlow/RCE%20-%20CVE-2024-3660)

### UnrealIRCd
- [RCE - CVE-2010-2075](./UnrealIRCd/RCE%20-%20CVE-2010-2075)

### vm2
- [RCE - CVE-2023-30547](./vm2/RCE%20-%20CVE-2023-30547)

### vsftpd
- [RCE - CVE-2011-2523](./vsftpd/RCE%20-%20CVE-2011-2523)

### Webmin
- [RCE - CVE-2019-12840](./Webmin/RCE%20-%20CVE-2019-12840)
- [RCE - CVE-2019-15107](./Webmin/RCE%20-%20CVE-2019-15107)

### Wing FTP Server
- [RCE - CVE-2025-47812](./Wing%20FTP%20Server/RCE%20-%20CVE-2025-47812)

### WordPress
- [SQLi - CVE-2026-63030](./WordPress/SQLi%20-%20CVE-2026-63030)

### WordPress Canto Plugin
- [RFI - CVE-2023-3452](./WordPress%20Canto%20Plugin/RFI%20-%20CVE-2023-3452)

### XWiki Platform
- [RCE - CVE-2025-24893](./XWiki%20Platform/RCE%20-%20CVE-2025-24893)

### ZoneMinder
- [SQLi - CVE-2024-51482](./ZoneMinder/SQLi%20-%20CVE-2024-51482)

<!-- INDEX:END -->

## License

Released for educational and research use only. All product names and CVE identifiers are the property of their respective owners.
