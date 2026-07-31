# Verified Exploits

*Reproduced exploits and technical write-ups for public security advisories, organized by affected product and indexed by weakness.*

Every entry here is an exploit that was actually run and reproduced against the affected product. Nothing in this repository is a copied, theoretical or untested proof-of-concept.

Entries cover advisories from any public namespace, not only CVE. GitHub Security Advisories (GHSA), language ecosystem databases (PYSEC, GO, RUSTSEC), distribution errata, and vendor or broker advisories (ZDI, Exploit-DB) all belong here: whether a bug received a CVE depends on which body assigned the identifier, not on how exploitable the bug is. Plenty of GHSAs never get a CVE at all, and plenty of CVEs are published by GitHub weeks before NVD lists them.

Only vulnerabilities that are **already public and already patched** are archived. Nothing unpatched, embargoed or withdrawn goes in here.

Each entry carries a technical write-up, a machine-readable `metadata.json`, and, where applicable, a proof-of-concept script.

## Disclaimer

The exploits, proof-of-concept code, and technical write-ups in this repository were developed and are published **strictly for educational purposes and authorized security research**, including learning, defensive testing, and coordinated vulnerability disclosure.

You must have **explicit, written authorization** to test any system that you do not own. Using this material against systems without permission may be illegal and is entirely your own responsibility.

The author provides this material "as is", without warranty of any kind, and **accepts no liability** for any misuse, damage, or unlawful activity carried out with it. By accessing or using anything in this repository, you agree that you alone are responsible for your actions and for complying with all applicable laws and regulations.

## Repository Structure

Entries are grouped by PRODUCT. One product folder holds entries from different advisory namespaces side by side, because the namespace names the identifier, not the bug.

```
<Product>/<CLASS> - <ID>/
|-- README.md       # technical write-up and reproduction steps
|-- metadata.json   # machine-readable record: aliases, CWE, CVSS, affected and fixed versions
`-- <poc>           # optional proof-of-concept script (not always present)
```

- `<Product>` - the affected product (e.g. `Linux Kernel`, `Keycloak`, `Gitea`).
- `<CLASS>` - the vulnerability class (e.g. `RCE`, `SQLi`, `LPE`, `PathTraversal`, `AuthBypass`, `CWE###`).
- `<ID>` - the advisory identifier from any public namespace (`CVE-...`, `GHSA-...`, `ZDI-...`, `EDB-...`).

When one advisory carries several identifiers, the entry is filed under its **CVE** and every other id is recorded as an alias in `metadata.json`. A GHSA that already has a CVE alias is therefore filed under the CVE even while NVD still shows nothing for it, so there is one entry per vulnerability instead of one per identifier.

## Indices

- **[INDEX_BY_CWE.md](./INDEX_BY_CWE.md)** - grouped by weakness (CWE). Read this one to map a class of weakness to working proof rather than to look up a single identifier.
- **[INDEX_BY_CLASS.md](./INDEX_BY_CLASS.md)** - grouped by vulnerability class (RCE, SQLi, AuthBypass, LPE, ...).
- **By product** - the listing below, alphabetical.

All three are generated from the `metadata.json` files, which are the source of truth. See **[tools/](./tools)** to regenerate them, and to backfill severity and CVSS data that upstream databases published after an entry was filed.

## Vulnerabilities by Product

<!-- INDEX:START -->

### Adminer
- [FileRead - CVE-2020-35572](./Adminer/FileRead%20-%20CVE-2020-35572)

### Adobe ColdFusion
- [RCE - CVE-2009-2265](./Adobe%20ColdFusion/RCE%20-%20CVE-2009-2265)

### aiohttp
- [PathTraversal - CVE-2024-23334](./aiohttp/PathTraversal%20-%20CVE-2024-23334)

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

### binwalk
- [PathTraversal - CVE-2022-4510](./binwalk/PathTraversal%20-%20CVE-2022-4510)

### Bludit
- [RCE - CVE-2019-16113](./Bludit/RCE%20-%20CVE-2019-16113)

### Cacti
- [RCE - CVE-2022-46169](./Cacti/RCE%20-%20CVE-2022-46169)
- [RCE - CVE-2025-24367](./Cacti/RCE%20-%20CVE-2025-24367)

### Camaleon CMS
- [AuthBypass - CVE-2025-2304](./Camaleon%20CMS/AuthBypass%20-%20CVE-2025-2304)

### Chamilo LMS
- [RCE - CVE-2023-4220](./Chamilo%20LMS/RCE%20-%20CVE-2023-4220)

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
- [PathTraversal - CVE-2025-61678](./FreePBX/PathTraversal%20-%20CVE-2025-61678)
- [SQLi - CVE-2025-57819](./FreePBX/SQLi%20-%20CVE-2025-57819)

### Froxlor
- [RXSS - CVE-2024-34070](./Froxlor/RXSS%20-%20CVE-2024-34070)

### Ghost CMS
- [PathTraversal - CVE-2023-40028](./Ghost%20CMS/PathTraversal%20-%20CVE-2023-40028)

### Gitea
- [AuthBypass - CVE-2026-26231](./Gitea/AuthBypass%20-%20CVE-2026-26231)

### GitPython
- [RCE - CVE-2022-24439](./GitPython/RCE%20-%20CVE-2022-24439)

### GlobalProtect
- [RXSS - CVE-2025-0133](./GlobalProtect/RXSS%20-%20CVE-2025-0133)

### GLPI
- [SQLi - CVE-2025-24799](./GLPI/SQLi%20-%20CVE-2025-24799)

### GNU Bash
- [RCE - CVE-2014-6271](./GNU%20Bash/RCE%20-%20CVE-2014-6271)

### Grafana
- [PathTraversal - CVE-2021-43798](./Grafana/PathTraversal%20-%20CVE-2021-43798)
- [RCE - CVE-2024-9264](./Grafana/RCE%20-%20CVE-2024-9264)

### Handlebars.js
- [RCE - CVE-2026-33937](./Handlebars.js/RCE%20-%20CVE-2026-33937)

### HFS (HttpFileServer)
- [RCE - CVE-2014-6287](./HFS%20%28HttpFileServer%29/RCE%20-%20CVE-2014-6287)

### HTTP/2
- [DoS - ADV190005](./ADV190005)
- [DoS - CVE-2023-44487](./CVE-2023-44487)

### ImageMagick
- [FileRead - CVE-2022-44268](./ImageMagick/FileRead%20-%20CVE-2022-44268)
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

### KeePass
- [InfoDisclosure - CVE-2023-32784](./KeePass/InfoDisclosure%20-%20CVE-2023-32784)

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
- [CWE665 - CVE-2022-0847](./Linux%20Kernel/CWE665%20-%20CVE-2022-0847)
- [LPE - CVE-2017-16995](./Linux%20Kernel/LPE%20-%20CVE-2017-16995)
- [LPE - CVE-2021-3493](./Linux%20Kernel/LPE%20-%20CVE-2021-3493)
- [LPE - CVE-2023-0386](./Linux%20Kernel/LPE%20-%20CVE-2023-0386)

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

### Moby
- [LPE - CVE-2021-41091](./Moby/LPE%20-%20CVE-2021-41091)

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
- [RCE - CVE-2019-16278](./Nostromo%20%28nhttpd%29/RCE%20-%20CVE-2019-16278)

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

### PDF.js
- [RCE - CVE-2024-4367](./PDF.js/RCE%20-%20CVE-2024-4367)

### PDF24 Creator
- [LPE - CVE-2023-49147](./PDF24%20Creator/LPE%20-%20CVE-2023-49147)

### pdfminer.six
- [RCE - CVE-2025-64512](./pdfminer.six/RCE%20-%20CVE-2025-64512)

### PHP
- [RCE - ADV20210328-PHP-GIT-BACKDOOR](./PHP/RCE%20-%20ADV20210328-PHP-GIT-BACKDOOR)

### Pluck
- [RCE - CVE-2023-50564](./Pluck/RCE%20-%20CVE-2023-50564)

### polkit
- [LPE - CVE-2021-4034](./polkit/LPE%20-%20CVE-2021-4034)

### PrivateBin
- [LFI - CVE-2025-64714](./PrivateBin/LFI%20-%20CVE-2025-64714)

### pyLoad
- [RCE - CVE-2023-0297](./pyLoad/RCE%20-%20CVE-2023-0297)

### pymatgen
- [RCE - CVE-2024-23346](./pymatgen/RCE%20-%20CVE-2024-23346)

### request-baskets
- [SSRF - CVE-2023-27163](./request-baskets/SSRF%20-%20CVE-2023-27163)

### Roundcube Webmail
- [RCE - CVE-2025-49113](./Roundcube%20Webmail/RCE%20-%20CVE-2025-49113)

### Samba
- [RCE - CVE-2007-2447](./Samba/RCE%20-%20CVE-2007-2447)
- [RCE - CVE-2026-4480](./Samba/RCE%20-%20CVE-2026-4480)

### Searchor
- [RCE - CVE-2023-43364](./Searchor/RCE%20-%20CVE-2023-43364)

### snapd
- [LPE - CVE-2026-3888](./snapd/LPE%20-%20CVE-2026-3888)

### SQLPad
- [SSTI - CVE-2022-0944](./SQLPad/SSTI%20-%20CVE-2022-0944)

### sudo
- [AuthBypass - CVE-2019-14287](./sudo/AuthBypass%20-%20CVE-2019-14287)
- [LPE - CVE-2025-32462](./sudo/LPE%20-%20CVE-2025-32462)

### systemd
- [LPE - CVE-2023-26604](./systemd/LPE%20-%20CVE-2023-26604)

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

### WonderCMS
- [RCE - CVE-2023-41425](./WonderCMS/RCE%20-%20CVE-2023-41425)

### WordPress
- [SQLi - CVE-2026-63030](./WordPress/SQLi%20-%20CVE-2026-63030)

### WordPress Canto Plugin
- [RFI - CVE-2023-3452](./WordPress%20Canto%20Plugin/RFI%20-%20CVE-2023-3452)

### XWiki Platform
- [RCE - CVE-2025-24893](./XWiki%20Platform/RCE%20-%20CVE-2025-24893)

### ZoneMinder
- [SQLi - CVE-2024-51482](./ZoneMinder/SQLi%20-%20CVE-2024-51482)

> The following entries predate the `<Product>/<CLASS> - <ID>` layout and are kept at their original paths on purpose, since renaming them would break inbound links: [`ADV190005`](./ADV190005), [`CVE-2023-44487`](./CVE-2023-44487).

<!-- INDEX:END -->

## License

Released for educational and research use only. All product names and CVE identifiers are the property of their respective owners.
