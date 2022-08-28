<!-- markdownlint-disable -->

# banIPs - ban incoming and/or outgoing ip adresses via ipsets

## Description
IP address blocking is commonly used to protect against brute force attacks, prevent disruptive or unauthorized address(es) from access or it can be used to restrict access to or from a particular geographic area. This tools uses publicly available address lists that have been reported as sources of questionable traffic to block all traffic from the listed addresses.

## Main Features
* Support of the following fully pre-configured domain blocklist sources (free for private usage, for commercial use please check their individual licenses)

| Source              | Focus                          | Information                                                                       |
| :------------------ | :----------------------------: | :-------------------------------------------------------------------------------- |
| asn                 | ASN block                      | [Link](https://asn.ipinfo.app)                                                    |
| bogon               | Bogon prefixes                 | [Link](https://team-cymru.com)                                                    |
| country             | Country blocks                 | [Link](https://www.ipdeny.com/ipblocks)                                           |
| darklist            | blocks suspicious attacker IPs | [Link](https://darklist.de)                                                       |
| debl                | Fail2ban IP blacklist          | [Link](https://www.blocklist.de)                                                  |
| doh                 | Public DoH-Provider            | [Link](https://github.com/dibdot/DoH-IP-blocklists)                               |
| drop                | Spamhaus drop compilation      | [Link](https://www.spamhaus.org)                                                  |
| dshield             | Dshield IP blocklist           | [Link](https://www.dshield.org)                                                   |
| edrop               | Spamhaus edrop compilation     | [Link](https://www.spamhaus.org)                                                  |
| feodo               | Feodo Tracker                  | [Link](https://feodotracker.abuse.ch)                                             |
| firehol1            | Firehol Level 1 compilation    | [Link](https://iplists.firehol.org/?ipset=firehol_level1)                         |
| firehol2            | Firehol Level 2 compilation    | [Link](https://iplists.firehol.org/?ipset=firehol_level2)                         |
| firehol3            | Firehol Level 3 compilation    | [Link](https://iplists.firehol.org/?ipset=firehol_level3)                         |
| firehol4            | Firehol Level 4 compilation    | [Link](https://iplists.firehol.org/?ipset=firehol_level4)                         |
| greensnow           | blocks suspicious server IPs   | [Link](https://greensnow.co)                                                      |
| iblockads           | Advertising blocklist          | [Link](https://www.iblocklist.com)                                                |
| iblockspy           | Malicious spyware blocklist    | [Link](https://www.iblocklist.com)                                                |
| myip                | Myip Live IP blacklist         | [Link](https://myip.ms)                                                           |
| nixspam             | iX spam protection             | [Link](http://www.nixspam.org)                                                    |
| proxy               | Firehol list of open proxies   | [Link](https://iplists.firehol.org/?ipset=proxylists)                             |
| ssbl                | SSL botnet IP blacklist        | [Link](https://sslbl.abuse.ch)                                                    |
| talos               | Cisco Talos IP Blacklist       | [Link](https://talosintelligence.com/reputation_center)                           |
| threat              | Emerging Threats               | [Link](https://rules.emergingthreats.net)                                         |
| tor                 | Tor exit nodes                 | [Link](https://fissionrelays.net/lists)                                           |
| uceprotect1         | Spam protection level 1        | [Link](http://www.uceprotect.net/en/index.php)                                    |
| uceprotect2         | Spam protection level 2        | [Link](http://www.uceprotect.net/en/index.php)                                    |
| voip                | VoIP fraud blocklist           | [Link](http://www.voipbl.org)                                                     |
| yoyo                | Ad protection blacklist        | [Link](https://pgl.yoyo.org/adservers/)                                           |

* full IPv4 and IPv6 support
* ipsets (one per source) are used to ban a large number of IP addresses
* supports blocking by ASN numbers
* supports blocking by iso country codes
* supports local black- & whitelist (IPv4, IPv6, CIDR notation or domain names)
* black- and whitelist also accept domain names as input to allow IP filtering based on these names
* supports a 'whitelist only' mode, this option allows to restrict Internet access from/to a small number of secure websites/IPs
* per source configuration of SRC (incoming) and DST (outgoing)
* blocklist source parsing by fast & flexible regex rulesets
* minimal status & error logging to syslog, enable debug logging to receive more output
* automatic blocklist backup & restore, they will be used in case of download errors or during startup
* provides comprehensive runtime information
* provides a detailed IPSet Report
* provides a powerful query function to quickly find blocked IPs/CIDR in banIP related IPSets
* optional: add new banIP sources on your own

## Prerequisites

## banIP CLI
* All important banIP functions are accessible via CLI as well.  
<pre><code>
~# /usr/sbin/banips -h
usage: banips.py [-h] [-D] [-V] [-b] [-c CONFIG] [-s SRCFILE] [-S] [-K] [A] [P]

Load configured ipsets

positional arguments:
  A                     What to do. One of:
                        download|start|stop|refresh|suspend|resume|restore_backup|remove_backup|report|query|exporter
  P                     required IP address for a query; optional type of report; optional name of a set to refresh, suspend,
                        resume, restore_backup, or remove_backup

options:
  -h, --help            show this help message and exit
  -D, --debug
  -V, --verbose
  -b, --banip           OpenWRT banip format configuration file pointed to by -c
  -c CONFIG, --config CONFIG
                        INI style configuration file
  -s SRCFILE, --srcfile SRCFILE
                        JSON IP source list
  -S, --skip            Skip downloading, if the target file exists
  -K, --keep            Keep downloaded files for use with -S

Available commands:
	start           Start the service
	stop            Stop the service
	restart         Restart the service
	reload          Reload configuration files (or restart if service does not implement reload)
	enable          Enable service autostart
	disable         Disable service autostart
	enabled         Check if service is started on boot
	refresh         Refresh ipsets without new list downloads
	suspend         Suspend banIP processing
	resume          Resume banIP processing
	query           &lt;IP&gt; Query active banIP IPSets for a specific IP address
	report          [&lt;cli&gt;|&lt;mail&gt;|&lt;gen&gt;|&lt;json&gt;] Print banIP related IPset statistics
	list            [&lt;add&gt;|&lt;add_asn&gt;|&lt;add_country&gt;|&lt;remove>|&lt;remove_asn&gt;|&lt;remove_country&gt;] &lt;source(s)&gt; List/Edit available sources
	timer           [&lt;add&gt; &lt;tasks&gt; &lt;hour&gt; [&lt;minute&gt;] [&lt;weekday&gt;]]|[&lt;remove&gt; &lt;line no.&gt;] List/Edit cron update intervals
	version         Print version information
	running         Check if service is running
	status          Service status
	trace           Start with syscall trace
</code></pre>

## banIP config options
* Usually the auto pre-configured banIP setup works quite well and no manual overrides are needed

| Option                  | Type   | Default                       | Description                                                                           |
| :---------------------- | :----- | :---------------------------- | :------------------------------------------------------------------------------------ |
| ban_proto4_enabled      | option | 1                             | enable IPv4 allows and blocks                                                         |
| ban_proto6_enabled      | option | 1                             | enable IPv6 allows and blocks                                                         |
| ban_oklistonly          | option | 0                             | allow to restrict Internet access from/to a small number of secure websites/IPs       |
| ban_banlist             | option | /etc/banIP/banip.banlist      | file of IPv4, IPv6, or hostnames to drop, one per line                                |
| ban_oklist              | option | /etc/banIP/banip.oklist       | file of IPv4, IPv6, or hostnames to allow, one per line                               |
| ban_maclist             | option | /etc/banIP/banip.maclist      | file of Ethernet MAC addresses to drop, one per line                                  |
| ban_srcfile             | option | /etc/banip/banip.sources      | full path to the compressed source archive file used by banIP                         |
| ban_reportdir           | option | /var/local/banIP/Report       | directory where banIP stores the report files                                         |
| ban_backupdir           | option | /var/local/banIP/Backup       | directory where banIP stores the compressed backup files                              |
| ban_tmpdir              | option | /var/local/banIP/tmp          | directory where banIP stores operational files                                        |
| ban_sources             | list   |                               | list option to add banIP sources                                                      |
| ban_countries           | list   |                               | list option to add certain countries as an alpha-2 ISO code, e.g. 'de' for germany    |
| ban_asns                | list   |                               | list option to add certain ASNs (autonomous system number), e.g. '32934' for facebook |
| ban_chain               | option | banIP                         | name of the root chain used by banIP                                                  |
| ban_global_settype      | option | src+dst                       | global settype as default for all sources                                             |
| ban_settype_src         | list   |                               | special SRC settype for a certain sources                                             |
| ban_settype_dst         | list   |                               | special DST settype for a certain sources                                             |
| ban_settype_all         | list   |                               | special SRC+DST settype for a certain sources                                         |
| ban_wait                | option | -w5                           | how long to wait for other iptables operations to complete (default: 5 seconds)       |
| ban_target_src          | option | DROP                          | default src action (used by log chains as well)                                       |
| ban_target_dst          | option | REJECT                        | default dst action (used by log chains as well)                                       |
| ban_lan_inputchains_4   | list   | INPUT                         | list option to add IPv4 lan input chains                                              |
| ban_lan_inputchains_6   | list   | INPUT                         | list option to add IPv6 lan input chains                                              |
| ban_lan_forwardchains_4 | list   | FORWARD                       | list option to add IPv4 lan forward chains                                            |
| ban_lan_forwardchains_6 | list   | FORWARD                       | list option to add IPv6 lan forward chains                                            |
| ban_lan_outputchains_4  | list   | OUTPUT                        | list option to add IPv4 lan input chains                                              |
| ban_lan_outputchains_6  | list   | OUTPUT                        | list option to add IPv6 lan input chains                                              |
| ban_wan_inputchains_4   | list   | input_wan_rule                | list option to add IPv4 wan input chains                                              |
| ban_wan_inputchains_6   | list   | input_wan_rule                | list option to add IPv6 wan input chains                                              |
| ban_wan_forwardchains_4 | list   | forwarding_wan_rule           | list option to add IPv4 wan forward chains                                            |
| ban_wan_forwardchains_6 | list   | forwarding_wan_rule           | list option to add IPv6 wan forward chains                                            |
| ban_wan_outputchains_4  | list   | output_wan_rule               | list option to add IPv4 wan input chains                                              |
| ban_wan_outputchains_6  | list   | output_wan_rule               | list option to add IPv6 wan input chains                                              |
| ban_log_accept          | option | banIP_ACCEPT                  | name of chain to use with the allowed packets, and possibly logging activity          |
| ban_log_accept_enabled  | option | 0                             | enable logging of packets from oklist entries                                         |
| ban_log_accept_opts     | option | -m limit --limit 2/sec        | controls for limitting the allowed logging ammount                                    |
| ban_log_accept_prefix   | option | banIP_ACCEPT                  | prefix for logging output                                                             |
| ban_log_drop            | option | banIP_DROP                    | name of chain to use with the blocked packages, and possibly logging activity         |
| ban_log_drop_enabled    | option | 0                             | enable logging of packets from oklist entries                                         |
| ban_log_drop_opts       | option | -m limit --limit 2/sec        | controls for limitting the blocked logging ammount                                    |
| ban_log_drop_prefix     | option | banIP_DROP                    | prefix for logging output                                                             |
| ban_mail_enabled        | option | 0                             | enable the mail service                                                               |
| ban_mailreceiver        | option |                               | receiver address for banIP related notification E-Mails                               |
| ban_mailsender          | option | no-reply@banIP                | sender address for banIP related notification E-Mails                                 |
| ban_mailsubject         | option | banIP notification            | topic for banIP related notification E-Mails                                          |
| ban_localsources        | list   | maclist, whitelist, blacklist | limit the selection to certain local sources                                          |
| ban_extrasources        | list   |                               | add additional, non-banIP related IPSets e.g. for reporting or queries                |
| ban_exporter_host       | option | all interfaces                | IP address to provide Prometheus metrics on                                           |
| ban_exporter_port       | option | 9100                          | IP port to provide Prometheus metrics on                                              |
| ban_geoip4              | option | /usr/share/GeoIP/GeoIP.dat    | Maxmind IPv4 to country and region lookup file, for use in Prometheus metrics         |
| ban_geoip6              | option | /usr/share/GeoIP/GeoIP6.dat   | Maxmind IPv6 to country and region lookup file, for use in Prometheus metrics         |
  
## Examples
**list/edit banIP sources:**  
<pre><code>
~# /etc/banIP/banip.sources list
::: Available banIP sources
:::
    Name                 Enabled   Focus                               Info URL
    ---------------------------------------------------------------------------
  + asn                            ASN blocks                          https://asn.ipinfo.app
  + bogon                          Bogon prefixes                      https://team-cymru.com
  + country              x         Country blocks                      https://www.ipdeny.com/ipblocks
  + darklist             x         Blocks suspicious attacker IPs      https://darklist.de
  + debl                 x         Fail2ban IP blacklist               https://www.blocklist.de
  + doh                  x         Public DoH-Provider                 https://github.com/dibdot/DoH-IP-blocklists
  + drop                 x         Spamhaus drop compilation           https://www.spamhaus.org
  + dshield              x         Dshield IP blocklist                https://www.dshield.org
  + edrop                          Spamhaus edrop compilation          https://www.spamhaus.org
  + feodo                x         Feodo Tracker                       https://feodotracker.abuse.ch
  + firehol1             x         Firehol Level 1 compilation         https://iplists.firehol.org/?ipset=firehol_level1
  + firehol2                       Firehol Level 2 compilation         https://iplists.firehol.org/?ipset=firehol_level2
  + firehol3                       Firehol Level 3 compilation         https://iplists.firehol.org/?ipset=firehol_level3
  + firehol4                       Firehol Level 4 compilation         https://iplists.firehol.org/?ipset=firehol_level4
  + greensnow            x         Blocks suspicious server IPs        https://greensnow.co
  + iblockads                      Advertising blocklist               https://www.iblocklist.com
  + iblockspy            x         Malicious spyware blocklist         https://www.iblocklist.com
  + myip                           Myip Live IP blacklist              https://myip.ms
  + nixspam              x         iX spam protection                  http://www.nixspam.org
  + proxy                          Firehol list of open proxies        https://iplists.firehol.org/?ipset=proxylists
  + sslbl                x         SSL botnet IP blacklist             https://sslbl.abuse.ch
  + talos                x         Cisco Talos IP Blacklist            https://talosintelligence.com/reputation_center
  + threat               x         Emerging Threats                    https://rules.emergingthreats.net
  + tor                  x         Tor exit nodes                      https://fissionrelays.net/lists
  + uceprotect1          x         Spam protection level 1             http://www.uceprotect.net/en/index.php
  + uceprotect2                    Spam protection level 2             http://www.uceprotect.net/en/index.php
  + voip                 x         VoIP fraud blocklist                http://www.voipbl.org
  + yoyo                 x         Ad protection blacklist             https://pgl.yoyo.org/adservers/
    ---------------------------------------------------------------------------
  * Configured ASNs: -
  * Configured Countries: af, bd, br, cn, hk, hu, id, il, in, iq, ir, kp, kr, no, pk, pl, ro, ru, sa, th, tr, ua, gb
</code></pre>
  
**receive banIP runtime information:**  
<pre><code>
~# /usr/sbin/banIP status
::: banIP runtime information
  + status          : enabled
  + version         : 0.7.7
  + ipset_info      : 2 IPSets with 30 IPs/Prefixes
  + active_sources  : whitelist
  + active_devs     : wlan0
  + active_ifaces   : trm_wwan, trm_wwan6
  + active_logterms : dropbear, sshd, luci, nginx
  + active_subnets  : xxx.xxx.xxx.xxx/24, xxxx:xxxx:xxxx:xx::xxx/128
  + run_infos       : settype: src+dst, backup_dir: /tmp/banIP-Backup, report_dir: /tmp/banIP-Report
  + run_flags       : protocols (4/6): ✔/✔, log (src/dst): ✔/✘, monitor: ✔, mail: ✘, whitelist only: ✔
  + last_run        : restart, 0m 3s, 122/30/14, 21.04.2021 20:14:36
  + system          : TP-Link RE650 v1, OpenWrt SNAPSHOT r16574-f7e00d81bc
</code></pre>

**generate an IPSet report:**  
<pre><code>
~# /usr/sbin/banIP report
:::
::: report on all banIP related IPSets
:::
  + Report timestamp           ::: 04.02.2021 06:24:41
  + Number of all IPSets       ::: 24
  + Number of all entries      ::: 302448
  + Number of IP entries       ::: 224748
  + Number of CIDR entries     ::: 77700
  + Number of MAC entries      ::: 0
  + Number of accessed entries ::: 36
:::
::: IPSet details
:::
    Name                 Type        Count      Cnt_IP    Cnt_CIDR  Cnt_MAC   Cnt_ACC   Entry details (Entry/Count)
    --------------------------------------------------------------------------------------------------------------------
    whitelist_4          src+dst     1          0         1         0         1
                                                                                        xxx.xxxx.xxx.xxxx/24     85
    --------------------------------------------------------------------------------------------------------------------
    whitelist_6          src+dst     2          0         2         0         1
                                                                                        xxxx:xxxx:xxxx::/64      29
    --------------------------------------------------------------------------------------------------------------------
    blacklist_4          src+dst     513        513       0         0         2
                                                                                        192.35.168.16            3
                                                                                        80.82.65.74              1
    --------------------------------------------------------------------------------------------------------------------
    blacklist_6          src+dst     1          1         0         0         0
    --------------------------------------------------------------------------------------------------------------------
    country_4            src         52150      0         52150     0         23
                                                                                        124.5.0.0/16             1
                                                                                        95.188.0.0/14            1
                                                                                        121.16.0.0/12            1
                                                                                        46.161.0.0/18            1
                                                                                        42.56.0.0/14             1
                                                                                        113.64.0.0/10            1
                                                                                        113.252.0.0/14           1
                                                                                        5.201.128.0/17           1
                                                                                        125.64.0.0/11            1
                                                                                        90.188.0.0/15            1
                                                                                        60.0.0.0/11              1
                                                                                        78.160.0.0/11            1
                                                                                        1.80.0.0/12              1
                                                                                        183.184.0.0/13           1
                                                                                        175.24.0.0/14            1
                                                                                        119.176.0.0/12           1
                                                                                        59.88.0.0/13             1
                                                                                        103.78.12.0/22           1
                                                                                        123.128.0.0/13           1
                                                                                        116.224.0.0/12           1
                                                                                        42.224.0.0/12            1
                                                                                        82.80.0.0/15             1
                                                                                        14.32.0.0/11             1
    --------------------------------------------------------------------------------------------------------------------
    country_6            src         20099      0         20099     0         0
    --------------------------------------------------------------------------------------------------------------------
    debl_4               src+dst     29389      29389     0         0         1
                                                                                        5.182.210.16             4
    --------------------------------------------------------------------------------------------------------------------
    debl_6               src+dst     64         64        0         0         0
    --------------------------------------------------------------------------------------------------------------------
    doh_4                src+dst     168        168       0         0         0
    --------------------------------------------------------------------------------------------------------------------
    doh_6                src+dst     122        122       0         0         0
    --------------------------------------------------------------------------------------------------------------------
    drop_4               src+dst     965        0         965       0         0
    --------------------------------------------------------------------------------------------------------------------
    drop_6               src+dst     36         0         36        0         0
    --------------------------------------------------------------------------------------------------------------------
    dshield_4            src+dst     20         0         20        0         1
                                                                                        89.248.165.0/24          1
    --------------------------------------------------------------------------------------------------------------------
    feodo_4              src+dst     325        325       0         0         0
    --------------------------------------------------------------------------------------------------------------------
    firehol1_4           src+dst     2763       403       2360      0         0
    --------------------------------------------------------------------------------------------------------------------
    iblockspy_4          src+dst     3650       2832      818       0         0
    --------------------------------------------------------------------------------------------------------------------
    nixspam_4            src+dst     9577       9577      0         0         0
    --------------------------------------------------------------------------------------------------------------------
    sslbl_4              src+dst     104        104       0         0         0
    --------------------------------------------------------------------------------------------------------------------
    threat_4             src+dst     1300       315       985       0         0
    --------------------------------------------------------------------------------------------------------------------
    tor_4                src+dst     1437       1437      0         0         0
    --------------------------------------------------------------------------------------------------------------------
    tor_6                src+dst     478        478       0         0         0
    --------------------------------------------------------------------------------------------------------------------
    uceprotect1_4        src+dst     156249     156249    0         0         6
                                                                                        192.241.220.137          1
                                                                                        128.14.137.178           1
                                                                                        61.219.11.153            1
                                                                                        138.34.32.33             1
                                                                                        107.174.133.130          2
                                                                                        180.232.99.46            1
    --------------------------------------------------------------------------------------------------------------------
    voip_4               src+dst     12563      12299     264       0         0
    --------------------------------------------------------------------------------------------------------------------
    yoyo_4               src+dst     10472      10472     0         0         1
                                                                                        204.79.197.200           2
    --------------------------------------------------------------------------------------------------------------------
</code></pre>
  
**Enable E-Mail notification:**
  
**Edit, add new banIP sources:**  
The banIP blocklist sources are stored in an external JSON file '/etc/banIP/banip.sources'.

A valid JSON source object contains the following required information, e.g.:
<pre><code>
	[...]
	"tor": {
		"url_4": "https://lists.fissionrelays.net/tor/exits-ipv4.txt",
		"url_6": "https://lists.fissionrelays.net/tor/exits-ipv6.txt",
		"rule_4": "/^(([0-9]{1,3}\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])(\\/(1?[0-9]|2?[0-9]|3?[0-2]))?)([[:space:]]|$)/{print \"add tor_4 \"$1}",
		"rule_6": "/^(([0-9A-f]{0,4}:){1,7}[0-9A-f]{0,4}:?(\\/(1?[0-2][0-8]|[0-9][0-9]))?)([[:space:]]|$)/{print \"add tor_6 \"$1}",
		"focus": "Tor exit nodes",
		"descurl": "https://fissionrelays.net/lists"
	},
	[...]
</code></pre>
Add an unique object name, make the required changes to 'url_4', 'rule_4' (and/or 'url_6', 'rule_6'), 'focus' and 'descurl'. <b>Please note:</b> if you're going to add new sources on your own, please make a copy of the default file and work with that copy further on, cause the default will be overwritten with every banIP update. To reference your copy set the option 'ban\_srcarc' which points by default to '/etc/banIP/banip.sources'

## Support
Please use the Issues function at https://github.com/alanbbr/banips.

## Removal
* stop all banIP related services with _/usr/sbin/nbanIP stop_

Have fun!  
Alan and originally, Dirk
