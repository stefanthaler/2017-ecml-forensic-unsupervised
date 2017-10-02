"""
    Maps similar messages to similar event id. For example, consider the following two events A and B:
    A: [sshd  pid: 686] : Server listening on 0.0.0.0 port 22.
    B: [sshd  pid: 684] : Server listening on 0.0.0.0 port 22.

    They should be mapped to the same event id, because except for the process id they are the same.
"""

# imports
import argparse     # parse command line ptions
import csv          # csv files
import re as re    # for regular expressions

# configurations
USED_LOG_FILES = [
    'TSK:/var/log/syslog'
    #,
    #'TSK:/var/log/auth.log'
]

# helper regexes
IPv4AddressRegex = "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
IPv6AddressRegex = "::"
MemAddressRange = "\[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+?\]" # [mem 0x00000000-0x00000fff]

KNOWN_LOGLINE_PATTERN = {
    # 0 is reserved for unknown lines
    # auth.log regexp
    1837: r'^\[CRON  pid: [0-9]+?\] : pam_unix\(cron:session\): session closed for user [^\s]*?$',                    # [CRON  pid: 1356] : pam_unix(cron:session): session closed for user root
    1838: r'^\[CRON  pid: [0-9]+?\] : pam_unix\(cron:session\): session opened for user [^\s]*? by \(uid=[0-9]+?\)$', # [CRON  pid: 1356] : pam_unix(cron:session): session opened for user root by (uid=0)
    1839: r'^\[sshd  pid: [0-9]+?\] : Received SIGHUP; restarting\.$', # [sshd  pid: 684] : Received SIGHUP; restarting.
    1840: r'^\[sshd  pid: [0-9]+?\] : Received signal [0-9]+?; terminating\.$', # [sshd  pid: 684] : Received signal 15; terminating.
    1841: r'^\[sshd  pid: [0-9]+?\] : Server listening on '+IPv4AddressRegex+' port [0-9]+?\.$', # [sshd  pid: 684] : Server listening on 0.0.0.0 port 22.
    1842: r'^\[sshd  pid: [0-9]+?\] : Server listening on '+IPv6AddressRegex+' port [0-9]+?\.$', # [sshd  pid: 684] : Server listening on :: port 22.
    1843: r'^\[gnome-keyring-daemon  pid: [0-9]+?\] : The .+? was already initialized$',  #[gnome-keyring-daemon  pid: 1037] : The PKCS#11 component was already initialized
    1844: r'^\[lightdm\] : PAM adding faulty module: .+?$', # [lightdm] : PAM adding faulty module: pam_kwallet5.so
    1845: r'^\[lightdm\] : pam_succeed_if\(.+?\): requirement "user ingroup nopasswdlogin" not met by user ".+?"$', # [lightdm] : pam_succeed_if(lightdm:auth): requirement "user ingroup nopasswdlogin" not met by user "stefan"
    1846:r'^\[lightdm\] : PAM unable to dlopen\(.+?\): .+?: cannot open shared object file: No such file or directory$', # [lightdm] : PAM unable to dlopen(pam_kwallet5.so): /lib/security/pam_kwallet5.so: cannot open shared object file: No such file or directory
    1847:r'^\[lightdm\] : pam_unix(.*?): session closed for user [^\s]+?$', # [lightdm] : pam_unix(lightdm-greeter:session): session closed for user lightdm
    1848:r'^\[lightdm\] : pam_unix(.*?): session opened for user [^\s]+? by \(uid=[0-9]+?\)$', # [lightdm] : pam_unix(lightdm-greeter:session): session opened for user lightdm by (uid=0)
    1849:r'^\[polkitd\(authority=local\)\] : Registered Authentication Agent for unix-session:c[0-9]+? \(system bus name :[^\s]+? \[.+?\]  object path [^\s]+?  locale [^\s]+?\)$', # [polkitd(authority=local)] : Registered Authentication Agent for unix-session:c2 (system bus name :1.37 [/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1]  object path /org/gnome/PolicyKit1/AuthenticationAgent  locale en_US.UTF-8)
    3001:r'^\[polkitd\(authority=local\)\] : Unregistered Authentication Agent for unix-session:c.*?$', # [polkitd(authority=local)] : Registered Authentication Agent for unix-session:c2 (system bus name :1.37 [/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1]  object path /org/gnome/PolicyKit1/AuthenticationAgent  locale en_US.UTF-8)
    3000:r'^\[lightdm\] : pam_unix(.*?): authentication failure; logname=.*? uid=[0-9]+? euid=[0-9]+? tty=.+? ruser=.*? rhost=.*? user=.+?$', #[lightdm] : pam_unix(lightdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=stefan\n',
    1850:r'^\[sudo\] : pam_unix(.*?): authentication failure; logname=.*? uid=[0-9]+? euid=[0-9]+? tty=.+? ruser=.*? rhost=.*? user=.+?$', # [sudo] : pam_unix(sudo:auth): authentication failure; logname=stefan uid=1000 euid=0 tty=/dev/pts/5 ruser=stefan rhost=  user=stefan
    1851:r'^\[sudo\] : pam_unix(.*?): session closed for user .+?$', # [sudo] : pam_unix(sudo:session): session closed for user root
    1852:r'^\[sudo\] : pam_unix(.*?): session opened for user .+? by .+?\(uid=[0-9]+?\)$', # [sudo] : pam_unix(sudo:session): session opened for user root by stefan(uid=0)
    1853:r'^\[sudo\] :   .+? : TTY=.+? ; PWD=.+? ; USER=.+? ; COMMAND=.+?$', # [sudo] :   stefan : TTY=pts/5 ; PWD=/etc/logrotate.d ; USER=root ; COMMAND=/sbin/reboot
    1854:r'^\[systemd-logind  pid: [0-9]+?\] : New seat .+?\.$', # [systemd-logind  pid: 518] : New seat seat0.
    1855:r'^\[systemd-logind  pid: [0-9]+?\] : New session .+? of user .+?\.$', # [systemd-logind  pid: 518] : New session c1 of user lightdm.
    1856:r'^\[systemd-logind  pid: [0-9]+?\] : Removed session .+?\.$', # [systemd-logind  pid: 518] : Removed session c1.
    1857:r'^\[systemd-logind  pid: [0-9]+?\] : Watching system buttons on .+? \(.+?\)$', # [systemd-logind  pid: 518] : Watching system buttons on /dev/input/event0 (Power Button)
    1858:r'^\[systemd-logind  pid: [0-9]+?\] : System is powering down\.$', # [systemd-logind  pid: 586] : System is powering down.
    1859:r'^\[systemd\] : pam_unix\(.+?\): session closed for user .+?$', # [systemd] : pam_unix(systemd-user:session): session closed for user lightdm
    1860:r'^\[systemd\] : pam_unix\(.+?\): session opened for user .+? by \(uid=[0-9]+?\)$', # [systemd] : pam_unix(systemd-user:session): session opened for user lightdm by (uid=0)
    # syslog - accounts-daemon
    1000:r'^\[accounts-daemon  pid: [0-9]+?\] : started daemon version .+?$',  # [accounts-daemon  pid: 519] : started daemon version 0.6.40
    1001:r'^\[accounts-daemon  pid: [0-9]+?\] : \*\* \(accounts-daemon:[0-9]+?\): WARNING \*\*: Could not talk to message bus to find uid of sender :.+?: GDBus\.Error:org\.freedesktop\.DBus\.Error\.NameHasNoOwner: Could not get UID of name \':.+?\': no such name$',  # [accounts-daemon  pid: 519] : ** (accounts-daemon:575): WARNING **: Could not talk to message bus to find uid of sender :1.44: GDBus.Error:org.freedesktop.DBus.Error.NameHasNoOwner: Could not get UID of name ':1.44': no such name
    # syslog - acpid
    1002:r'^\[acpid\] : [0-9]+? rules loaded$',   # [acpid] : 9 rules loaded
    1003:r'^\[acpid\] : starting up with netlink and the input layer$',   # [acpid] : 9 rules loaded
    1004:r'^\[acpid\] : waiting for events: event logging is off$',   # [acpid] : waiting for events: event logging is off
    # syslog - alsactl
    1005:r'^\[alsactl  pid: [0-9]+?\] : Found hardware: \".+?\"$', #[alsactl  pid: 600] : Found hardware: "ICH" "Analog Devices AD1980" "AC97a:41445370" "0x1028" "0x0177"
    1006:r'^\[alsactl  pid: [0-9]+?\] : Hardware is initialized using a generic method$', #[alsactl  pid: 600] : Hardware is initialized using a generic method
    1007:r'^\[alsactl  pid: [0-9]+?\] : /usr/sbin/alsactl: load_state:[0-9]+?: Cannot open /var/lib/alsa/asound.state for reading: No such file or directory$', # [alsactl  pid: 600] : /usr/sbin/alsactl: load_state:1683: Cannot open /var/lib/alsa/asound.state for reading: No such file or directory
    # syslog - anacron
    1008:r'^\[anacron  pid: [0-9]+?\] : Anacron .+? started on .+?$',# [anacron  pid: 491] : Anacron 2.3 started on 2016-06-21
    1009:r'^\[anacron  pid: [0-9]+?\] : Jobs will be executed sequentially$',# [anacron  pid: 491] : Jobs will be executed sequentially
    1010:r'^\[anacron  pid: [0-9]+?\] : Will run job \`.+?\' in [0-9]+? min\.$', # [anacron  pid: 491] : Will run job `cron.daily' in 5 min.
    # syslog - apparmor
    1011:r'^\[apparmor  pid: [0-9]+?\] :    ...done\.$',  # [apparmor  pid: 278] :    ...done.
    1012:r'^\[apparmor  pid: [0-9]+?\] : Skipping profile in /etc/apparmor.d/disable: .+?$', # [apparmor  pid: 278] : Skipping profile in /etc/apparmor.d/disable: usr.bin.firefox
    1013:r'^\[apparmor  pid: [0-9]+?\] :  \* Starting AppArmor profiles$', # [apparmor  pid: 278] :  * Starting AppArmor profiles
    # syslog - apport
    1014:r'^\[apport  pid: [0-9]+?\] :    \.\.\.done\.$', # [apport  pid: 537] :    ...done.
    1015:r'^\[apport  pid: [0-9]+?\] :  \* Starting automatic crash report generation: .+?$',# [apport  pid: 537] :  * Starting automatic crash report generation: apport
    # syslog - avahi daemon
    1016:r'^\[avahi-daemon  pid: [0-9]+?\] : avahi-daemon .+? starting up\.$', # [avahi-daemon  pid: 522] : avahi-daemon 0.6.32-rc starting up.
    1017:r'^\[avahi-daemon  pid: [0-9]+?\] : Found user \'.+?\' \(UID [0-9]+?\) and group \'.+?\' \(GID [0-9]+?\)\.$', # [avahi-daemon  pid: 522] : Found user 'avahi' (UID 110) and group 'avahi' (GID 119).
    1018:r'^\[avahi-daemon  pid: [0-9]+?\] : Joining mDNS multicast group on interface .+?\.IPv4 with address '+IPv4AddressRegex+'\.$', # [avahi-daemon  pid: 522] : Joining mDNS multicast group on interface enp0s3.IPv4 with address 10.0.2.15.
    1019:r'^\[avahi-daemon  pid: [0-9]+?\] : Joining mDNS multicast group on interface .+?\.IPv6 with address .+?\.$', # [avahi-daemon  pid: 522] : Joining mDNS multicast group on interface enp0s3.IPv6 with address fe80::a00:27ff:fe3d:5d0e.
    1020:r'^\[avahi-daemon  pid: [0-9]+?\] : Network interface enumeration completed\.$', # [avahi-daemon  pid: 522] : Network interface enumeration completed.
    1021:r'^\[avahi-daemon  pid: [0-9]+?\] : New relevant interface .+?\.IPv4 for mDNS\.$', # [avahi-daemon  pid: 522] : New relevant interface enp0s3.IPv4 for mDNS.
    1022:r'^\[avahi-daemon  pid: [0-9]+?\] : New relevant interface .+?\.IPv6 for mDNS\.$', # [avahi-daemon  pid: 522] : New relevant interface enp0s3.IPv6 for mDNS.
    1023:r'^\[avahi-daemon  pid: [0-9]+?\] : No service file found in /etc/avahi/services\.$', # [avahi-daemon  pid: 522] : No service file found in /etc/avahi/services.
    1024:r'^\[avahi-daemon  pid: [0-9]+?\] : Registering new address record for '+IPv4AddressRegex+' on .+?\.IPv4\.$', # [avahi-daemon  pid: 522] : Registering new address record for 10.0.2.15 on enp0s3.IPv4.
    1025:r'^\[avahi-daemon  pid: [0-9]+?\] : Registering new address record for .+? on .+?\.\*\.$', # [avahi-daemon  pid: 522] : Registering new address record for fe80::a00:27ff:fe3d:5d0e on enp0s3.*.
    1026:r'^\[avahi-daemon  pid: [0-9]+?\] : Server startup complete\. Host name is .+?\. Local service cookie is [0-9]+?\.$', # Server startup complete. Host name is ubuntu.local. Local service cookie is 2102004505.
    1027:r'^\[avahi-daemon  pid: [0-9]+?\] : Successfully called chroot\(\)\.$', #[avahi-daemon  pid: 522] : Successfully called chroot().
    1028:r'^\[avahi-daemon  pid: [0-9]+?\] : Successfully dropped remaining capabilities\.$', # [avahi-daemon  pid: 522] : Successfully dropped remaining capabilities.
    1029:r'^\[avahi-daemon  pid: [0-9]+?\] : Successfully dropped root privileges\.$',# Successfully dropped root privileges.
    # syslog - chron
    1030:r'^\[CRON  pid: [0-9]+?\] : \(root\) CMD \(.+?\)$', # [CRON  pid: 1357] : (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
    1031:r'^\[cron  pid: [0-9]+?\] : \(CRON\) INFO \(pidfile fd = [0-9]+?\)$', #  [cron  pid: 534] : (CRON) INFO (pidfile fd = 3)
    1032:r'^\[cron  pid: [0-9]+?\] : \(CRON\) INFO \(Running @reboot jobs\)$', # [cron  pid: 534] : (CRON) INFO (Running @reboot jobs))
    # syslog - dbus daemon
    1033:r'^\[dbus-daemon  pid: [0-9]+?\] : Unknown username ".+?" in message bus configuration file$',  # [dbus-daemon  pid: 557] : Unknown username "whoopsie" in message bus configuration file
    # syslog - dbus
    1034:r'^\[dbus  pid: [0-9]+?\] : \[system\] Activating via systemd: service name=\'.+?\' unit=\'.+?\'$', # [dbus  pid: 557] : [system] Activating via systemd: service name='org.freedesktop.hostname1' unit='dbus-org.freedesktop.hostname1.service'
    1035:r'^\[dbus  pid: [0-9]+?\] : \[system\] Successfully activated service \'.+?\'$', # [dbus  pid: 557] : [system] Successfully activated service 'org.freedesktop.hostname1'
    1036:r'^\[dbus  pid: [0-9]+?\] : \[system\] AppArmor D-Bus mediation is enabled$', # [dbus  pid: 557] : [system] AppArmor D-Bus mediation is enabled
    1037:r'^\[dbus  pid: [0-9]+?\] : \[system\] Reloaded configuration$', # [dbus  pid: 558] : [system] Reloaded configuration
    # syslog - dhclient
    1038:r'^\[dhclient  pid: [0-9]+?\] : bound to '+IPv4AddressRegex+' -- renewal in [0-9]+? seconds\.$', # [dhclient  pid: 729] : bound to 10.0.2.15 -- renewal in 35609 seconds.
    1039:r'^\[dhclient  pid: [0-9]+?\] : .*? of '+IPv4AddressRegex+' from '+IPv4AddressRegex, # [dhclient  pid: 729] : DHCPACK of 10.0.2.15 from 10.0.2.2
    1040:r'^\[dhclient  pid: [0-9]+?\] : DHCPDISCOVER on .+? to '+IPv4AddressRegex+' port [0-9]+? interval [0-9]+? \(xid=.+?\)', # [dhclient  pid: 729] : DHCPDISCOVER on enp0s3 to 255.255.255.255 port 67 interval 3 (xid=0x1bf3792a)
    #1041:r'^\[dhclient  pid: [0-9]+?\] : DHCPOFFER of '+IPv4AddressRegex+' from '+IPv4AddressRegex+'$', # [dhclient  pid: 729] : DHCPOFFER of 10.0.2.15 from 10.0.2.2
    1042:r'^\[dhclient  pid: [0-9]+?\] : DHCPREQUEST of '+IPv4AddressRegex+' on .+? to '+IPv4AddressRegex+' port [0-9]+? \(xid=.+?\)$',  # [dhclient  pid: 729] : DHCPREQUEST of 10.0.2.15 on enp0s3 to 255.255.255.255 port 67 (xid=0x2a79f31b)
    # syslog - dnsmasq
    1043:r'^\[dnsmasq  pid: [0-9]+?\] : compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify$',   #[dnsmasq  pid: 738] : compile time options: IPv6 GNU-getopt DBus i18n IDN DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify
    1044:r'^\[dnsmasq  pid: [0-9]+?\] : DBus support enabled: connected to system bus$', # [dnsmasq  pid: 738] : DBus support enabled: connected to system bus
    1045:r'^\[dnsmasq  pid: [0-9]+?\] : setting upstream servers from DBus$', # [dnsmasq  pid: 738] : setting upstream servers from DBus
    1046:r'^\[dnsmasq  pid: [0-9]+?\] : started  version .+? cache disabled$', # [dnsmasq  pid: 738] : started  version 2.75 cache disabled
    1047:r'^\[dnsmasq  pid: [0-9]+?\] : using nameserver '+IPv4AddressRegex+'#[0-9]+?$', # [dnsmasq  pid: 738] : using nameserver 131.155.2.3#53
    1048:r'^\[dnsmasq  pid: [0-9]+?\] : warning: no upstream servers configured$', # [dnsmasq  pid: 738] : warning: no upstream servers configured
    # syslog - gpu - manager
    1049:r'^\[gpu-manager  pid: [0-9]+?\] : Error: can\'t open .+?$',  # [gpu-manager  pid: 518] : Error: can't open /lib/modules/4.4.0-24-generic/updates/dkms
    1050:r'^\[gpu-manager  pid: [0-9]+?\] : /etc/modprobe.d is not a file$',  # [gpu-manager  pid: 518] : /etc/modprobe.d is not a file
    1051:r'^\[gpu-manager  pid: [0-9]+?\] : message repeated [0-9]+? times: \[ /etc/modprobe.d is not a file\]$', # message repeated 2 times: [ /etc/modprobe.d is not a file]
    1052:r'^\[gpu-manager  pid: [0-9]+?\] : update-alternatives: error: no alternatives for x86_64-linux-gnu_gfxcore_conf$', # [gpu-manager  pid: 518] : update-alternatives: error: no alternatives for x86_64-linux-gnu_gfxcore_conf
    # syslog - irqbalance
    1053:r'^\[irqbalance  pid: [0-9]+?\] :    \.\.\.done\.$', # [irqbalance  pid: 504] :    ...done.
    1054:r'^\[irqbalance  pid: [0-9]+?\] :  \* Starting SMP IRQ Balancer: irqbalance$', # [irqbalance  pid: 504] :  * Starting SMP IRQ Balancer: irqbalance
    # syslog - kernel - acpi
    1055:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  0000000000000086.+?$', # [kernel] : [    0.000000]  0000000000000086 92185c74a31f862c ffffffff81e03d80 ffffffff813eab23
    1056:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: APIC 0x000000002FFF0240 000054 \(v02 VBOX   VBOXAPIC 00000001 ASL  00000061\)$', # [kernel] : [    0.000000] ACPI: APIC 0x000000002FFF0240 000054 (v02 VBOX   VBOXAPIC 00000001 ASL  00000061)
    1057:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: DSDT 0x000000002FFF0470 002106 \(v01 VBOX   VBOXBIOS 00000002 INTL 20160108\)$', #[    0.000000] ACPI: DSDT 0x000000002FFF0470 002106 (v01 VBOX   VBOXBIOS 00000002 INTL 20160108)
    1058:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Early table checksum verification disabled$', # [kernel] : [    0.000000] ACPI: Early table checksum verification disabled
    1059:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: FACP 0x000000002FFF00F0 0000F4 \(v04 VBOX   VBOXFACP 00000001 ASL  00000061\)$', # [kernel] : [    0.000000] ACPI: FACP 0x000000002FFF00F0 0000F4 (v04 VBOX   VBOXFACP 00000001 ASL  00000061)
    1060:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: FACS 0x000000002FFF0200 000040$', # [kernel] : [    0.000000] ACPI: FACS 0x000000002FFF0200 000040
    1061:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: INT_SRC_OVR \(bus 0 bus_irq 0 global_irq 2 dfl dfl\)$', # [kernel] : [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
    1062:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: INT_SRC_OVR \(bus 0 bus_irq 9 global_irq 9 high level\)$',   # [kernel] : [    0.000000] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)
    1063:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: IRQ[0-9]+? used by override\.$',   # [kernel] : [    0.000000] ACPI: IRQ0 used by override.
    1064:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Local APIC address 0xfee00000$', # [kernel] : [    0.000000] ACPI: Local APIC address 0xfee00000
    1065:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: PM-Timer IO Port: 0x4008$', # [kernel] : [    0.000000] ACPI: PM-Timer IO Port: 0x4008
    1066:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: RSDP 0x00000000000E0000 000024 \(v02 VBOX  \)$', # [kernel] : [    0.000000] ACPI: RSDP 0x00000000000E0000 000024 (v02 VBOX  )
    1067:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: SSDT 0x000000002FFF02A0 0001CC \(v01 VBOX   VBOXCPUT 00000002 INTL 20160108\)$', # [kernel] : [    0.000000] ACPI: SSDT 0x000000002FFF02A0 0001CC (v01 VBOX   VBOXCPUT 00000002 INTL 20160108)
    1068:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: XSDT 0x000000002FFF0030 00003C \(v01 VBOX   VBOXXSDT 00000001 ASL  00000061\)$', # [kernel] : [    0.000000] ACPI: XSDT 0x000000002FFF0030 00003C (v01 VBOX   VBOXXSDT 00000001 ASL  00000061)
    1069:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   AMD AuthenticAMD$', #  [kernel] : [    0.000000]   AMD AuthenticAMD
    1070:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Base memory trampoline at \[ffff880000099000\] 99000 size 24576$', #  [kernel] : [    0.000000] Base memory trampoline at [ffff880000099000] 99000 size 24576
    # syslog - kernel - bios
    1071:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] BIOS-e820: \[mem .+?-.+?\] usable$', # [kernel] : [    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
    1072:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] BIOS-e820: \[mem .+?-.+?\] reserved$', # [kernel] : [    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
    1073:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] BIOS-e820: \[mem .+?-.+?\] ACPI data$', # [kernel] : [    0.000000] BIOS-e820: [mem 0x000000002fff0000-0x000000002fffffff] ACPI data
    1074:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Booting paravirtualized kernel on KVM$', # [kernel] : [    0.000000] Booting paravirtualized kernel on KVM
    1075:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] BRK \[.+?  .+?\] PGTABLE$', # [kernel] : [    0.000000] BRK [0x021ff000  0x021fffff] PGTABLE
    1076:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] 	Build-time adjustment of leaf fanout to 64\.$',
    1077:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Built 1 zonelists in Node order  mobility grouping on\.  Total pages: 193401$', # Built 1 zonelists in Node order  mobility grouping on.  Total pages: 193401
    1078:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Calgary: detecting Calgary via BIOS EBDA area$', #  [kernel] : [    0.000000] Calgary: detecting Calgary via BIOS EBDA area
    1079:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Calgary: Unable to locate Rio Grande table in EBDA - bailing!$', # [kernel] : [    0.000000] Calgary: Unable to locate Rio Grande table in EBDA - bailing!
    1080:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Call Trace:$', # [kernel] : [    0.000000] Call Trace:
    1081:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   Centaur CentaurHauls$', # [kernel] : [    0.000000] Call Trace:
    # clocksource
    1082:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb  max_idle_ns: 881590591483 ns$',# [kernel] : [    0.000000] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb  max_idle_ns: 881590591483 ns
    1083:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff  max_idle_ns: 7645519600211568 ns$',# [kernel] : [    0.000000] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff  max_idle_ns: 7645519600211568 ns
    # boot
    1084:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Command line: BOOT_IMAGE=.*? root=.*? ro splash quiet$', # [kernel] : [    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-4.4.0-24-generic root=UUID=45d5551c-ba7b-4e39-a2db-a97dfd81e8f1 ro splash quiet
    1085:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Console: colour VGA\+ 80x25$', # [kernel] : [    0.000000] Console: colour VGA+ 80x25
    1086:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] console \[tty0\] enabled$', # [kernel] : [    0.000000] console [tty0] enabled
    1087:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] CPU: 0 PID: 0 Comm: swapper Not tainted .+?$', # [kernel] : [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 4.4.0-24-generic #43-Ubuntu
    1088:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] CPUID\[0d  .+?\]: eax=.+? ebx=.+? ecx=.+? edx=.+?$', # [kernel] : [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 4.4.0-24-generic #43-Ubuntu
    1089:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] CPU MTRRs all blank - virtualized system\.$',   # [kernel] : [    0.000000] CPU MTRRs all blank - virtualized system.
    1090:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ------------\[ cut here \]------------$',   # [kernel] : [    0.000000] ------------[ cut here ]------------
    1091:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   Device   empty$', # [kernel] : [    0.000000]   Device   empty
    1092:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA32    \[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+?\]$',    # [kernel] : [    0.000000]   DMA32    [mem 0x0000000001000000-0x000000002ffeffff]
    1093:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA32 zone: 192496 pages  LIFO batch:31$',   #[kernel] : [    0.000000]   DMA32 zone: 192496 pages  LIFO batch:31
    1094:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA32 zone: 3008 pages used for memmap$',   #[kernel] : [    0.000000]   DMA32 zone: 3008 pages used for memmap
    1095:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA      \[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+?\]$',    # [kernel] : [    0.000000]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
    1096:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA zone: 21 pages reserved$', # [kernel] : [    0.000000]   DMA zone: 21 pages reserved
    1097:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA zone: 3998 pages  LIFO batch:0$',   #[kernel] : [    0.000000]   DMA zone: 3998 pages  LIFO batch:0
    1098:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   DMA zone: 64 pages used for memmap$',  #[kernel] : [    0.000000]   DMA zone: 64 pages used for memmap
    1099:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] DMI: innotek GmbH VirtualBox/VirtualBox  BIOS VirtualBox 12/01/2006$', # [kernel] : [    0.000000] DMI: innotek GmbH VirtualBox/VirtualBox  BIOS VirtualBox 12/01/2006
    1100:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: BIOS-provided physical RAM map:$', # [kernel] : [    0.000000] e820: BIOS-provided physical RAM map:
    1101:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: last_pfn = 0x2fff0 max_arch_pfn = 0x400000000$', # [kernel] : [    0.000000] e820: last_pfn = 0x2fff0 max_arch_pfn = 0x400000000
    1102:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: '+MemAddressRange+' available for PCI devices$', #[    0.000000] e820: [mem 0x30000000-0xfffbffff] available for PCI devices
    1103:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: remove '+MemAddressRange+' usable$',  # [    0.000000] e820: remove [mem 0x000a0000-0x000fffff] usable
    1104:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: update '+MemAddressRange+' usable ==> reserved$', # [kernel] : [    0.000000] e820: [mem 0x30000000-0xfffbffff] available for PCI devices
    1105:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Early memory node ranges$', # [kernel] : [    0.000000] Early memory node ranges
    1106:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ---\[ end trace .+? \]---$', # [kernel] : [    0.000000] ---[ end trace 4d5ff9f2f68c4233 ]---
    1107:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Faking a node at '+MemAddressRange+'$', # [kernel] : [    0.000000] Faking a node at [mem 0x0000000000000000-0x000000002ffeffff]
    1108:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff8107ced0>\] \? xfeature_size\+0x59/0x77$', # [kernel] : [    0.000000]  [<ffffffff8107ced0>] ? xfeature_size+0x59/0x77
    1109:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] warn_slowpath_common\+0x82/0xc0$', # [<ffffffff810810d2>] warn_slowpath_common+0x82/0xc0
    1110:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] warn_slowpath_fmt\+0x5c/0x80$', #  [kernel] : [    0.000000]  [<ffffffff8108116c>] warn_slowpath_fmt+0x5c/0x80
    1111:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] dump_stack\+0x63/0x90$', #  [kernel] : [    0.000000]  [<ffffffff813eab23>] dump_stack+0x63/0x90
    1112:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  [0-9a-fA-F]+? [0-9a-fA-F]+? [0-9a-fA-F]+? [0-9a-fA-F]+?$', # [    0.000000]  ffffffff81e03dc8 ffffffff81c9fe70 ffffffff81e03db8 ffffffff810810d2
    1113:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] \? early_idt_handler_array\+0x120/0x120$', # [    0.000000]  [<ffffffff81f59120>] ? early_idt_handler_array+0x120/0x120
    1114:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] x86_64_start_reservations\+0x2a/0x2c$', #  [kernel] : [    0.000000]  [<ffffffff81f59339>] x86_64_start_reservations+0x2a/0x2c
    1115:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] x86_64_start_kernel\+0x14a/0x16d$', #[kernel] : [    0.000000]  [<ffffffff81f59485>] x86_64_start_kernel+0x14a/0x16d
    1116:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] start_kernel\+0xe4/0x4a2$', #[kernel] : [    0.000000]  [<ffffffff81f59c74>] start_kernel+0xe4/0x4a2
    1117:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] setup_arch\+0xb4/0x[0-9a-fA-F]+?$', # [kernel] : [    0.000000]  [<ffffffff81f65e73>] setup_arch+0xb4/0xd16
    1118:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] fpu__init_system\+0x10d/0x245$', #  [kernel] : [    0.000000]  [<ffffffff81f6988f>] fpu__init_system+0x10d/0x245
    1119:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] fpu__init_system_xstate\+0x38b/0x75a$', # [kernel] : [    0.000000]  [<ffffffff81f6988f>] fpu__init_system+0x10d/0x245
    1120:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] \? early_cpu_init\+0x139/0x13e$', #  [kernel] : [    0.000000]  [<ffffffff81f6a998>] ? early_cpu_init+0x139/0x13e
    1121:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  \[<ffffffff[0-9a-fA-F]+?>\] early_cpu_init\+0x139/0x13e$', # [kernel] : [    0.000000]  [<ffffffff81f6a998>] early_cpu_init+0x139/0x13e
    1122:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] found SMP MP-table at '+MemAddressRange+' mapped at \[[0-9a-fA-F]+?\]$', # [kernel] : [    0.000000] found SMP MP-table at [mem 0x0009fff0-0x0009ffff] mapped at [ffff88000009fff0]
    1123:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Hierarchical RCU implementation\.$', #  [kernel] : [    0.000000] Hierarchical RCU implementation.
    1124:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Hypervisor detected: KVM$', # [kernel] : [    0.000000] Hypervisor detected: KVM
    1125:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Initializing cgroup subsys .+?$',  # [kernel] : [    0.000000] Initializing cgroup subsys cpu
    1128:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Initmem setup node 0 '+MemAddressRange+'$', #  [kernel] : [    0.000000] Initmem setup node 0 [mem 0x0000000000001000-0x000000002ffeffff]
    1129:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   Intel GenuineIntel$', # [kernel] : [    0.000000]   Intel GenuineIntel
    1130:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] IOAPIC\[0\]: apic_id 1  version 17  address 0xfec00000  GSI 0-23$', # [kernel] : [    0.000000] IOAPIC[0]: apic_id 1  version 17  address 0xfec00000  GSI 0-23
    1131:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Kernel command line: BOOT_IMAGE=.+? root=.+? ro splash quiet$',  # [kernel] : [    0.000000] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-4.4.0-24-generic root=UUID=45d5551c-ba7b-4e39-a2db-a97dfd81e8f1 ro splash quiet
    1132:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] KERNEL supported cpus:$', # [kernel] : [    0.000000] KERNEL supported cpus:
    1133:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] kvm-clock: cpu 0  msr 0:2ffe7001  primary cpu clock$', # [kernel] : [    0.000000] kvm-clock: cpu 0  msr 0:2ffe7001  primary cpu clock
    1134:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] kvm-clock: Using msrs 4b564d01 and 4b564d00$', # [kernel] : [    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
    1135:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] kvm-clock: using sched offset of [0-9]+? cycles$', # [kernel] : [    0.000000] kvm-clock: using sched offset of 15309137013128 cycles kvm-clock: using sched offset of 15309137013128 cycles
    1136:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Linux version .+? \(.+?\) \(gcc version .+? \(Ubuntu 5.3.1-14ubuntu2.1\) \) #.+? \(.+?\)$', # [kernel] : [    0.000000] Linux version 4.4.0-24-generic (buildd@lgw01-12) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2.1) ) #43-Ubuntu SMP Wed Jun 8 19:27:37 UTC 2016 (Ubuntu 4.4.0-24.43-generic 4.4.10)
    1137:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Memory: [0-9]+?K/785976K available \([0-9]+?K kernel code  [0-9]+?K rwdata  [0-9]+?K rodata  1480K init  1292K bss  [0-9]+?K reserved  0K cma-reserved\)$', # [    0.000000] Memory: 719380K/785976K available (8361K kernel code  1278K rwdata  3920K rodata  1480K init  1292K bss  66596K reserved  0K cma-reserved)
    1140:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Modules linked in:$',  #  [kernel] : [    0.000000] Modules linked in:
    1141:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Movable zone start for each node$',
    1142:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] MTRR default type: uncachable$',
    1143:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] MTRR: Disabled$',
    1144:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] MTRR variable ranges disabled:$',
    1145:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   node   0: '+MemAddressRange+'$', # [kernel] : [    0.000000]   node   0: [mem 0x0000000000001000-0x000000000009efff]
    1146:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NODE_DATA\(0\) allocated '+MemAddressRange+'$', # [kernel] : [    0.000000] NODE_DATA(0) allocated [mem 0x2ffeb000-0x2ffeffff]
    1147:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] No NUMA configuration found$',
    1148:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   Normal   empty$',
    1149:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NR_IRQS:16640 nr_irqs:256 16$',
    1150:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NX \(Execute Disable\) protection: active$',
    1151:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] On node 0 totalpages: 196494$',
    1152:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pcpu-alloc: \[0\] 0$',
    1153:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pcpu-alloc: s98008 r8192 d28968 u2097152 alloc=1\*2097152$',
    1154:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PERCPU: Embedded 33 pages/cpu @ffff88002fc00000 s98008 r8192 d28968 u2097152$',
    1155:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PID hash table entries: 4096 \(order: 3  32768 bytes\)$',
    1156:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PM: Registered nosave memory: '+MemAddressRange+'$', #  [kernel] : [    0.000000] PM: Registered nosave memory: [mem 0x00000000-0x00000fff]
    1157:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Policy zone: DMA32$',
    1158:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PV qspinlock hash table entries: 256 \(order: 0  4096 bytes\)$',
    1159:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] RAMDISK: '+MemAddressRange+'$',
    1160:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] RCU: Adjusting geometry for rcu_fanout_leaf=64  nr_cpu_ids=1$',
    1161:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] 	RCU restricting CPUs from NR_CPUS=256 to nr_cpu_ids=1\.$',
    1162:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Scanning 1 areas for low memory corruption$',
    1163:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] setup_percpu: NR_CPUS:256 nr_cpumask_bits:256 nr_cpu_ids:1 nr_node_ids:1$',
    1164:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] SLUB: HWalign=64  Order=0-3  MinObjects=0  CPUs=1  Nodes=1$',
    1165:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] SMBIOS 2\.5 present\.$',
    1166:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] smpboot: Allowing 1 CPUs  0 hotplug CPUs$',
    1167:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] tsc: Detected [0-9]+?\.[0-9]+? MHz processor$',
    1168:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Using ACPI \(MADT\) for SMP configuration information$',
    1169:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] WARNING: CPU: 0 PID: 0 at .+? fpu__init_system_xstate\+0x38b/0x75a\(\)$',
    1170:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: Enabled xstate features 0x7  context size is 1088 bytes  using \'standard\' format\.$',
    1171:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: Supporting XSAVE feature 0x01: \'x87 floating point registers\'$',
    1172:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: Supporting XSAVE feature 0x02: \'SSE registers\'$',
    1173:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: Supporting XSAVE feature 0x04: \'AVX registers\'$',
    1174:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: Using \'lazy\' FPU context switches\.$',
    1175:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/fpu: xstate_offset\[2\]:  576  xstate_sizes\[2\]:  256$',
    1176:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86/PAT: Configuration \[0\-7\]: WB  WC  UC\- UC  WB  WC  UC\- WT$',
    1177:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] XSAVE consistency problem  dumping leaves$',
    1178:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Zone ranges:$',
    1179:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Calibrating delay loop \(skipped\) preset value\.\. [0-9]+?\.[0-9]+? BogoMIPS \(lpj=[0-9]+?\)$',
    1180:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pid_max: default: 32768 minimum: 301$',
    1181:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Core revision 20150930$',
    1182:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: 2 ACPI AML tables successfully acquired and loaded$',
    1183:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Security Framework initialized$',
    1184:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Yama: becoming mindful\.$',
    1185:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] AppArmor: AppArmor initialized$',
    1189:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] .*? hash table entries: [0-9]+? \(order: [0-9]+?  [0-9]+? bytes\)$',
    1199:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] CPU: Physical Processor ID: 0$',
    1200:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] mce: CPU supports 0 MCE banks$',
    1201:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] process: using mwait in idle threads$',
    1202:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Last level dTLB entries: 4KB 64  2MB 0  4MB 0  1GB 4$',
    1203:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Freeing SMP alternatives memory: 28K \(ffffffff[0-9a-fA-F]+? - ffffffff[0-9a-fA-F]+?\)$',
    1204:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ftrace: allocating [0-9].*? entries in 125 pages$',
    1205:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Last level iTLB entries: 4KB 64  2MB 8  4MB 8$',
    1206:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] smpboot: Max logical packages: 1$',
    1207:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] smpboot: APIC\(0\) Converting physical 0 to logical package 0$',
    1208:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \.\.TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1$',
    1209:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] APIC calibration not consistent with PM-Timer: [0-9]+?ms instead of [0-9]+?ms$',
    1210:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] APIC delta adjusted to PM-Timer: [0-9]+? \([0-9]+?\)$',
    1211:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] smpboot: CPU0: Intel\(R\) Core\(TM\) i7-6700HQ CPU @ 2.60GHz \(family: 0x6  model: 0x5e  stepping: 0x3\)$',
    1212:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Performance Events: unsupported p6 CPU model 94 no PMU driver  software events only\.$',
    1213:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] KVM setup paravirtual spinlock$',
    1214:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] x86: Booted up 1 node  1 CPUs$',
    1215:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] smpboot: Total of 1 processors activated \([0-9]+?\.[0-9]+? BogoMIPS\)$',
    1216:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] devtmpfs: initialized$',
    1217:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.selinux$',
    1218:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.SMACK64$',
    1219:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.SMACK64EXEC$',
    1220:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.SMACK64MMAP$',
    1221:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.SMACK64TRANSMUTE$',
    1222:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.ima$',
    1223:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: security\.capability$',
    1224:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff  max_idle_ns: 7645041785100000 ns$',
    1225:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pinctrl core: initialized pinctrl subsystem$',
    1226:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] RTC time: .+?  date: .+?$',
    1227:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NET: Registered protocol family 16$',
    1228:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] cpuidle: using governor .+?$',
    1230:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCCT header not found\.$',
    1231:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: bus type PCI registered$',
    1232:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] acpiphp: ACPI Hot Plug PCI Controller Driver version: 0.5$',
    1233:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI: Using configuration type 1 for base access$',
    1234:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Added _OSI\(Module Device\)$',
    1235:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Added _OSI\(Processor Device\)$',
    1236:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Added _OSI\(3.0 _SCP Extensions\)$',
    1237:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Added _OSI\(Processor Aggregator Device\)$',
    1238:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Executed 1 blocks of module-level executable AML code$',
    1239:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Interpreter enabled$',
    1240:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI Exception: AE_NOT_FOUND  While evaluating Sleep State \[\\_S[0-9]_\] \(20150930/hwxface-580\)$',
    1241:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: \(supports S0 S5\)$',
    1242:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Using IOAPIC for interrupt routing$',
    1243:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI: Using host bridge windows from ACPI; if necessary  use "pci=nocrs" and report a bug$',
    1244:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: PCI Root Bridge \[PCI0\] \(domain 0000 \[bus 00-ff\]\)$',
    1245:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] acpi PNP0A03:00: _OSC: OS supports \[ASPM ClockPM Segments MSI\]$',
    1246:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] acpi PNP0A03:00: _OSC failed \(AE_NOT_FOUND\); disabling ASPM$',
    1247:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] acpi PNP0A03:00: fail to add MMCONFIG information  can\'t access extended PCI configuration space under this bridge\.$',
    1248:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI host bridge to bus 0000:00$',
    1249:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: root bus resource \[io  0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+? window\]$',
    1250:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: root bus resource \[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+? window\]$',
    1251:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: root bus resource \[bus 00-ff\]$',
    1252:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:00\.0: \[8086:1237\] type 00 class 0x060000$',
    1253:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.0: \[8086:7000\] type 00 class 0x060100$',
    1254:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: \[8086:7111\] type 00 class 0x01018a$',
    1255:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:00\.0: \[8086:1237\] type 00 class 0x060000$',
    1256:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: reg 0x20: \[io  0xd000-0xd00f\]$',
    1257:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: legacy IDE quirk: reg 0x10: \[io  .+?\]$', # dev_info(&dev->dev, "legacy IDE quirk: reg 0x10: %pR\n",
    1258:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: legacy IDE quirk: reg 0x14: \[io  .+?\]$',
    1259:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: legacy IDE quirk: reg 0x18: \[io  .+?\]$',
    1260:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.1: legacy IDE quirk: reg 0x1c: \[io  .+?\]$',
    1261:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:02\.0: \[80ee:beef\] type 00 class 0x030000$',
    1262:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:02\.0: reg 0x10: \[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+? pref\]$',
    1263:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:03\.0: \[8086:100e\] type 00 class 0x020000$',
    1264:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:03\.0: reg 0x10: \[mem 0x[0-9a-fA-F]+?-0x[0-9a-fA-F]+?\]$',
    1265:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:03\.0: reg 0x18: \[io  0xd010-0xd017\]$',
    1266:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:04\.0: \[80ee:cafe\] type 00 class 0x088000$',
    1267:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:04\.0: reg 0x10: \[io  0xd020-0xd03f\]$',
    1268:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:04\.0: reg 0x14: \[mem 0xf0400000-0xf07fffff\]$',
    1269:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:04\.0: reg 0x18: \[mem 0xf0800000-0xf0803fff pref\]$',
    1270:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:05\.0: \[8086:2415\] type 00 class 0x040100$',
    1271:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:05\.0: reg 0x10: \[io  0xd100-0xd1ff\]$',
    1272:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:05\.0: reg 0x14: \[io  0xd200-0xd23f\]$',
    1273:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:06\.0: \[106b:003f\] type 00 class 0x0c0310$',
    1274:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:06\.0: reg 0x10: \[mem 0xf0804000-0xf0804fff\]$',
    1275:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:07\.0: \[8086:7113\] type 00 class 0x068000$',
    1276:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:0d\.0: \[8086:2829\] type 00 class 0x010601$',
    1277:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:0d\.0: reg 0x10: \[io  0xd240-0xd247\]$',
    1278:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:0d\.0: reg 0x18: \[io  0xd250-0xd257\]$',
    1279:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:0d\.0: reg 0x20: \[io  0xd260-0xd26f\]$',
    1280:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:0d\.0: reg 0x24: \[mem 0xf0806000-0xf0807fff\]$',
    1281:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: PCI Interrupt Link \[.*?\] \(IRQs .*?\)$',
    1285:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Enabled 2 GPEs in block 00 to 07$',
    1286:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vgaarb: setting as boot device: PCI:0000:00:02\.0$',
    1287:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vgaarb: device added: PCI:0000:00:02\.0 decodes=io\+mem owns=io\+mem locks=none$',
    1288:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vgaarb: loaded$',
    1289:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vgaarb: bridge control possible 0000:00:02\.0$',
    1290:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] libata version 3\.00 loaded\.$',
    1291:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: bus type USB registered$',
    1292:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usbcore: registered new interface driver usbfs$',
    1293:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usbcore: registered new device driver usb$',
    1294:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI: Using ACPI for IRQ routing$',
    1295:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI: pci_cache_line_size set to 64 bytes$',
    1296:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e820: reserve RAM buffer '+MemAddressRange+'$',
    1297:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] SCSI subsystem initialized$',
    1298:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usbcore: registered new interface driver hub$',
    1299:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NetLabel: Initializing$',
    1300:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NetLabel:  domain hash size = 128$',
    1301:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NetLabel:  protocols = UNLABELED CIPSOv4$',
    1302:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NetLabel:  unlabeled traffic allowed by default$',
    1303:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: Switched to clocksource kvm-clock$',
    1304:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] AppArmor: AppArmor Filesystem Enabled$',
    1305:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pnp: PnP ACPI init$',
    1306:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pnp 00:0[0-9]: Plug and Play ACPI device  IDs .+? \(active\)$',
    1307:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pnp: PnP ACPI: found [0-9] devices$',
    1308:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0xffffff  max_idle_ns: 2085701024 ns$',
    1309:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: resource 4 \[io  0x0000-0x0cf7 window\]$',
    1310:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: resource 5 \[io  0x0d00-0xffff window\]$',
    1311:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: resource 6 \[mem 0x000a0000-0x000bffff window\]$',
    1312:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_bus 0000:00: resource 7 \[mem 0x30000000-0xffdfffff window\]$',
    1313:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NET: Registered protocol family 2$',
    1314:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] TCP established hash table entries: 8192 \(order: 4  65536 bytes\)$',
    1315:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] TCP bind hash table entries: 8192 \(order: 5  131072 bytes\)$',
    1316:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] TCP: Hash tables configured \(established 8192 bind 8192\)$',
    1317:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] UDP hash table entries: 512 \(order: 2  16384 bytes\)$',
    1318:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] UDP-Lite hash table entries: 512 \(order: 2  16384 bytes\)$',
    1319:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] UDP-Lite hash table entries: 512 \(order: 2  16384 bytes\)$',
    1320:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NET: Registered protocol family 1$',
    1321:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:00\.0: Limiting direct PCI/PCI transfers$',
    1322:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:01\.0: Activating ISA DMA hang workarounds$',
    1323:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci 0000:00:02\.0: Video device with shadowed ROM$',
    1324:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PCI: CLS 0 bytes  default 64$',
    1325:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Trying to unpack rootfs image as initramfs\.\.\.$',
    1326:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Freeing initrd memory: [0-9]+?K \(ffff[0-9a-fA-F]+? - ffff[0-9a-fA-F]+?\)$',
    1327:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] platform rtc_cmos: registered platform RTC device \(no PNP device found\)$',
    1328:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Scanning for low memory corruption every 60 seconds$',

    1330:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] audit: initializing netlink subsys \(disabled\)$',
    1331:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] audit: type=2000 audit\([0-9]+?\.[0-9]+?:1\): initialized$',
    1332:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Initialise system trusted keyring$',
    1333:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] HugeTLB registered 2 MB page size  pre-allocated 0 pages$',
    1334:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] zbud: loaded$',
    1335:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] VFS: Disk quotas dquot_6\.6\.0$',
    1336:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] VFS: Dquot-cache hash table entries: 512 \(order 0  4096 bytes\)$',
    1337:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] fuse init \(API version 7\.23\)$',
    1338:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Allocating IMA MOK and blacklist keyrings\.$',
    1339:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Key type asymmetric registered$',
    1340:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Asymmetric key parser \'x509\' registered$',
    1341:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Block layer SCSI generic \(bsg\) driver version 0\.4 loaded \(major 249\)$',
    1342:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] io scheduler noop registered$',
    1343:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] io scheduler deadline registered \(default\)$',
    1344:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] io scheduler cfq registered$',
    1345:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pci_hotplug: PCI Hot Plug PCI Core version: 0\.5$',
    1346:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] pciehp: PCI Express Hot Plug Controller Driver version: 0\.4$',
    1347:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: AC Adapter \[AC\] \(on-line\)$',
    1348:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: Power Button as /devices/LNXSYSTM:00/LNXPWRBN:00/input/input0$',
    1349:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Power Button \[PWRF\]$',
    1350:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: Sleep Button as /devices/LNXSYSTM:00/LNXSLPBN:00/input/input1$',
    1351:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Sleep Button \[SLPF\]$',
    1352:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] GHES: HEST is not enabled!$',
    1353:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Battery Slot \[BAT0\] \(battery present\)$',
    1354:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Serial: 8250/16550 driver  32 ports  IRQ sharing enabled$',
    1355:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Linux agpgart interface v0\.103$',
    1356:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] brd: module loaded$',
    1357:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] loop: module loaded$',
    1358:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata_piix 0000:00:01\.1: version 2\.13$',
    1360:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] scsi host[0-9]*?: ata_piix$',
    1361:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata1: PATA max UDMA/33 cmd 0x1f0 ctl 0x3f6 bmdma 0xd000 irq 14$',
    1362:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata2: PATA max UDMA/33 cmd 0x170 ctl 0x376 bmdma 0xd008 irq 15$',
    1363:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Key type big_key registered$',
    1364:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] libphy: Fixed MDIO Bus: probed$',
    1365:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] tun: Universal TUN/TAP device driver  1\.6$',
    1366:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] tun: \(C\) 1999-2004 Max Krasnyansky <maxk@qualcomm\.com>$',
    1367:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PPP generic driver version 2\.4\.2$',
    1368:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ehci_hcd: USB 2\.0 \'Enhanced\' Host Controller \(EHCI\) Driver$',
    1369:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ehci-pci: EHCI PCI platform driver$',
    1370:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ehci-platform: EHCI generic platform driver$',
    1371:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci_hcd: USB 1\.1 \'Open\' Host Controller \(OHCI\) Driver$',
    1372:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci-pci: OHCI PCI platform driver$',
    1373:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci-pci 0000:00:06\.0: OHCI PCI host controller$',
    1374:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci-pci 0000:00:06\.0: new USB bus registered  assigned bus number 1$',
    1375:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci-pci 0000:00:06\.0: irq 22  io mem 0xf0804000$',
    1378:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb usb1: New USB device found  idVendor=1d6b  idProduct=0001$',
    1379:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb usb1: New USB device strings: Mfr=3  Product=2  SerialNumber=1$',
    1380:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb usb1: Product: OHCI PCI host controller$',
    1381:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb usb1: Manufacturer: Linux 4.*?$',
    1382:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb usb1: SerialNumber: 0000:00:06\.0$',
    1383:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] hub 1-0:1.0: USB hub found$',
    1384:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] hub 1-0:1.0: 12 ports detected$',
    1385:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ohci-platform: OHCI generic platform driver$',
    1386:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] uhci_hcd: USB Universal Host Controller Interface driver$',
    1387:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] i8042: PNP: PS/2 Controller \[PNP0303:PS2K PNP0f03:PS2M\] at 0x60 0x64 irq 1 12$',
    1388:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] serio: i8042 KBD port at 0x60 0x64 irq 1$',
    1389:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] serio: i8042 AUX port at 0x60 0x64 irq 12$',
    1390:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] mousedev: PS/2 mouse device common for all mice$',
    1391:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input2$',
    1392:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] rtc_cmos rtc_cmos: rtc core: registered rtc_cmos as rtc0$',
    1393:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] rtc_cmos rtc_cmos: alarms up to one day  114 bytes nvram$',
    1394:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] i2c /dev entries driver$',
    1395:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] device-mapper: uevent: version 1\.0\.3$',
    1396:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] device-mapper: ioctl: 4.34.0-ioctl \(2015-10-28\) initialised: dm-devel@redhat.com$',
    1397:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ledtrig-cpu: registered to indicate activity on CPUs$',
    1398:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NET: Registered protocol family 10$',
    1399:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] NET: Registered protocol family 17$',
    1400:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Key type dns_resolver registered$',
    1401:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] microcode: CPU0 sig=0x506e3  pf=0x40  revision=0x0$',
    1402:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] microcode: Microcode Update Driver: v2.01 <tigran@aivazian.fsnet.co.uk>  Peter Oruba$',
    1403:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] registered taskstats version 1$',
    1404:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Loading compiled-in X.509 certificates$',
    1405:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Loaded X.509 cert \'Build time autogenerated kernel key: [0-9a-fA-F]+?\'$',
    1406:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] zswap: loaded using pool lzo/zbud$',
    1407:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Key type trusted registered$',
    1408:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Key type encrypted registered$',
    1409:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] AppArmor: AppArmor sha1 policy hashing enabled$',
    1410:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ima: No TPM chip found  activating TPM-bypass!$',
    1411:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] evm: HMAC attrs: 0x1$',
    1412:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]   Magic number: [0-9]:[0-9]+?:[0-9]+?$',
    1413:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] rtc_cmos rtc_cmos: setting system clock to .+? .+? (.+?)$',
    1414:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] BIOS EDD facility v0.16 2004-Jun-25  0 devices found$',
    1415:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] EDD information not available\.$',
    1416:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] PM: Hibernation image not present or could not be loaded\.$',
    1417:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] machinecheck machinecheck0: hash matches$',
    1418:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] tty tty55: hash matches$',
    1419:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata2.00: ATAPI: VBOX CD-ROM  1.0  max UDMA/133$',
    1420:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata2.00: configured for UDMA/33$',
    1421:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] scsi 1:0:0:0: CD-ROM            VBOX     CD-ROM           1.0  PQ: 0 ANSI: 5$',
    1422:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sr 1:0:0:0: \[sr0\] scsi3-mmc drive: 32x/32x xa/form2 tray$',
    1423:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] cdrom: Uniform CD-ROM driver Revision: 3.20$',
    1424:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sr 1:0:0:0: Attached scsi CD-ROM sr0$',
    1425:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sr 1:0:0:0: Attached scsi generic sg0 type 5$',
    1426:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Freeing unused kernel memory: [0-9]+?K \([0-9a-fA-F]+? - [0-9a-fA-F]+?\)$',
    1427:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Write protecting the kernel read-only data: 14336k$',
    1428:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] random: udevadm urandom read with 2 bits of entropy available$',
    1429:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ACPI: Video Device \[GFX0\] \(multi-head: yes  rom: no  post: no\)$',
    1430:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: Video Bus as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A03:00/LNXVIDEO:00/input/input4$',
    1431:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] FUJITSU Extended Socket Network Device Driver - version 1.0 - Copyright \(c\) 2015 FUJITSU LIMITED$',
    1432:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000: Intel\(R\) PRO/1000 Network Driver - version 7.3.21-k8-NAPI$',
    1433:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000: Copyright \(c\) 1999-2006 Intel Corporation.$',
    1434:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: ImExPS/2 Generic Explorer Mouse as /devices/platform/i8042/serio1/input/input5$',
    1435:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb 1-1: new full-speed USB device number 2 using ohci-pci$',
    1436:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000 0000:00:03.0 eth0: \(PCI:33MHz:32-bit\) 08:00:27:3d:5d:0e$',
    1437:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000 0000:00:03.0 eth0: Intel\(R\) PRO/1000 Network Connection$',
    1438:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ahci 0000:00:0d.0: version 3.0$',
    1439:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ahci 0000:00:0d.0: SSS flag set  parallel bus scan disabled$',
    1440:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ahci 0000:00:0d.0: AHCI 0001.0100 32 slots 1 ports 3 Gbps 0x1 impl SATA mode$',
    1441:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ahci 0000:00:0d.0: flags: 64bit ncq stag only ccc$',
    1442:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000 0000:00:03.0 enp0s3: renamed from eth0$',
    1443:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] scsi host2: ahci$',
    1444:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata3: SATA max UDMA/133 abar m8192@0xf0806000 port 0xf0806100 irq 21$',
    1445:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] SGI XFS with ACLs  security attributes  realtime  no debug enabled$',
    1446:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] JFS: nTxBlock = 5924  nTxLock = 47392$',
    1447:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ntfs: driver 2\.1\.32 \[Flags: R/O MODULE\]\.$',
    1448:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] QNX4 filesystem 0.2.3 registered.$',
    1449:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] raid6: sse2x[0-9]   gen\(\)\s+?[0-9]+? MB/s$',
    1450:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] raid6: sse2x[0-9]   xor\(\)\s+?[0-9]+? MB/s$',
    1451:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] raid6: using algorithm sse2x4 gen\(\)\s+?[0-9]+? MB/s$',
    1452:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] raid6: \.\.\.\. xor\(\)\s+?[0-9]+? MB/s  rmw enabled$',
    1453:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] raid6: using ssse3x2 recovery algorithm$',
    1454:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] xor: automatically using best checksumming function:$',
    1455:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]    avx       :\s+?[0-9]+?\.[0-9]+? MB/sec$',
    1456:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Btrfs loaded$',
    1457:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb 1-1: New USB device found  idVendor=80ee  idProduct=0021$',
    1458:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb 1-1: New USB device strings: Mfr=1  Product=3  SerialNumber=0$',
    1459:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb 1-1: Manufacturer: VirtualBox$',
    1460:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usb 1-1: Product: USB Tablet$',
    1461:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] hidraw: raw HID events driver \(C\) Jiri Kosina$',
    1462:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usbcore: registered new interface driver usbhid$',
    1463:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] usbhid: USB HID core driver$',
    1464:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: VirtualBox USB Tablet as /devices/pci0000:00/0000:00:06.0/usb1/1-1/1-1:1.0/0003:80EE:0021.0001/input/input6$',
    1465:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] hid-generic 0003:80EE:0021.0001: input hidraw0: USB HID v1.10 Mouse \[VirtualBox USB Tablet\] on usb-0000:00:06.0-1/input0$',
    1466:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata3: SATA link up 3.0 Gbps \(SStatus 123 SControl 300\)$',
    1467:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata3.00: ATA-6: VBOX HARDDISK  1.0  max UDMA/133$',
    1468:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata3.00: 12582912 sectors  multi 128: LBA48 NCQ \(depth 31/32\)$',
    1469:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ata3.00: configured for UDMA/133$',
    1470:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] scsi 2:0:0:0: Direct-Access     ATA      VBOX HARDDISK    1.0  PQ: 0 ANSI: 5$',
    1471:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: \[sda\] 12582912 512-byte logical blocks: \(6.44 GB/6.00 GiB\)$',
    1472:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: \[sda\] Write Protect is off$',
    1473:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: \[sda\] Mode Sense: 00 3a 00 00$',
    1474:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: \[sda\] Write cache: enabled  read cache: enabled  doesn\'t support DPO or FUA$',
    1475:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: Attached scsi generic sg1 type 0$',
    1476:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\]  sda: sda1 sda2 < sda5 >$',
    1477:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] sd 2:0:0:0: \[sda\] Attached SCSI disk$',
    1478:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] tsc: Refined TSC clocksource calibration: [0-9]+?\.[0-9]+? MHz$',
    1479:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x[0-9a-fA-F]+?  max_idle_ns: [0-9]+? ns$',
    1480:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] show_signal_msg: [0-9] callbacks suppressed$',
    1481:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] xfsettingsd\[1169\]: segfault at 0 ip 00007fc0b9c6c036 sp 00007ffefc9858f0 error 4 in libxfconf-0.so.2.0.0\[7fc0b9c65000\+12000\]$',
    1482:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] floppy0: no floppy controllers found$',
    1483:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] work still pending$',
    1484:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] EXT4-fs \(sda1\): mounted filesystem with ordered data mode. Opts: \(null\)$',
    1485:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] lp: driver loaded but no devices found$',
    1486:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] ppdev: user-space parallel port driver$',
    1487:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] EXT4-fs \(sda1\): re-mounted. Opts: errors=remount-ro$',
    1488:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] random: nonblocking pool is initialized$',
    1489:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] audit: type=1400 audit\([0-9]+?.[0-9]+?:[0-9]+?\): apparmor="STATUS" operation="profile_load" profile="unconfined" name=".+?" pid=[0-9]+? comm=".+?"$',
    1498:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] piix4_smbus 0000:00:07.0: SMBus base address uninitialized - upgrade BIOS or use force_addr=0xaddr$',
    1499:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vgdrvHeartbeatInit: Setting up heartbeat to trigger every 2000 milliseconds$',
    1500:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] input: Unspecified device as /devices/pci0000:00/0000:00:04.0/input/input7$',
    1501:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vboxguest: misc device minor 55  IRQ 20  I/O port d020  MMIO at 00000000f0400000 \(size 0x400000\)$',
    1502:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vboxguest: Successfully loaded version 5.0.18_Ubuntu \(interface 0x00010004\)$',
    1503:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[drm\] Initialized drm 1.1.0 20060810$',
    1504:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[drm\] VRAM 00c00000$',
    1505:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[TTM\] Zone  kernel: Available graphics memory: [0-9]*? kiB$',
    1506:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[TTM\] Initializing pool allocator$',
    1507:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[TTM\] Initializing DMA pool allocator$',
    1508:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] fbcon: vboxdrmfb \(fb0\) is primary device$',
    1509:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] AVX version of gcm_enc/dec engaged\.$',
    1510:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] AES CTR mode by8 optimization enabled$',
    1511:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Console: switching to colour frame buffer device 100x37$',
    1512:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] vboxvideo 0000:00:02.0: fb0: vboxdrmfb frame buffer device$',
    1513:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] \[drm\] Initialized vboxvideo 1.0.0 20130823 for 0000:00:02.0 on minor 0$',
    1514:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] Adding 783356k swap on /dev/sda5.  Priority:-1 extents:1 across:783356k FS$',
    1515:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] snd_intel8x0 0000:00:05.0: disable \(unknown or VT-d\) VM optimization$',
    1516:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] intel_rapl: no valid rapl domains found in package 0$',
    1517:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] IPv6: ADDRCONF\(NETDEV_UP\): .+?: link is not ready$',
    1518:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] snd_intel8x0 0000:00:05.0: white list rate for 1028:0177 is 48000$',
    1519:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] e1000: enp0s3 NIC Link is Up 1000 Mbps Full Duplex  Flow Control: RX$',
    1520:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] IPv6: ADDRCONF\(NETDEV_CHANGE\): .+?: link becomes ready$',
    # loadkeys service
    1521:r'^\[loadkeys  pid: [0-9]+?\] : Loading /etc/console-setup/cached\.kmap\.gz$',  # [loadkeys  pid: 275] : Loading /etc/console-setup/cached.kmap.gz
    # Modem Manager
    1522:r'^\[ModemManager  pid: [0-9]+?\] : <info>  Couldn\'t find support for device at \'/sys/devices/pci0000:00/0000:00:03.0\': not supported by any plugin$',
    1523:r'^\[ModemManager  pid: [0-9]+?\] : <info>  ModemManager \(version 1\.4\.12\) starting in system bus\.\.\.$',
    # Network Manager
    1524:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] NetworkManager \(version 1\.2\.0\) is starting\.\.\.$',
    1525:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] Read config: /etc/NetworkManager/NetworkManager\.conf$',
    1526:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager\[0x[0-9a-fA-F]+?\]: monitoring kernel firmware directory \'/lib/firmware\'.$',
    1527:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] monitoring ifupdown state file \'/run/network/ifstate\'\.$',
    1528:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dns-mgr\[0x[0-9a-fA-F]+?\]: set resolv-conf-mode: dnsmasq  plugin=\"dnsmasq\"$',
    1529:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dns-mgr\[0x[0-9a-fA-F]+?\]: using resolv.conf manager \'resolvconf\'$',
    1530:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] init!$',
    1531:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] management mode: unmanaged$',
    1532:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] device added \(path: .+?  iface: .+?\): no ifupdown configuration found\.$',
    1533:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] devices added \(path: .+?  iface: .+?\)$',
    1534:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] end _init\.$',
    1535:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] settings: loaded plugin ifupdown: \(C\) 2008 Canonical Ltd\.  To report bugs please use the NetworkManager mailing list\. \(/usr/lib/x86_64-linux-gnu/NetworkManager/libnm-settings-plugin-ifupdown\.so\)$',
    1536:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] settings: loaded plugin keyfile: \(c\) 2007 - 2015 Red Hat  Inc\.  To report bugs please use the NetworkManager mailing list\.$',
    1537:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] \([0-9]+?\) \.\.\. get_connections\.$',
    1538:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] \([0-9]+?\) \.\.\. get_connections \(managed=false\): return empty list\.$',
    1539:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] settings: loaded plugin ofono: \(C\) 2013-2016 Canonical Ltd\.  To report bugs please use the NetworkManager mailing list\. \(/usr/lib/x86_64-linux-gnu/NetworkManager/libnm-settings-plugin-ofono\.so\)$',
    1540:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] SettingsPlugin-Ofono: end _init\.$',
    1541:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] SettingsPlugin-Ofono: init!$',
    1542:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] keyfile: new connection /etc/NetworkManager/system-connections/Wired connection 1 \(eec65aa0-35c6-4836-9b4b-7d75ed2f5fb1 "Wired connection 1"\)$',
    1543:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] SettingsPlugin-Ofono: \([0-9]+?\) \.\.\. get_connections\.$',
    1544:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] SettingsPlugin-Ofono: \([0-9]+?\) connections count: [0-9]+?$',
    1545:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] get unmanaged devices count: [0-9]+?$',
    1546:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] settings: hostname: using hostnamed$',
    1547:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] settings: hostname changed from \(none\) to "ubuntu"$',
    1548:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] Using DHCP client \'dhclient\'$',
    1549:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] Loaded device plugin: .+? \(.+?\)$',
    1551:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: Networking is enabled by state file$',
    1552:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: WiFi enabled by radio killswitch; enabled by state file$',
    1553:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: WWAN enabled by radio killswitch; enabled by state file$',
    1555:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: \(.+?\): new .+? device \(/org/freedesktop/NetworkManager/Devices/[0-9]\)$',
    1556:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] device \(.+?\): state change: .+? -> .+? \(reason \'.+?\'\) \[[0-9]+? [0-9]+? [0-9]+?\]$', # LOGD (LOGD_DEVICE, "state change: %s -> %s (reason '%s') [%d %d %d]%s",
    1557:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] device \(.+?\): link connected$',
    1558:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] urfkill disappeared from the bus$',
    1559:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] ModemManager available in the bus$',
    1560:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] ofono is now available$',
    1562:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] policy: auto-activating connection \'Wired connection 1\'$',
    1563:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] device \(.+?\): Activation: starting connection \'Wired connection 1\' \(eec65aa0-35c6-4836-9b4b-7d75ed2f5fb1\)$',
    1565:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: NetworkManager state is now CONNECTING$',
    1568:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dhcp4 \(.+?\): activation: beginning transaction \(timeout in [0-9]+? seconds\)$',
    1569:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dhcp4 \(.+?\): dhclient started with pid [0-9]+?$',
    1570:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dhcp4 \(.+?\): dhclient started with pid [0-9]+?$',
    1571:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   address '+IPv4AddressRegex,
    1572:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   plen [0-9]+? \('+IPv4AddressRegex+'\)$',
    1573:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   gateway '+IPv4AddressRegex,
    1574:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   server identifier '+IPv4AddressRegex,
    1575:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   lease time [0-9]+?$',
    1576:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\]   nameserver \''+IPv4AddressRegex+'\'$',
    1578:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dhcp4 \(.+?\): state changed unknown -> bound$',
    1582:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: NetworkManager state is now CONNECTED_LOCAL$',
    1583:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: NetworkManager state is now CONNECTED_GLOBAL$',
    1584:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] policy: set \'.+?\' \(.+?\) as default for IPv4 routing and DNS$',
    1585:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] DNS: starting dnsmasq\.\.\.$',
    1586:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dns-mgr: Writing DNS information to /sbin/resolvconf$',
    1587:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] device \(.+?\): Activation: successful  device activated\.$',
    1588:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] dnsmasq\[0x[0-9a-fA-F]+?\]: dnsmasq appeared as :1\.[0-9]+?$',
    1589:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: startup complete$',
    1590:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] .+? hardware radio set .+?$',
    1592:r'^\[NetworkManager  pid: [0-9]+?\] : nm_device_get_device_type: assertion \'NM_IS_DEVICE \(self\)\' failed$',
    1593:r'^\[NetworkManager  pid: [0-9]+?\] : <warn>  \[[0-9]+?\.[0-9]+?\] SettingsPlugin-Ofono: file doesn\'t exist: /var/lib/ofono$',
    1594:r'^\[NetworkManager  pid: [0-9]+?\] : <warn>  \[[0-9]+?\.[0-9]+?\] failed to enumerate oFono devices: GDBus.Error:org\.freedesktop\.DBus\.Error\.ServiceUnknown: The name org\.ofono was not provided by any \.service files$',
    1595:r'^\[NetworkManager  pid: [0-9]+?\] : <warn>  \[[0-9]+?\.[0-9]+?\] dnsmasq\[0x[0-9a-fA-F]+?\]: dnsmasq not found on the bus\. The nameserver update will be sent when dnsmasq appears$',
    1596:r'^\[NetworkManager  pid: [0-9]+?\] : <warn>  \[[0-9]+?\.[0-9]+?\] error requesting auth for .+?: .+?$',
    #error requesting auth for %s: %s
    1598:r'^\[NetworkManager  pid: [0-9]+?\] : <info>  \[[0-9]+?\.[0-9]+?\] manager: kernel firmware directory \'/lib/firmware\' changed$',
    #nm dispatcher
    1599:r'^\[nm-dispatcher\] : req:1 \'hostname\': new request \(1 scripts\)$',
    1600:r'^\[nm-dispatcher\] : req:1 \'hostname\': start running ordered scripts\.\.\.$',
    1601:r'^\[nm-dispatcher\] : req:2 \'up\' \[enp0s3\]: new request \(1 scripts\)$',
    1602:r'^\[nm-dispatcher\] : req:2 \'up\' \[enp0s3\]: start running ordered scripts\.\.\.$',
    # org.a11y.atspi.Registry
    1603:r'^\[org\.a11y\.atspi\.Registry  pid: [0-9]+?\] : SpiRegistry daemon is running with well-known name - org\.a11y\.atspi\.Registry$',
    1604:r'^\[org\.a11y\.Bus  pid: [0-9]+?\] : Activating service name=\'org\.a11y\.atspi\.Registry\'',
    1605:r'^\[org\.a11y\.Bus  pid: [0-9]+?\] : \*\* \(process:[0-9]+?\): WARNING \*\*: Failed to register client: GDBus\.Error:org\.freedesktop\.DBus\.Error\.ServiceUnknown: The name org\.gnome\.SessionManager was not provided by any \.service files$',
    1606:r'^\[org\.a11y\.Bus  pid: [0-9]+?\] : Successfully activated service \'org\.a11y\.atspi\.Registry\'$',
    #org.gtk.vfs.Daemon [org.gtk.vfs.Daemon  pid: 901] : A connection to the bus can't be made
    1607:r'^\[org\.gtk\.vfs\.Daemon  pid: [0-9]+?\] : A connection to the bus can\'t be made$',
    # os prober
    1608:r'^\[os-prober\] : debug: /dev/sda2: DOS extended partition; skipping$',
    1609:r'^\[os-prober\] : debug: /dev/sda5: is active swap$',
    # polk started daemon version 0.105 using authority implementation `local' version `0.105'it
    1610:r'^\[polkitd  pid: [0-9]+?\] : started daemon version 0\.105 using authority implementation \`local\' version \`0\.105\'$',
    # pulseaudio
    1611:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] alsa-util\.c: Disabling timer-based scheduling because running inside a VM\.$',
    1612:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] authkey\.c: Failed to load authentication key \'.+?\': No such file or directory$',
    1613:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] authkey\.c: Failed to open cookie file \'.+?\': No such file or directory$',
    1614:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] sink\.c: Default and alternate sample rates are the same\.$',
    1615:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] module-x11-publish\.c: PulseAudio information vanished from X11!$',
    1616:r'^\[pulseaudio  pid: [0-9]+?\] : \[pulseaudio\] pid\.c: Daemon already running\.$',
    # rsyslogd
    1617:r'^\[rsyslogd-[0-9]+?\] : action \'action 10\' suspended  next retry is .+? \[v8.16.0 try http://www.rsyslog.com/e/.*?\]$',
    1618:r'^\[rsyslogd-[0-9]+?\] : Could not open output pipe \'/dev/xconsole\':: No such file or directory \[v8.16.0 try http://www.rsyslog.com/e/[0-9]+? \]$',

    1619:r'^\[rsyslogd-[0-9]+?\] : command \'.+?\' is currently not permitted - did you already set it via a RainerScript command \(v6\+ config\)\? \[v8.16.0 try http://www.rsyslog.com/e/[0-9]+? \]$',
    1620:r'^\[rsyslogd\] : \[origin software=\"rsyslogd\" swVersion="8.16.0" x-pid=\"[0-9]+?\" x-info="http://www.rsyslog.com"\] exiting on signal [0-9]+?\.$',
    1621:r'^\[rsyslogd\] : \[origin software=\"rsyslogd\" swVersion="8.16.0" x-pid=\"[0-9]+?\" x-info="http://www.rsyslog.com"\] start$',
    1622:r'^\[rsyslogd\] : rsyslogd\'s groupid changed to [0-9]+?$',
    1623:r'^\[rsyslogd\] : rsyslogd\'s userid changed to [0-9]+?$',
    # rtkit daemon
    1624:r'^\[rtkit-daemon  pid: [0-9]+?\] : Canary thread running.$',
    1625:r'^\[rtkit-daemon  pid: [0-9]+?\] : Running.$',
    1626:r'^\[rtkit-daemon  pid: [0-9]+?\] : Successfully called chroot.$',
    1627:r'^\[rtkit-daemon  pid: [0-9]+?\] : Successfully limited resources.$',
    1628:r'^\[rtkit-daemon  pid: [0-9]+?\] : Successfully made thread [0-9]+? of process [0-9]+? \(n/a\) owned by \'[0-9]+?\' high priority at nice level -11.$',
    1629:r'^\[rtkit-daemon  pid: [0-9]+?\] : Successfully made thread [0-9]+? of process [0-9]+? \(n/a\) owned by \'[0-9]+?\' RT at priority 5.$',
    1630:r'^\[rtkit-daemon  pid: [0-9]+?\] : Supervising [0-9]+? threads of [0-9]+? processes of [0-9]+? users.$',
    1631:r'^\[rtkit-daemon  pid: [0-9]+?\] : Watchdog thread running.$',
    1632:r'^\[rtkit-daemon  pid: [0-9]+?\] : Successfully dropped privileges.$',
    # snapd
    1633:r'^\[snapd  pid: [0-9]+?\] : .*? main.go:64: Exiting on terminated signal.$',
    1634:r'^\[snap  pid: [0-9]+?\] : error: cannot list updates: cannot list snaps: cannot list updates: .*?$',
    # system modules load
    1635:r'^\[systemd-modules-load  pid: [0-9]+?\] : Inserted module \'.*?\'$',
    # systemd
    1636:r'^\[systemd  pid: [0-9]+?\] : Reached target .+?\.$',
    1642:r'^\[systemd  pid: [0-9]+?\] : Received SIGRTMIN\+[0-9]+? from PID [0-9]+? \(.*?\).$',
    1643:r'^\[systemd  pid: [0-9]+?\] : Starting Exit the Session...$',
    1644:r'^\[systemd  pid: [0-9]+?\] : Startup finished in [0-9]+?ms.$',
    1645:r'^\[systemd  pid: [0-9]+?\] : Stopped target .+?\.$',
    1650:r'^\[systemd  pid: [0-9]+?\] : Activated swap /dev/disk/by-uuid/.+?\.$',
    1651:r'^\[systemd  pid: [0-9]+?\] : Activating swap /dev/disk/by-uuid/.+?\.+?$',
    1652:r'^\[systemd  pid: [0-9]+?\] : apt-daily.timer: Adding [0-9]+?h [0-9]+?min [0-9]+?.[0-9]+?s random time.$',
    1653:r'^\[systemd  pid: [0-9]+?\] : Closed Load/Save RF Kill Switch Status /dev/rfkill Watch.$',
    1654:r'^\[systemd  pid: [0-9]+?\] : Closed Socket activation for snappy daemon.$',
    1655:r'^\[systemd  pid: [0-9]+?\] : Created slice User Slice of .+?\.$',
    1656:r'^\[systemd  pid: [0-9]+?\] : Failed to start Automatically refresh installed snaps.$',
    1657:r'^\[systemd  pid: [0-9]+?\] : Found device .+? [0-9].$',
    1658:r'^\[systemd  pid: [0-9]+?\] : Listening on Avahi mDNS/DNS-SD Stack Activation Socket.$',
    1659:r'^\[systemd  pid: [0-9]+?\] : Listening on Avahi mDNS/DNS-SD Stack Activation Socket.$',
    1660:r'^\[systemd  pid: [0-9]+?\] : Listening on CUPS Scheduler.$',
    1661:r'^\[systemd  pid: [0-9]+?\] : Listening on D-Bus System Message Bus Socket.$',
    1662:r'^\[systemd  pid: [0-9]+?\] : Listening on Load/Save RF Kill Switch Status /dev/rfkill Watch.$',
    1663:r'^\[systemd  pid: [0-9]+?\] : Listening on Socket activation for snappy daemon.$', # dbgprintf("Listening on %s syslogd socket %d (%s/port %d).\n",
    1664:r'^\[systemd  pid: [0-9]+?\] : Listening on UUID daemon activation socket.$',
    1665:r'^\[systemd  pid: [0-9]+?\] : Mounted FUSE Control File System\.$',
    1666:r'^\[systemd  pid: [0-9]+?\] : Mounting FUSE Control File System\.\.\.$',
    1677:r'^\[systemd  pid: [0-9]+?\] : Reloaded OpenBSD Secure Shell server.$',
    1678:r'^\[systemd  pid: [0-9]+?\] : Reloading OpenBSD Secure Shell server.$',
    1679:r'^\[systemd  pid: [0-9]+?\] : Listening on ACPID Listen Socket.$',
    1680:r'^\[systemd  pid: [0-9]+?\] : Removed slice User Slice of .+?\.$',
    1681:r'^\[systemd  pid: [0-9]+?\] : snapd.refresh.service: Failed with result \'exit-code\'.$',
    1682:r'^\[systemd  pid: [0-9]+?\] : snapd.refresh.service: Main process exited  code=exited  status=1/FAILURE$',
    1683:r'^\[systemd  pid: [0-9]+?\] : snapd.refresh.service: Unit entered failed state.$',
    1684:r'^\[systemd  pid: [0-9]+?\] : snapd.refresh.timer: Adding [0-9]*?h{0,1}.*?[0-9]+?min [0-9]+?.[0-9]+?s random time.$',
    1685:r'^\[systemd  pid: [0-9]+?\] : Started .+?.$',
    1745:r'^\[systemd  pid: [0-9]+?\] : Starting .+...$',
    1790:r'^\[systemd  pid: [0-9]+?\] : Startup finished in [0-9]+?.[0-9]+?s \(kernel\) \+ [0-9]*?(min )*?[0-9]+\.[0-9]+?s \(userspace\) = [0-9]*?(min )*?[0-9]+\.[0-9]+?s\.$',
    1791:r'^\[systemd  pid: [0-9]+?\] : Stopped .+?\.$',
    1797:r'^\[systemd  pid: [0-9]+?\] : Stopping .+?\.\.\.$',
    1809:r'^\[systemd  pid: [0-9]+?\] : Stopping Session c[0-9] of user .+?\.$',
    1813:r'^\[systemd  pid: [0-9]+?\] : Time has been changed$',
    3003:r'^\[systemd  pid: [0-9]+?\] : Mounted Debug File System.$',
    3004:r'^\[systemd  pid: [0-9]+?\] : Mounted Huge Pages File System.$',
    3005:r'^\[systemd  pid: [0-9]+?\] : Mounted POSIX Message Queue File System.$',
    3006:r'^\[ModemManager  pid: [0-9]+?\] : <info>  Caught signal  shutting down...$',
    # systemd-timesyncd
    1814:r'^\[systemd-timesyncd  pid: [0-9]+?\] : Synchronized to time server '+IPv4AddressRegex+':[0-9]+? \(ntp.ubuntu.com\).$',
    #systemd-tmpfiles
    1815:r'^\[systemd-tmpfiles  pid: [0-9]+?\] : \[/usr/lib/tmpfiles.d/var.conf:14\] Duplicate line for path "/var/log"  ignoring.$',
    #systemd-tmpfiles
    1816:r'^\[systemd-udevd  pid: [0-9]+?\] : Process \'.+?\' failed with exit code [0-9]+?.$',
    #udsiksd
    1817:r'^\[udisksd  pid: [0-9]+?\] : Acquired the name org.freedesktop.UDisks2 on the system message bus$',
    1818:r'^\[udisksd  pid: [0-9]+?\] : udisks daemon version 2.1.7 starting$',
    # snapd
    1819:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: init done in [0-9]+?.[0-9]+?ms$',
    1820:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /$',
    1821:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/assertions$',
    1822:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/assertions/\{assertType\}$',
    1823:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/changes$',
    1824:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/changes/\{id\}$',
    1825:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/events$',
    1826:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/find$',
    1827:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/icons/\{name\}/icon$',
    1828:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/interfaces$',
    1829:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/login$',
    1830:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/logout$',
    1831:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/snaps$',
    1832:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/snaps/\{name\}$',
    1833:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:[0-9]+?: DEBUG: adding /v2/system-info$',
    1834:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : main.go:64: Exiting on terminated signal.$',
    1835:r'^\[/usr/lib/snapd/snapd  pid: [0-9]+?\] : daemon.go:181: DEBUG: uid=0;@ GET /v2/find.*?$',

    # irqbalance
    1836:r'^\[/usr/sbin/irqbalance\] : Balancing is ineffective on systems with a single cpu.  Shutting down$',
    1900:r'^\[systemd  pid: [0-9]+?\] : Stopped Timer to automatically refresh installed snaps.$',
    1901:r'^\[systemd  pid: [0-9]+?\] : Reloading.$',
    1902:r'^\[systemd  pid: [0-9]+?\] : Stopuname -a: Linux ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 GNU/Linux$',
    1903:r'^\[kernel\] : \[\s+?[0-9]+?\.[0-9]+?\] audit: type=1400 audit\([0-9]+?.[0-9]+?:[0-9]+?\): apparmor="STATUS" operation="profile_load" profile="unconfined" name="/usr/sbin/cupsd" pid=[0-9]+? comm="apparmor_parser"$',
    # next id is: 1861 because there are some 18xx numbes in the beginnings
}

# compile regular expression for faster execution (patterns get cached)
signatures_by_id = {}
for pattern_id, pattern in KNOWN_LOGLINE_PATTERN.items():
    KNOWN_LOGLINE_PATTERN[pattern_id]=re.compile(pattern)
    signatures_by_id[pattern_id]=pattern

def extract_pattern_id(message):
    for pattern_id, pattern in KNOWN_LOGLINE_PATTERN.items():
        #print message, pattern
        if re.search(pattern, message):
            return pattern_id
    return 0 # no pattern to parse log line, unknown message

# Note: log2timeline replaces commas in log messages with a space ' '
# See : https://github.com/log2timeline/plaso/blob/master/plaso/output/l2t_csv.py
# auth.log / syslog
if __name__ == '__main__':
    import numpy as np
    import json
    # parse command line arguments
    datafile="unix_log.log"
    DATASET_STATS_FILE="unix_log_stats.txt"
    with open(datafile,"r") as logs:
        counts = {}
        for i, log_line in enumerate(logs):
            pid = extract_pattern_id(log_line)
            if not pid in counts:
                counts[pid]=1
            else:
                counts[pid]+=1

        counts_wt_zero = [c for c in counts.values() if c>0]


        print("Dataset statistics:")
        print("Min: %i"%min(counts_wt_zero))
        print("Max: %i"%max(counts_wt_zero))
        print("Lower Quartile %.2f"%np.percentile(counts_wt_zero, 25))
        print("Median: %.2f"%np.median(counts_wt_zero))
        print("Upper Quartile %.2f"%np.percentile(counts_wt_zero, 75))
        print("Mean: %.2f"%np.mean(counts_wt_zero))
        print("Std: %0.2f"%np.std(counts_wt_zero))

        ## numpy is used for creating fake data
        import matplotlib as mpl
        ## agg backend is used to create plot as a .png file
        mpl.use('agg')
        import matplotlib.pyplot as plt
        # Create a figure instance
        fig = plt.figure(1, figsize=(9, 6))
        # Create an axes instance
        ax = fig.add_subplot(111)

        # Create the boxplot
        bp = ax.boxplot(counts_wt_zero)

        # Save the figure
        fig.savefig('unix_log_stats.png', bbox_inches='tight')

        with open(DATASET_STATS_FILE,"w") as f:
            json_coutns_str = json.dumps(counts)
            f.write(json_coutns_str)
