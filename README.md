# feed_server
# feed_server


# SRX Configuration

## SRX Syslog configuration

The script needs to receive IDP logs triggred by the Psiphon signature:

```
# show security log | display set
set security log mode stream
set security log source-interface OUTGOING_INTERFACE
set security log stream PSI format sd-syslog
set security log stream PSI category idp
set security log stream PSI host SERVER_IP
set security log stream PSI host port 514
```

## SRX Security policy example

This example used UTM Web Filetring module to display the notification to a temporary blocked user.


_Firewall policy_

```
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users match source-address custom-feed-clients
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users match destination-address any
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users match application junos-http
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users match application junos-https
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users then permit application-services ssl-proxy profile-name ssl-inspect
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users then permit application-services utm-policy utm-wf-psiphon
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users then log session-init
set security policies from-zone Trust to-zone Untrust policy Block-Notify-Psiphon-Users then log session-close
set security policies from-zone Trust to-zone Untrust policy Block-Psiphon-Users match source-address custom-feed-clients
set security policies from-zone Trust to-zone Untrust policy Block-Psiphon-Users match destination-address any
set security policies from-zone Trust to-zone Untrust policy Block-Psiphon-Users match application any
set security policies from-zone Trust to-zone Untrust policy Block-Psiphon-Users then deny
set security policies from-zone Trust to-zone Untrust policy Block-Psiphon-Users then log session-init
set security policies from-zone Trust to-zone Untrust policy Blacklist-IP match source-address any
set security policies from-zone Trust to-zone Untrust policy Blacklist-IP match destination-address custom-feed
set security policies from-zone Trust to-zone Untrust policy Blacklist-IP match application any
set security policies from-zone Trust to-zone Untrust policy Blacklist-IP then deny
set security policies from-zone Trust to-zone Untrust policy Blacklist-IP then log session-close
set security policies from-zone Trust to-zone Untrust policy deny-service match source-address any
set security policies from-zone Trust to-zone Untrust policy deny-service match destination-address any
set security policies from-zone Trust to-zone Untrust policy deny-service match application junos-netbios-session
set security policies from-zone Trust to-zone Untrust policy deny-service match application junos-ssh
set security policies from-zone Trust to-zone Untrust policy deny-service match application junos-ike
set security policies from-zone Trust to-zone Untrust policy deny-service match application junos-dns-tcp
set security policies from-zone Trust to-zone Untrust policy deny-service match application esp
set security policies from-zone Trust to-zone Untrust policy deny-service then deny
set security policies from-zone Trust to-zone Untrust policy Blacklist-App match source-address any
set security policies from-zone Trust to-zone Untrust policy Blacklist-App match destination-address any
set security policies from-zone Trust to-zone Untrust policy Blacklist-App match application junos-defaults
set security policies from-zone Trust to-zone Untrust policy Blacklist-App match dynamic-application junos:PSIPHON
set security policies from-zone Trust to-zone Untrust policy Blacklist-App then reject profile custom-block
set security policies from-zone Trust to-zone Untrust policy Blacklist-App then log session-init
set security policies from-zone Trust to-zone Untrust policy Blacklist-App then log session-close
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic match source-address any
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic match destination-address any
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic match application junos-defaults
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic match dynamic-application junos:SSL
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic match dynamic-application junos:HTTP
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic then permit application-services idp-policy cutom-idp-policy
set security policies from-zone Trust to-zone Untrust policy Allowed-Traffic then permit application-services ssl-proxy profile-name ssl-inspect
```

_IDP Policy_

below signature is a pre-defined Juniper IDP signature.

```
set security idp idp-policy custom-idp-policy rulebase-ips rule 1 match attacks predefined-attacks HTTP:TUNNEL:PSIPHON-TUNNEL
set security idp idp-policy custom-idp-policy rulebase-ips rule 1 then action drop-connection
set security idp idp-policy custom-idp-policy rulebase-ips rule 1 then notification log-attacks
```

_UTM Policy_

juniper-local type can also be used. 

```
set security utm default-configuration web-filtering type juniper-enhanced
set security utm feature-profile web-filtering juniper-enhanced profile catch-all-display-msg-psiphon default block
set security utm feature-profile web-filtering juniper-enhanced profile catch-all-display-msg-psiphon custom-block-message "You have been blocked because we detected the use of psiphon from your IP address. You will be block for 5 minutes. Do not attempt to use this sofware again!"
set security utm utm-policy utm-wf-psiphon web-filtering http-profile catch-all-display-msg-psiphon
```

_Dynamic Address_

```
set security dynamic-address feed-server custom-feed hostname 0.0.0.0:4443
set security dynamic-address feed-server custom-feed update-interval 30
set security dynamic-address feed-server custom-feed hold-interval 300
set security dynamic-address feed-server custom-feed feed-name vpnfeed path vpnfeed.gz
set security dynamic-address address-name custom-feed profile feed-name custom-feed
set security dynamic-address feed-server custom-feed feed-name clientfeed path clients.gz
set security dynamic-address address-name custom-feed-clients profile feed-name clientfeed
```
