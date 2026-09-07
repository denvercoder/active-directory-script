<#
    New-ADLabUsers.ps1

    Builds a realistic Active Directory lab environment for training: a full
    medium-sized-company OU structure, department security groups,
    department distribution groups, and randomly generated employees (with
    names/addresses/phone numbers pulled from the Mockaroo API, or generated
    locally with -Offline) wired up with job titles, a manager hierarchy,
    and group memberships.

    Everything can be driven interactively (just run it, answer the
    prompts) or non-interactively via parameters, for scripted/classroom use.

    REQUIREMENTS
      - Run on a machine with the ActiveDirectory PowerShell module (RSAT or
        a domain controller), by an account with rights to create OUs, users,
        and groups in the target domain.
      - A free Mockaroo API key (https://mockaroo.com) unless you pass
        -Offline - see README.md for how to get one. The free tier caps
        requests at 1,000 rows, so this script limits user counts to 1-1000.
      - Only intended for lab/training domains. It creates real objects
        (no -WhatIf on the AD cmdlets themselves) - review before pointing
        it at anything else. Use -DryRun to preview a run with no writes.

    See README.md for full parameter docs, the misconfiguration catalog, and
    the companion Remove-ADLabUsers.ps1 / Find-ADLabMisconfigurations.ps1
    scripts.
#>

[CmdletBinding()]
param(
    # How many users to create (1-1000). Omit to be prompted.
    [ValidateRange(1,1000)]
    [int]$UserCount,

    # Skip the misconfiguration prompt and force it on/off. Omit both to be prompted.
    [switch]$AddMisconfigurations,
    [switch]$SkipMisconfigurations,

    # Skip the password-mode prompt: pass one of these to go non-interactive.
    [switch]$UseRandomPasswords,
    [string]$SharedPassword,

    # Your Mockaroo API key. Falls back to $MockarooApiKeyDefault below, then prompts.
    [string]$MockarooApiKey,

    # Generate identities locally instead of calling Mockaroo (no internet/API key needed).
    [switch]$Offline,

    # Which fictitious company to build. See ADLabHelpers.ps1 for the full templates.
    [ValidateSet('NimbusSoftwareSolutions','SummitRetailGroup','HarborLogisticsCo')]
    [string]$CompanyTemplate = 'NimbusSoftwareSolutions',

    # Seeds Get-Random so a run is reproducible (same allocation, offices, passwords,
    # misconfig picks). Mockaroo-sourced names/addresses are NOT seeded - combine
    # with -Offline for a fully reproducible run.
    [int]$Seed,

    # Preview the full plan (OUs, groups, users, misconfigs) without creating or
    # modifying anything in Active Directory. Still requires domain connectivity
    # to resolve the real domain name and check for existing accounts.
    [switch]$DryRun
)

# ============================== CONFIGURATION ==============================

. (Join-Path $PSScriptRoot 'ADLabHelpers.ps1')

if ($PSBoundParameters.ContainsKey('Seed')) {
    Write-Host "Seeding randomness with -Seed $Seed for a reproducible run." -ForegroundColor Cyan
    $null = Get-Random -SetSeed $Seed
}

# Paste your own Mockaroo API key here to skip the runtime prompt, or leave
# blank and you'll be asked for it once when the script runs (ignored with -Offline).
$MockarooApiKeyDefault = ''

$CredentialReportPath = Join-Path -Path $PSScriptRoot -ChildPath ("ADLabUsers_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$AnswerKeyPath        = Join-Path -Path $PSScriptRoot -ChildPath ("ADLabMisconfigurations_ANSWERKEY_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

# Weak-but-policy-compliant passwords used by several misconfiguration categories below.
$WeakPasswords = @('Password1','Welcome1!','Summer2026!','ChangeMe1!','Company123!')

# Each misconfiguration category below can be toggled off individually (Enabled = $false)
# without disabling the whole feature. Pct/Min/Max size the sample relative to headcount.
$MisconfigTypes = @{
    WeakPassword           = @{ Enabled = $true; Pct = 0.08; Min = 1; Max = 10; Severity = 'Medium';   Description = 'Account has a weak, guessable password that still passes complexity requirements' }
    PasswordNotRequired    = @{ Enabled = $true; Pct = 0.04; Min = 1; Max = 5;  Severity = 'High';     Description = 'PASSWD_NOTREQD flag set - account is allowed to have a blank password' }
    ASREPRoastable         = @{ Enabled = $true; Pct = 0.04; Min = 1; Max = 5;  Severity = 'High';     Description = 'Kerberos pre-authentication disabled (AS-REP roastable), and the account has a weak password' }
    Kerberoastable         = @{ Enabled = $true; Pct = 0.03; Min = 1; Max = 5;  Severity = 'High';     Description = 'A fake SPN is set on a standard user account with a weak password (Kerberoastable)' }
    RestrictedWorkstation  = @{ Enabled = $true; Pct = 0.06; Min = 1; Max = 8;  Severity = 'Low';      Description = 'LogonWorkstations restricts sign-in to a single (possibly stale) machine name' }
    PasswordInDescription  = @{ Enabled = $true; Pct = 0.04; Min = 1; Max = 5;  Severity = 'Medium';   Description = 'Description field contains the account''s real plaintext password' }
    StaleTerminatedAccount = @{ Enabled = $true; Pct = 0.03; Min = 1; Max = 4;  Severity = 'Medium';   Description = 'Account is still enabled even though its description says the employee was terminated' }
    MisplacedOU            = @{ Enabled = $true; Pct = 0.03; Min = 1; Max = 4;  Severity = 'Low';      Description = 'Account was left in the default Users container instead of its department OU' }
    RoguePrivilegedAccess  = @{ Enabled = $true; MinTotalUsers = 8;             Severity = 'Critical'; Description = 'A standard employee account was added directly to Domain Admins' }
    DangerousACL           = @{ Enabled = $true; MinTotalUsers = 8;             Severity = 'Critical'; Description = 'A standard employee account was granted GenericAll over another user object (BloodHound-style attack path)' }
    WeakPasswordPolicy     = @{ Enabled = $true; MinTotalUsers = 5;             Severity = 'High';     Description = 'A Fine-Grained Password Policy with weak settings (short length, no complexity, no lockout) applies to one department group' }
    GPPCPassword           = @{ Enabled = $true; MinTotalUsers = 1;             Severity = 'Critical'; Description = 'A Group Policy Preference drive mapping stores a "encrypted" password (MS14-025) that is trivially decryptable' }
}

# ============================ AD-TOUCHING HELPERS ===========================

function Get-MockarooRecords {
    param([string]$ApiKey, [int]$Count)

    $schema = @(
        @{ name = 'first_name';     type = 'First Name' }
        @{ name = 'last_name';      type = 'Last Name' }
        @{ name = 'street_address'; type = 'Street Address' }
        @{ name = 'city';           type = 'City' }
        @{ name = 'state_abbr';     type = 'State (abbrev)'; onlyUSPlaces = $true }
        @{ name = 'postal_code';    type = 'Postal Code' }
        @{ name = 'mobile_phone';   type = 'Phone'; format = '###-###-####' }
    )
    $body = $schema | ConvertTo-Json -Depth 5

    # Mockaroo's free tier caps a single request at 1,000 rows, which is why
    # user counts above are capped at 1000 too.
    $uri = "https://api.mockaroo.com/api/generate.json?key=$ApiKey&count=$Count"
    $result = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json'
    if ($result -is [string]) {
        throw "Mockaroo returned an unexpected response (likely an error message instead of data): $result"
    }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($result)) { $records.Add($r) }
    return $records
}

function New-OUIfMissing {
    param([string]$Name, [string]$Path, [switch]$DryRun)
    $dn = "OU=$Name,$Path"
    if ($DryRun) {
        Write-Host "  [DryRun] Would ensure OU exists: $dn" -ForegroundColor DarkGray
        return $dn
    }
    try {
        Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop | Out-Null
    } catch {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false | Out-Null
    }
    return $dn
}

function New-GroupIfMissing {
    param([string]$Name, [string]$Path, [string]$Category, [string]$Description, [switch]$DryRun)
    if ($DryRun) {
        Write-Host "  [DryRun] Would ensure group exists: $Name" -ForegroundColor DarkGray
        return
    }
    try {
        Get-ADGroup -Identity $Name -ErrorAction Stop | Out-Null
    } catch {
        New-ADGroup -Name $Name -Path $Path -GroupScope Global -GroupCategory $Category -Description $Description | Out-Null
    }
}

function Get-MisconfigSample {
    param([array]$Eligible, [hashtable]$Cfg)
    $n = Get-MisconfigCount -PoolSize $Eligible.Count -Pct $Cfg.Pct -Min $Cfg.Min -Max $Cfg.Max
    if ($n -le 0) { return @() }
    return @(Get-Random -InputObject $Eligible -Count $n)
}

function Add-LabMisconfigurations {
    param(
        [array]$Users,
        [object]$Domain,
        [string]$DomainDN,
        [string]$DnsRoot,
        [string]$CompanyOU,
        [hashtable]$Config,
        [string[]]$WeakPasswordList,
        [string[]]$DepartmentSecurityGroups,
        [switch]$DryRun
    )

    $answerKey = [System.Collections.Generic.List[object]]::new()
    $passwordOverrides = @{}
    $eligible = @($Users | Where-Object { -not $_.IsCEO })

    function Set-LabWeakPassword {
        param([string]$Sam)
        $weakPwd = Get-Random -InputObject $WeakPasswordList
        Set-ADAccountPassword -Identity $Sam -Reset -NewPassword (ConvertTo-SecureString $weakPwd -AsPlainText -Force) -ErrorAction SilentlyContinue
        $passwordOverrides[$Sam] = $weakPwd
        return $weakPwd
    }

    $cfg = $Config.WeakPassword
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            if ($DryRun) { Write-Host "  [DryRun] Would set a weak password on $($u.Sam)" -ForegroundColor DarkGray; continue }
            $weakPwd = Set-LabWeakPassword -Sam $u.Sam
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'WeakPassword'; Severity = $cfg.Severity; Details = "Password reset to weak value: $weakPwd"; SuggestedFix = 'Reset to a strong, unique password.' })
        }
    }

    $cfg = $Config.PasswordNotRequired
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            if ($DryRun) { Write-Host "  [DryRun] Would set PASSWD_NOTREQD on $($u.Sam)" -ForegroundColor DarkGray; continue }
            Set-ADUser -Identity $u.Sam -PasswordNotRequired $true -ErrorAction SilentlyContinue
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'PasswordNotRequired'; Severity = $cfg.Severity; Details = 'PASSWD_NOTREQD flag enabled'; SuggestedFix = 'Clear PasswordNotRequired and enforce a strong password.' })
        }
    }

    $cfg = $Config.ASREPRoastable
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            if ($DryRun) { Write-Host "  [DryRun] Would disable Kerberos pre-auth on $($u.Sam)" -ForegroundColor DarkGray; continue }
            Set-ADAccountControl -Identity $u.Sam -DoesNotRequirePreAuth $true -ErrorAction SilentlyContinue
            $weakPwd = Set-LabWeakPassword -Sam $u.Sam
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'ASREPRoastable'; Severity = $cfg.Severity; Details = "Kerberos pre-auth disabled; password reset to weak value: $weakPwd"; SuggestedFix = 'Re-enable Kerberos pre-authentication and reset the password.' })
        }
    }

    $cfg = $Config.Kerberoastable
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            $spn = "HTTP/svc-$($u.Sam).$DnsRoot"
            if ($DryRun) { Write-Host "  [DryRun] Would add SPN '$spn' to $($u.Sam)" -ForegroundColor DarkGray; continue }
            Set-ADUser -Identity $u.Sam -ServicePrincipalNames @{Add = $spn} -ErrorAction SilentlyContinue
            $weakPwd = Set-LabWeakPassword -Sam $u.Sam
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'Kerberoastable'; Severity = $cfg.Severity; Details = "Fake SPN '$spn' set on a standard user; password reset to weak value: $weakPwd"; SuggestedFix = 'Remove the SPN (it belongs on a service account, not a user) and reset the password.' })
        }
    }

    $cfg = $Config.RestrictedWorkstation
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            $deptLetters = ($u.Department -replace '[^A-Za-z]', '')
            $deptAbbrev = $deptLetters.Substring(0, [Math]::Min(3, $deptLetters.Length)).ToUpper()
            $fakeHost = "{0}-WKS-{1:D2}" -f $deptAbbrev, (Get-Random -Minimum 1 -Maximum 99)
            if ($DryRun) { Write-Host "  [DryRun] Would restrict $($u.Sam) to logon workstation '$fakeHost'" -ForegroundColor DarkGray; continue }
            Set-ADUser -Identity $u.Sam -LogonWorkstations $fakeHost -ErrorAction SilentlyContinue
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'RestrictedWorkstation'; Severity = $cfg.Severity; Details = "Logon restricted to '$fakeHost' only"; SuggestedFix = 'Confirm the correct machine name with the user, or clear LogonWorkstations if the restriction is not needed.' })
        }
    }

    $cfg = $Config.PasswordInDescription
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            if ($DryRun) { Write-Host "  [DryRun] Would put a plaintext password in the Description of $($u.Sam)" -ForegroundColor DarkGray; continue }
            $weakPwd = Set-LabWeakPassword -Sam $u.Sam
            $desc = "New hire - temp pwd $weakPwd - change at first logon"
            Set-ADUser -Identity $u.Sam -Description $desc -ErrorAction SilentlyContinue
            $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'PasswordInDescription'; Severity = $cfg.Severity; Details = "Description field reads: '$desc'"; SuggestedFix = 'Remove the password from the description and reset the credential.' })
        }
    }

    $cfg = $Config.StaleTerminatedAccount
    if ($cfg.Enabled) {
        $sample = Get-MisconfigSample -Eligible $eligible -Cfg $cfg
        if ($sample.Count -gt 0) {
            $disabledOU = New-OUIfMissing -Name 'Disabled Accounts' -Path $CompanyOU -DryRun:$DryRun
            foreach ($u in $sample) {
                $termDate = (Get-Date).AddDays(-(Get-Random -Minimum 10 -Maximum 90)).ToString('yyyy-MM-dd')
                if ($DryRun) { Write-Host "  [DryRun] Would mark $($u.Sam) as terminated $termDate but leave it enabled" -ForegroundColor DarkGray; continue }
                Set-ADUser -Identity $u.Sam -Description "Terminated $termDate - pending offboarding" -ErrorAction SilentlyContinue
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'StaleTerminatedAccount'; Severity = $cfg.Severity; Details = "Description says terminated $termDate, but the account is still Enabled"; SuggestedFix = "Disable the account and move it to the 'Disabled Accounts' OU." })
            }
        }
    }

    $cfg = $Config.MisplacedOU
    if ($cfg.Enabled) {
        foreach ($u in (Get-MisconfigSample -Eligible $eligible -Cfg $cfg)) {
            if ($DryRun) { Write-Host "  [DryRun] Would move $($u.Sam) into the default Users container" -ForegroundColor DarkGray; continue }
            try {
                Move-ADObject -Identity $u.DN -TargetPath "CN=Users,$DomainDN" -ErrorAction Stop
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'MisplacedOU'; Severity = $cfg.Severity; Details = 'Account is sitting in the default Users container instead of its department OU'; SuggestedFix = 'Move the account back into its correct department OU so department GPOs apply.' })
            } catch {
                Write-Warning "Could not move $($u.Sam) to the default container: $($_.Exception.Message)"
            }
        }
    }

    $cfg = $Config.RoguePrivilegedAccess
    if ($cfg.Enabled -and $Users.Count -ge $cfg.MinTotalUsers) {
        $pool = @($eligible | Where-Object { $_.Department -notin @('IT','Executive') })
        if ($pool.Count -eq 0) { $pool = $eligible }
        if ($pool.Count -gt 0) {
            $target = Get-Random -InputObject $pool
            if ($DryRun) {
                Write-Host "  [DryRun] Would add $($target.Sam) to Domain Admins" -ForegroundColor DarkGray
            } else {
                try {
                    $daGroup = Get-ADGroup -Identity "$($Domain.DomainSID.Value)-512" -ErrorAction Stop
                    Add-ADGroupMember -Identity $daGroup -Members $target.Sam -ErrorAction Stop
                    $answerKey.Add([pscustomobject]@{ Username = $target.Sam; Department = $target.Department; Category = 'RoguePrivilegedAccess'; Severity = $cfg.Severity; Details = 'Standard employee account was made a member of Domain Admins'; SuggestedFix = 'Remove the account from Domain Admins immediately.' })
                } catch {
                    Write-Warning "Could not add $($target.Sam) to Domain Admins: $($_.Exception.Message)"
                }
            }
        }
    }

    $cfg = $Config.DangerousACL
    if ($cfg.Enabled -and $Users.Count -ge $cfg.MinTotalUsers) {
        $victimPool = @($eligible | Where-Object { $_.Department -in @('IT','Executive') })
        if ($victimPool.Count -eq 0) { $victimPool = $eligible }
        $victim = Get-Random -InputObject $victimPool
        $attackerPool = @($eligible | Where-Object { $_.Sam -ne $victim.Sam })
        if ($attackerPool.Count -gt 0) {
            $attacker = Get-Random -InputObject $attackerPool
            if ($DryRun) {
                Write-Host "  [DryRun] Would grant $($attacker.Sam) GenericAll over $($victim.Sam)" -ForegroundColor DarkGray
            } else {
                try {
                    $victimObj = Get-ADUser -Identity $victim.Sam -ErrorAction Stop
                    $attackerObj = Get-ADUser -Identity $attacker.Sam -Properties SID -ErrorAction Stop
                    $acl = Get-Acl -Path "AD:\$($victimObj.DistinguishedName)"
                    $sid = [System.Security.Principal.SecurityIdentifier]$attackerObj.SID
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    )
                    $acl.AddAccessRule($ace)
                    Set-Acl -Path "AD:\$($victimObj.DistinguishedName)" -AclObject $acl
                    $answerKey.Add([pscustomobject]@{ Username = $victim.Sam; Department = $victim.Department; Category = 'DangerousACL'; Severity = $cfg.Severity; Details = "$($attacker.Sam) holds GenericAll over this account (can reset its password, add SPNs, etc.) - a classic BloodHound attack-path edge"; SuggestedFix = "Remove the ACE granting $($attacker.Sam) GenericAll over this object." })
                } catch {
                    Write-Warning "Could not grant a dangerous ACL for the DangerousACL scenario: $($_.Exception.Message)"
                }
            }
        }
    }

    $cfg = $Config.WeakPasswordPolicy
    if ($cfg.Enabled -and $Users.Count -ge $cfg.MinTotalUsers -and $DepartmentSecurityGroups.Count -gt 0) {
        $targetGroup = Get-Random -InputObject $DepartmentSecurityGroups
        $psoName = 'Legacy Compatibility Policy'
        if ($DryRun) {
            Write-Host "  [DryRun] Would create weak Fine-Grained Password Policy '$psoName' applied to $targetGroup" -ForegroundColor DarkGray
        } else {
            try {
                New-ADFineGrainedPasswordPolicy -Name $psoName -Precedence 10 -MinPasswordLength 4 -ComplexityEnabled $false `
                    -LockoutThreshold 0 -PasswordHistoryCount 0 -ReversibleEncryptionEnabled $false -MinPasswordAge '0.00:00:00' `
                    -MaxPasswordAge '0.00:00:00' -ErrorAction Stop
                Add-ADFineGrainedPasswordPolicySubject -Identity $psoName -Subjects $targetGroup -ErrorAction Stop
                $answerKey.Add([pscustomobject]@{ Username = '(N/A - PSO)'; Department = $targetGroup; Category = 'WeakPasswordPolicy'; Severity = $cfg.Severity; Details = "Fine-Grained Password Policy '$psoName' (min length 4, no complexity, no lockout, passwords never expire) applies to $targetGroup"; SuggestedFix = "Remove or correct the '$psoName' PSO so this group falls back to the domain default policy." })
            } catch {
                Write-Warning "Could not create the WeakPasswordPolicy scenario (needs a 2008+ domain functional level): $($_.Exception.Message)"
            }
        }
    }

    $cfg = $Config.GPPCPassword
    if ($cfg.Enabled -and $Users.Count -ge $cfg.MinTotalUsers) {
        if ($DryRun) {
            Write-Host "  [DryRun] Would create a GPO with a Group Policy Preference drive mapping containing a decryptable cpassword" -ForegroundColor DarkGray
        } elseif (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Warning "GroupPolicy module isn't available here - skipping the GPPCPassword scenario. Run this script on/near a DC with GPMC installed to include it."
        } else {
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                $gpoName = 'Legacy Drive Mapping Policy'
                $gpo = New-GPO -Name $gpoName -Comment 'Maps a shared drive for all employees' -ErrorAction Stop
                New-GPLink -Guid $gpo.Id -Target $CompanyOU -ErrorAction Stop | Out-Null

                $gppPassword = Get-Random -InputObject $WeakPasswordList
                $encryptedCpassword = ConvertTo-GPPCPassword -PlainText $gppPassword

                $prefsPath = "\\$DnsRoot\SYSVOL\$DnsRoot\Policies\{$($gpo.Id)}\User\Preferences\Drives"
                New-Item -Path $prefsPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

                $driveGuid = [guid]::NewGuid().ToString('B').ToUpper()
                $changed = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $drivesXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="Z:" status="Z:" image="2" changed="$changed" uid="$driveGuid">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="$DnsRoot\svc-fileshare" cpassword="$encryptedCpassword" path="\\fileserver01\shared" label="Shared Drive" persistent="1" useLetter="1" letter="Z"/>
  </Drive>
</Drives>
"@
                Set-Content -Path (Join-Path $prefsPath 'Drives.xml') -Value $drivesXml -Encoding UTF8 -ErrorAction Stop

                $answerKey.Add([pscustomobject]@{ Username = 'svc-fileshare'; Department = '(GPO)'; Category = 'GPPCPassword'; Severity = $cfg.Severity; Details = "GPO '$gpoName' linked at the company OU maps drive Z: using account 'svc-fileshare' with a Group Policy Preferences cpassword - decryptable with the public MS14-025 AES key (e.g. Get-GPPPassword)"; SuggestedFix = "Delete the '$gpoName' GPO (or its Drives.xml), rotate svc-fileshare's password, and confirm MS14-025 (KB2962486) is applied so GPP passwords can't be set going forward." })
            } catch {
                Write-Warning "Could not create the GPPCPassword scenario: $($_.Exception.Message)"
            }
        }
    }

    return [pscustomobject]@{ AnswerKey = $answerKey; PasswordOverrides = $passwordOverrides }
}

# ================================= START ====================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "The ActiveDirectory PowerShell module isn't available. Run this on a domain controller or a machine with RSAT AD tools installed, joined to the target domain."
    return
}

try {
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Error "Couldn't reach a domain. Make sure you're running this on a domain-joined machine with connectivity to a domain controller."
    return
}
$domainDN = $domain.DistinguishedName
$dnsRoot  = $domain.DNSRoot

if ($DryRun) {
    Write-Host "==================== DRY RUN - no AD objects will be created or modified ====================" -ForegroundColor Yellow
}

$template = $script:CompanyTemplates[$CompanyTemplate]
$CompanyName = $template.CompanyName
$Offices     = $template.Offices
$Departments = $template.Departments
Write-Host "Company template: $CompanyName ($CompanyTemplate)" -ForegroundColor Cyan

if (-not $Offline -and -not $PSBoundParameters.ContainsKey('MockarooApiKey') -and -not [string]::IsNullOrWhiteSpace($MockarooApiKeyDefault)) {
    $MockarooApiKey = $MockarooApiKeyDefault
}
if (-not $Offline -and [string]::IsNullOrWhiteSpace($MockarooApiKey)) {
    $MockarooApiKey = Read-Host "Enter your Mockaroo API key (get a free one at mockaroo.com, or Ctrl+C and re-run with -Offline)"
}
if (-not $Offline -and [string]::IsNullOrWhiteSpace($MockarooApiKey)) {
    Write-Error "A Mockaroo API key is required (or pass -Offline)."
    return
}

if ($PSBoundParameters.ContainsKey('UserCount')) {
    $userCount = $UserCount
} else {
    [int]$userCount = 0
    do {
        $inputVal = Read-Host "How many users do you want? (1-1000)"
    } until ([int]::TryParse($inputVal, [ref]$userCount) -and $userCount -gt 0 -and $userCount -le 1000)
}

if ($AddMisconfigurations) {
    $addMisconfigs = $true
} elseif ($SkipMisconfigurations) {
    $addMisconfigs = $false
} else {
    do {
        $mcInput = Read-Host "Add Misconfigurations? (true/false)"
    } until ($mcInput -match '^(?i:true|false|t|f|y|n|yes|no)$')
    $addMisconfigs = $mcInput -match '^(?i:true|t|y|yes)$'
}

if ($PSBoundParameters.ContainsKey('SharedPassword')) {
    $useRandomPasswords = $false
    $meetsComplexity = $SharedPassword.Length -ge 8 -and $SharedPassword -cmatch '[A-Z]' -and $SharedPassword -match '\d' -and $SharedPassword -match '[^a-zA-Z0-9]'
    if (-not $meetsComplexity) {
        Write-Error "SharedPassword must be at least 8 characters and include an uppercase letter, a number, and a special character."
        return
    }
    $sharedPassword = $SharedPassword
} elseif ($UseRandomPasswords) {
    $useRandomPasswords = $true
    $sharedPassword = $null
} else {
    do {
        $pwModeInput = Read-Host "Would you like random passwords? (Y/N)"
    } until ($pwModeInput -match '^(?i:y|n|yes|no)$')
    $useRandomPasswords = $pwModeInput -match '^(?i:y|yes)$'

    $sharedPassword = $null
    if (-not $useRandomPasswords) {
        do {
            $sharedPassword = Read-Host "Enter the password to use for every user"
            $meetsComplexity = $sharedPassword.Length -ge 8 -and $sharedPassword -cmatch '[A-Z]' -and $sharedPassword -match '\d' -and $sharedPassword -match '[^a-zA-Z0-9]'
            if (-not $meetsComplexity) {
                Write-Warning "Password must be at least 8 characters and include an uppercase letter, a number, and a special character."
            }
        } until ($meetsComplexity)
    }
}

if ($Offline) {
    Write-Host "Generating $userCount identities locally (-Offline, no Mockaroo call)..." -ForegroundColor Cyan
    $mockData = Get-OfflineIdentityRecords -Count $userCount -Offices $Offices
} else {
    Write-Host "Requesting $userCount randomly generated identities from Mockaroo..." -ForegroundColor Cyan
    try {
        $mockData = Get-MockarooRecords -ApiKey $MockarooApiKey -Count $userCount
    } catch {
        Write-Warning "Mockaroo request failed ($($_.Exception.Message)) - falling back to locally generated identities."
        $mockData = Get-OfflineIdentityRecords -Count $userCount -Offices $Offices
    }
}
if ($mockData.Count -lt $userCount) {
    Write-Warning "Only got $($mockData.Count) identity record(s) instead of $userCount. Continuing with what was returned."
    $userCount = $mockData.Count
}

Write-Host "Building OU and group scaffold for '$CompanyName'..." -ForegroundColor Cyan

$companyOU     = New-OUIfMissing -Name $CompanyName -Path $domainDN -DryRun:$DryRun
$employeesOU   = New-OUIfMissing -Name 'Employees' -Path $companyOU -DryRun:$DryRun
$groupsOU      = New-OUIfMissing -Name 'Groups' -Path $companyOU -DryRun:$DryRun
$secGroupsOU   = New-OUIfMissing -Name 'Security Groups' -Path $groupsOU -DryRun:$DryRun
$distGroupsOU  = New-OUIfMissing -Name 'Distribution Groups' -Path $groupsOU -DryRun:$DryRun

foreach ($d in $Departments) {
    $d.OUPath = New-OUIfMissing -Name $d.DisplayName -Path $employeesOU -DryRun:$DryRun
    New-GroupIfMissing -Name "SG-$($d.Key)" -Path $secGroupsOU -Category Security -Description "Security group for the $($d.DisplayName) department" -DryRun:$DryRun
    New-GroupIfMissing -Name "DL-$($d.Key)" -Path $distGroupsOU -Category Distribution -Description "Distribution list for the $($d.DisplayName) department" -DryRun:$DryRun
}
New-GroupIfMissing -Name 'SG-Managers'            -Path $secGroupsOU  -Category Security     -Description 'All people managers and executives' -DryRun:$DryRun
New-GroupIfMissing -Name 'SG-VPN-Users'           -Path $secGroupsOU  -Category Security     -Description 'Users granted remote VPN access' -DryRun:$DryRun
New-GroupIfMissing -Name 'SG-RemoteDesktop-Users' -Path $secGroupsOU  -Category Security     -Description 'Users granted RDP access to workstations' -DryRun:$DryRun
New-GroupIfMissing -Name 'DL-AllEmployees'        -Path $distGroupsOU -Category Distribution -Description 'Company-wide distribution list' -DryRun:$DryRun
New-GroupIfMissing -Name 'DL-Managers'            -Path $distGroupsOU -Category Distribution -Description 'All people managers and executives' -DryRun:$DryRun
New-GroupIfMissing -Name 'DL-Executives'          -Path $distGroupsOU -Category Distribution -Description 'Executive leadership team' -DryRun:$DryRun

Write-Host "Allocating $userCount users across departments..." -ForegroundColor Cyan
$allocation = Get-DepartmentAllocation -TotalUsers $userCount -Departments $Departments

$existingSams = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName), [System.StringComparer]::OrdinalIgnoreCase)

$recordIndex = 0
$employeeIdCounter = 10001
$credentialReport = [System.Collections.Generic.List[object]]::new()

foreach ($d in $Departments) {
    $count = [int]$allocation[$d.Key]
    $d.CreatedUsers = [System.Collections.Generic.List[object]]::new()
    if ($count -le 0) { continue }

    Write-Host "  Creating $count user(s) in $($d.DisplayName)..." -ForegroundColor DarkCyan

    for ($i = 0; $i -lt $count; $i++) {
        $rec = $mockData[$recordIndex]
        $recordIndex++
        Write-Progress -Activity "Creating AD users" -Status "$($d.DisplayName): $($rec.first_name) $($rec.last_name) ($recordIndex of $userCount)" -PercentComplete ([math]::Min(100, [math]::Round(($recordIndex / [math]::Max(1,$userCount)) * 100)))

        $first = $rec.first_name
        $last  = $rec.last_name
        $sam   = Get-UniqueSamAccountName -First $first -Last $last -Existing $existingSams
        $upn   = "$sam@$dnsRoot"
        $office = Get-WeightedOffice -Offices $Offices
        $officePhone = "{0}-555-{1:D4}" -f $office.AreaCode, (Get-Random -Minimum 0 -Maximum 9999)

        if ($d.IsExecutive) {
            $title = $d.ExecTitles[$i]
        } elseif ($i -eq 0 -and $count -ge 2) {
            $title = $d.LeadTitle
        } else {
            $title = $d.ICTitles | Get-Random
        }

        $password = if ($useRandomPasswords) { New-RandomPassword } else { $sharedPassword }

        $userDN = $null
        if ($DryRun) {
            Write-Host "    [DryRun] Would create $sam ($first $last, $title)" -ForegroundColor DarkGray
            $userDN = "CN=$first $last,$($d.OUPath)"
        } else {
            $securePw = ConvertTo-SecureString $password -AsPlainText -Force
            $newUserParams = @{
                Name                  = "$first $last"
                GivenName             = $first
                Surname               = $last
                DisplayName           = "$first $last"
                SamAccountName        = $sam
                UserPrincipalName     = $upn
                EmailAddress          = $upn
                Title                 = $title
                Department            = $d.DisplayName
                Company               = $CompanyName
                Office                = $office.Name
                OfficePhone           = $officePhone
                MobilePhone           = $rec.mobile_phone
                StreetAddress         = $rec.street_address
                City                  = $rec.city
                State                 = $rec.state_abbr
                PostalCode            = $rec.postal_code
                Country               = 'US'
                Description           = "$title - $($d.DisplayName)"
                Path                  = $d.OUPath
                AccountPassword       = $securePw
                Enabled               = $true
                ChangePasswordAtLogon = $false
                PasswordNeverExpires  = $true
                OtherAttributes       = @{ employeeID = [string]$employeeIdCounter }
            }
            try {
                New-ADUser @newUserParams -ErrorAction Stop
            } catch {
                Write-Warning "Failed to create user '$sam': $($_.Exception.Message)"
                continue
            }
            $userDN = (Get-ADUser -Identity $sam).DistinguishedName
        }

        $employeeIdCounter++

        $isLeadOrExec = $d.IsExecutive -or ($i -eq 0 -and $count -ge 2)
        $d.CreatedUsers.Add([pscustomobject]@{
            Sam        = $sam
            DN         = $userDN
            Department = $d.DisplayName
            Title      = $title
            IsLead     = $isLeadOrExec
            IsCEO      = ($d.IsExecutive -and $i -eq 0)
        })

        $credentialReport.Add([pscustomobject]@{
            Username   = $sam
            Password   = $password
            FirstName  = $first
            LastName   = $last
            Department = $d.DisplayName
            Title      = $title
            Email      = $upn
            Office     = $office.Name
        })
    }
}
Write-Progress -Activity "Creating AD users" -Completed

Write-Host "Wiring up manager hierarchy..." -ForegroundColor Cyan

$execDept = $Departments | Where-Object { $_.IsExecutive }
$ceo = $null
if ($execDept -and $execDept.CreatedUsers.Count -gt 0) {
    $ceo = $execDept.CreatedUsers | Where-Object { $_.IsCEO } | Select-Object -First 1
}

foreach ($d in $Departments) {
    if ($d.CreatedUsers.Count -eq 0) { continue }

    if ($d.IsExecutive) {
        if ($ceo) {
            foreach ($u in $d.CreatedUsers) {
                if ($u.Sam -ne $ceo.Sam) {
                    if ($DryRun) { Write-Host "  [DryRun] Would set $($u.Sam)'s manager to $($ceo.Sam)" -ForegroundColor DarkGray }
                    else { Set-ADUser -Identity $u.Sam -Manager $ceo.DN -ErrorAction SilentlyContinue }
                }
            }
        }
        continue
    }

    $lead = $d.CreatedUsers[0]
    if ($d.CreatedUsers.Count -ge 2) {
        foreach ($u in $d.CreatedUsers | Select-Object -Skip 1) {
            if ($DryRun) { Write-Host "  [DryRun] Would set $($u.Sam)'s manager to $($lead.Sam)" -ForegroundColor DarkGray }
            else { Set-ADUser -Identity $u.Sam -Manager $lead.DN -ErrorAction SilentlyContinue }
        }
    }
    if ($ceo) {
        if ($DryRun) { Write-Host "  [DryRun] Would set $($lead.Sam)'s manager to $($ceo.Sam)" -ForegroundColor DarkGray }
        else { Set-ADUser -Identity $lead.Sam -Manager $ceo.DN -ErrorAction SilentlyContinue }
    }
}

Write-Host "Populating security and distribution groups..." -ForegroundColor Cyan

$allSams = @()
$managerSams = @()
$departmentSecurityGroups = @()

foreach ($d in $Departments) {
    if ($d.CreatedUsers.Count -eq 0) { continue }
    $sams = $d.CreatedUsers | ForEach-Object { $_.Sam }
    $departmentSecurityGroups += "SG-$($d.Key)"
    if ($DryRun) {
        Write-Host "  [DryRun] Would add $($sams.Count) user(s) to SG-$($d.Key) and DL-$($d.Key)" -ForegroundColor DarkGray
    } else {
        Add-ADGroupMember -Identity "SG-$($d.Key)" -Members $sams -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "DL-$($d.Key)" -Members $sams -ErrorAction SilentlyContinue
    }
    $allSams += $sams

    $leads = $d.CreatedUsers | Where-Object { $_.IsLead } | ForEach-Object { $_.Sam }
    $managerSams += $leads

    if ($d.IsExecutive) {
        if ($DryRun) { Write-Host "  [DryRun] Would add $($sams.Count) user(s) to DL-Executives" -ForegroundColor DarkGray }
        else { Add-ADGroupMember -Identity 'DL-Executives' -Members $sams -ErrorAction SilentlyContinue }
    }
}

if ($allSams.Count -gt 0) {
    if ($DryRun) { Write-Host "  [DryRun] Would add $($allSams.Count) user(s) to DL-AllEmployees" -ForegroundColor DarkGray }
    else { Add-ADGroupMember -Identity 'DL-AllEmployees' -Members $allSams -ErrorAction SilentlyContinue }
}
if ($managerSams.Count -gt 0) {
    if ($DryRun) { Write-Host "  [DryRun] Would add $($managerSams.Count) manager(s) to SG-Managers and DL-Managers" -ForegroundColor DarkGray }
    else {
        Add-ADGroupMember -Identity 'SG-Managers' -Members $managerSams -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity 'DL-Managers' -Members $managerSams -ErrorAction SilentlyContinue
    }
}
if ($allSams.Count -gt 0) {
    $vpnUsers = Get-Random -InputObject $allSams -Count ([Math]::Max(1, [Math]::Ceiling($allSams.Count * 0.4)))
    $rdpUsers = Get-Random -InputObject $allSams -Count ([Math]::Max(1, [Math]::Ceiling($allSams.Count * 0.25)))
    if ($DryRun) {
        Write-Host "  [DryRun] Would add $($vpnUsers.Count) user(s) to SG-VPN-Users" -ForegroundColor DarkGray
        Write-Host "  [DryRun] Would add $($rdpUsers.Count) user(s) to SG-RemoteDesktop-Users" -ForegroundColor DarkGray
    } else {
        Add-ADGroupMember -Identity 'SG-VPN-Users' -Members $vpnUsers -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity 'SG-RemoteDesktop-Users' -Members $rdpUsers -ErrorAction SilentlyContinue
    }
}

$misconfigResult = $null
if ($addMisconfigs) {
    Write-Host "Injecting intentional misconfigurations for training..." -ForegroundColor Magenta
    $allUsersDetailed = @($Departments | ForEach-Object { $_.CreatedUsers })
    $misconfigResult = Add-LabMisconfigurations -Users $allUsersDetailed -Domain $domain -DomainDN $domainDN -DnsRoot $dnsRoot -CompanyOU $companyOU -Config $MisconfigTypes -WeakPasswordList $WeakPasswords -DepartmentSecurityGroups $departmentSecurityGroups -DryRun:$DryRun

    foreach ($entry in $misconfigResult.PasswordOverrides.GetEnumerator()) {
        $row = $credentialReport | Where-Object { $_.Username -eq $entry.Key }
        if ($row) { $row.Password = $entry.Value }
    }

    if (-not $DryRun) {
        $misconfigResult.AnswerKey | Export-Csv -Path $AnswerKeyPath -NoTypeInformation
    }
}

if (-not $DryRun) {
    $credentialReport | Export-Csv -Path $CredentialReportPath -NoTypeInformation
}

Write-Host ""
if ($DryRun) {
    Write-Host "Dry run complete. Would have created $($allSams.Count) user(s) across $((@($Departments | Where-Object { $_.CreatedUsers.Count -gt 0 })).Count) departments. Nothing was written to Active Directory." -ForegroundColor Yellow
} else {
    Write-Host "Done. Created $($allSams.Count) user(s) across $((@($Departments | Where-Object { $_.CreatedUsers.Count -gt 0 })).Count) departments." -ForegroundColor Green
}
foreach ($d in $Departments) {
    if ($d.CreatedUsers.Count -gt 0) {
        Write-Host ("  {0,-20} {1}" -f $d.DisplayName, $d.CreatedUsers.Count)
    }
}

if (-not $DryRun) {
    Write-Host ""
    Write-Host "Credentials (plaintext) for every generated account were written to:" -ForegroundColor Yellow
    Write-Host "  $CredentialReportPath" -ForegroundColor Yellow
    Write-Host "This file is for lab use only - move it somewhere safe or delete it once you're done training." -ForegroundColor Yellow

    if ($addMisconfigs -and $misconfigResult) {
        Write-Host ""
        Write-Host "Injected $($misconfigResult.AnswerKey.Count) intentional misconfiguration(s) across $((@($misconfigResult.AnswerKey | Select-Object -ExpandProperty Username -Unique)).Count) account(s)/object(s)." -ForegroundColor Magenta
        Write-Host "DO NOT open the answer key until you're ready to grade / check your work:" -ForegroundColor Red
        Write-Host "  $AnswerKeyPath" -ForegroundColor Red
        if ($misconfigResult.AnswerKey | Where-Object { $_.Category -eq 'RoguePrivilegedAccess' }) {
            Write-Host "  NOTE: one account was added to Domain Admins as part of this exercise - make sure it gets removed once found." -ForegroundColor Red
        }
        if ($misconfigResult.AnswerKey | Where-Object { $_.Category -eq 'GPPCPassword' }) {
            Write-Host "  NOTE: a GPO with a decryptable Group Policy Preferences password was created - make sure it gets found and removed." -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "When you're ready to check your own findings, run:" -ForegroundColor Cyan
    Write-Host "  .\Find-ADLabMisconfigurations.ps1 -CompanyName '$CompanyName'" -ForegroundColor Cyan
    Write-Host "To tear this lab down and start over, run:" -ForegroundColor Cyan
    Write-Host "  .\Remove-ADLabUsers.ps1 -CompanyName '$CompanyName'" -ForegroundColor Cyan
}
