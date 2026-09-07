<#
    Find-ADLabMisconfigurations.ps1

    An independent AD misconfiguration auditor for the lab New-ADLabUsers.ps1
    builds. It does NOT read the generator's answer key - it inspects live
    AD state the same way a real security review would (LDAP filters, ACL
    reads, SYSVOL scans, an optional safe password spray) and produces its
    own findings. That makes it useful two ways:

      1. As practice: run it AFTER you've done your own manual review, and
         diff its findings against what you found by hand.
      2. As grading: an instructor can pass -CompareTo pointing at the
         generator's ADLabMisconfigurations_ANSWERKEY_*.csv to get a
         precision/recall scorecard.

    Findings are written to ADLabFindings_<timestamp>.csv and summarized on
    the console.

    SAFETY: password-spraying (-TestWeakPasswords) is OFF by default. It
    only runs against accounts inside the target company OU, and it
    auto-caps attempts per account to the domain's lockout threshold minus
    one so it can't lock anyone out - but you still shouldn't point this at
    anything but a lab/training domain.
#>

[CmdletBinding()]
param(
    [string]$CompanyName = 'Nimbus Software Solutions',
    [string]$OutputPath,
    [string]$CompareTo,
    [switch]$TestWeakPasswords,
    [string[]]$PasswordCandidates = @('Password1','Welcome1!','Summer2026!','ChangeMe1!','Company123!'),
    [switch]$SkipACLScan
)

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
$companyDN = "OU=$CompanyName,$domainDN"

try {
    Get-ADOrganizationalUnit -Identity $companyDN -ErrorAction Stop | Out-Null
} catch {
    Write-Error "No OU found at '$companyDN'. Pass -CompanyName if you used a different company template (e.g. 'Summit Retail Group', 'Harbor Logistics Co')."
    return
}

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath ("ADLabFindings_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Username, [string]$Department, [string]$Category, [string]$Severity, [string]$Details)
    $findings.Add([pscustomobject]@{ Username = $Username; Department = $Department; Category = $Category; Severity = $Severity; Details = $Details })
}

Write-Host "Auditing '$CompanyName' ($companyDN)..." -ForegroundColor Cyan

# --- Per-account LDAP-detectable flags -------------------------------------

Write-Host "  Checking PASSWD_NOTREQD..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase $companyDN -Filter {PasswordNotRequired -eq $true} -Properties Department -ErrorAction SilentlyContinue |
    ForEach-Object { Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'PasswordNotRequired' -Severity 'High' -Details 'PASSWD_NOTREQD flag is set on this account.' }

Write-Host "  Checking for AS-REP roastable accounts..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase $companyDN -Filter {DoesNotRequirePreAuth -eq $true} -Properties Department -ErrorAction SilentlyContinue |
    ForEach-Object { Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'ASREPRoastable' -Severity 'High' -Details 'Kerberos pre-authentication is disabled (AS-REP roastable).' }

Write-Host "  Checking for Kerberoastable accounts (SPN on a user object)..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase $companyDN -Filter {ServicePrincipalName -like '*'} -Properties Department, ServicePrincipalName -ErrorAction SilentlyContinue |
    ForEach-Object { Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'Kerberoastable' -Severity 'High' -Details "SPN(s) set on a standard user account: $($_.ServicePrincipalName -join ', ')" }

Write-Host "  Checking for restricted logon workstations..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase $companyDN -Filter {LogonWorkstations -like '*'} -Properties Department, LogonWorkstations -ErrorAction SilentlyContinue |
    ForEach-Object { Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'RestrictedWorkstation' -Severity 'Low' -Details "LogonWorkstations is set to: $($_.LogonWorkstations)" }

Write-Host "  Checking Description fields for passwords or termination notes..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase $companyDN -Filter * -Properties Description, Department, Enabled -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Description -match '(?i)pass(word)?|pwd') {
        Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'PasswordInDescription' -Severity 'Medium' -Details "Description: '$($_.Description)'"
    }
    if ($_.Enabled -and $_.Description -match '(?i)terminat') {
        Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'StaleTerminatedAccount' -Severity 'Medium' -Details "Account is enabled but Description says: '$($_.Description)'"
    }
}

Write-Host "  Checking for accounts sitting in the default Users container..." -ForegroundColor DarkCyan
Get-ADUser -SearchBase "CN=Users,$domainDN" -Filter "Company -eq '$CompanyName'" -Properties Company, Department -ErrorAction SilentlyContinue |
    ForEach-Object { Add-Finding -Username $_.SamAccountName -Department $_.Department -Category 'MisplacedOU' -Severity 'Low' -Details 'Account belongs to this company but is sitting in the default Users container instead of its department OU.' }

# --- Group / privilege checks ------------------------------------------------

Write-Host "  Checking Domain Admins for employee accounts..." -ForegroundColor DarkCyan
try {
    Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction Stop |
        Where-Object { $_.distinguishedName -like "*,$companyDN" } |
        ForEach-Object {
            $u = Get-ADUser -Identity $_.SamAccountName -Properties Department -ErrorAction SilentlyContinue
            Add-Finding -Username $_.SamAccountName -Department $u.Department -Category 'RoguePrivilegedAccess' -Severity 'Critical' -Details 'This employee account is a member of Domain Admins.'
        }
} catch {
    Write-Warning "Could not enumerate Domain Admins: $($_.Exception.Message)"
}

Write-Host "  Checking for a weak Fine-Grained Password Policy..." -ForegroundColor DarkCyan
Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.MinPasswordLength -lt 8 -or $_.ComplexityEnabled -eq $false -or $_.LockoutThreshold -eq 0) {
        $subjects = (Get-ADFineGrainedPasswordPolicySubject -Identity $_ -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', '
        Add-Finding -Username '(N/A - PSO)' -Department $subjects -Category 'WeakPasswordPolicy' -Severity 'High' -Details "PSO '$($_.Name)': MinPasswordLength=$($_.MinPasswordLength), ComplexityEnabled=$($_.ComplexityEnabled), LockoutThreshold=$($_.LockoutThreshold). Applies to: $subjects"
    }
}

if ($SkipACLScan) {
    Write-Host "  Skipping ACL scan (-SkipACLScan)." -ForegroundColor DarkGray
} else {
    Write-Host "  Scanning ACLs on every account for dangerous grants (this can take a while for large labs)..." -ForegroundColor DarkCyan
    $defaultPrincipals = @(
        'NT AUTHORITY\SYSTEM','NT AUTHORITY\SELF','NT AUTHORITY\Authenticated Users','NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'Everyone','BUILTIN\Administrators','BUILTIN\Account Operators','BUILTIN\Print Operators',
        'BUILTIN\Pre-Windows 2000 Compatible Access','BUILTIN\Windows Authorization Access Group',
        "$($domain.NetBIOSName)\Domain Admins","$($domain.NetBIOSName)\Enterprise Admins","$($domain.NetBIOSName)\Cert Publishers",
        "$($domain.NetBIOSName)\Domain Controllers","$($domain.NetBIOSName)\Read-only Domain Controllers"
    )
    $dangerousRights = [System.DirectoryServices.ActiveDirectoryRights]'GenericAll,WriteDacl,WriteOwner,GenericWrite'

    Get-ADUser -SearchBase $companyDN -Filter * -Properties Department -ErrorAction SilentlyContinue | ForEach-Object {
        $u = $_
        try {
            $acl = Get-Acl -Path "AD:\$($u.DistinguishedName)" -ErrorAction Stop
        } catch { return }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.IdentityReference.Value -in $defaultPrincipals) { continue }
            if (($ace.ActiveDirectoryRights -band $dangerousRights) -eq 0) { continue }
            Add-Finding -Username $u.SamAccountName -Department $u.Department -Category 'DangerousACL' -Severity 'Critical' -Details "'$($ace.IdentityReference.Value)' holds '$($ace.ActiveDirectoryRights)' over this account - check whether that's expected."
        }
    }
}

Write-Host "  Scanning SYSVOL for Group Policy Preferences cpassword values..." -ForegroundColor DarkCyan
$policiesPath = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies"
if (Test-Path -Path $policiesPath -ErrorAction SilentlyContinue) {
    Get-ChildItem -Path $policiesPath -Recurse -Include '*.xml' -ErrorAction SilentlyContinue | ForEach-Object {
        $matches = Select-String -Path $_.FullName -Pattern 'cpassword="([^"]+)"' -ErrorAction SilentlyContinue
        if ($matches) {
            Add-Finding -Username '(GPO file)' -Department '(GPO)' -Category 'GPPCPassword' -Severity 'Critical' -Details "$($_.FullName) contains a Group Policy Preferences cpassword value - decryptable with the public MS14-025 key."
        }
    }
} else {
    Write-Warning "Couldn't reach SYSVOL at $policiesPath - skipping the GPPCPassword check."
}

# --- Optional: safe password spray for the WeakPassword category ------------

if ($TestWeakPasswords) {
    Write-Host "  Password-spraying $($PasswordCandidates.Count) candidate password(s) against accounts in this OU..." -ForegroundColor Magenta
    $lockoutThreshold = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).LockoutThreshold
    $maxAttempts = $PasswordCandidates.Count
    if ($lockoutThreshold -and $lockoutThreshold -gt 0) {
        $maxAttempts = [Math]::Max(0, $lockoutThreshold - 1)
        Write-Warning "Domain lockout threshold is $lockoutThreshold - capping this to $maxAttempts candidate password(s) per account so nobody gets locked out."
    }
    if ($maxAttempts -eq 0) {
        Write-Warning "Lockout threshold leaves no safe attempts - skipping the password spray. Re-run with a domain/OU where lockout is >1, or accept the risk and edit this script."
    } else {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $dnsRoot)
        $sprayList = $PasswordCandidates | Select-Object -First $maxAttempts
        Get-ADUser -SearchBase $companyDN -Filter * -Properties Department -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_
            foreach ($pwd in $sprayList) {
                if ($ctx.ValidateCredentials($u.SamAccountName, $pwd)) {
                    Add-Finding -Username $u.SamAccountName -Department $u.Department -Category 'WeakPassword' -Severity 'Medium' -Details "Account authenticates with a common weak password from the candidate list."
                    break
                }
            }
        }
        $ctx.Dispose()
    }
}

# --- Output -------------------------------------------------------------

$findings | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host ""
Write-Host "Wrote $($findings.Count) finding(s) to:" -ForegroundColor Green
Write-Host "  $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "By category:" -ForegroundColor Cyan
$findings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { Write-Host ("  {0,-24} {1}" -f $_.Name, $_.Count) }

if (-not $TestWeakPasswords) {
    Write-Host ""
    Write-Host "Note: WeakPassword accounts are NOT detectable via LDAP alone and were not checked (pass -TestWeakPasswords to safely spray a small candidate list, or use a real password-auditing tool)." -ForegroundColor DarkGray
}

# --- Optional scoring against the generator's answer key --------------------

if ($CompareTo) {
    if (-not (Test-Path $CompareTo)) {
        Write-Warning "Answer key not found at '$CompareTo' - skipping scoring."
    } else {
        $answerKey = Import-Csv -Path $CompareTo
        $answerSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $answerKey | ForEach-Object { [void]$answerSet.Add("$($_.Username)|$($_.Category)") }
        $foundSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $findings | ForEach-Object { [void]$foundSet.Add("$($_.Username)|$($_.Category)") }

        $truePositives  = @($foundSet | Where-Object { $answerSet.Contains($_) })
        $falseNegatives = @($answerSet | Where-Object { -not $foundSet.Contains($_) })
        $falsePositives = @($foundSet | Where-Object { -not $answerSet.Contains($_) })

        $precision = if (($truePositives.Count + $falsePositives.Count) -gt 0) { $truePositives.Count / ($truePositives.Count + $falsePositives.Count) } else { 0 }
        $recall    = if (($truePositives.Count + $falseNegatives.Count) -gt 0) { $truePositives.Count / ($truePositives.Count + $falseNegatives.Count) } else { 0 }
        $f1        = if (($precision + $recall) -gt 0) { 2 * $precision * $recall / ($precision + $recall) } else { 0 }

        Write-Host ""
        Write-Host "=== Scorecard vs. $CompareTo ===" -ForegroundColor Yellow
        Write-Host ("  True positives:  {0}" -f $truePositives.Count)
        Write-Host ("  Missed (FN):     {0}" -f $falseNegatives.Count)
        Write-Host ("  Over-flagged(FP):{0}" -f $falsePositives.Count)
        Write-Host ("  Precision: {0:P1}   Recall: {1:P1}   F1: {2:P1}" -f $precision, $recall, $f1)
        if ($falseNegatives.Count -gt 0) {
            Write-Host ""
            Write-Host "  Missed findings:" -ForegroundColor Red
            $falseNegatives | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        }
    }
}
