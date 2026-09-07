<#
    New-ADLabUsers.ps1

    Builds a realistic Active Directory lab environment for training: a full
    medium-sized-software-company OU structure, department security groups,
    department distribution groups, and randomly generated employees (with
    names/addresses/phone numbers pulled from the Mockaroo API) wired up with
    job titles, a manager hierarchy, and group memberships.

    The ONLY thing this script asks interactively is "How many users do you
    want?" (plus, if you haven't pasted your own key below, your Mockaroo API
    key once). Everything else - company/department structure, offices,
    titles, hierarchy, groups - is generated automatically.

    REQUIREMENTS
      - Run on a machine with the ActiveDirectory PowerShell module (RSAT or
        a domain controller), by an account with rights to create OUs, users,
        and groups in the target domain.
      - A free Mockaroo API key (https://mockaroo.com) - see README.md for how
        to get one. The free tier caps requests at 1,000 rows, so this script
        limits "How many users do you want?" to 1-1000.
      - Only intended for lab/training domains. It creates real objects
        (no -WhatIf) - review before pointing it at anything else.

    Each person running this in class can either paste their own key into
    $MockarooApiKey below, or just leave it blank and enter it when prompted.
#>

# ============================== CONFIGURATION ==============================

# Paste your own Mockaroo API key here to skip the runtime prompt, or leave
# blank and you'll be asked for it once when the script runs.
$MockarooApiKey = ''

$CompanyName = 'Nimbus Software Solutions'

# Fictitious company offices. Each new user is randomly assigned to one.
$Offices = @(
    @{ Name = 'Denver HQ';       City = 'Denver';  State = 'CO'; AreaCode = '303'; Weight = 60 }
    @{ Name = 'Austin Office';   City = 'Austin';  State = 'TX'; AreaCode = '512'; Weight = 20 }
    @{ Name = 'Raleigh Office';  City = 'Raleigh'; State = 'NC'; AreaCode = '919'; Weight = 20 }
)

# Department scaffold: Weight controls the proportional share of headcount.
# LeadTitle is given to the first hire in a department (once it has 2+
# people); everyone else gets a random title from ICTitles. The Executive
# department is handled specially (see below).
$Departments = @(
    @{ Key = 'Engineering';     DisplayName = 'Engineering';       Weight = 30
       LeadTitle = 'Engineering Manager'
       ICTitles  = @('Software Engineer I','Software Engineer II','Senior Software Engineer','Staff Software Engineer','QA Engineer','DevOps Engineer','Site Reliability Engineer') }
    @{ Key = 'Product';         DisplayName = 'Product';           Weight = 8
       LeadTitle = 'Product Manager'
       ICTitles  = @('Associate Product Manager','Senior Product Manager','Product Analyst','UX Designer','UX Researcher') }
    @{ Key = 'Sales';           DisplayName = 'Sales';             Weight = 15
       LeadTitle = 'Sales Manager'
       ICTitles  = @('Sales Development Representative','Account Executive','Senior Account Executive','Sales Engineer','Customer Success Manager') }
    @{ Key = 'Marketing';       DisplayName = 'Marketing';         Weight = 8
       LeadTitle = 'Marketing Manager'
       ICTitles  = @('Marketing Coordinator','Content Marketing Specialist','Digital Marketing Specialist','SEO Specialist','Brand Manager') }
    @{ Key = 'CustomerSupport'; DisplayName = 'Customer Support';  Weight = 10
       LeadTitle = 'Support Team Lead'
       ICTitles  = @('Support Specialist I','Support Specialist II','Technical Support Engineer','Customer Support Representative') }
    @{ Key = 'IT';              DisplayName = 'IT';                Weight = 7
       LeadTitle = 'IT Manager'
       ICTitles  = @('IT Support Technician','Systems Administrator','Network Administrator','Help Desk Technician','Security Analyst') }
    @{ Key = 'Finance';         DisplayName = 'Finance';           Weight = 6
       LeadTitle = 'Finance Manager'
       ICTitles  = @('Staff Accountant','Financial Analyst','Accounts Payable Specialist','Accounts Receivable Specialist','Payroll Specialist') }
    @{ Key = 'HumanResources';  DisplayName = 'Human Resources';   Weight = 5
       LeadTitle = 'HR Manager'
       ICTitles  = @('HR Coordinator','HR Generalist','Recruiter','Talent Acquisition Specialist','Benefits Administrator') }
    @{ Key = 'Legal';           DisplayName = 'Legal';             Weight = 3
       LeadTitle = 'Legal Counsel'
       ICTitles  = @('Paralegal','Legal Assistant','Compliance Analyst','Contracts Administrator') }
    @{ Key = 'Executive';       DisplayName = 'Executive';         Weight = 3
       IsExecutive = $true
       ExecTitles  = @('Chief Executive Officer','Chief Operating Officer','Chief Technology Officer','Chief Financial Officer','Chief Marketing Officer') }
)

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
}

# ================================ HELPERS ===================================

function New-RandomPassword {
    param([int]$Length = 14)
    # Ambiguous characters (I, O, l, 0, 1) are excluded so credentials are easy to type by hand.
    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghijkmnopqrstuvwxyz'
    $digits  = [char[]]'23456789'
    $special = [char[]]'!@#$%^&*-_+='
    $all = $upper + $lower + $digits + $special

    $passChars = @(($upper | Get-Random), ($lower | Get-Random), ($digits | Get-Random), ($special | Get-Random))
    for ($i = $passChars.Count; $i -lt $Length; $i++) { $passChars += $all | Get-Random }

    -join ($passChars | Sort-Object { Get-Random })
}

function Get-UniqueSamAccountName {
    param(
        [string]$First,
        [string]$Last,
        [System.Collections.Generic.HashSet[string]]$Existing
    )
    $base = (($First.Substring(0,1) + $Last) -replace '[^a-zA-Z0-9]', '').ToLower()
    if ($base.Length -eq 0) { $base = 'user' }

    $candidate = if ($base.Length -gt 20) { $base.Substring(0,20) } else { $base }
    $n = 1
    while ($Existing.Contains($candidate)) {
        $suffix = [string]$n
        $maxBaseLen = 20 - $suffix.Length
        $trimmedBase = if ($base.Length -gt $maxBaseLen) { $base.Substring(0,$maxBaseLen) } else { $base }
        $candidate = "$trimmedBase$suffix"
        $n++
    }
    [void]$Existing.Add($candidate)
    return $candidate
}

function Get-DepartmentAllocation {
    param([int]$TotalUsers, [array]$Departments)

    $totalWeight = ($Departments | ForEach-Object { $_.Weight } | Measure-Object -Sum).Sum
    $floor = @{}
    $remainder = @{}
    foreach ($d in $Departments) {
        $raw = $TotalUsers * $d.Weight / $totalWeight
        $floor[$d.Key] = [math]::Floor($raw)
        $remainder[$d.Key] = $raw - $floor[$d.Key]
    }

    $assigned = ($floor.Values | Measure-Object -Sum).Sum
    $leftover = $TotalUsers - $assigned
    $order = $remainder.GetEnumerator() | Sort-Object -Property Value -Descending
    foreach ($entry in $order) {
        if ($leftover -le 0) { break }
        $floor[$entry.Key]++
        $leftover--
    }

    # Keep the C-suite realistically small no matter how large the class is.
    if ($floor.ContainsKey('Executive') -and $floor['Executive'] -gt 5) {
        $overflow = $floor['Executive'] - 5
        $floor['Executive'] = 5
        $floor['Engineering'] += $overflow
    }
    return $floor
}

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
    # the "How many users do you want?" prompt below is capped at 1000 too.
    $uri = "https://api.mockaroo.com/api/generate.json?key=$ApiKey&count=$Count"
    try {
        $result = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json'
    } catch {
        throw "Mockaroo API request failed: $($_.Exception.Message). Check that your API key is valid and that you haven't exceeded your daily request limit."
    }
    if ($result -is [string]) {
        throw "Mockaroo returned an unexpected response (likely an error message instead of data): $result"
    }

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($result)) { $records.Add($r) }
    return $records
}

function Get-WeightedOffice {
    param([array]$Offices)
    $totalWeight = ($Offices | ForEach-Object { $_.Weight } | Measure-Object -Sum).Sum
    $roll = Get-Random -Minimum 1 -Maximum ($totalWeight + 1)
    $running = 0
    foreach ($o in $Offices) {
        $running += $o.Weight
        if ($roll -le $running) { return $o }
    }
    return $Offices[0]
}

function New-OUIfMissing {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    try {
        Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop | Out-Null
    } catch {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false | Out-Null
    }
    return $dn
}

function New-GroupIfMissing {
    param([string]$Name, [string]$Path, [string]$Category, [string]$Description)
    try {
        Get-ADGroup -Identity $Name -ErrorAction Stop | Out-Null
    } catch {
        New-ADGroup -Name $Name -Path $Path -GroupScope Global -GroupCategory $Category -Description $Description | Out-Null
    }
}

function Get-MisconfigCount {
    param([int]$PoolSize, [double]$Pct, [int]$Min, [int]$Max)
    if ($PoolSize -le 0) { return 0 }
    $n = [Math]::Ceiling($PoolSize * $Pct)
    if ($n -lt $Min) { $n = $Min }
    if ($n -gt $Max) { $n = $Max }
    if ($n -gt $PoolSize) { $n = $PoolSize }
    return $n
}

function Add-LabMisconfigurations {
    param(
        [array]$Users,
        [object]$Domain,
        [string]$DomainDN,
        [string]$DnsRoot,
        [string]$CompanyOU,
        [hashtable]$Config,
        [string[]]$WeakPasswordList
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
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                $weakPwd = Set-LabWeakPassword -Sam $u.Sam
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'WeakPassword'; Severity = $cfg.Severity; Details = "Password reset to weak value: $weakPwd"; SuggestedFix = 'Reset to a strong, unique password.' })
            }
        }
    }

    $cfg = $Config.PasswordNotRequired
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                Set-ADUser -Identity $u.Sam -PasswordNotRequired $true -ErrorAction SilentlyContinue
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'PasswordNotRequired'; Severity = $cfg.Severity; Details = 'PASSWD_NOTREQD flag enabled'; SuggestedFix = 'Clear PasswordNotRequired and enforce a strong password.' })
            }
        }
    }

    $cfg = $Config.ASREPRoastable
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                Set-ADAccountControl -Identity $u.Sam -DoesNotRequirePreAuth $true -ErrorAction SilentlyContinue
                $weakPwd = Set-LabWeakPassword -Sam $u.Sam
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'ASREPRoastable'; Severity = $cfg.Severity; Details = "Kerberos pre-auth disabled; password reset to weak value: $weakPwd"; SuggestedFix = 'Re-enable Kerberos pre-authentication and reset the password.' })
            }
        }
    }

    $cfg = $Config.Kerberoastable
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                $spn = "HTTP/svc-$($u.Sam).$DnsRoot"
                Set-ADUser -Identity $u.Sam -ServicePrincipalNames @{Add = $spn} -ErrorAction SilentlyContinue
                $weakPwd = Set-LabWeakPassword -Sam $u.Sam
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'Kerberoastable'; Severity = $cfg.Severity; Details = "Fake SPN '$spn' set on a standard user; password reset to weak value: $weakPwd"; SuggestedFix = 'Remove the SPN (it belongs on a service account, not a user) and reset the password.' })
            }
        }
    }

    $cfg = $Config.RestrictedWorkstation
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                $deptLetters = ($u.Department -replace '[^A-Za-z]', '')
                $deptAbbrev = $deptLetters.Substring(0, [Math]::Min(3, $deptLetters.Length)).ToUpper()
                $fakeHost = "{0}-WKS-{1:D2}" -f $deptAbbrev, (Get-Random -Minimum 1 -Maximum 99)
                Set-ADUser -Identity $u.Sam -LogonWorkstations $fakeHost -ErrorAction SilentlyContinue
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'RestrictedWorkstation'; Severity = $cfg.Severity; Details = "Logon restricted to '$fakeHost' only"; SuggestedFix = 'Confirm the correct machine name with the user, or clear LogonWorkstations if the restriction is not needed.' })
            }
        }
    }

    $cfg = $Config.PasswordInDescription
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                $weakPwd = Set-LabWeakPassword -Sam $u.Sam
                $desc = "New hire - temp pwd $weakPwd - change at first logon"
                Set-ADUser -Identity $u.Sam -Description $desc -ErrorAction SilentlyContinue
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'PasswordInDescription'; Severity = $cfg.Severity; Details = "Description field reads: '$desc'"; SuggestedFix = 'Remove the password from the description and reset the credential.' })
            }
        }
    }

    $cfg = $Config.StaleTerminatedAccount
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            $disabledOU = New-OUIfMissing -Name 'Disabled Accounts' -Path $CompanyOU
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                $termDate = (Get-Date).AddDays(-(Get-Random -Minimum 10 -Maximum 90)).ToString('yyyy-MM-dd')
                Set-ADUser -Identity $u.Sam -Description "Terminated $termDate - pending offboarding" -ErrorAction SilentlyContinue
                $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'StaleTerminatedAccount'; Severity = $cfg.Severity; Details = "Description says terminated $termDate, but the account is still Enabled"; SuggestedFix = "Disable the account and move it to the 'Disabled Accounts' OU." })
            }
        }
    }

    $cfg = $Config.MisplacedOU
    if ($cfg.Enabled) {
        $n = Get-MisconfigCount -PoolSize $eligible.Count -Pct $cfg.Pct -Min $cfg.Min -Max $cfg.Max
        if ($n -gt 0) {
            foreach ($u in (Get-Random -InputObject $eligible -Count $n)) {
                try {
                    Move-ADObject -Identity $u.DN -TargetPath "CN=Users,$DomainDN" -ErrorAction Stop
                    $answerKey.Add([pscustomobject]@{ Username = $u.Sam; Department = $u.Department; Category = 'MisplacedOU'; Severity = $cfg.Severity; Details = 'Account is sitting in the default Users container instead of its department OU'; SuggestedFix = 'Move the account back into its correct department OU so department GPOs apply.' })
                } catch {
                    Write-Warning "Could not move $($u.Sam) to the default container: $($_.Exception.Message)"
                }
            }
        }
    }

    $cfg = $Config.RoguePrivilegedAccess
    if ($cfg.Enabled -and $Users.Count -ge $cfg.MinTotalUsers) {
        $pool = @($eligible | Where-Object { $_.Department -notin @('IT','Executive') })
        if ($pool.Count -eq 0) { $pool = $eligible }
        if ($pool.Count -gt 0) {
            $target = Get-Random -InputObject $pool
            try {
                $daGroup = Get-ADGroup -Identity "$($Domain.DomainSID.Value)-512" -ErrorAction Stop
                Add-ADGroupMember -Identity $daGroup -Members $target.Sam -ErrorAction Stop
                $answerKey.Add([pscustomobject]@{ Username = $target.Sam; Department = $target.Department; Category = 'RoguePrivilegedAccess'; Severity = $cfg.Severity; Details = 'Standard employee account was made a member of Domain Admins'; SuggestedFix = 'Remove the account from Domain Admins immediately.' })
            } catch {
                Write-Warning "Could not add $($target.Sam) to Domain Admins: $($_.Exception.Message)"
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

if ([string]::IsNullOrWhiteSpace($MockarooApiKey)) {
    $MockarooApiKey = Read-Host "Enter your Mockaroo API key (get a free one at mockaroo.com)"
}
if ([string]::IsNullOrWhiteSpace($MockarooApiKey)) {
    Write-Error "A Mockaroo API key is required."
    return
}

[int]$userCount = 0
do {
    $inputVal = Read-Host "How many users do you want? (1-1000)"
} until ([int]::TryParse($inputVal, [ref]$userCount) -and $userCount -gt 0 -and $userCount -le 1000)

do {
    $mcInput = Read-Host "Add Misconfigurations? (true/false)"
} until ($mcInput -match '^(?i:true|false|t|f|y|n|yes|no)$')
$addMisconfigs = $mcInput -match '^(?i:true|t|y|yes)$'

Write-Host "Requesting $userCount randomly generated identities from Mockaroo..." -ForegroundColor Cyan
$mockData = Get-MockarooRecords -ApiKey $MockarooApiKey -Count $userCount
if ($mockData.Count -lt $userCount) {
    Write-Warning "Mockaroo returned $($mockData.Count) records instead of $userCount. Continuing with what was returned."
    $userCount = $mockData.Count
}

Write-Host "Building OU and group scaffold for '$CompanyName'..." -ForegroundColor Cyan

$companyOU     = New-OUIfMissing -Name $CompanyName -Path $domainDN
$employeesOU   = New-OUIfMissing -Name 'Employees' -Path $companyOU
$groupsOU      = New-OUIfMissing -Name 'Groups' -Path $companyOU
$secGroupsOU   = New-OUIfMissing -Name 'Security Groups' -Path $groupsOU
$distGroupsOU  = New-OUIfMissing -Name 'Distribution Groups' -Path $groupsOU

foreach ($d in $Departments) {
    $d.OUPath = New-OUIfMissing -Name $d.DisplayName -Path $employeesOU
    New-GroupIfMissing -Name "SG-$($d.Key)" -Path $secGroupsOU -Category Security -Description "Security group for the $($d.DisplayName) department"
    New-GroupIfMissing -Name "DL-$($d.Key)" -Path $distGroupsOU -Category Distribution -Description "Distribution list for the $($d.DisplayName) department"
}
New-GroupIfMissing -Name 'SG-Managers'          -Path $secGroupsOU  -Category Security     -Description 'All people managers and executives'
New-GroupIfMissing -Name 'SG-VPN-Users'         -Path $secGroupsOU  -Category Security     -Description 'Users granted remote VPN access'
New-GroupIfMissing -Name 'SG-RemoteDesktop-Users' -Path $secGroupsOU -Category Security    -Description 'Users granted RDP access to workstations'
New-GroupIfMissing -Name 'DL-AllEmployees'      -Path $distGroupsOU -Category Distribution -Description 'Company-wide distribution list'
New-GroupIfMissing -Name 'DL-Managers'          -Path $distGroupsOU -Category Distribution -Description 'All people managers and executives'
New-GroupIfMissing -Name 'DL-Executives'        -Path $distGroupsOU -Category Distribution -Description 'Executive leadership team'

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

        $password = New-RandomPassword
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

        $employeeIdCounter++
        $userDN = (Get-ADUser -Identity $sam).DistinguishedName

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
                    Set-ADUser -Identity $u.Sam -Manager $ceo.DN -ErrorAction SilentlyContinue
                }
            }
        }
        continue
    }

    $lead = $d.CreatedUsers[0]
    if ($d.CreatedUsers.Count -ge 2) {
        foreach ($u in $d.CreatedUsers | Select-Object -Skip 1) {
            Set-ADUser -Identity $u.Sam -Manager $lead.DN -ErrorAction SilentlyContinue
        }
    }
    if ($ceo) {
        Set-ADUser -Identity $lead.Sam -Manager $ceo.DN -ErrorAction SilentlyContinue
    }
}

Write-Host "Populating security and distribution groups..." -ForegroundColor Cyan

$allSams = @()
$managerSams = @()

foreach ($d in $Departments) {
    if ($d.CreatedUsers.Count -eq 0) { continue }
    $sams = $d.CreatedUsers | ForEach-Object { $_.Sam }
    Add-ADGroupMember -Identity "SG-$($d.Key)" -Members $sams -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity "DL-$($d.Key)" -Members $sams -ErrorAction SilentlyContinue
    $allSams += $sams

    $leads = $d.CreatedUsers | Where-Object { $_.IsLead } | ForEach-Object { $_.Sam }
    $managerSams += $leads

    if ($d.IsExecutive) {
        Add-ADGroupMember -Identity 'DL-Executives' -Members $sams -ErrorAction SilentlyContinue
    }
}

if ($allSams.Count -gt 0)     { Add-ADGroupMember -Identity 'DL-AllEmployees' -Members $allSams -ErrorAction SilentlyContinue }
if ($managerSams.Count -gt 0) {
    Add-ADGroupMember -Identity 'SG-Managers' -Members $managerSams -ErrorAction SilentlyContinue
    Add-ADGroupMember -Identity 'DL-Managers' -Members $managerSams -ErrorAction SilentlyContinue
}
if ($allSams.Count -gt 0) {
    $vpnUsers = Get-Random -InputObject $allSams -Count ([Math]::Max(1, [Math]::Ceiling($allSams.Count * 0.4)))
    Add-ADGroupMember -Identity 'SG-VPN-Users' -Members $vpnUsers -ErrorAction SilentlyContinue

    $rdpUsers = Get-Random -InputObject $allSams -Count ([Math]::Max(1, [Math]::Ceiling($allSams.Count * 0.25)))
    Add-ADGroupMember -Identity 'SG-RemoteDesktop-Users' -Members $rdpUsers -ErrorAction SilentlyContinue
}

$misconfigResult = $null
if ($addMisconfigs) {
    Write-Host "Injecting intentional misconfigurations for training..." -ForegroundColor Magenta
    $allUsersDetailed = @($Departments | ForEach-Object { $_.CreatedUsers })
    $misconfigResult = Add-LabMisconfigurations -Users $allUsersDetailed -Domain $domain -DomainDN $domainDN -DnsRoot $dnsRoot -CompanyOU $companyOU -Config $MisconfigTypes -WeakPasswordList $WeakPasswords

    foreach ($entry in $misconfigResult.PasswordOverrides.GetEnumerator()) {
        $row = $credentialReport | Where-Object { $_.Username -eq $entry.Key }
        if ($row) { $row.Password = $entry.Value }
    }

    $misconfigResult.AnswerKey | Export-Csv -Path $AnswerKeyPath -NoTypeInformation
}

$credentialReport | Export-Csv -Path $CredentialReportPath -NoTypeInformation

Write-Host ""
Write-Host "Done. Created $($allSams.Count) user(s) across $((@($Departments | Where-Object { $_.CreatedUsers.Count -gt 0 })).Count) departments." -ForegroundColor Green
foreach ($d in $Departments) {
    if ($d.CreatedUsers.Count -gt 0) {
        Write-Host ("  {0,-20} {1}" -f $d.DisplayName, $d.CreatedUsers.Count)
    }
}
Write-Host ""
Write-Host "Credentials (plaintext) for every generated account were written to:" -ForegroundColor Yellow
Write-Host "  $CredentialReportPath" -ForegroundColor Yellow
Write-Host "This file is for lab use only - move it somewhere safe or delete it once you're done training." -ForegroundColor Yellow

if ($addMisconfigs -and $misconfigResult) {
    Write-Host ""
    Write-Host "Injected $($misconfigResult.AnswerKey.Count) intentional misconfiguration(s) across $((@($misconfigResult.AnswerKey | Select-Object -ExpandProperty Username -Unique)).Count) account(s)." -ForegroundColor Magenta
    Write-Host "DO NOT open the answer key until you're ready to grade / check your work:" -ForegroundColor Red
    Write-Host "  $AnswerKeyPath" -ForegroundColor Red
    if ($misconfigResult.AnswerKey | Where-Object { $_.Category -eq 'RoguePrivilegedAccess' }) {
        Write-Host "  NOTE: one account was added to Domain Admins as part of this exercise - make sure it gets removed once found." -ForegroundColor Red
    }
}
