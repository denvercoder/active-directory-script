<#
    ADLabHelpers.ps1

    Pure, side-effect-free logic shared by New-ADLabUsers.ps1 and its Pester
    tests: password/username generation, department allocation math, company
    templates, and the offline (no-Mockaroo) identity generator.

    Nothing in this file touches Active Directory, the network, or the
    console - it's safe to dot-source anywhere, including from tests.
#>

# ============================ COMPANY TEMPLATES =============================
# Each template is a self-contained fictitious company: name, offices, and a
# department scaffold (weights, titles). New-ADLabUsers.ps1 picks one via
# -CompanyTemplate; the Tests file exercises the allocation math against all
# of them.

$script:CompanyTemplates = [ordered]@{

    NimbusSoftwareSolutions = @{
        CompanyName = 'Nimbus Software Solutions'
        Offices = @(
            @{ Name = 'Denver HQ';       City = 'Denver';  State = 'CO'; AreaCode = '303'; Weight = 60 }
            @{ Name = 'Austin Office';   City = 'Austin';  State = 'TX'; AreaCode = '512'; Weight = 20 }
            @{ Name = 'Raleigh Office';  City = 'Raleigh'; State = 'NC'; AreaCode = '919'; Weight = 20 }
        )
        Departments = @(
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
    }

    SummitRetailGroup = @{
        CompanyName = 'Summit Retail Group'
        Offices = @(
            @{ Name = 'Chicago HQ';                City = 'Chicago'; State = 'IL'; AreaCode = '312'; Weight = 50 }
            @{ Name = 'Dallas Distribution Center'; City = 'Dallas';  State = 'TX'; AreaCode = '214'; Weight = 25 }
            @{ Name = 'Atlanta Office';             City = 'Atlanta'; State = 'GA'; AreaCode = '404'; Weight = 25 }
        )
        Departments = @(
            @{ Key = 'Merchandising';    DisplayName = 'Merchandising';     Weight = 15
               LeadTitle = 'Merchandising Manager'
               ICTitles  = @('Buyer','Assistant Buyer','Merchandise Planner','Inventory Analyst') }
            @{ Key = 'StoreOperations';  DisplayName = 'Store Operations';  Weight = 30
               LeadTitle = 'Store Operations Manager'
               ICTitles  = @('Store Manager','Assistant Store Manager','Sales Associate','Cashier','Visual Merchandiser') }
            @{ Key = 'LossPrevention';   DisplayName = 'Loss Prevention';   Weight = 6
               LeadTitle = 'Loss Prevention Manager'
               ICTitles  = @('Loss Prevention Officer','Asset Protection Specialist','Security Analyst') }
            @{ Key = 'SupplyChain';      DisplayName = 'Supply Chain';      Weight = 10
               LeadTitle = 'Supply Chain Manager'
               ICTitles  = @('Logistics Coordinator','Warehouse Supervisor','Inventory Control Specialist','Distribution Analyst') }
            @{ Key = 'Marketing';        DisplayName = 'Marketing';         Weight = 8
               LeadTitle = 'Marketing Manager'
               ICTitles  = @('Marketing Coordinator','Digital Marketing Specialist','Brand Manager','Social Media Specialist') }
            @{ Key = 'CustomerService';  DisplayName = 'Customer Service';  Weight = 10
               LeadTitle = 'Customer Service Manager'
               ICTitles  = @('Customer Service Representative','Support Specialist') }
            @{ Key = 'IT';               DisplayName = 'IT';                Weight = 7
               LeadTitle = 'IT Manager'
               ICTitles  = @('IT Support Technician','Systems Administrator','Network Administrator','POS Systems Specialist','Security Analyst') }
            @{ Key = 'Finance';          DisplayName = 'Finance';           Weight = 6
               LeadTitle = 'Finance Manager'
               ICTitles  = @('Staff Accountant','Financial Analyst','Accounts Payable Specialist','Payroll Specialist') }
            @{ Key = 'HumanResources';   DisplayName = 'Human Resources';   Weight = 5
               LeadTitle = 'HR Manager'
               ICTitles  = @('HR Coordinator','HR Generalist','Recruiter','Benefits Administrator') }
            @{ Key = 'Executive';        DisplayName = 'Executive';         Weight = 3
               IsExecutive = $true
               ExecTitles  = @('Chief Executive Officer','Chief Operating Officer','Chief Financial Officer','Chief Merchandising Officer','Chief Marketing Officer') }
        )
    }

    HarborLogisticsCo = @{
        CompanyName = 'Harbor Logistics Co'
        Offices = @(
            @{ Name = 'Newark Terminal';   City = 'Newark';   State = 'NJ'; AreaCode = '973'; Weight = 40 }
            @{ Name = 'Savannah Terminal'; City = 'Savannah'; State = 'GA'; AreaCode = '912'; Weight = 30 }
            @{ Name = 'Houston Terminal';  City = 'Houston';  State = 'TX'; AreaCode = '713'; Weight = 30 }
        )
        Departments = @(
            @{ Key = 'Operations';        DisplayName = 'Operations';         Weight = 25
               LeadTitle = 'Operations Manager'
               ICTitles  = @('Dispatcher','Operations Coordinator','Route Planner','Logistics Analyst') }
            @{ Key = 'FleetMaintenance';  DisplayName = 'Fleet Maintenance';  Weight = 12
               LeadTitle = 'Fleet Maintenance Manager'
               ICTitles  = @('Diesel Mechanic','Fleet Technician','Maintenance Coordinator') }
            @{ Key = 'Warehousing';       DisplayName = 'Warehousing';        Weight = 18
               LeadTitle = 'Warehouse Manager'
               ICTitles  = @('Warehouse Associate','Forklift Operator','Inventory Specialist','Shipping Clerk') }
            @{ Key = 'CustomerService';   DisplayName = 'Customer Service';   Weight = 8
               LeadTitle = 'Customer Service Manager'
               ICTitles  = @('Customer Service Representative','Freight Coordinator') }
            @{ Key = 'Sales';             DisplayName = 'Sales';              Weight = 10
               LeadTitle = 'Sales Manager'
               ICTitles  = @('Account Executive','Sales Representative','Business Development Representative') }
            @{ Key = 'IT';                DisplayName = 'IT';                 Weight = 6
               LeadTitle = 'IT Manager'
               ICTitles  = @('IT Support Technician','Systems Administrator','Network Administrator','Security Analyst') }
            @{ Key = 'Finance';           DisplayName = 'Finance';            Weight = 6
               LeadTitle = 'Finance Manager'
               ICTitles  = @('Staff Accountant','Financial Analyst','Accounts Payable Specialist','Payroll Specialist') }
            @{ Key = 'HumanResources';    DisplayName = 'Human Resources';    Weight = 5
               LeadTitle = 'HR Manager'
               ICTitles  = @('HR Coordinator','HR Generalist','Recruiter','Safety & Compliance Specialist') }
            @{ Key = 'Executive';         DisplayName = 'Executive';          Weight = 3
               IsExecutive = $true
               ExecTitles  = @('Chief Executive Officer','Chief Operating Officer','Chief Financial Officer','VP of Logistics') }
        )
    }
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
    $execKey = ($Departments | Where-Object { $_.IsExecutive } | Select-Object -First 1 -ExpandProperty Key)
    $icKey   = ($Departments | Sort-Object -Property Weight -Descending | Where-Object { -not $_.IsExecutive } | Select-Object -First 1 -ExpandProperty Key)
    if ($execKey -and $floor.ContainsKey($execKey) -and $floor[$execKey] -gt 5) {
        $overflow = $floor[$execKey] - 5
        $floor[$execKey] = 5
        if ($icKey) { $floor[$icKey] += $overflow }
    }
    return $floor
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

function Get-MisconfigCount {
    param([int]$PoolSize, [double]$Pct, [int]$Min, [int]$Max)
    if ($PoolSize -le 0) { return 0 }
    $n = [Math]::Ceiling($PoolSize * $Pct)
    if ($n -lt $Min) { $n = $Min }
    if ($n -gt $Max) { $n = $Max }
    if ($n -gt $PoolSize) { $n = $PoolSize }
    return $n
}

function ConvertTo-GPPCPassword {
    <#
        Encrypts $PlainText the same way Group Policy Preferences did before
        MS14-025: AES-256-CBC with Microsoft's published, publicly-known
        static key and a zero IV, then unpadded base64url. Anyone with the
        GroupPolicy module (or tools like Get-GPPPassword) can reverse this
        instantly - that's the point. Used only to seed the intentionally
        vulnerable GPPCPassword lab finding.
    #>
    param([Parameter(Mandatory)][string]$PlainText)

    $key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                     0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = New-Object byte[] 16
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($PlainText)
    $encryptor = $aes.CreateEncryptor()
    try {
        $encrypted = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    } finally {
        $encryptor.Dispose()
        $aes.Dispose()
    }

    ([Convert]::ToBase64String($encrypted)).TrimEnd('=').Replace('+','-').Replace('/','_')
}

# ========================= OFFLINE IDENTITY FALLBACK =========================
# Used when -Offline is passed, or automatically as a fallback if the
# Mockaroo API call fails (e.g. no internet in an isolated lab VLAN). Not as
# varied as Mockaroo's data, but good enough to build a believable lab, and
# fully deterministic under -Seed since it's driven entirely by Get-Random.

$script:OfflineFirstNames = @(
    'James','Mary','Robert','Patricia','John','Jennifer','Michael','Linda','David','Elizabeth',
    'William','Barbara','Richard','Susan','Joseph','Jessica','Thomas','Sarah','Charles','Karen',
    'Christopher','Nancy','Daniel','Lisa','Matthew','Betty','Anthony','Margaret','Mark','Sandra',
    'Donald','Ashley','Steven','Kimberly','Andrew','Emily','Paul','Donna','Joshua','Michelle',
    'Kenneth','Dorothy','Kevin','Carol','Brian','Amanda','George','Melissa','Edward','Deborah',
    'Ronald','Stephanie','Timothy','Rebecca','Jason','Sharon','Jeffrey','Laura','Ryan','Cynthia',
    'Jacob','Kathleen','Gary','Amy','Nicholas','Angela','Eric','Shirley','Jonathan','Anna',
    'Stephen','Brenda','Larry','Pamela','Justin','Emma','Scott','Nicole','Brandon','Helen',
    'Benjamin','Samantha','Samuel','Katherine','Gregory','Christine','Alexander','Debra','Frank','Rachel',
    'Patrick','Carolyn','Raymond','Janet','Jack','Maria','Dennis','Heather','Jerry','Diane'
)

$script:OfflineLastNames = @(
    'Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Rodriguez','Martinez',
    'Hernandez','Lopez','Gonzalez','Wilson','Anderson','Thomas','Taylor','Moore','Jackson','Martin',
    'Lee','Perez','Thompson','White','Harris','Sanchez','Clark','Ramirez','Lewis','Robinson',
    'Walker','Young','Allen','King','Wright','Scott','Torres','Nguyen','Hill','Flores',
    'Green','Adams','Nelson','Baker','Hall','Rivera','Campbell','Mitchell','Carter','Roberts',
    'Gomez','Phillips','Evans','Turner','Diaz','Parker','Cruz','Edwards','Collins','Reyes',
    'Stewart','Morris','Morales','Murphy','Cook','Rogers','Gutierrez','Ortiz','Morgan','Cooper',
    'Peterson','Bailey','Reed','Kelly','Howard','Ramos','Kim','Cox','Ward','Richardson',
    'Watson','Brooks','Chavez','Wood','Bennett','Gray','Mendoza','Ruiz','Hughes','Price',
    'Alvarez','Castillo','Sanders','Patel','Myers','Long','Ross','Foster','Jimenez','Powell'
)

$script:OfflineStreetNames = @(
    'Main St','Oak Ave','Maple Dr','Cedar Ln','Elm St','Washington Ave','Park Rd','Sunset Blvd',
    'Highland Ave','Lakeview Dr','River Rd','2nd St','3rd Ave','5th St','Pine St','Hill St',
    'Church St','Spring St','Meadow Ln','Ridge Rd'
)

function Get-OfflineIdentityRecords {
    <#
        Local stand-in for Get-MockarooRecords. Returns $Count pscustomobjects
        shaped exactly like Mockaroo's response (first_name, last_name,
        street_address, city, state_abbr, postal_code, mobile_phone), built
        entirely from the embedded name/street lists above plus the target
        company's own office list (for realistic city/state/area-code pairing).
    #>
    param(
        [Parameter(Mandatory)][int]$Count,
        [Parameter(Mandatory)][array]$Offices
    )
    $records = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $office = Get-WeightedOffice -Offices $Offices
        $records.Add([pscustomobject]@{
            first_name     = Get-Random -InputObject $script:OfflineFirstNames
            last_name      = Get-Random -InputObject $script:OfflineLastNames
            street_address = ("{0} {1}" -f (Get-Random -Minimum 100 -Maximum 9999), (Get-Random -InputObject $script:OfflineStreetNames))
            city           = $office.City
            state_abbr     = $office.State
            postal_code    = '{0:D5}' -f (Get-Random -Minimum 10000 -Maximum 99999)
            mobile_phone   = ('{0}-555-{1:D4}' -f $office.AreaCode, (Get-Random -Minimum 0 -Maximum 9999))
        })
    }
    return $records
}
