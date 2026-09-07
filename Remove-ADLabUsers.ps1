<#
    Remove-ADLabUsers.ps1

    Tears down everything New-ADLabUsers.ps1 built: the company OU tree
    (employees, department OUs, security/distribution groups - all deleted
    recursively in one shot), plus the handful of objects that scenario
    generator deliberately places OUTSIDE that OU tree and so wouldn't
    otherwise get cleaned up:
      - The 'Legacy Drive Mapping Policy' GPO (GPPCPassword scenario)
      - The 'Legacy Compatibility Policy' Fine-Grained Password Policy (WeakPasswordPolicy scenario)

    Anything New-ADLabUsers.ps1 added to Domain Admins, or any dangerous ACL
    it granted, disappears on its own once the underlying user objects are
    deleted - AD removes a deleted object's own memberships and ACEs
    automatically.

    Run this between class sessions, or whenever you want to regenerate a
    lab from scratch with different settings.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$CompanyName = 'Nimbus Software Solutions',
    [switch]$Force
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
$companyDN = "OU=$CompanyName,$domainDN"

try {
    $companyOU = Get-ADOrganizationalUnit -Identity $companyDN -ErrorAction Stop
} catch {
    Write-Warning "No OU found at '$companyDN' - nothing to remove there."
    $companyOU = $null
}

if ($companyOU) {
    $userCount = (Get-ADUser -SearchBase $companyDN -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count
    $groupCount = (Get-ADGroup -SearchBase $companyDN -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count

    if (-not $Force) {
        Write-Host "About to permanently delete:" -ForegroundColor Yellow
        Write-Host "  OU tree:  $companyDN" -ForegroundColor Yellow
        Write-Host "  Contains: $userCount user(s), $groupCount group(s), and all sub-OUs" -ForegroundColor Yellow
        $confirm = Read-Host "Type YES to continue"
        if ($confirm -ne 'YES') {
            Write-Host "Aborted - nothing was deleted." -ForegroundColor Cyan
            return
        }
    }

    if ($PSCmdlet.ShouldProcess($companyDN, "Recursively delete OU and all $userCount user(s) / $groupCount group(s) inside it")) {
        # Every OU created by New-ADLabUsers.ps1 is left with ProtectedFromAccidentalDeletion
        # off, but child OUs may still carry the default AD protection - clear it recursively first.
        Get-ADOrganizationalUnit -SearchBase $companyDN -Filter * -ErrorAction SilentlyContinue |
            Set-ADObject -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
        Set-ADObject -Identity $companyOU -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue

        Remove-ADOrganizationalUnit -Identity $companyDN -Recursive -Confirm:$false
        Write-Host "Removed OU tree: $companyDN" -ForegroundColor Green
    }
}

# --- Objects the misconfiguration generator places outside the company OU ---

if (Get-Module -ListAvailable -Name GroupPolicy) {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpo = Get-GPO -Name 'Legacy Drive Mapping Policy' -ErrorAction SilentlyContinue
    if ($gpo) {
        if ($Force -or $PSCmdlet.ShouldProcess('Legacy Drive Mapping Policy', 'Remove GPO')) {
            Remove-GPO -Guid $gpo.Id -ErrorAction SilentlyContinue
            Write-Host "Removed GPO: Legacy Drive Mapping Policy" -ForegroundColor Green
        }
    }
} else {
    Write-Host "GroupPolicy module not available here - skipping GPO cleanup (only relevant if you ran the GPPCPassword scenario)." -ForegroundColor DarkGray
}

$pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'Legacy Compatibility Policy'" -ErrorAction SilentlyContinue
if ($pso) {
    if ($Force -or $PSCmdlet.ShouldProcess('Legacy Compatibility Policy', 'Remove Fine-Grained Password Policy')) {
        Remove-ADFineGrainedPasswordPolicy -Identity $pso -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed Fine-Grained Password Policy: Legacy Compatibility Policy" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Teardown complete for '$CompanyName'." -ForegroundColor Green
