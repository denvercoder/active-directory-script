<#
    New-ADLabUsers.Tests.ps1

    Pester (v5+) tests for the pure logic in ADLabHelpers.ps1 - password and
    username generation, department allocation math, the GPP cpassword
    encryption, the offline identity generator, and the company template
    data itself. None of this touches Active Directory, so it runs anywhere
    pwsh + Pester is installed:

        Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0
        Invoke-Pester .\New-ADLabUsers.Tests.ps1
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'ADLabHelpers.ps1')
}

Describe 'New-RandomPassword' {
    It 'returns a password of the requested length' {
        (New-RandomPassword -Length 20).Length | Should -Be 20
    }

    It 'defaults to length 14' {
        (New-RandomPassword).Length | Should -Be 14
    }

    It 'always includes an upper, lower, digit, and special character' {
        1..25 | ForEach-Object {
            $pwd = New-RandomPassword
            $pwd | Should -Match '[A-Z]'
            $pwd | Should -Match '[a-z]'
            $pwd | Should -Match '\d'
            $pwd | Should -Match '[!@#\$%\^&\*\-_\+=]'
        }
    }

    It 'never includes ambiguous characters (I, O, l, 0, 1)' {
        1..25 | ForEach-Object {
            New-RandomPassword -Length 40 | Should -Not -Match '[IOl01]'
        }
    }
}

Describe 'Get-UniqueSamAccountName' {
    It 'builds first-initial + last-name, lowercased' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        Get-UniqueSamAccountName -First 'Jane' -Last 'Doe' -Existing $existing | Should -Be 'jdoe'
    }

    It 'strips non-alphanumeric characters from the name' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        Get-UniqueSamAccountName -First 'Mary' -Last "O'Brien-Smith" -Existing $existing | Should -Be 'mobriensmith'
    }

    It 'appends a numeric suffix on collision' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        [void]$existing.Add('jdoe')
        Get-UniqueSamAccountName -First 'Jane' -Last 'Doe' -Existing $existing | Should -Be 'jdoe1'
    }

    It 'keeps incrementing the suffix through multiple collisions' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        [void]$existing.Add('jdoe'); [void]$existing.Add('jdoe1'); [void]$existing.Add('jdoe2')
        Get-UniqueSamAccountName -First 'Jane' -Last 'Doe' -Existing $existing | Should -Be 'jdoe3'
    }

    It 'never returns a name longer than 20 characters, even with a long suffix' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        $long = 'j' + ('x' * 30)
        [void]$existing.Add($long.Substring(0,20))
        $result = Get-UniqueSamAccountName -First 'J' -Last ('x' * 30) -Existing $existing
        $result.Length | Should -BeLessOrEqual 20
    }

    It 'adds every generated name to the Existing set so later calls see it' {
        $existing = [System.Collections.Generic.HashSet[string]]::new()
        Get-UniqueSamAccountName -First 'Jane' -Last 'Doe' -Existing $existing | Out-Null
        $existing.Contains('jdoe') | Should -BeTrue
    }
}

Describe 'Get-MisconfigCount' {
    It 'returns 0 when the pool is empty' {
        Get-MisconfigCount -PoolSize 0 -Pct 0.5 -Min 1 -Max 10 | Should -Be 0
    }

    It 'never returns less than Min (when the pool allows it)' {
        Get-MisconfigCount -PoolSize 100 -Pct 0.001 -Min 3 -Max 10 | Should -Be 3
    }

    It 'never returns more than Max' {
        Get-MisconfigCount -PoolSize 10000 -Pct 0.9 -Min 1 -Max 5 | Should -Be 5
    }

    It 'never returns more than PoolSize' {
        Get-MisconfigCount -PoolSize 2 -Pct 0.9 -Min 1 -Max 10 | Should -BeLessOrEqual 2
    }
}

Describe 'Get-DepartmentAllocation' {
    foreach ($templateName in $script:CompanyTemplates.Keys) {
        Context "Template: $templateName" {
            $departments = $script:CompanyTemplates[$templateName].Departments

            It 'allocates exactly TotalUsers across departments for a range of sizes' {
                foreach ($total in @(1, 2, 7, 50, 137, 1000)) {
                    $allocation = Get-DepartmentAllocation -TotalUsers $total -Departments $departments
                    ($allocation.Values | Measure-Object -Sum).Sum | Should -Be $total
                }
            }

            It 'never allocates more than 5 people to the Executive department' {
                $allocation = Get-DepartmentAllocation -TotalUsers 1000 -Departments $departments
                $execKey = ($departments | Where-Object { $_.IsExecutive }).Key
                $allocation[$execKey] | Should -BeLessOrEqual 5
            }

            It 'never produces a negative allocation' {
                $allocation = Get-DepartmentAllocation -TotalUsers 3 -Departments $departments
                foreach ($v in $allocation.Values) { $v | Should -BeGreaterOrEqual 0 }
            }
        }
    }
}

Describe 'Get-WeightedOffice' {
    It 'always returns one of the supplied offices' {
        $offices = @(
            @{ Name = 'A'; Weight = 1 }
            @{ Name = 'B'; Weight = 1 }
        )
        1..20 | ForEach-Object {
            (Get-WeightedOffice -Offices $offices).Name | Should -BeIn @('A','B')
        }
    }

    It 'roughly respects the configured weights over many draws' {
        $null = Get-Random -SetSeed 42
        $offices = @(
            @{ Name = 'Heavy'; Weight = 90 }
            @{ Name = 'Light'; Weight = 10 }
        )
        $draws = 1..2000 | ForEach-Object { (Get-WeightedOffice -Offices $offices).Name }
        $heavyShare = (@($draws | Where-Object { $_ -eq 'Heavy' })).Count / $draws.Count
        $heavyShare | Should -BeGreaterThan 0.8
        $heavyShare | Should -BeLessThan 1.0
    }
}

Describe 'ConvertTo-GPPCPassword' {
    # Independently re-implements the MS14-025 decryption (the same published
    # AES key, in reverse) to prove our encryption is actually the real,
    # publicly-known-broken scheme - not just some arbitrary encoding.
    function Get-DecryptedGPPCPassword {
        param([string]$Cpassword)
        $key = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                         0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
        $padded = $Cpassword.Replace('-','+').Replace('_','/')
        switch ($padded.Length % 4) { 2 { $padded += '==' }; 3 { $padded += '=' } }
        $encrypted = [Convert]::FromBase64String($padded)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = New-Object byte[] 16
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        try {
            $plainBytes = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
        } finally {
            $decryptor.Dispose(); $aes.Dispose()
        }
        [System.Text.Encoding]::Unicode.GetString($plainBytes)
    }

    It 'produces a cpassword that decrypts back to the original plaintext' {
        foreach ($candidate in @('Password1','Sup3r$ecret!','a')) {
            $encrypted = ConvertTo-GPPCPassword -PlainText $candidate
            Get-DecryptedGPPCPassword -Cpassword $encrypted | Should -Be $candidate
        }
    }

    It 'produces URL-safe base64 with no padding characters' {
        $encrypted = ConvertTo-GPPCPassword -PlainText 'Whatever123!'
        $encrypted | Should -Not -Match '[+/=]'
    }
}

Describe 'Get-OfflineIdentityRecords' {
    $offices = @(
        @{ Name = 'HQ'; City = 'Springfield'; State = 'IL'; AreaCode = '217'; Weight = 1 }
    )

    It 'returns exactly the requested count' {
        (Get-OfflineIdentityRecords -Count 25 -Offices $offices).Count | Should -Be 25
    }

    It 'populates every field Mockaroo would' {
        $record = Get-OfflineIdentityRecords -Count 1 -Offices $offices | Select-Object -First 1
        foreach ($prop in 'first_name','last_name','street_address','city','state_abbr','postal_code','mobile_phone') {
            $record.$prop | Should -Not -BeNullOrEmpty
        }
    }

    It 'assigns city/state consistent with one of the supplied offices' {
        $record = Get-OfflineIdentityRecords -Count 1 -Offices $offices | Select-Object -First 1
        $record.city | Should -Be 'Springfield'
        $record.state_abbr | Should -Be 'IL'
    }
}

Describe 'Company templates' {
    foreach ($templateName in $script:CompanyTemplates.Keys) {
        Context "Template: $templateName" {
            $t = $script:CompanyTemplates[$templateName]

            It 'has a non-empty company name and at least one office' {
                $t.CompanyName | Should -Not -BeNullOrEmpty
                $t.Offices.Count | Should -BeGreaterThan 0
            }

            It 'has exactly one Executive department' {
                (@($t.Departments | Where-Object { $_.IsExecutive })).Count | Should -Be 1
            }

            It 'has an IT department (misconfig logic depends on this key existing)' {
                (@($t.Departments | Where-Object { $_.Key -eq 'IT' })).Count | Should -Be 1
            }

            It 'has unique department keys' {
                $keys = $t.Departments | ForEach-Object { $_.Key }
                ($keys | Select-Object -Unique).Count | Should -Be $keys.Count
            }

            It 'gives every non-executive department at least one IC title' {
                foreach ($d in ($t.Departments | Where-Object { -not $_.IsExecutive })) {
                    $d.ICTitles.Count | Should -BeGreaterThan 0
                }
            }
        }
    }
}
