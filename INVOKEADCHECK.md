# Running InvokeADCheck against this lab

[InvokeADCheck](https://github.com/sensepost/InvokeADCheck) (by [SensePost](https://sensepost.com/)) is a third-party PowerShell module that runs a broad set of read-only Active Directory security checks and reports the results to the console, JSON, or Excel. It's vendored into this project as a git submodule at `tools/InvokeADCheck` (forked to [denvercoder/InvokeADCheck](https://github.com/denvercoder/InvokeADCheck), BSD-3-Clause license, unmodified) so you have a real, independent third-party tool to point at the lab alongside `Find-ADLabMisconfigurations.ps1`.

Where our own auditor script mirrors exactly what the generator injects, InvokeADCheck doesn't know or care that this is a lab — it's the same tool you'd run against a real environment. Running both against the same lab is a good exercise in itself: **no single tool catches everything**, and seeing what InvokeADCheck misses is as instructive as seeing what it finds.

## Setup

If you haven't cloned this project with `--recurse-submodules`, pull the submodule in first:

```powershell
git submodule update --init --recursive
```

The submodule already ships a pre-built release, so there's nothing to compile — just import it directly:

```powershell
Import-Module .\tools\InvokeADCheck\release\InvokeADCheck\InvokeADCheck.psm1
```

(The upstream `README.md` inside `tools/InvokeADCheck` also documents installing from their published `Install.ps1` instead, if you'd rather pull straight from GitHub than use the vendored copy.)

## Running it against a lab you generated here

```powershell
# From anywhere, once the module is imported:
Invoke-ADCheck -OutputTypes CLI, JSON -OutputPath C:\Temp

# Or just the checks most relevant to this lab's misconfigurations:
Invoke-ADCheck -Checks UserAccountHealth, BuiltInGroupMembership, GPPPassword, DefaultDomainPasswordPolicy -OutputTypes CLI
```

It scans the whole domain, not just the lab's OU — on a dedicated lab/training domain that's exactly the population you want checked.

## What it will and won't catch, mapped to this lab's misconfiguration catalog

This is based on reading the actual check source in `tools/InvokeADCheck/src/private/`, not just the feature list — a couple of checks fetch a property but don't end up flagging it, which is worth knowing before you trust a "clean" result.

| Our misconfiguration category | InvokeADCheck check | Catches it? |
|---|---|---|
| `PasswordNotRequired` | `UserAccountHealth` (buckets `PasswordNotRequired`) | ✅ Yes |
| `ASREPRoastable` | `UserAccountHealth` (buckets `KerberosDoesNotRequirePreAuth`) | ✅ Yes |
| `RoguePrivilegedAccess` (Domain Admins) | `BuiltInGroupMembership` (lists members of Domain Admins and other privileged groups vs. the expected default count) | ✅ Yes |
| `GPPCPassword` | `GPPPassword` (greps SYSVOL `*.xml` for `cpassword`) | ✅ Yes |
| `Kerberoastable` (fake SPN on a user) | `UserAccountHealth` | ❌ **No** — it requests `ServicePrincipalName` from AD but doesn't include it in the buckets it actually reports. A real SPN sweep (`Get-ADUser -Filter {ServicePrincipalName -like '*'}`, or our own `Find-ADLabMisconfigurations.ps1`) still finds it. |
| `RestrictedWorkstation` | — | ❌ No check inspects `LogonWorkstations`. |
| `PasswordInDescription` | — | ❌ No check reads the `Description` field. |
| `StaleTerminatedAccount` | `UserAccountHealth` (`Inactive` bucket) | ⚠️ Partial — `Inactive` requires *both* `LastLogonDate` and `PasswordLastSet` to be past the cutoff (180 days by default). A freshly generated lab account has a recent `PasswordLastSet`, so it won't trip this even though it's "terminated" by description. |
| `MisplacedOU` | — | ❌ No check compares OU placement to department. |
| `DangerousACL` (GenericAll on a user object) | `RootACL` *(experimental)* | ❌ No — `RootACL` only inspects the ACL at the **domain root**, not on individual user objects. This lab's ACL misconfiguration is planted on a user object specifically to require BloodHound-style path analysis instead. |
| `WeakPasswordPolicy` (Fine-Grained Password Policy) | — | ❌ No check enumerates PSOs; `DefaultDomainPasswordPolicy` only reports the domain-wide policy, which this scenario deliberately bypasses. |
| `WeakPassword` | — | ❌ No check tests credentials (by design — InvokeADCheck is read-only/LDAP-only, same limitation as our own auditor unless you pass it `-TestWeakPasswords`). |

A side effect worth noticing, not a graded finding: every account this lab creates has `PasswordNeverExpires = $true` (done for lab convenience), so `UserAccountHealth`'s `PasswordNeverExpires` bucket will list essentially the whole company. Real environments occasionally do this too for service-like accounts — worth discussing why it's a smell at scale even outside the intentional misconfig categories.

## Suggested exercise

1. Generate a lab with `.\New-ADLabUsers.ps1 -AddMisconfigurations`.
2. Run `Invoke-ADCheck` and write down everything it flags.
3. Run `.\Find-ADLabMisconfigurations.ps1` and compare.
4. Manually check the categories neither tool fully covers (`RestrictedWorkstation`, `PasswordInDescription`, `MisplacedOU`, the `WeakPasswordPolicy` PSO, the `DangerousACL` grant) using plain `Get-ADUser`/`Get-Acl`/`Get-ADFineGrainedPasswordPolicy` — this is the part that best simulates a real review, where your tooling gets you most of the way and the rest is you.
5. Only then open the answer key CSV to see what you missed.

## License note

`tools/InvokeADCheck` is an unmodified fork of [sensepost/InvokeADCheck](https://github.com/sensepost/InvokeADCheck) by Niels Hofland and Justin Perdok, distributed under the BSD 3-Clause license (see `tools/InvokeADCheck/LICENSE.txt`). It's included here as a submodule, not copied into this repo's own code, so it stays independently updatable (`git submodule update --remote tools/InvokeADCheck`) and its license/history stay intact.
