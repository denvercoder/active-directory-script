# AD User Generation For Labs

A set of PowerShell scripts that build a realistic Active Directory lab for training: a full org structure (OUs, security groups, distribution groups) for a fictitious medium-sized company, populated with randomly generated employees — names, addresses, phone numbers, job titles, a manager hierarchy, and group memberships.

It can also optionally sprinkle a set of realistic, real-world security misconfigurations across the accounts and objects it creates, so you can practice auditing and fixing them the same way you would in a live environment — then check your work against an independent auditor script or a bundled answer key.

## Files

| File | Purpose |
|---|---|
| `New-ADLabUsers.ps1` | Builds the lab: OUs, groups, users, optional misconfigurations. |
| `ADLabHelpers.ps1` | Pure logic shared by the generator and the tests (company templates, password/username generation, allocation math, offline identity data). Dot-sourced automatically — you don't run this directly. |
| `Remove-ADLabUsers.ps1` | Tears a lab down completely so you can start over. |
| `Find-ADLabMisconfigurations.ps1` | Independent auditor: inspects live AD and reports what it finds, without reading the answer key. Doubles as a self-grading tool. |
| `New-ADLabUsers.Tests.ps1` | Pester tests for the logic in `ADLabHelpers.ps1`. |
| `tools/InvokeADCheck/` | A vendored copy of [InvokeADCheck](https://github.com/sensepost/InvokeADCheck) — a real third-party AD security auditor to run against the lab. Comes with a plain clone, no extra setup. See [`INVOKEADCHECK.md`](INVOKEADCHECK.md). |

## Requirements

- A machine with the ActiveDirectory PowerShell module (RSAT AD tools, or run directly on a domain controller)
- An account with rights to create OUs, users, and groups in the target domain
- A free Mockaroo API key (see below) — **or** pass `-Offline` and skip this entirely
- A lab/training domain — these scripts create/delete real objects (no `-WhatIf` on the AD cmdlets themselves); don't point them at production. Use `-DryRun` (see below) to preview a run with zero writes.

## Getting a Mockaroo API key

This script uses [Mockaroo](https://www.mockaroo.com) to generate realistic names, addresses, and phone numbers for each user. If you don't want to sign up for anything (or you're on an isolated lab network with no internet), pass `-Offline` instead and skip this whole section — you'll get locally generated names instead.

1. Go to [mockaroo.com](https://www.mockaroo.com) and sign up for a free account (or log in if you already have one).
2. Click your account name in the top right and choose **My Account**.
3. Copy the **API Key** shown on that page.
4. Either:
   - Paste it into the `$MockarooApiKeyDefault` variable near the top of `New-ADLabUsers.ps1`, so it's already set every time you run the script, **or**
   - Pass it with `-MockarooApiKey <key>` each run, **or**
   - Leave it blank — the script will ask you to paste it in when it runs.

> The Mockaroo free plan caps a single request at **1,000 rows**, which is why every script here limits you to 1-1000 users per run.

## Usage

### Interactive (the original way)

```powershell
.\New-ADLabUsers.ps1
```

You'll be asked for your Mockaroo API key (if not already set), how many users you want, whether to add misconfigurations, and whether you want random or shared passwords. Everything else — company structure, departments, offices, groups, titles, hierarchy — is generated automatically.

### Non-interactive (for scripting a whole class at once)

Every prompt has a matching parameter, so you can skip straight past them:

```powershell
.\New-ADLabUsers.ps1 -UserCount 150 -AddMisconfigurations -UseRandomPasswords -MockarooApiKey $key
```

| Parameter | Replaces the prompt for... |
|---|---|
| `-UserCount <1-1000>` | "How many users do you want?" |
| `-AddMisconfigurations` / `-SkipMisconfigurations` | "Add Misconfigurations?" |
| `-UseRandomPasswords` | "Would you like random passwords?" (yes) |
| `-SharedPassword <password>` | "Would you like random passwords?" (no) + "Enter the password..." |
| `-MockarooApiKey <key>` | "Enter your Mockaroo API key..." |
| `-Offline` | Skips Mockaroo entirely; generates identities locally |
| `-CompanyTemplate <name>` | Which fictitious company to build (see below) |
| `-Seed <int>` | Makes the run reproducible |
| `-DryRun` | Preview only — creates/changes nothing |

### Company templates

Pick from three built-in fictitious companies with `-CompanyTemplate` (default `NimbusSoftwareSolutions`):

- **`NimbusSoftwareSolutions`** — a software company (Engineering, Product, Sales, Marketing, Support, IT, Finance, HR, Legal, Executive)
- **`SummitRetailGroup`** — a retail chain (Merchandising, Store Operations, Loss Prevention, Supply Chain, Marketing, Customer Service, IT, Finance, HR, Executive)
- **`HarborLogisticsCo`** — a freight/logistics company (Operations, Fleet Maintenance, Warehousing, Customer Service, Sales, IT, Finance, HR, Executive)

Each has its own offices, department weights, and job titles, so repeated labs (e.g. across a class) don't all look identical.

### Reproducible runs

Pass `-Seed <int>` to make department allocation, office assignment, password generation, and misconfiguration selection deterministic — the same seed plus the same `-UserCount`/`-CompanyTemplate` produces the same lab shape every time. Mockaroo's identity data isn't seeded (it's a live API call), so combine `-Seed` with `-Offline` for a fully reproducible run, e.g. for handing out a fixed lab + matching answer key to grade against.

### Offline mode

`-Offline` skips the Mockaroo API entirely and generates first/last names, addresses, and phone numbers from a built-in local list instead. Also kicks in automatically (with a warning) if a live Mockaroo call fails partway through, so a flaky connection doesn't abort the whole run.

### Dry run

`-DryRun` walks through the entire plan — OUs, groups, department allocation, every user, every misconfiguration — and prints what it *would* do, without creating or modifying a single AD object. It still needs a real domain connection (to resolve the domain name and check for existing accounts realistically), but nothing is written. Good for sanity-checking `-UserCount`/`-CompanyTemplate` choices or reviewing what a misconfiguration pass would touch before committing to it.

```powershell
.\New-ADLabUsers.ps1 -UserCount 200 -AddMisconfigurations -DryRun
```

## What gets created

**OU structure** (under a top-level company OU, e.g. `Nimbus Software Solutions`):
- `Employees` — with one sub-OU per department
- `Groups` — with `Security Groups` and `Distribution Groups` sub-OUs

**Groups:**
- A security group (`SG-<Department>`) and distribution group (`DL-<Department>`) per department
- Company-wide: `SG-Managers`, `SG-VPN-Users`, `SG-RemoteDesktop-Users`, `DL-AllEmployees`, `DL-Managers`, `DL-Executives`

**Users**, distributed across departments the way a real company roughly skews for the chosen template (see Company templates above), each with a name/address/phone (from Mockaroo or `-Offline`) plus a department-appropriate job title, employee ID, office assignment, manager (reporting up to a department lead, who reports to the CEO), and group memberships.

**Output files**, written next to the script:
- `ADLabUsers_<timestamp>.csv` — every generated username and password (plaintext). Lab use only — move it somewhere safe or delete it once you're done.
- `ADLabMisconfigurations_ANSWERKEY_<timestamp>.csv` — only created if you opt into misconfigurations (see below).

## Misconfigurations

Answering `true` (or passing `-AddMisconfigurations`) makes the script deliberately introduce a small set of security misconfigurations across a handful of the accounts/objects it just created — the kind of thing a real AD security review is meant to catch. The idea is to practice finding these yourself first, using whatever auditing approach or tooling you're learning, before checking your work.

Most categories only affect a few accounts (scaled to how many users you generated), so most accounts stay clean. Findings are written to a separate answer-key CSV rather than printed to the screen, so you can hold off on looking at it until you're ready to grade yourself.

<details>
<summary><strong>⚠️ Spoilers — click to reveal the misconfiguration types</strong></summary>

**Per-account:**
- **Weak password** — a few accounts get a common, easily-guessable password that still technically passes complexity requirements (e.g. `Password1`).
- **Password not required** — the `PASSWD_NOTREQD` flag is set on a few accounts, meaning AD will accept a blank password for them.
- **AS-REP roastable** — Kerberos pre-authentication is disabled on a few accounts (also given a weak password), making them vulnerable to AS-REP roasting.
- **Kerberoastable** — a fake service principal name (SPN) is added to a standard user account (also given a weak password), making it a Kerberoasting target.
- **Restricted logon workstation** — a few accounts have `LogonWorkstations` set to a single (possibly stale or wrong) machine name, so they can only log on from that one machine.
- **Password in the description field** — a few accounts have their actual current password sitting in plaintext in their AD `Description` field.
- **Stale terminated account** — a few accounts have a description saying the employee was terminated, but the account is still enabled. A `Disabled Accounts` OU is created as the correct place to move it.
- **Misplaced OU** — a few accounts are moved into the default `Users` container instead of their department OU, so department group policies won't apply to them.

**Privilege / infrastructure-level** *(only if you generate 8+ users)*:
- **Rogue privileged access** — exactly one ordinary employee account is added directly to **Domain Admins**. Flagged as Critical, called out loudly in the console output.
- **Dangerous ACL** — one ordinary employee account is granted `GenericAll` over another (usually IT or Executive) account's AD object — a classic BloodHound-style attack-path edge (reset their password, add an SPN to it, take over the account). Good practice for ACL/attack-path review, not just flat findings.
- **Weak password policy** — a Fine-Grained Password Policy named `Legacy Compatibility Policy` (4-character minimum, no complexity, no lockout, passwords never expire) is applied to a random department's security group. Requires a 2008+ domain functional level.
- **GPP cpassword** *(requires the GroupPolicy module — usually only available on/near a DC)* — a GPO named `Legacy Drive Mapping Policy` maps a network drive using a Group Policy Preferences password. That "encryption" (MS14-025) uses a key Microsoft published years ago, and is trivially reversible with any GPP-password decryption tool. Skipped automatically with a warning if the GroupPolicy module isn't present.

Each category can be individually turned off in the `$MisconfigTypes` table near the top of `New-ADLabUsers.ps1` if you'd rather skip one.

</details>

## Grading yourself / auditing the lab

`Find-ADLabMisconfigurations.ps1` is a standalone auditor. It does **not** read the answer key — it inspects live AD the way a real review would (LDAP filters for account flags, ACL reads, an ADFineGrainedPasswordPolicy check, a SYSVOL scan for GPP cpasswords) and writes its own findings to `ADLabFindings_<timestamp>.csv`.

```powershell
# Just audit and see what it finds
.\Find-ADLabMisconfigurations.ps1 -CompanyName 'Nimbus Software Solutions'

# Also grade against the generator's answer key (precision/recall/F1 + a list of what was missed)
.\Find-ADLabMisconfigurations.ps1 -CompareTo .\ADLabMisconfigurations_ANSWERKEY_20260907_120000.csv
```

Weak passwords can't be detected via LDAP alone. Pass `-TestWeakPasswords` to have it safely spray a small candidate list against accounts in the lab OU — it auto-caps attempts per account to (domain lockout threshold − 1) so it can't lock anyone out, and skips the spray entirely if the lockout policy leaves no safe margin. Still lab-domain-only.

Pass `-SkipACLScan` to skip the (slower) per-account ACL check on very large labs.

For a second opinion from a real, independent third-party tool (not written for this lab), see [`INVOKEADCHECK.md`](INVOKEADCHECK.md) — it covers running [InvokeADCheck](https://github.com/sensepost/InvokeADCheck) against the same lab, plus exactly which of this lab's misconfiguration categories it does and doesn't catch.

## Tearing a lab down

```powershell
.\Remove-ADLabUsers.ps1 -CompanyName 'Nimbus Software Solutions'
```

Recursively deletes the whole company OU (all users, groups, and sub-OUs in one shot), plus the `Legacy Drive Mapping Policy` GPO and `Legacy Compatibility Policy` Fine-Grained Password Policy if the GPP/weak-policy scenarios were used (those live outside the company OU, so they need explicit cleanup). Prompts for confirmation unless you pass `-Force`. Anything added to Domain Admins, or any dangerous ACL granted, disappears on its own once the underlying account is deleted.

## Running the tests

The pure logic (password/username generation, department allocation, the GPP cpassword encryption, the offline identity generator, and the company template data) has Pester tests that don't need AD at all:

```powershell
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0
Invoke-Pester .\New-ADLabUsers.Tests.ps1
```
