# New-ADLabUsers.ps1

A PowerShell script that builds a realistic Active Directory lab for training: a full org structure (OUs, security groups, distribution groups) for a fictitious medium-sized software company, populated with randomly generated employees — names, addresses, phone numbers, job titles, a manager hierarchy, and group memberships.

It can also optionally sprinkle a small number of realistic, real-world security misconfigurations across a handful of the accounts it creates, so you can practice auditing and fixing them the same way you would in a live environment.

## Requirements

- A machine with the ActiveDirectory PowerShell module (RSAT AD tools, or run directly on a domain controller)
- An account with rights to create OUs, users, and groups in the target domain
- A free Mockaroo API key (see below)
- A lab/training domain — this script creates real objects (no `-WhatIf`); don't point it at production

## Getting a Mockaroo API key

This script uses [Mockaroo](https://www.mockaroo.com) to generate realistic names, addresses, and phone numbers for each user.

1. Go to [mockaroo.com](https://www.mockaroo.com) and sign up for a free account (or log in if you already have one).
2. Click your account name in the top right and choose **My Account**.
3. Copy the **API Key** shown on that page.
4. Either:
   - Paste it into the `$MockarooApiKey` variable near the top of `New-ADLabUsers.ps1`, so it's already set every time you run the script, **or**
   - Leave it blank — the script will just ask you to paste it in when it runs.

> The Mockaroo free plan caps a single request at **1,000 rows**, which is why this script limits you to 1-1000 users per run.

## Usage

Open a PowerShell session as an account with rights to create OUs/users/groups, on a machine joined to the target domain with the ActiveDirectory module available, then run:

```powershell
.\New-ADLabUsers.ps1
```

You'll be asked:

1. **Your Mockaroo API key** — only if you didn't already paste it into the script.
2. **How many users do you want? (1-1000)**
3. **Add Misconfigurations? (true/false)**

Everything else — company structure, departments, offices, groups, titles, hierarchy — is generated automatically. No other questions.

## What gets created

**OU structure** (under a top-level `Nimbus Software Solutions` OU):
- `Employees` — with one sub-OU per department (Engineering, Product, Sales, Marketing, Customer Support, IT, Finance, Human Resources, Legal, Executive)
- `Groups` — with `Security Groups` and `Distribution Groups` sub-OUs

**Groups:**
- A security group (`SG-<Department>`) and distribution group (`DL-<Department>`) per department
- Company-wide: `SG-Managers`, `SG-VPN-Users`, `SG-RemoteDesktop-Users`, `DL-AllEmployees`, `DL-Managers`, `DL-Executives`

**Users**, distributed across departments the way a real software company roughly skews (Engineering largest, then Sales, Support, etc.), each with a name/address/phone from Mockaroo plus a department-appropriate job title, employee ID, office assignment, manager (reporting up to a department lead, who reports to the CEO), and group memberships.

**Output files**, written next to the script:
- `ADLabUsers_<timestamp>.csv` — every generated username and password (plaintext). Lab use only — move it somewhere safe or delete it once you're done.
- `ADLabMisconfigurations_ANSWERKEY_<timestamp>.csv` — only created if you opt into misconfigurations (see below).

## Misconfigurations

Answering `true` to the misconfiguration prompt makes the script deliberately introduce a small set of security misconfigurations across a handful of the accounts it just created — the kind of thing a real AD security review is meant to catch. The idea is to practice finding these yourself first, using whatever auditing approach or tooling you're learning, before checking your work.

Each category only affects a few accounts (scaled to how many users you generated), so most accounts stay clean. Findings are written to a separate answer-key CSV rather than printed to the screen, so you can hold off on looking at it until you're ready to grade yourself.

<details>
<summary><strong>⚠️ Spoilers — click to reveal the misconfiguration types</strong></summary>

- **Weak password** — a few accounts get a common, easily-guessable password that still technically passes complexity requirements (e.g. `Password1`).
- **Password not required** — the `PASSWD_NOTREQD` flag is set on a few accounts, meaning AD will accept a blank password for them.
- **AS-REP roastable** — Kerberos pre-authentication is disabled on a few accounts (also given a weak password), making them vulnerable to AS-REP roasting.
- **Kerberoastable** — a fake service principal name (SPN) is added to a standard user account (also given a weak password), making it a Kerberoasting target.
- **Restricted logon workstation** — a few accounts have `LogonWorkstations` set to a single (possibly stale or wrong) machine name, so they can only log on from that one machine.
- **Password in the description field** — a few accounts have their actual current password sitting in plaintext in their AD `Description` field.
- **Stale terminated account** — a few accounts have a description saying the employee was terminated, but the account is still enabled. A `Disabled Accounts` OU is created as the correct place to move it.
- **Misplaced OU** — a few accounts are moved into the default `Users` container instead of their department OU, so department group policies won't apply to them.
- **Rogue privileged access** *(only if you generate 8+ users)* — exactly one ordinary employee account is added directly to **Domain Admins**. This is flagged as Critical in the answer key and called out loudly in the console output — make sure it actually gets found and removed.

Each category can be individually turned off in the `$MisconfigTypes` table near the top of the script if you'd rather skip one (for example, disabling the Domain Admins scenario for a particular class).

</details>
