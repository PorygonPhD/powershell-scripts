# [PowerShell Script] Deploy YellowKey Mitigation #

> **Notice:** **Tested** within a small test environment with no issues however, this mitigation does disable the Windows Recovery Environment. It's rarely used but something to be aware of.

## Usage ##

- Deploys across every Windows 11, Server 2022, and Server 2025 asset on the domain.
  - `.\Deploy-YellowKeyMitigation.ps1`
- Deploys to only the specified machines (bypasses the `Get-ADComputer` lookup so no RSAT tools are required).
  - `.\Deploy-YellowKeyMitigation.ps1 -mitigationTarget PC1,PC2,PC3`
- Uses a separate admin credential for the remote sessions.
  - `.\Deploy-YellowKeyMitigation.ps1 -useCredential`

## Description ##

- This script disables the Windows Recovery Environment (WinRE) on every targeted machine. WinRE is where the YellowKey exploit resides, so disabling it removes the attack surface until a proper patch is available.
- For each asset, the script will:
  - Filter AD for Windows 11, Windows Server 2022, and Windows Server 2025 (only affected OSes).
  - Open a `PSSession` to each reachable host.
  - Run `reagentc /info` to check current WinRE state; skip the host if it's already disabled.
  - Run `reagentc /disable` and re-verify via `reagentc /info` to confirm the state actually flipped.
- After the loop, the script prints a console table of every host that failed (including any that were unreachable) so you can chase them down manually.

## Prerequisites ##

- RSAT tools installed locally or run the script on a domain controller (only needed if you don't pass `-mitigationTarget`, since that's how it enumerates affected assets via `Get-ADComputer`).
- WinRM enabled on the targets.

## Available Arguments ##

- `-logDirectory`
  - Where the local consolidated logfile is written.
  - Default: `C:\temp\Logs`.

- `-mitigationTarget`
  - One or more machine names to deploy to (e.g. `-mitigationTarget PC1,PC2,PC3`).
  - If omitted, the script enumerates every Windows 11 / Server 2022 / Server 2025 computer in AD via `Get-ADComputer`.

- `-useCredential`
  - Prompts for credentials and uses them for `New-PSSession`.
  - If omitted, the script uses the current user's context.

## Known Issues ##

- Remote `Write-TxtLog` calls do not write to a file; only the local-side log captures persistent output.

## Sources ##

- [reagentc.exe Documentation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options)
- [YellowKey Exploit Article](https://thehackernews.com/2026/05/windows-zero-days-expose-bitlocker.html)
