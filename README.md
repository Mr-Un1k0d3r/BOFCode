# BOFCode

BOF files and CNA scripts for Cobalt Strike

## Description

This repository contains multiple BOFs and theit accompanying .cna scripts for Cobalt Strike, which are useful during Red Team engagements.

## Summary

| Command | Description |
| --- | --- |
| [createproc](https://github.com/Mr-Un1k0d3r/BOFCode/blob/main/all.cna) | BOF that attempts to spawn a new process on the target system using CreateProcessA. |
| [elevate_pid](https://github.com/Mr-Un1k0d3r/BOFCode/blob/main/elevate_pid.cna) | Privilege escalation via token impersonation in Windows BOF |
| [envdump](https://github.com/Mr-Un1k0d3r/BOFCode/blob/main/env.cna) | BOF to list environment variables available to the current process |
| [getcmdline](https://github.com/Mr-Un1k0d3r/BOFCode/blob/main/getcmdline.cna) | BOF to extract the full command-line arguments used to launch a specific process by its name (e.g., notepad.exe), from another process’s memory. |
| [servicelookup](https://github.com/Mr-Un1k0d3r/BOFCode/blob/main/service_lookup.cna) | BOF that checks whether a given Windows service account exists locally or remotely by resolving its Security Identifier (SID) using LookupAccountNameA. It can also optionally impersonate a user using LogonUserA before performing the lookup. |
