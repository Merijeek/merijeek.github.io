---
layout: post
title: "Building a Multi-Vendor Switch Compliance Auditor on a Locked-Down Linux Host"
date: 2026-10-16
tags: [network-security, configuration-management, compliance, python, cisco, juniper, linux-hardening]
---

Most network teams have a hardening standard somewhere. Fewer have a way to prove, on any given day, that every switch actually matches it. Configuration drift is quiet: a temporary change during an outage that never gets backed out, a replacement switch staged from an old template, a trap destination that points at a tool retired two years ago. None of it shows up until an audit, an incident, or both.

This post walks through how I built a tool to close that gap: a Python-based compliance auditor that checks Cisco and Juniper switches against a consolidated security and operational baseline, on demand, for a single switch or the whole network. It covers three pieces of work: building the baseline itself, turning it into software, and getting that software to run properly on a hardened Linux host.

## Part 1: One baseline, four platforms

The first problem wasn't code. It was that "best practice" means something different depending on whose documentation you're reading. I studied CIS benchmarks and vendor hardening guidance for four switching families:

- HPE / Aruba switches
- Juniper EX
- Cisco Catalyst (IOS / IOS-XE)
- Cisco Nexus (NX-OS)

Each vendor covers roughly the same ground (management-plane protection, administrative access, logging, monitoring, Layer 2 protections) but with different defaults, different syntax, and different opinions about what matters. Juniper and Cisco, for example, express SNMP community and trap configuration in materially different ways, so "the trap destinations are correct" has to be evaluated differently on each platform even though the intent is identical.

The baseline that came out of that study covers:

- **Administrative access:** centralized AAA via TACACS+, restrictions on local accounts, and login banners
- **Management-plane protection:** SSH-only management with telnet disabled, management access ACLs, and control-plane policing
- **Time and logging:** NTP for consistent timestamps, and syslog sent to approved collectors
- **Monitoring:** SNMP version and community requirements, and approved trap destinations
- **Layer 2 protections:** unused ports shut down, BPDU guard, port security, and DHCP snooping

The output of that study was a single vendor-neutral baseline: a list of *intents* (e.g., "logging must be sent to the approved collectors," "only approved local accounts may exist," "link state changes must be logged," "SNMP traps must go to the approved monitoring hosts and nowhere else") with the platform-specific way to verify each one. Writing it that way was the most useful decision in the project. It forced every check to answer "what are we actually trying to guarantee?" before "what command shows it?"

## Part 2: Turning the baseline into software

The auditor connects to each switch over SSH, collects the relevant configuration and operational state, and evaluates it against the baseline. It runs two ways:

- **Spot check:** audit one switch on demand, useful after a change or when something looks off.
- **Mass scan:** walk the full device list and produce a report for the whole network.

### Checks beyond configuration

Pure configuration compliance turned out to be only half the picture. A switch can have a perfect config and still be running unhealthy. So the tool also evaluates operational state: software version against a minimum, power and hardware health, CPU and memory, routing adjacencies, and topology. For topology, the tool validates that specific switches see the neighbors they're supposed to see. A device that should be dual-homed but only sees one uplink is a resiliency finding even if nothing is down yet.

Interface errors were a good lesson in measuring the right thing. The first version used absolute error counters, which flagged switches whose counters simply hadn't been cleared in a long time. Switching to a *rate*, errors per minute calculated against each interface's last-clearing timestamp, eliminated most of the false positives and made the remaining findings worth looking at.

### Severity, not just pass/fail

A wall of red teaches people to ignore red. Every finding is tagged, and every tag maps to a severity level, so the report distinguishes between "this violates the baseline" and "this is unexpected and a human should look at it." An unrecognized trap destination, for instance, is flagged for review rather than as a failure, because it might be a legitimate tool nobody documented. Each device's overall status is driven by its worst finding, so the summary view sorts itself.

Equally important: **a check that couldn't run is not a check that passed.** Command errors, from unsupported syntax on older platforms or a timeout, go into their own report section instead of being silently counted as clean or lumped in with real failures. Platforms the tool doesn't support yet are detected and explicitly skipped rather than half-audited.

### Reporting and drift over time

The tool serves results through a web interface over HTTPS and also produces a monthly report. The monthly run saves an inventory snapshot, which lets the report answer the questions a single scan can't:

- **Regressions:** what was compliant last month and isn't now?
- **New devices:** what showed up that wasn't there before?
- **Unreachable devices:** what disappeared, and is that expected?

That shifts the tool from "here's the current state" to "here's what changed," which is what you actually need for drift management and what an auditor actually asks for.

### A note on configuration-as-data

All baseline values (required hosts, thresholds, minimum versions, severity mappings, per-device exceptions) live in a separate configuration module rather than in the audit logic. That keeps the baseline reviewable on its own. It also created the project's most instructive bug: a deployment failed because the code referenced baseline constants that were missing from the config file. The fix was a pre-deploy cross-check that verifies every finding tag the code can emit has a severity defined, and that every constant the code imports actually exists. For a security tool, failing loudly at deploy time beats quietly skipping a check in production.

## Part 3: Running it on a hardened host

The auditor runs as a systemd service under a dedicated service account with no interactive use, on a Linux host with a hardened system-wide crypto policy. That combination produced the most interesting security problem in the project.

### When the hardened host can't talk to the legacy switch

Some older switches in the environment only support legacy SSH key exchange and SHA-1 based signatures. The host's crypto policy, correctly, disables SHA-1. The result was persistent SSH failures to exactly the older devices that most needed auditing.

There were a few bad ways to fix this:

- **Relax the system-wide crypto policy.** This would have weakened every service on the host to accommodate one tool talking to a handful of old switches.
- **Exclude the old switches from auditing.** The devices most likely to be out of compliance would become the devices nobody checks.

The fix that held up was two-part: pinning the SSH library to a version compatible with those legacy algorithms, and enabling SHA-1 signature support **only within the auditor's own process** via an environment variable the script sets for itself at startup. The host's system-wide policy stays strict; the exception is scoped to one process, documented in the code, and goes away when the legacy switches do.

That's a small example of a general principle: when you have to accept a weaker control, make the exception as narrow as possible, make it visible, and tie it to the thing that justifies it.

### Other hardening decisions

- **TLS from the internal CA.** The web interface is served over HTTPS with a certificate issued by the organization's internal certificate authority, not a self-signed one, so browsers trust it and nobody has to get used to clicking through warnings.
- **Credentials are prompted at runtime, not embedded.** The tool asks for device credentials when a scan is launched, holds them in memory for that run only, and never writes them to disk, to its configuration, or to the code. There is no credential file on the host to steal, because there is no credential file.
- **Dedicated non-interactive service account.** The service runs under its own account with no interactive login, and its home directory is restricted so other users can't read its files. (This occasionally inconvenienced me personally, which is the point.)
- **systemd sandboxing.** The service unit uses systemd's sandboxing options to limit what the process can see and do on the host, so even a compromised auditor has a small blast radius.
- **Scripted deployment.** A deploy script stages the files, sets ownership and permissions, and updates and restarts the systemd service. No hand-copying onto the server and no forgotten permission fixes.

## What I'd tell someone starting this

1. **Write the baseline as intents first.** Platform syntax is the easy part. Agreeing on what you're guaranteeing is the hard part.
2. **Severity tiers matter more than check count.** A report people trust beats a report that's comprehensive and ignored.
3. **Treat "couldn't check" as its own result.** Silent gaps are worse than known failures.
4. **Track drift, not just state.** Month-over-month regressions are where the real findings are.
5. **Scope your exceptions.** If a legacy device forces a weaker control, contain it to the smallest possible blast radius and document why.

Next on the list is extending full audit coverage to the HPE/Aruba platforms, which the tool currently detects and skips.
