# CastleLoader Sigma detection

This repository contains a behavior-based Sigma rule derived from ANY.RUN's
[CastleLoader execution analysis](https://any.run/cybersecurity-blog/castleloader-malware-analysis/).

## Detection strategy

CastleLoader's observed chain uses an Inno Setup package to extract `AutoIt3.exe`
and the obfuscated `freely.a3x` script. AutoIt then creates the legacy .NET
JScript compiler `jsc.exe` in a suspended state and injects the CastleLoader PE
into that process. The rule detects the uncommon, durable process relationship
of AutoIt spawning `jsc.exe` rather than relying only on sample hashes or the
reported command-and-control address.

The rule requires Windows process-creation telemetry that populates `Image` and
`ParentImage`, such as Sysmon Event ID 1 or an equivalent EDR event. Ensure your
Sigma backend maps those fields to the corresponding SIEM fields.

## Triage guidance

When the rule fires:

1. Inspect the AutoIt parent command line and recover the referenced `.a3x` or
   `.au3` script. The analyzed campaign used `freely.a3x`, but that filename is
   intentionally not required by the rule.
2. Check whether `jsc.exe` was created suspended and whether the parent obtained
   a handle to it, allocated executable memory, called `WriteProcessMemory`,
   changed its thread context, or resumed its primary thread.
3. Review network activity from `jsc.exe`, especially HTTP requests to
   `94.159.113.32` on port 80 with the path `/service`. Treat this address as a
   campaign IOC that may age or be reassigned, not as the sole detection signal.
4. Look for the mutex `N3sBJNQKOyBSqzOgQSQVf9` and the unusual user agent
   `gM7dczM61ejubNuJljRx` in endpoint or proxy telemetry.
5. Scope for other affected hosts, isolate confirmed systems, and collect memory
   from `jsc.exe` before termination when your response procedures permit it.

## Tuning

Allow-list only verified automation by specific script hash, signer, host, or
managed path. Avoid globally excluding AutoIt or `jsc.exe`, because their parent-
child relationship is the core signal. If the SIEM supports event correlation,
raise confidence when this process event is followed by remote-thread or
cross-process memory modification telemetry involving the same `jsc.exe` PID.
