# C21 `patch_cred_label_update_execve`

## Scope

- Kernel used for reverse engineering: `kernelcache.research.vphone600`.
- IDA symbol / address: `__Z25_cred_label_update_execveP5ucredS0_P4procP5vnodexS4_P5labelS6_S6_PjPvmPi` at `0xFFFFFE000864DEFC`.
- XNU semantic reference: `research/reference/xnu/security/mac_vfs.c`, `research/reference/xnu/bsd/kern/kern_exec.c`, `research/reference/xnu/bsd/kern/kern_credential.c`, `research/reference/xnu/osfmk/kern/cs_blobs.h`.

This note is a fresh re-analysis. Older notes for this patch were treated as untrusted and not reused as ground truth.

## Call Stack

Exec-time path in XNU source:

1. `exec_handle_sugid()` asks `mac_cred_check_label_update_execve(...)` whether any MAC policy wants an exec-time credential transition.
2. If yes, `exec_handle_sugid()` calls `kauth_proc_label_update_execve(...)`.
3. `kauth_proc_label_update_execve(...)` allocates / updates the new credential and calls `mac_cred_label_update_execve(...)`.
4. `mac_cred_label_update_execve(...)` iterates `mac_policy_list` and invokes each policy's `mpo_cred_label_update_execve` hook.
5. AMFI's hook is `_cred_label_update_execve` in `com.apple.driver.AppleMobileFileIntegrity`.

Relevant source anchors:

- `research/reference/xnu/bsd/kern/kern_exec.c:6854`
- `research/reference/xnu/bsd/kern/kern_exec.c:6950`
- `research/reference/xnu/bsd/kern/kern_credential.c:4367`
- `research/reference/xnu/security/mac_vfs.c:777`

## What The Function Actually Does

Reverse engineering of `0xFFFFFE000864DEFC` shows that AMFI's hook is not just a boolean kill gate.

It performs all of the following before returning success or failure:

- validates the exec target / `cs_blob` and reports AMFI analytics;
- checks multiple kill conditions and returns `1` on rejection;
- mutates `*csflags` during successful exec handling;
- derives extra flags from entitlement state;
- performs final bookkeeping before returning `0`.

Observed kill / deny subpaths in IDA:

- completely unsigned code path;
- Restricted Execution Mode denials;
- legacy VPN plugin rejection;
- dyld signature verification failure;
- helper failure from `sub_FFFFFE000864E5A0(...)` with reason string.

All of those failure edges converge on the shared kill return at `0xFFFFFE000864E38C` (`mov w0, #1`).

Observed success-path `csflags` mutations in IDA:

- `0xFFFFFE000864E1E8`: ORs `0x2200` or `0x200` into `*csflags` depending on dyld / helper state.
- `0xFFFFFE000864E200`: ORs `0x802A00` into `*csflags` when AMFI-derived entitlement flags require SIP-style inheritance.
- `0xFFFFFE000864E4EC`, `0xFFFFFE000864E500`, `0xFFFFFE000864E51C`, `0xFFFFFE000864E534`: OR installer / rootless / datavault / NVRAM-related bits into `*csflags`.
- `0xFFFFFE000864E570`: ORs `0x2A00` into `*csflags` in the final success tail.

The relevant flag meanings from XNU are in `research/reference/xnu/osfmk/kern/cs_blobs.h:32`.

## Why The Old Patch Broke Boot

The previous implementations were both too broad:

1. the original shellcode version forged new `csflags` at function exit;
2. the later "low-risk" version simply returned from function entry.

The entry-return strategy is fundamentally wrong for boot stability because it skips AMFI's normal exec-time work entirely.

That means it bypasses:

- `cs_blob` / signature-state handling;
- AMFI auxiliary analytics / bookkeeping;
- entitlement-derived `csflags` propagation;
- final per-exec state setup that later code expects to have happened.

In short: `_cred_label_update_execve` is on the boot-critical exec path, so turning it into an unconditional `return 0` is not a safe jailbreak strategy.

## Repaired Patch Strategy

The new patcher no longer returns from function entry.

Instead it:

1. keeps AMFI's full exec-time logic intact;
2. locates the final success tail while `x26 == csflags` is still live;
3. redirects that tail to a small trampoline;
4. clears only the restrictive execution bits from `*csflags`;
5. branches back into the original epilogue.

The current trampoline clears this mask:

- `CS_HARD`
- `CS_KILL`
- `CS_CHECK_EXPIRATION`
- `CS_RESTRICT`
- `CS_ENFORCEMENT`
- `CS_REQUIRE_LV`

Bitmask used by the patcher: `0xFFFFC0FF`.

This preserves AMFI's normal validation / entitlement work while removing the sticky exec-time restrictions that are most hostile to jailbreak tooling.

## Intended Effect

After the repaired patch:

- AMFI still runs its normal exec-time hook and keeps boot-critical side effects intact.
- Exec success remains driven by the existing AMFI flow; kill-return bypass is still handled separately by `patch_amfi_execve_kill_path`.
- Successfully launched processes end up with a less restrictive `csflags` set, especially around kill / hard / library-validation style behavior.

This is a much narrower and more defensible jailbreak patch than forcing an unconditional success return at function entry.

## Current Status

- Patch implementation updated in `scripts/patchers/kernel_jb_patch_cred_label.py`.
- Default schedule remains disabled in `scripts/patchers/kernel_jb.py` until boot validation is rerun.
- If this patch still fails, the next suspect is not AMFI's kill return itself, but over-broad `csflags` relaxation semantics for specific early-boot binaries.
