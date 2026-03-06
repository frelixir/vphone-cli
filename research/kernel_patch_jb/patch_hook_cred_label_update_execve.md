# C23 `patch_hook_cred_label_update_execve`

## Scope

- Kernel analyzed: `kernelcache.research.vphone600`
- Analysis date: `2026-03-06`
- Method: IDA MCP + local `research/reference/xnu`
- Trust policy: prior notes for this patch are treated as untrusted and were not reused as ground truth

## Executive Verdict

`patch_hook_cred_label_update_execve` is currently failing because the repo implementation is not patching `_hook_cred_label_update_execve`.

It is patching the sandbox MAC-policy wrapper at `0xfffffe00093d2ce4` (`sub_FFFFFE00093D2CE4`) by using a heuristic of “largest early sandbox op in `ops[0..29]`”. That wrapper is the actual `mpo_cred_label_update_execve` dispatch entry in the sandbox policy ops table, but the internal hook body is a different function: `_hook_cred_label_update_execve` at `0xfffffe00093d0d0c`.

That mismatch is sufficient to explain why enabling the current patch prevents boot.

## Verified Binary Facts

### 1. The sandbox ops table entry points to a wrapper, not the hook body

- Verified ops table base used by existing notes/code: `0xfffffe0007a66d20`
- IDA memory read of table entries shows:
  - `ops[0x12]` / `ops[18]` at `0xfffffe0007a66db0` -> `0xfffffe00093d2ce4` (`sub_FFFFFE00093D2CE4`)
- Xref-to-wrapper result:
  - `0xfffffe00093d2ce4` has a data xref from `0xfffffe0007a66db0`

This proves the table entry is the wrapper function at `0xfffffe00093d2ce4`.

### 2. The wrapper calls the real hook body

- IDA decompilation of `sub_FFFFFE00093D2CE4` shows:
  - `updated = hook_cred_label_update_execve(&v98, a2, a3, &v97);`
- IDA disassembly of the same site shows:
  - `0xfffffe00093d3a4c  BL  _hook_cred_label_update_execve`
- Xrefs to `_hook_cred_label_update_execve` show one code caller:
  - `0xfffffe00093d3a4c` inside `sub_FFFFFE00093D2CE4`

This proves `_hook_cred_label_update_execve` is an internal callee of the wrapper, not the ops-table function itself.

### 3. The current repo patch logic hits the wrapper entry, not the hook

Current implementation in `scripts/patchers/kernel_jb_patch_hook_cred_label.py`:

- Finds the sandbox ops table
- Scans `ops[0..29]`
- Chooses the largest function as the target
- Emits:
  - `mov x0, xzr` at `orig_hook + 4`
  - `retab` at `orig_hook + 8`

For this kernel, the selected function is the wrapper at `0xfffffe00093d2ce4`, so the emitted low-risk patch lands at:

- `0xfffffe00093d2ce8` -> `mov x0, xzr`
- `0xfffffe00093d2cec` -> `retab`

This matches the existing runtime-verification artifacts:

- `research/kernel_patch_jb/runtime_verification/runtime_verification_summary.md`
  - `0xFFFFFE00093D2CE8` `mov x0,xzr [_hook_cred_label_update_execve low-risk]`
  - `0xFFFFFE00093D2CEC` `retab [_hook_cred_label_update_execve low-risk]`

So the repo’s current “validated hit” is validating the wrong function.

## XNU Semantics: What This Callback Actually Means

From open-source XNU in `research/reference/xnu`:

- `bsd/kern/kern_exec.c`
  - `exec_handle_sugid(struct image_params *imgp)` drives the exec-time credential transition
  - it stores the MAC label-update result in `imgp->ip_mac_return`
  - if `imgp->ip_mac_return != 0`, exec later fails with `EXEC_EXIT_REASON_SECURITY_POLICY`
- `bsd/kern/kern_credential.c`
  - `kauth_proc_label_update_execve(...)` creates/updates the new credential and calls MAC policy label-update logic
- `security/mac_vfs.c`
  - `mac_cred_label_update_execve(...)` iterates policy callbacks and invokes each non-NULL `mpo_cred_label_update_execve`
- `security/mac_policy.h`
  - `mpo_cred_label_update_execve_t(...)` returns `0` on success, nonzero if the update should terminate/deny the child

So for the sandbox policy callback in this path:

- returning `0` means “label update succeeded / do not kill exec”
- returning nonzero means the policy wants exec to fail later in the exec pipeline

## What The Real Hook Does

IDA decompilation of `_hook_cred_label_update_execve` at `0xfffffe00093d0d0c` shows that it is not a trivial gate. It performs sandbox state construction and process hardening work, including:

- calls to `_sandbox_create` / `_sandbox_create_for_executable`
- calls to `_label_set_sandbox`
- calls to `_proc_apply_syscall_masks`
- container/profile propagation
- mach message filtering setup (`sub_FFFFFE0007FD0EB0` in current IDA state)
- error-string output through the optional `const char **` out-parameter

At a high level, this hook applies the exec-time sandbox profile transition to the new process and then installs the corresponding syscall-mask and related runtime restrictions.

## Intended Effect Of A Correct Patch

If we early-return `0` from the real `_hook_cred_label_update_execve` body, the likely effect is:

- sandbox exec-time label update is skipped
- `label_set_sandbox(...)` is skipped
- `proc_apply_syscall_masks(...)` is skipped
- the sandbox policy reports success instead of deny/terminate

That matches the jailbreak goal described for this patch family: allow userland to invoke behaviors that would otherwise be blocked later by sandbox label transitions and syscall-mask enforcement.

## Why The Current Patch Breaks Boot

### Facts

- the current patch is applied to `sub_FFFFFE00093D2CE4`, not `_hook_cred_label_update_execve`
- `sub_FFFFFE00093D2CE4` is a large wrapper with stack allocation, temporary state construction, profile-name handling, container-manager interaction, and cleanup logic
- it calls `_hook_cred_label_update_execve` only near `0xfffffe00093d3a4c`, deep inside the function

### Strong inference

Returning `0` immediately from the wrapper entry suppresses the entire sandbox `mpo_cred_label_update_execve` callback, not just the final internal policy hook. That is much broader than intended and almost certainly changes launchd / early-userspace exec behavior in ways the rest of the kernel expects not to happen.

In contrast, returning `0` from the internal `_hook_cred_label_update_execve` body preserves the wrapper’s surrounding setup/cleanup logic and only disables the internal sandbox application stage.

This wrapper-vs-hook mismatch is the most plausible root cause of the no-boot regression.

## Recommended Patch Strategy For This Kernel

### Safe target for `kernelcache.research.vphone600`

- Function: `_hook_cred_label_update_execve`
- Address: `0xfffffe00093d0d0c`
- Suggested low-risk patchpoint (preserve `PACIBSP`):
  - `0xfffffe00093d0d10` -> `mov x0, xzr`
  - `0xfffffe00093d0d14` -> `retab`

Expected instruction replacement:

- before:
  - `0xfffffe00093d0d10  SUB SP, SP, #0x90`
  - `0xfffffe00093d0d14  STP X28, X27, [SP,#...]`
- after:
  - `0xfffffe00093d0d10  MOV X0, XZR`
  - `0xfffffe00093d0d14  RETAB`

Expected bytes:

- `mov x0, xzr` -> `E0 03 1F AA`
- `retab` -> `FF 0F 5F D6`

### Matcher requirements

The patcher should not use “largest function in sandbox ops table” for this patch.

For this patch, the correct resolution order is:

1. resolve `_hook_cred_label_update_execve` directly from symbols if present
2. otherwise resolve the sandbox `ops[18]` wrapper and follow its internal `BL` target to `_hook_cred_label_update_execve`
3. verify the resolved hook body contains the expected structural features:
   - `PACIBSP` prologue
   - calls to `_sandbox_create` or `_sandbox_create_for_executable`
   - call to `_label_set_sandbox`
   - call to `_proc_apply_syscall_masks`
4. only then emit the low-risk early return at `hook + 4` and `hook + 8`

## Proposed Non-Persistent Python Fix

User requested no repo source edits, so this is documented here only.

```python
def patch_hook_cred_label_update_execve(self):
    self._log("\n[JB] _hook_cred_label_update_execve: retargeted low-risk early return")

    hook = self._resolve_symbol("_hook_cred_label_update_execve")
    if hook < 0:
        wrapper = self._read_ops_entry(self._find_sandbox_ops_table_via_conf(), 18)
        if wrapper is None or wrapper <= 0:
            return False
        hook = self._find_bl_target_in_func(wrapper, "_hook_cred_label_update_execve")
        if hook < 0:
            return False

    if self.raw[hook:hook+4] != PACIBSP:
        return False

    self.emit(hook + 4, asm("mov x0, xzr"), "mov x0,xzr [_hook_cred_label_update_execve]")
    self.emit(hook + 8, bytes([0xFF, 0x0F, 0x5F, 0xD6]), "retab [_hook_cred_label_update_execve]")
    return True
```

The important change is not the emitted bytes; it is the target-resolution logic.

## Final Assessment

- Current repo status: unsafe / mis-targeted / should remain disabled
- Root cause: wrapper entry is being patched instead of the real hook body
- Expected effect of the corrected patch: disable exec-time sandbox label application and syscall-mask enforcement for this sandbox policy path while preserving the wrapper’s surrounding logic
- Confidence:
  - high that the current patcher hits the wrong function
  - medium-high that retargeting to `_hook_cred_label_update_execve` is the correct repair direction
  - medium that the exact `hook+4` / `hook+8` early return is sufficient on first try, because interaction with the separately-disabled `patch_syscallmask_apply_to_proc` path still needs combined runtime validation

## Source Artifacts Used

- `research/reference/xnu/security/mac_policy.h`
- `research/reference/xnu/security/mac_vfs.c`
- `research/reference/xnu/bsd/kern/kern_exec.c`
- `research/kernel_patch_jb/runtime_verification/runtime_verification_summary.md`
- `scripts/patchers/kernel_jb_patch_hook_cred_label.py`

