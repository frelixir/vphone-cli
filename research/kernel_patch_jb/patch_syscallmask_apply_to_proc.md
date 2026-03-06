# C22 `patch_syscallmask_apply_to_proc`

## Status

- Re-analysis date: `2026-03-06`
- Scope: `kernelcache.research.vphone600`
- Prior notes for this patch are treated as untrusted unless restated below.
- Current conclusion: the shipped/recorded C22 implementation does **not** patch the syscall-mask apply path. Its verified writes land in `_profile_syscallmask_destroy` under an underflow-panic slow path, so the old patch is effectively a misidentification with little or no normal-path effect.

## What This Mechanism Actually Does

This path is not a generic parser or allocator hook. Its real job is to **install per-process syscall filter masks** used later by three enforcement sites:

- Unix syscall dispatch
- Mach trap dispatch
- Kernel MIG / kobject dispatch

In XNU source terms, the closest semantic match is `proc_set_syscall_filter_mask(proc_t p, int which, unsigned char *maskptr, size_t masklen)` in `research/reference/xnu/bsd/kern/kern_proc.c:5142`.

Important XNU references:

- `research/reference/xnu/bsd/sys/proc.h:558` — `SYSCALL_MASK_UNIX`, `SYSCALL_MASK_MACH`, `SYSCALL_MASK_KOBJ`
- `research/reference/xnu/bsd/kern/kern_proc.c:5142` — setter for the three mask kinds
- `research/reference/xnu/bsd/dev/arm/systemcalls.c:161` — Unix syscall enforcement
- `research/reference/xnu/osfmk/arm64/bsd_arm64.c:253` — Mach trap enforcement
- `research/reference/xnu/osfmk/kern/ipc_kobject.c:568` — kobject/MIG enforcement
- `research/reference/xnu/bsd/kern/kern_fork.c:1028` — Unix mask inheritance on fork
- `research/reference/xnu/osfmk/kern/task.c:1759` — Mach/KOBJ filter inheritance

Semantics from XNU:

- If a filter mask pointer is `NULL`, the later dispatch path does **not** perform the extra mask-based deny/evaluate step.
- If a filter mask pointer is present and the bit is clear, the kernel falls back into MACF/Sandbox evaluation.
- Therefore, for jailbreak purposes, the most conservative way to neutralize this layer is **not** to corrupt parsing or destroy paths, but to ensure the per-proc/task mask pointers are installed as `NULL`.

## Revalidated Live Call Chain (IDA)

### 1. Real apply layer in the sandbox kext

`_proc_apply_syscall_masks` at `0xfffffe00093b1a88`

Decompiled shape:

- Calls helper `sub_FFFFFE00093AE5E8(proc, 0, unix_mask)`
- Calls helper `sub_FFFFFE00093AE5E8(proc, 1, mach_mask)`
- Calls helper `sub_FFFFFE00093AE5E8(proc, 2, kobj_mask)`
- On failure, reports:
  - `"failed to apply unix syscall mask"`
  - `"failed to apply mach trap mask"`
  - `"failed to apply kernel MIG routine mask"`

This is the real high-level “apply to proc” logic for the current kernel, even though the stripped symbol is now named `_proc_apply_syscall_masks`, not `_syscallmask_apply_to_proc`.

### 2. Immediate callers of `_proc_apply_syscall_masks`

IDA xrefs show live callers:

- `_proc_apply_sandbox` at `0xfffffe00093b17d4`
- `_hook_cred_label_update_execve` at `0xfffffe00093d0dfc`

That means this path is exercised both when sandbox labels are applied and during exec-time label updates.

### 3. Helper that bridges into kernel proc/task RO state setters

`sub_FFFFFE00093AE5E8` at `0xfffffe00093ae5e8`

Observed behavior:

- Accepts `(proc, which, maskptr)`
- If `maskptr != NULL`, loads the expected mask length for `which`
- Tail-calls into kernel text at `0xfffffe0007fd0c74`

This helper is a narrow wrapper for the true setter logic.

### 4. Kernel-side setter core

The tail-call target is inside `sub_FFFFFE0007FD0B64`, entered at `0xfffffe0007fd0c74`.

Validated behavior from disassembly:

- `which == 0` (Unix): if `X2 == 0`, length validation is skipped and the proc RO syscall-mask pointer is updated with `NULL`
- `which == 1` (Mach): if `X2 == 0`, length validation is skipped and the task Mach filter pointer is updated with `NULL`
- `which == 2` (KOBJ/MIG): if `X2 == 0`, length validation is skipped and the task KOBJ filter pointer is updated with `NULL`
- Invalid `which` returns `EINVAL` (`0x16`)

This matches the XNU setter semantics closely enough to trust the mapping.

## What The Old C22 Implementation Actually Hit

Historical runtime verification logged these writes:

- `0xfffffe00093ae6e4`: `ff8300d1 -> e0031faa`
- `0xfffffe00093ae6e8`: `fd7b01a9 -> ff0f5fd6`

IDA mapping shows both addresses are inside `_profile_syscallmask_destroy` at `0xfffffe00093ae6a4`, not inside any apply-to-proc routine.

More specifically:

- `_profile_syscallmask_destroy` normal path ends at `0xfffffe00093ae6dc`
- `0xfffffe00093ae6e0` is the start of the **underflow panic slow path**
- The old patch replaced instructions in that slow path only

So the old “low-risk early return” did **not** disable syscall mask installation. It merely neutered a panic-reporting subpath after profile mask count underflow.

## Why The Old Matcher Misidentified The Target

The old patcher logic in `scripts/patchers/kernel_jb_patch_syscallmask.py` relies on:

- string anchor `"syscallmask.c"`
- nearby function-start recovery using `PACIBSP`
- legacy 4-argument prologue heuristics from an older shellcode-based implementation

On this kernel:

- the legacy `_syscallmask_apply_to_proc` shape is gone
- the nearby string cluster includes create/destroy/populate helpers
- the nearest `PACIBSP` around the string is at `0xfffffe00093ae6e0`, which is **not a real function entry** for the apply path

That is why the old low-risk fallback produced a false positive.

## Real Targets That Matter

### Safe semantic target

`_proc_apply_syscall_masks` at `0xfffffe00093b1a88`

This is the right place if the goal is:

- allow processes to keep running without syscall/mach/kobj mask-based interception
- preserve surrounding control flow and error handling
- avoid corrupting parser state or shared kernel setter logic

### Alternative narrower helper target

`sub_FFFFFE00093AE5E8` at `0xfffffe00093ae5e8`

This helper only appears to serve the apply layer here, but it is still a broader patch than changing the three call sites directly.

## Recommended Patch Strategy (Not Applied Here)

Per your instruction, no repository code changes are landed here. This section documents the patch strategy that appears correct from the live re-analysis.

### Preferred strategy: clear masks explicitly at the three call sites

Patch the three `LDR X2, [X8]` instructions in `_proc_apply_syscall_masks` to `MOV X2, XZR`.

Patchpoints:

1. Unix mask load
   - VA: `0xfffffe00093b1abc`
   - Before: `020140f9` (`ldr x2, [x8]`)
   - After:  `e2031faa` (`mov x2, xzr`)

2. Mach trap mask load
   - VA: `0xfffffe00093b1af0`
   - Before: `020140f9` (`ldr x2, [x8]`)
   - After:  `e2031faa` (`mov x2, xzr`)

3. KOBJ/MIG mask load
   - VA: `0xfffffe00093b1b28`
   - Before: `020140f9` (`ldr x2, [x8]`)
   - After:  `e2031faa` (`mov x2, xzr`)

Why this is preferred:

- It preserves `_proc_apply_syscall_masks` control flow and error propagation.
- It still calls the existing setter path for all three mask types.
- The setter already supports `maskptr == NULL`, so this becomes a clean “clear installed filters” operation instead of a malformed early return.
- It avoids stale inherited masks remaining attached to the process.

### Secondary strategy: null out the helper argument once

Single-site alternative:

- VA: `0xfffffe00093ae600`
- Before: `f40301aa` (`mov x19, x2`)
- After:  `f3031faa` (`mov x19, xzr`)

This also forces all three setter calls to receive `NULL`, but it is slightly wider than the three-site `_proc_apply_syscall_masks` patch and depends on there being no unintended callers of this helper entry.

## What Not To Patch

### Do not patch `_profile_syscallmask_destroy`

- Address: `0xfffffe00093ae6a4`
- Reason: lifecycle cleanup only; old C22 hit this by mistake

### Do not patch `_populate_syscall_mask`

- Address: `0xfffffe00093cf7f4`
- Reason: parser/allocation path for sandbox profile data; breaking it risks malformed state during sandbox construction and early boot

### Avoid patching the kernel-side setter core directly unless necessary

- Entry used here: `0xfffffe0007fd0c74`
- Reason: shared proc/task RO setters are broader-scope and easier to overpatch than the sandbox apply wrapper

## Expected Effect Of The Recommended Patch

If the three load sites are rewritten to `mov x2, xzr`:

- Unix syscall filter mask is cleared
- Mach trap filter mask is cleared
- Kernel MIG/kobject filter mask is cleared
- Later dispatchers no longer see an installed mask pointer for those channels
- The syscall/mach/kobj “bit clear -> consult MACF/Sandbox evaluator” layer is therefore skipped for these mask-based checks

This does **not** disable every sandbox/MACF path. It only removes this specific mask-installation layer.

## Why A Plain Early Return Is Inferior

A naive early return from `_proc_apply_syscall_masks` would likely return success, but it may leave previously inherited masks untouched.

That is especially risky because XNU inherits these masks across fork/task creation:

- Unix: `research/reference/xnu/bsd/kern/kern_fork.c:1028`
- Mach/KOBJ: `research/reference/xnu/osfmk/kern/task.c:1759`

So an early return can leave stale filter pointers in place, while the explicit `NULL`-setter strategy actively clears them.

## Boot-Risk Assessment

Most plausible failure modes if this family is patched incorrectly:

- stale or invalid mask pointers remain attached to early boot tasks
- Mach/KOBJ traffic gets filtered unexpectedly during bootstrap
- parser/create/destroy bookkeeping becomes inconsistent
- a broad setter patch corrupts proc/task RO state outside the intended sandbox apply path

The proposed three-site `mov x2, xzr` strategy is the narrowest approach found so far that still achieves the intended jailbreak effect.

## Bottom Line

- The historical C22 implementation is mis-targeted.
- The real current “apply to proc” logic is `_proc_apply_syscall_masks`, not `_profile_syscallmask_destroy`.
- The correct modern strategy is to keep the setter path intact but pass `NULL` masks for Unix/Mach/KOBJ, preferably by patching the three `LDR X2, [X8]` instructions at:
  - `0xfffffe00093b1abc`
  - `0xfffffe00093b1af0`
  - `0xfffffe00093b1b28`
- This should neutralize syscall-mask-based interception more safely than the previous pseudo-success patch.
