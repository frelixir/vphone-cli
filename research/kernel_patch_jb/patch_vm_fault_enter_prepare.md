# B9 `patch_vm_fault_enter_prepare` — re-analysis (2026-03-06)

## Scope

- Kernel: `kernelcache.research.vphone600`
- Primary function: `vm_fault_enter_prepare` @ `0xfffffe0007bb8818`
- Existing patch point emitted by the patcher: `0xfffffe0007bb898c`
- Existing callee at that point: `sub_FFFFFE0007C4B7DC`
- Paired unlock callee immediately after the guarded block: `sub_FFFFFE0007C4B9A4`

## Executive Summary

The current `patch_vm_fault_enter_prepare` analysis was wrong.

The patched instruction at `0xfffffe0007bb898c` is **not** a runtime code-signing gate and **not** a generic policy-deny helper. It is the lock-acquire half of a `pmap_lock_phys_page()` / `pmap_unlock_phys_page()` pair used while consuming the page's `vmp_clustered` state.

So the current patch does this:

- skips the physical-page / PVH lock acquire,
- still executes the protected critical section,
- still executes the corresponding unlock,
- therefore breaks lock pairing and page-state synchronization inside the VM fault path.

That is fully consistent with a boot-time failure.

## What the current patcher actually matches

Current implementation: `scripts/patchers/kernel_jb_patch_vm_fault.py:7`

The matcher looks for this in-function shape:

- `BL target(rare)`
- `LDRB wN, [xM, #0x2c]`
- `TBZ/TBNZ wN, #bit, ...`

That logic resolves to exactly one site in `vm_fault_enter_prepare` and emits:

- VA: `0xFFFFFE0007BB898C`
- Patch: `944b0294 -> 1f2003d5`
- Description: `NOP [_vm_fault_enter_prepare]`

IDA disassembly at the matched site:

```asm
0xfffffe0007bb8988  MOV   X0, X27
0xfffffe0007bb898c  BL    sub_FFFFFE0007C4B7DC
0xfffffe0007bb8990  LDRB  W8, [X20,#0x2C]
0xfffffe0007bb8994  TBZ   W8, #5, loc_FFFFFE0007BB89C4
0xfffffe0007bb8998  LDR   W8, [X20,#0x1C]
...
0xfffffe0007bb89c0  STR   W8, [X20,#0x2C]
0xfffffe0007bb89c4  MOV   X0, X27
0xfffffe0007bb89c8  BL    sub_FFFFFE0007C4B9A4
```

The old assumption was: “call helper, then test a security flag, so NOP the helper.”

The re-analysis result is: the call is a lock acquire, the tested bit is `m->vmp_clustered`, and the second call is the matching unlock.

## IDA evidence: what the callees really are

### `sub_FFFFFE0007C4B7DC`

IDA shows a physical-page-index based lock acquisition routine, not a deny/policy check:

- takes `X0` as page number / index input,
- checks whether the physical page is in-range,
- on the normal path acquires a lock associated with that physical page,
- on contended paths may sleep / block,
- returns only after the lock is acquired.

Key observations from IDA:

- the function begins by deriving an indexed address from `X0` (`UBFIZ X9, X0, #0xE, #0x20`),
- it performs lock acquisition with `LDXR` / `CASA` on a fallback lock or calls into a lower lock primitive,
- it contains a contended-wait path (`assert_wait`, `thread_block` style flow),
- it does **not** contain a boolean policy return used by the caller.

This matches `pmap_lock_phys_page(ppnum_t pn)` semantics.

### `sub_FFFFFE0007C4B9A4`

IDA shows the paired unlock routine:

- same page-number based addressing scheme,
- direct fast-path jump into a low-level unlock helper for the backup lock case,
- range-based path that reconstructs a `locked_pvh_t`-like wrapper and unlocks the per-page PVH lock.

This matches `pmap_unlock_phys_page(ppnum_t pn)` semantics.

## XNU source mapping

The matched basic block in `vm_fault_enter_prepare()` maps cleanly onto the `m->vmp_pmapped == FALSE && m->vmp_clustered` handling in XNU.

Relevant source: `research/reference/xnu/osfmk/vm/vm_fault.c:3958`

```c
if (m->vmp_pmapped == FALSE) {
    if (m->vmp_clustered) {
        if (*type_of_fault == DBG_CACHE_HIT_FAULT) {
            if (object->internal) {
                *type_of_fault = DBG_PAGEIND_FAULT;
            } else {
                *type_of_fault = DBG_PAGEINV_FAULT;
            }
            VM_PAGE_COUNT_AS_PAGEIN(m);
        }
        VM_PAGE_CONSUME_CLUSTERED(m);
    }
}
```

The lock/unlock comes from `VM_PAGE_CONSUME_CLUSTERED(mem)` in `research/reference/xnu/osfmk/vm/vm_page_internal.h:999`:

```c
#define VM_PAGE_CONSUME_CLUSTERED(mem)                          \
    MACRO_BEGIN                                                 \
    ppnum_t __phys_page;                                        \
    __phys_page = VM_PAGE_GET_PHYS_PAGE(mem);                   \
    pmap_lock_phys_page(__phys_page);                           \
    if (mem->vmp_clustered) {                                   \
        vm_object_t o;                                          \
        o = VM_PAGE_OBJECT(mem);                                \
        assert(o);                                              \
        o->pages_used++;                                        \
        mem->vmp_clustered = FALSE;                             \
        VM_PAGE_SPECULATIVE_USED_ADD();                         \
    }                                                           \
    pmap_unlock_phys_page(__phys_page);                         \
    MACRO_END
```

And those helpers are defined here:

- `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap.c:7520` — `pmap_lock_phys_page(ppnum_t pn)`
- `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap.c:7535` — `pmap_unlock_phys_page(ppnum_t pn)`
- `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap_data.h:330` — `pvh_lock(unsigned int index)`
- `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap_data.h:497` — `pvh_unlock(locked_pvh_t *locked_pvh)`

## Why the current patch can break boot

The current patch NOPs only the acquire side:

- before: `BL sub_FFFFFE0007C4B7DC`
- after: `NOP`

But the surrounding code still:

- reads `m->vmp_clustered`,
- may increment `object->pages_used`,
- clears `m->vmp_clustered`,
- calls `sub_FFFFFE0007C4B9A4` unconditionally afterwards.

That means the patch turns a balanced critical section into:

1. no lock acquire,
2. mutate shared page/object state,
3. unlock a lock that was never acquired.

Concrete risks:

- PVH / backup-lock state corruption,
- waking or releasing waiters against an unowned lock,
- racing `m->vmp_clustered` / `object->pages_used` updates during active fault handling,
- early-boot hangs or panics when clustered pages are first faulted in.

This is a much stronger explanation for the observed boot failure than the old “wrong security helper” theory.

## What this patch actually changes semantically

If applied successfully, the patch does **not** bypass code-signing validation.

It only removes synchronization from this clustered-page bookkeeping path:

- page-in accounting (`DBG_CACHE_HIT_FAULT` -> `DBG_PAGEIND_FAULT` / `DBG_PAGEINV_FAULT`),
- `object->pages_used++`,
- `m->vmp_clustered = FALSE`,
- speculative-page accounting.

So the effective behavior is:

- **not** “allow weird userspace methods,”
- **not** “disable vm fault code-signing rejection,”
- **not** “bypass a kernel deny path,”
- only “break the lock discipline around clustered-page consumption.”

For the jailbreak goal, this patch is mis-targeted.

## Where the real security-relevant logic is in this function

Two genuinely security-relevant regions exist in the same XNU function, but they are **not** the current patch site:

1. `pmap_has_prot_policy(...)` handling in `research/reference/xnu/osfmk/vm/vm_fault.c:3943`
   - this is where protection-policy constraints are enforced for the requested mapping protections.
2. `vm_fault_validate_cs(...)` in `research/reference/xnu/osfmk/vm/vm_fault.c:3991`
   - this is the runtime code-signing validation path.

So if the jailbreak objective is “allow runtime execution / invocation patterns without kernel interception,” the current B9 patch is aimed at the wrong block.

## Practical conclusion

### Verdict on the current patch

- Keep `patch_vm_fault_enter_prepare` disabled.
- Do **not** re-enable the current NOP at `0xFFFFFE0007BB898C`.
- Treat the previous “Skip fault check” description as incorrect for `vphone600` research kernel.

### Likely root cause of boot failure

Most likely root cause: unbalanced `pmap_lock_phys_page()` / `pmap_unlock_phys_page()` behavior in the hot VM fault path.

### Recommended next research direction

If we still want a B9-class runtime-memory patch, the next candidates to study are:

- `vm_fault_validate_cs()`
- `vm_fault_cs_check_violation()`
- `vm_fault_cs_handle_violation()`
- the `pmap_has_prot_policy()` / `cs_bypass` decision region

Those are the places that can plausibly affect runtime execution restrictions. The current B9 site cannot.

## Minimal safe recommendation for patch schedule

For now, the correct action is not “retarget this exact byte write,” but:

- leave `patch_vm_fault_enter_prepare` disabled,
- mark its prior purpose label as wrong,
- open a fresh analysis track for the real code-signing fault-validation path.

## Evidence summary

- Function symbol: `vm_fault_enter_prepare` @ `0xfffffe0007bb8818`
- Current patchpoint: `0xfffffe0007bb898c`
- Current matched callee: `sub_FFFFFE0007C4B7DC` -> `pmap_lock_phys_page()` equivalent
- Paired callee: `sub_FFFFFE0007C4B9A4` -> `pmap_unlock_phys_page()` equivalent
- XNU semantic match:
  - `research/reference/xnu/osfmk/vm/vm_fault.c:3958`
  - `research/reference/xnu/osfmk/vm/vm_page_internal.h:999`
  - `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap.c:7520`
  - `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap_data.h:330`
  - `research/reference/xnu/osfmk/arm64/sptm/pmap/pmap_data.h:497`
