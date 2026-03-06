"""Mixin: KernelJBPatchHookCredLabelMixin."""

from .kernel_jb_base import asm, _rd32

PACIBSP = bytes([0x7F, 0x23, 0x03, 0xD5])  # 0xD503237F


class KernelJBPatchHookCredLabelMixin:
    def _find_vnode_getattr_via_string(self):
        """Find vnode_getattr by locating a caller function via string ref.

        The string "vnode_getattr" appears in format strings like
        "%s: vnode_getattr: %d" inside functions that CALL vnode_getattr.
        We find such a caller, then extract the BL target near the string
        reference to get the real vnode_getattr address.

        Previous approach: find_string → find_string_refs → find_function_start
        was wrong because it returned the CALLER (e.g. an AppleImage4 function)
        instead of vnode_getattr itself.
        """
        str_off = self.find_string(b"vnode_getattr")
        if str_off < 0:
            return -1

        refs = self.find_string_refs(str_off)
        if not refs:
            return -1

        # The string ref is inside a function that calls vnode_getattr.
        # Scan backward from the string ref for a BL instruction — the
        # nearest preceding BL is very likely the BL vnode_getattr call
        # (the error message prints right after the call fails).
        ref_off = refs[0][0]  # ADRP offset
        for scan_off in range(ref_off - 4, ref_off - 64, -4):
            if scan_off < 0:
                break
            insn = _rd32(self.raw, scan_off)
            if (insn >> 26) == 0x25:  # BL opcode
                imm26 = insn & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26  # sign extend
                target = scan_off + imm26 * 4
                if any(s <= target < e for s, e in self.code_ranges):
                    self._log(
                        f"  [+] vnode_getattr at 0x{target:X} "
                        f"(via BL at 0x{scan_off:X}, "
                        f"near string ref at 0x{ref_off:X})"
                    )
                    return target

        # Fallback: try additional string hits
        start = str_off + 1
        for _ in range(5):
            str_off2 = self.find_string(b"vnode_getattr", start)
            if str_off2 < 0:
                break
            refs2 = self.find_string_refs(str_off2)
            if refs2:
                ref_off2 = refs2[0][0]
                for scan_off in range(ref_off2 - 4, ref_off2 - 64, -4):
                    if scan_off < 0:
                        break
                    insn = _rd32(self.raw, scan_off)
                    if (insn >> 26) == 0x25:  # BL
                        imm26 = insn & 0x3FFFFFF
                        if imm26 & (1 << 25):
                            imm26 -= 1 << 26
                        target = scan_off + imm26 * 4
                        if any(s <= target < e for s, e in self.code_ranges):
                            self._log(
                                f"  [+] vnode_getattr at 0x{target:X} "
                                f"(via BL at 0x{scan_off:X})"
                            )
                            return target
            start = str_off2 + 1

        return -1

    def _find_hook_cred_label_update_execve_target(self):
        """Locate the real sandbox execve hook body, not its MAC wrapper."""
        hook_off = self._resolve_symbol("_hook_cred_label_update_execve")
        if hook_off >= 0 and any(s <= hook_off < e for s, e in self.code_ranges):
            self._log(f"  [+] _hook_cred_label_update_execve symbol -> 0x{hook_off:X}")
            return hook_off

        ops_table = self._find_sandbox_ops_table_via_conf()
        if ops_table is None:
            self._log("  [-] sandbox ops table not found")
            return -1

        wrapper = self._read_ops_entry(ops_table, 18)
        if wrapper is None or wrapper <= 0:
            self._log("  [-] mac_policy_ops[18] entry missing")
            return -1
        if not any(s <= wrapper < e for s, e in self.code_ranges):
            self._log(f"  [-] mac_policy_ops[18] points outside code: 0x{wrapper:X}")
            return -1

        self._log(f"  [*] mac_policy_ops[18] wrapper at 0x{wrapper:X}")

        sandbox_create = self._resolve_symbol("_sandbox_create")
        proc_apply_masks = self._resolve_symbol("_proc_apply_syscall_masks")
        label_set_sandbox = self._resolve_symbol("_label_set_sandbox")
        needed = {sandbox_create, proc_apply_masks, label_set_sandbox} - {-1}

        def bl_targets(func_start, max_size):
            targets = set()
            func_end = self._find_func_end(func_start, max_size)
            for off in range(func_start, func_end, 4):
                insn = _rd32(self.raw, off)
                if (insn >> 26) != 0x25:
                    continue
                imm26 = insn & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                target = off + imm26 * 4
                if any(s <= target < e for s, e in self.code_ranges):
                    targets.add(target)
            return targets

        wrapper_targets = bl_targets(wrapper, 0x1400)
        for target in sorted(wrapper_targets):
            if self.raw[target : target + 4] != PACIBSP:
                continue
            target_calls = bl_targets(target, 0x800)
            if needed and not needed.issubset(target_calls):
                continue
            self._log(f"  [+] wrapper calls hook candidate 0x{target:X}")
            return target

        self._log("  [-] unable to resolve real hook body from wrapper")
        return -1

    def patch_hook_cred_label_update_execve(self):
        """Force the sandbox hook down its no-sandbox transition path.

        The old implementation patched the wrapper selected from
        `mac_policy_ops[18]` and returned immediately, which skips the
        hook's label/syscall-mask housekeeping and can leave the new exec
        credential with inherited parent sandbox state.

        Safer strategy:
          - resolve the real `_hook_cred_label_update_execve` body,
          - patch `ldr x0, [x0]` to `mov x0, #1`,
          - let the existing `cmp x0, #1; b.eq ...` flow clear/reset the
            sandbox state through the normal success path.
        """
        self._log("\n[JB] _hook_cred_label_update_execve: force no-sandbox path")

        hook_off = self._find_hook_cred_label_update_execve_target()
        if hook_off < 0:
            return False

        if self.raw[hook_off : hook_off + 4] != PACIBSP:
            self._log(
                f"  [-] hook prologue is not PACIBSP "
                f"(got 0x{_rd32(self.raw, hook_off):08X})"
            )
            return False

        load_mode_off = hook_off + 0x44
        if _rd32(self.raw, load_mode_off) != 0xF9400000:  # ldr x0, [x0]
            self._log(
                f"  [-] unexpected mode-load insn at 0x{load_mode_off:X}: "
                f"0x{_rd32(self.raw, load_mode_off):08X}"
            )
            return False

        if _rd32(self.raw, hook_off + 0x48) != 0xF100041F:  # cmp x0, #1
            self._log(
                f"  [-] unexpected cmp at 0x{hook_off + 0x48:X}: "
                f"0x{_rd32(self.raw, hook_off + 0x48):08X}"
            )
            return False

        self.emit(
            load_mode_off,
            asm("mov x0, #1"),
            "mov x0,#1 [_hook_cred_label_update_execve force no-sandbox path]",
        )
        return True
