"""Mixin: KernelJBPatchCredLabelMixin."""

from .kernel_jb_base import asm, _rd32


class KernelJBPatchCredLabelMixin:
    _RET_INSNS = (0xD65F0FFF, 0xD65F0BFF, 0xD65F03C0)
    _RELAX_CSMASK = 0xFFFFC0FF

    def _is_cred_label_execve_candidate(self, func_off, anchor_refs):
        """Validate candidate function shape for _cred_label_update_execve."""
        func_end = self._find_func_end(func_off, 0x1000)
        if func_end - func_off < 0x200:
            return False, 0, func_end

        anchor_hits = sum(1 for r in anchor_refs if func_off <= r < func_end)
        if anchor_hits == 0:
            return False, 0, func_end

        has_arg9_load = False
        has_flags_load = False
        has_flags_store = False

        for off in range(func_off, func_end, 4):
            d = self._disas_at(off)
            if not d:
                continue
            i = d[0]
            op = i.op_str.replace(" ", "")
            if i.mnemonic == "ldr" and op.startswith("x26,[x29"):
                has_arg9_load = True
                break

        for off in range(func_off, func_end, 4):
            d = self._disas_at(off)
            if not d:
                continue
            i = d[0]
            op = i.op_str.replace(" ", "")
            if i.mnemonic == "ldr" and op.startswith("w") and ",[x26" in op:
                has_flags_load = True
            elif i.mnemonic == "str" and op.startswith("w") and ",[x26" in op:
                has_flags_store = True
            if has_flags_load and has_flags_store:
                break

        ok = has_arg9_load and has_flags_load and has_flags_store
        score = anchor_hits * 10 + (1 if has_arg9_load else 0) + (1 if has_flags_load else 0) + (1 if has_flags_store else 0)
        return ok, score, func_end

    def _find_cred_label_execve_func(self):
        """Locate _cred_label_update_execve by AMFI kill-path string cluster."""
        anchor_strings = (
            b"AMFI: hook..execve() killing",
            b"Attempt to execute completely unsigned code",
            b"Attempt to execute a Legacy VPN Plugin",
            b"dyld signature cannot be verified",
        )

        anchor_refs = set()
        candidates = set()
        s, e = self.amfi_text

        for anchor in anchor_strings:
            str_off = self.find_string(anchor)
            if str_off < 0:
                continue
            refs = self.find_string_refs(str_off, s, e)
            if not refs:
                refs = self.find_string_refs(str_off)
            for adrp_off, _, _ in refs:
                anchor_refs.add(adrp_off)
                func_off = self.find_function_start(adrp_off)
                if func_off >= 0 and s <= func_off < e:
                    candidates.add(func_off)

        best_func = -1
        best_score = -1
        for func_off in sorted(candidates):
            ok, score, _ = self._is_cred_label_execve_candidate(func_off, anchor_refs)
            if ok and score > best_score:
                best_score = score
                best_func = func_off

        return best_func

    def _find_cred_label_return_site(self, func_off):
        """Pick a return site with full epilogue restore (SP/frame restored)."""
        func_end = self._find_func_end(func_off, 0x1000)
        fallback = -1
        for off in range(func_end - 4, func_off, -4):
            val = _rd32(self.raw, off)
            if val not in self._RET_INSNS:
                continue
            if fallback < 0:
                fallback = off

            saw_add_sp = False
            saw_ldp_fp = False
            for prev in range(max(func_off, off - 0x24), off, 4):
                d = self._disas_at(prev)
                if not d:
                    continue
                i = d[0]
                op = i.op_str.replace(" ", "")
                if i.mnemonic == "add" and op.startswith("sp,sp,#"):
                    saw_add_sp = True
                elif i.mnemonic == "ldp" and op.startswith("x29,x30,[sp"):
                    saw_ldp_fp = True

            if saw_add_sp and saw_ldp_fp:
                return off

        return fallback

    def _find_cred_label_success_tail(self, func_off):
        """Locate the final success tail while the csflags pointer is still live.

        On vphone600 AMFI, the last success block looks like:
          ldr w8, [x26]
          tst w8, w27
          ...
          mov w0, #0
          ldp x29, x30, [sp, ...]

        We patch the first instruction of that tail so the trampoline can
        still use x26 (the spilled `u_int *csflags` argument) before the
        epilogue restores callee-saved registers.
        """
        func_end = self._find_func_end(func_off, 0x1000)

        epilogue_off = -1
        for off in range(func_end - 4, func_off, -4):
            d = self._disas_at(off)
            if not d:
                continue
            i = d[0]
            op = i.op_str.replace(" ", "")
            if i.mnemonic == "ldp" and op.startswith("x29,x30,[sp"):
                epilogue_off = off
                break

        if epilogue_off < 0:
            return -1, -1

        tail_off = -1
        scan_start = max(func_off, epilogue_off - 0x40)
        for off in range(epilogue_off - 8, scan_start - 4, -4):
            d0 = self._disas_at(off)
            d1 = self._disas_at(off + 4)
            if not d0 or not d1:
                continue
            i0 = d0[0]
            i1 = d1[0]
            op0 = i0.op_str.replace(" ", "")
            op1 = i1.op_str.replace(" ", "")
            if i0.mnemonic == "ldr" and op0 == "w8,[x26]" and i1.mnemonic == "tst" and op1 == "w8,w27":
                tail_off = off
                break

        return tail_off, epilogue_off

    def patch_cred_label_update_execve(self):
        """Relax exec-time code-signing flags after AMFI finishes normal work.

        The old entry-time early return broke boot because it skipped AMFI's
        normal exec-time processing entirely: cs_blob lookup, analytics,
        entitlement-derived csflags, and shared-state bookkeeping.

        The repaired strategy keeps the whole AMFI function intact and only
        redirects the final success tail to a tiny trampoline that clears the
        restrictive exec flags from `*csflags` before branching into the
        function's normal epilogue.
        """
        self._log("\n[JB] _cred_label_update_execve: tail csflags relax")

        func_off = -1

        # Try symbol first, but still validate shape.
        for sym, off in self.symbols.items():
            if "cred_label_update_execve" in sym and "hook" not in sym:
                ok, _, _ = self._is_cred_label_execve_candidate(off, set([off]))
                if ok:
                    func_off = off
                break

        if func_off < 0:
            func_off = self._find_cred_label_execve_func()

        if func_off < 0:
            self._log("  [-] function not found, skipping shellcode patch")
            return False

        tail_off, epilogue_off = self._find_cred_label_success_tail(func_off)
        if tail_off < 0 or epilogue_off < 0:
            self._log("  [-] final success tail not found")
            return False

        cave = self._find_code_cave(20)
        if cave < 0:
            self._log("  [-] no code cave found for csflags relax trampoline")
            return False

        branch_back = self._encode_b(cave + 16, epilogue_off)
        if not branch_back:
            self._log("  [-] branch from trampoline back to epilogue is out of range")
            return False

        shellcode = (
            asm("ldr w8, [x26]")
            + asm(f"and w8, w8, #{self._RELAX_CSMASK:#x}")
            + asm("str w8, [x26]")
            + asm("mov w0, #0")
            + branch_back
        )

        for index in range(0, len(shellcode), 4):
            self.emit(
                cave + index,
                shellcode[index : index + 4],
                f"trampoline+{index} [_cred_label_update_execve tail relax]",
            )

        branch_to_cave = self._encode_b(tail_off, cave)
        if not branch_to_cave:
            self._log("  [-] branch from success tail to trampoline is out of range")
            return False

        self.emit(
            tail_off,
            branch_to_cave,
            "b cave [_cred_label_update_execve success-tail relax]",
        )

        return True
