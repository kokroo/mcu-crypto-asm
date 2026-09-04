//! Static constant-time audit of the generated assembly.
//!
//! For hand-written assembly the strongest practical evidence is structural,
//! and it is machine-checkable: if the code contains no secret-dependent
//! branch, no secret-dependent memory address, and no variable-latency
//! instruction, then its instruction trace — and on these cores its cycle
//! count — cannot depend on the operand values.
//!
//! This audit runs in `cargo test` on the host by parsing the `.S` files, so
//! it also acts as a regression gate: an edit that introduces a data-dependent
//! branch fails the build rather than silently leaking.
//!
//! The complementary *dynamic* check lives in `harness/src/bin/ct.rs`, which
//! executes the real assembly under QEMU with `-icount` and asserts the
//! instruction count is byte-identical across operands chosen to take opposite
//! paths through the conditional subtraction.

use std::collections::BTreeSet;

/// Strip comments and blank lines, returning `(line_no, instruction)` pairs.
fn instructions(src: &str, comment: char) -> Vec<(usize, String)> {
    src.lines()
        .enumerate()
        .map(|(i, l)| {
            let l = match l.find(comment) {
                Some(p) => &l[..p],
                None => l,
            };
            (i + 1, l.trim().to_string())
        })
        .filter(|(_, l)| {
            !l.is_empty()
                && !l.starts_with('.')      // directives
                && !l.ends_with(':') // labels
        })
        .collect()
}

fn opcode(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

// ---------------------------------------------------------------------------
// Cortex-M4
// ---------------------------------------------------------------------------

const CM4_SRC: &str = include_str!("../asm/cortex_m4.S");

/// Instructions whose latency on Cortex-M4 does not depend on operand values.
/// Notably absent: `udiv`/`sdiv` (variable latency), and any of the
/// `it`-block conditional forms.
const CM4_ALLOWED: &[&str] = &[
    "ldr", "str", "umaal", "eor", "and", "orr", "mov", "mov.w", "add", "adds", "adc", "adcs",
    "adc.w", "sub", "subs", "sbc", "sbcs", "push", "pop", "bne", "mvn", "movw", "movt", "ldrd",
    "strd", "vpush", "vpop", "vldm", "vmov",
];

#[test]
fn cortex_m4_uses_only_constant_time_instructions() {
    let mut unexpected = BTreeSet::new();
    for (line_no, insn) in instructions(CM4_SRC, '@') {
        let op = opcode(&insn);
        if !CM4_ALLOWED.contains(&op) {
            unexpected.insert(format!("line {line_no}: {insn}"));
        }
    }
    assert!(
        unexpected.is_empty(),
        "cortex_m4.S contains instructions not on the constant-time allow-list \
         (add them only after confirming fixed latency):\n{}",
        unexpected.iter().cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn cortex_m4_has_no_data_dependent_branches() {
    // The only branches permitted are the outer-loop back-edges (one per
    // curve routine) and the function returns via `pop {..., pc}`.
    let mut branches = Vec::new();
    for (line_no, insn) in instructions(CM4_SRC, '@') {
        let op = opcode(&insn);
        if op.starts_with('b') && op != "bic" {
            branches.push((line_no, insn.clone()));
        }
    }
    // The Cortex-M4 routines are fully unrolled, so the expected count is
    // ZERO. Any branch that does appear must be a loop back-edge, never a
    // branch on a value.
    for (line_no, insn) in &branches {
        assert!(
            insn.starts_with("bne") && insn.ends_with("1b"),
            "line {line_no}: only a loop back-edge may branch, found `{insn}`"
        );
    }
    assert!(
        branches.len() <= 2,
        "more branches than the two possible loop back-edges: {:#?}",
        branches
    );
}

#[test]
fn cortex_m4_has_no_data_dependent_memory_addressing() {
    // Every memory operand must be `[rN]` or `[rN, #imm]` — a register-offset
    // form like `[r1, r2]` would mean the address depends on a value, which is
    // the classic cache/timing side channel.
    let re_ok = |operand: &str| -> bool {
        let inner = operand.trim_start_matches('[').trim_end_matches(']').trim();
        let mut parts = inner.split(',').map(str::trim);
        let base = parts.next().unwrap_or("");
        if !(base == "sp"
            || (base.starts_with('r') && base[1..].chars().all(|c| c.is_ascii_digit())))
        {
            return false;
        }
        match parts.next() {
            None => true,
            Some(off) => off.starts_with('#'),
        }
    };

    for (line_no, insn) in instructions(CM4_SRC, '@') {
        let op = opcode(&insn);
        if !matches!(op, "ldr" | "str" | "ldrd" | "strd") {
            continue;
        }
        let start = insn
            .find('[')
            .unwrap_or_else(|| panic!("line {line_no}: {insn}"));
        let end = insn
            .find(']')
            .unwrap_or_else(|| panic!("line {line_no}: {insn}"));
        let operand = &insn[start..=end];
        assert!(
            re_ok(operand),
            "line {line_no}: memory operand `{operand}` is not [reg] or [reg, #imm] \
             — address would depend on a runtime value: {insn}"
        );
        // A post-index suffix must also be a constant.
        if let Some(rest) = insn.get(end + 1..) {
            let rest = rest.trim().trim_start_matches(',').trim();
            if !rest.is_empty() {
                assert!(
                    rest.starts_with('#'),
                    "line {line_no}: post-index `{rest}` must be an immediate: {insn}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Xtensa LX7
// ---------------------------------------------------------------------------

const XTENSA_SRC: &str = include_str!("../asm/xtensa_lx7.S");

/// `mull`/`muluh` are fixed-latency on LX7, and `saltu` is the branchless
/// comparison primitive. No conditional-execution or division forms.
const XTENSA_ALLOWED: &[&str] = &[
    "l32i", "s32i", "mull", "muluh", "add", "addi", "sub", "saltu", "mov", "movi", "xor", "and",
    "or", "neg", "srli", "entry", "retw", "bnez",
];

#[test]
fn xtensa_uses_only_constant_time_instructions() {
    let mut unexpected = BTreeSet::new();
    for (line_no, insn) in instructions(XTENSA_SRC, '#') {
        let op = opcode(&insn);
        if !XTENSA_ALLOWED.contains(&op) {
            unexpected.insert(format!("line {line_no}: {insn}"));
        }
    }
    assert!(
        unexpected.is_empty(),
        "xtensa_lx7.S contains instructions not on the constant-time allow-list:\n{}",
        unexpected.iter().cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn xtensa_has_no_data_dependent_branches() {
    let mut branches = Vec::new();
    for (line_no, insn) in instructions(XTENSA_SRC, '#') {
        let op = opcode(&insn);
        // Every Xtensa branch mnemonic starts with 'b' (beq, bne, bltu, bnez…).
        if op.starts_with('b') {
            branches.push((line_no, insn.clone()));
        }
    }
    // Fully unrolled, so the expected count is ZERO. Any branch that does
    // appear must be on the loop counter, never on a value.
    for (line_no, insn) in &branches {
        assert!(
            insn.starts_with("bnez\ta13") || insn.starts_with("bnez a13"),
            "line {line_no}: only the loop counter may be branched on, found `{insn}`"
        );
    }
    assert!(
        branches.len() <= 2,
        "more branches than the two possible loop back-edges: {:#?}",
        branches
    );
}

#[test]
fn xtensa_has_no_data_dependent_memory_addressing() {
    // `l32i at, as, offset` / `s32i at, as, offset`: the offset must be a
    // literal, never a register.
    for (line_no, insn) in instructions(XTENSA_SRC, '#') {
        let op = opcode(&insn);
        if op != "l32i" && op != "s32i" {
            continue;
        }
        let operands: Vec<&str> = insn
            .splitn(2, char::is_whitespace)
            .nth(1)
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .collect();
        assert_eq!(operands.len(), 3, "line {line_no}: unexpected form: {insn}");
        assert!(
            operands[2].chars().all(|c| c.is_ascii_digit()),
            "line {line_no}: offset `{}` must be a literal, not a register: {insn}",
            operands[2]
        );
    }
}

// ---------------------------------------------------------------------------
// Portable backend
// ---------------------------------------------------------------------------

/// The portable reference must also avoid secret-dependent control flow: it is
/// the backend actually used on any target without assembly.
#[test]
fn portable_backend_has_no_value_dependent_branches() {
    let src = include_str!("../src/backend/portable.rs");
    // Strip line comments so prose about branches does not trip the scan.
    let code: String = src
        .lines()
        .map(|l| match l.find("//") {
            Some(p) => &l[..p],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");

    for kw in ["if ", "match ", "while "] {
        assert!(
            !code.contains(kw),
            "portable.rs contains `{kw}` — the reference implementation must be \
             branch-free with respect to operand values (loops over the limb \
             count are written as `for`, whose trip count is public)"
        );
    }
}
