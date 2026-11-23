# DWARF source names in dewolf

This branch (`add_dwarf_information`) attaches C source-variable names from DWARF to dewolf's
variables and carries them through the pipeline, so we can measure afterwards how well out-of-SSA
merges variables. **This is for evaluation only:** the names are metadata and never influence a
decision in the decompiler.

---

## 1. Ground rules

1. **Same output with and without DWARF.** Decompiling a binary with and without the DWARF
   matching must give byte-identical C code.
2. **Never guess.** A variable gets a source name only when the rule is unambiguous. If there are
   conflicting candidates, the variable gets no name, and an existing name is never overwritten.
3. **Handle names where they can be handled.** A name is passed on in the stage where the
   transformation happens, not in a later fix-up pass.
4. **Not part of identity.** `Variable.origin` is not part of `__eq__`/`__hash__` and is not
   printed in the output.

---

## 2. Where the names live

`Variable.origin` is a `VariableProvenance` (`decompiler/structures/pseudo/expressions.py`):

| Field | Meaning |
|---|---|
| `source_type`, `storage` | Binary Ninja storage (stack offset or register) |
| `value_address` | first address at which the value is live: the instruction after the defining one; for phis, mem-phis and parameters the block / function entry. Aliased versions use their memory definition (call, store, mem-phi). DWARF ranges are looked up here. |
| `function` | function start address |
| `source_name` | C source-variable name, or `None` |
| `name_via` | **how** the name was obtained (see below); `()` exactly when `source_name is None` |
| `dwarf_ambiguous` | several DWARF variables matched at `value_address`: no rule may infer a name for this version |
| `dwarf_storage_names` | all source variables DWARF places in this storage anywhere in the function (any address or scope) |

### `name_via`: the chain

The first element is the **root**, which is how the name first appeared. Every further element is
an **inheritance step**, in which the decompiler replaced a named variable by another one and the
replacement took over the name.

| Mechanism | Kind | Stage | Rule |
|---|---|---|---|
| `dwarf` | observed | lifter (`handlers/variables.py`, `dwarf.py`) | exactly one DWARF variable is in scope (its lexical block) and in the storage at `value_address` and at every use address of the version (addresses without any DWARF match are gaps and ignored; phi uses and uses where the storage already holds another version are skipped); several → no name, and the version is marked `dwarf_ambiguous` so no later rule names it either. Parameters are also matched by position. Aliased versions that only preprocessing creates (mem-phi conversion, missing definitions) are looked up by the lifter too, per memory version |
| `coherence` | inferred | `preprocessing/coherence.py` | all named SSA versions of one Binary Ninja variable agree on a name → the unnamed versions get it; not if DWARF places several source variables in the storage (`dwarf_storage_names`), also for aliased versions preprocessing creates |
| `copy` | inferred | `preprocessing/coherence.py` (`infer_source_names_from_copies`) | plain copy `a = b` with exactly one side named → the other side gets the name (one hop only, candidates collected over the whole CFG); only for pure temporaries, i.e. storage DWARF never uses for a source variable in the function (e.g. `rax` at -O0). The name then means "holds the value of", not "is the variable" |
| `propagation` | inherited | expression propagation (EP, EPM, EPFC) | `x = v` is propagated and x is gone → v takes over x's name; compound values are registered as "value of x" for CSE |
| `cse` | inherited | `dataflowanalysis/common_subexpression_elimination.py` | the new `cN` (or an existing variable) replaces values registered for exactly one name |
| `identity` | inherited | `dataflowanalysis/identity_elimination.py` | the unnamed replacement of an identity group takes the name all named members agree on |

Examples: `("dwarf",)`, `("dwarf", "cse")`, `("coherence", "propagation")`.

A conflict that one stage detects is recorded (`task.propagated_source_values.conflicts`), and
later stages do not name that variable either.

After out-of-SSA, every output variable occurrence carries the `origin` of the SSA variable it
replaced (`ssa/variable_renaming.py`).

Not named: a register pair (`loc_N`) unless both halves have the same name and chain; `tmp_N` from
the instruction length handler (created after out-of-SSA); variables the edge pruner creates (not
in the default pipeline).

---

## 3. Tools

All of these run inside `nix-shell`.

### Turn DWARF off
- **Binary Ninja's own DWARF import** (affects BN's analysis): `python decompile.py BINARY --no-use-debug-info`
  (sets `analysis.debugInfo.internal`). In the GUI: Settings → `analysis.debugInfo.internal`.
- **dewolf's DWARF matching** reads DWARF itself with pyelftools, independently of Binary Ninja.

### `report_variable_matching.py`: merge quality after out-of-SSA
```
python report_variable_matching.py BINARY [func1,func2] [out.json] [-q] [--ssa-algo min] [--mechanisms dwarf,cse,...]
```
Prints a table per function and a total, plus every wrong merge and missed merge pair with the
mechanism behind each name. All of it is also written to JSON (`metrics`).
Note: `--ssa-algo` defaults to `min`, while `decompile.py` uses `lift_minimal`.

---

## 4. Evaluation

### Units and pairs
- **Unit** = one SSA variable right before out-of-SSA (`name#label`). It has an output name after
  out-of-SSA and possibly a source name with its chain.
- Over all pairs of labeled units within a function:
  - **TP**: same source and same output name.
  - **FP**: different source but same output name (over-merge).
  - **FN**: same source but different output name (under-merge).
- **Achievable recall**: FN pairs that interfere (are live at the same time in SSA,
  `InterferenceGraph` right before out-of-SSA) can never be merged, so they are left out.
- Also reported: coverage (labeled/units) and DWARF variables that no unit carries ("lost").
- **Total**: the counts summed over all functions.

### Levels
A name counts at a level only if **every** mechanism in its chain is allowed at that level. So an
inherited name is never more certain than its root: `coherence>cse` only counts from L3 on.

| Level | Allowed mechanisms |
|---|---|
| L1 observed | dwarf |
| L2 +inherited | + propagation, cse |
| L3 +coherence | + coherence |
| L4 +copy (value of) | + copy |
| L5 +identity | + identity |
| custom | `--mechanisms ...` |

> The order follows what each rule claims (observed, value passed on, same Binary Ninja variable,
> same value). It is not a ranking by measured precision.

### Limits
- **The metric does not check whether a name is correct.** An FP can be out-of-SSA's fault even
  though both names are correct.
- **A name keeps the chain it got first.** Copy runs before propagation, so a name that propagation
  would also pass on can count at L4 instead of L2.
- **Source identity is the name only:** two C variables with the same name in different scopes of
  one function count as one source.

---

## 5. Tests

```
python -m pytest tests/frontend/test_dwarf_provenance.py \
                 tests/pipeline/preprocessing/test_source_name_provenance.py \
                 tests/pipeline/dataflowanalysis/test_source_name_inheritance.py \
                 tests/test_report_variable_matching_metrics.py -q
```
