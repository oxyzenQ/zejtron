# Zejtron Brand Guidelines

This document defines the visual identity and communication standards for the Zejtron project. It ensures consistent branding across all touchpoints — from the GitHub repository to the CLI output and documentation.

---

## 1. Brand Identity

**Zejtron** is a lightweight, efficient terminal utility. The brand reflects:

- **Simplicity** — focused functionality
- **Performance** — fast, Rust-powered execution
- **Utility** — practical, everyday terminal enhancement

---

## 2. Name Usage

### 2.1. Correct forms

| Context | Format |
|---|---|
| Running text / prose | Zejtron |
| Titles / headings | Zejtron |
| Code / CLI | `zejtron` (lowercase) |

### 2.2. Incorrect forms

- ~~ZejTron~~ (no internal capitalization)
- ~~ZejtronX~~ (derivative form)

---

## 3. Logo

### 3.1. Logo file

The official logo is located at [`assets/zejtron-logo-new.png`](assets/zejtron-logo-new.png).

### 3.2. Usage rules

- **Clear space**: maintain padding equal to at least 25% of the logo height on all sides
- **Aspect ratio**: always preserve the original aspect ratio — do not stretch or distort

---

## 4. Tone of Voice

Zejtron's communication should be direct, technical, and helpful.

- **Factual** — describe capabilities clearly
- **Concise** — respect the user's time
- **Professional** — maintain technical accuracy

---

## 5. Color System

The CLI speaks one palette on two surfaces, both anchored to the same values:

| Tier | Value | Surface |
|---|---|---|
| Brand purple | `#A855F7` (168,85,247) | clap headings (`Usage`, `Commands`, `Options`) in `-h`/`--help` and errors |
| Calm grey | `#8B8B8B` (139,139,139) | typeable grammar (flags, subcommands), valid-suggestion labels |
| Error red | `#FF5A5A` (255,90,90) | the `error:` label (bold) and body of every runtime error; clap error labels; doctor `FAIL` rows |
| Warning yellow | `#FFEB3C` (255,235,60) | invalid-input highlights on the clap lane; doctor `WARN` rows; the update check's "update available" verdict |
| Status green | `#50FA7B` (80,250,123) | affirmative verdicts: doctor `OK` rows; the update check's "up to date" verdict |

Implementation: the clap lane renders through `src/styles.rs`, the
runtime lane through `src/output.rs`; one palette, two modules.

Capability ladder (the runtime lane): TrueColor 24-bit when
`COLORTERM=truecolor/24bit` or the terminal names a truecolor-native
emulator; 256-color (nearest cube index) when `TERM` carries
`256color`; plain text otherwise - `NO_COLOR`, `CLICOLOR=0`,
`TERM=dumb`, a non-terminal stderr (unless `CLICOLOR_FORCE=1`), or an
unrecognized terminal all render byte-clean plain text. Piped output
never carries escape bytes.

Deliberately uncolored: "No X found" empty-result lines (informational,
not errors) and content facts such as touch's `actor: unknown` - tiers
mark verdicts, not prose.

---

## 6. Third-party Usage

External projects or articles referencing Zejtron should:

- Use the correct project name: Zejtron
- Link to the official repository: <https://github.com/oxyzenQ/zejtron>
