# Glass CLI / Automation API

Every analysis that the Glass GUI performs is also exposed as a CLI
verb that emits structured JSON to stdout. The same `glass` binary
that opens the GUI is the automation entry point — pick a subcommand
and you get a one-shot, scriptable result.

This document covers every automation verb. Legacy text-output
subcommands (`arm64`, `bundle`, `gui`, `db-inject-tab`, `string-comments`,
`plt-probe`, `hash-bench`, `cfg`) predate the automation API and are
not described here; run `glass help <name>` for those.

## Conventions

**Output.** JSON by default. Pass `--text` for a human-readable
rendering — useful when you're reading at the terminal rather than
piping to `jq`.

```sh
glass inspect ./app.apk            # JSON
glass inspect ./app.apk --text     # human-readable
```

**Envelope.** Every JSON response has shape `{ "data": ..., "meta": { "duration_ms": ... } }`.
Errors go to stderr in the parallel shape `{ "error": { "message": ... } }`
and the process exits non-zero.

**Addresses.** Always hex strings (`"0x1000058d4"`), never raw
numbers — JS / `jq` lose precision past 2^53.

**Artifact references.** Verbs that take `--artifact` accept either
the artifact's full label (`arm64-v8a/libnative.so`, `glass`, the
framework name for an IPA) or any hex prefix of its content-hash ID
(`f46f`, `f46fac70…`). Use `glass artifacts <path>` to enumerate
them.

**Class references.** Verbs that take `--class` accept either JNI
form (`Lcom/example/Foo;`) or Java form (`com.example.Foo`).

**Method references.** Method keys are in smali form:
`Lclass;->name(descriptor)return`. `method-calls` accepts a bare
name when unambiguous; otherwise pass `name(descriptor)`.

## Global flags

| Flag        | Meaning                                                |
|-------------|--------------------------------------------------------|
| `--text`    | Render automation verbs as text instead of JSON        |
| `--fresh`   | (GUI only) ignore persisted tab / expansion state      |
| `--help`    | Show the subcommand list                               |

## MCP-only verbs

A few verbs only make sense inside a long-lived MCP session,
where state survives across calls. They appear in the skill
catalog so MCP clients can use them, but the CLI is one-shot
and re-opens per call — so these print "MCP-only" and exit
non-zero:

- `bundle-open <path>` — cache a bundle for subsequent calls.
- `bundle-close` — drop the cache.
- `bundle-status` — report what's currently open.
- `frida-attach --pid <pid> [--host <host:port>]` — attach to a
  Frida-instrumented process (gadget mode default is
  `127.0.0.1:27042` after `adb forward tcp:27042 tcp:27042`).
- `frida-detach` — drop the session.
- `frida-status` — report the current Frida session.
- `frida-load-script --source <js> [--name <tag>]` — load JS;
  returns a `script_id`.
- `frida-unload-script --script-id <id>` — drop a loaded script.
- `frida-post-message --script-id <id> --message <json>` —
  forward a message; the script observes via `recv(...)`.
- `frida-poll-events` — drain accumulated `send(...)` / log /
  error / detach events.
- `frida-resume --pid <pid>` — unblock a gadget loaded with
  `on_load: wait`.

Run `glass mcp` and invoke them through an MCP client.

## Devices

### `device-list`
Snapshot every reachable device — Android via `adb`, iOS via
libimobiledevice. Returns `{devices: [{platform, serial, model?,
os_version?, state}]}`. `state` is one of `Authorised`,
`Unauthorised`, `Offline`.

### `device-pidof --serial <s> --name <name>`
Resolve a process / package name to live PIDs on an Android
device. Feed the first PID into `frida-attach` (MCP).

### `device-launch --serial <s> --package <pkg>`
Launch an Android app via `monkey -p <pkg> -c LAUNCHER 1`.

### `device-force-stop --serial <s> --package <pkg>`
`am force-stop <pkg>` — kills every process belonging to the
package.

### `device-shell --serial <s> -- <argv...>`
Run an arbitrary `adb shell` command. Arguments after `--` are
passed straight through.

## Bundle inspection

### `inspect <path>` — top-level summary
Kind (`apk` / `ipa` / `native`), label, content hash, and one line
per artifact (id, size, architecture, section count).

```sh
glass inspect ./app.apk --text
```

### `artifacts <path>` — flat artifact list
Same artifact rows as `inspect`, no bundle header.

### `sections <path> [--artifact <ref>]`
Per-artifact section table (name, kind, address, size, bytes-on-disk).
`--artifact` narrows to one.

### `binary-info <path>`
Per-artifact format / architecture / section count / symbol-count hint.

### `hash <path>`
Content-hash a file in isolation — returns `artifact_id`, byte size,
elapsed time. Replaces the old `hash-bench` for benchmarking.

```sh
glass hash ./libfoo.so
# {"data":{"artifact_id":"f46f…","size_bytes":12345678,"duration_ms":42}, …}
```

## Symbols

### `symbols <path> [--artifact <ref>] [--filter <s>] [--kind <k>] [--limit <n>]`
Lists symbols across one or all artifacts. `--filter` is a
case-insensitive substring match on the demangled name. `--kind` is
one of `function`, `object`, `other`. `--limit` caps results per
artifact.

```sh
glass symbols ./libfoo.so --filter init --kind function --limit 20
```

### `symbol-at <path> <addr> --artifact <ref>`
Symbol covering / at a hex address. `addr` can be with or without
the `0x` prefix. Returns `null` when no symbol covers the address.

```sh
glass symbol-at ./libfoo.so 0x1000058d4 --artifact libfoo.so
```

### `demangle <name>`
Run one symbol name through the C++/Rust/Swift demangler. No bundle
required.

```sh
glass demangle _ZN5glass4mainE
```

## Disassembly

### `disasm <path> --artifact <ref> [--section <name>] [--limit <n>]`
Linear-sweep disassembly of a text section. When `--section` is
omitted, picks the first text section in the artifact. Each row
includes address, raw bytes, mnemonic, operands, the covering
symbol (if any), and a resolved branch / ADRP / RIP-relative target
comment.

Supported architectures: AArch64, ARMv7 (ARM + Thumb), and
x86 / x86_64 (ELF, Mach-O, and PE/COFF containers). AArch64 and ARM
decode fixed-width words; x86 is decoded as a variable-length stream.
Architectures Glass can't decode are reported by `binary-info` and
should be inspected with `sections` / the GUI hex viewer instead.

```sh
glass disasm ./libfoo.so --artifact libfoo.so --section .text --limit 100
glass disasm ./app.exe   --artifact app.exe   --section .text --limit 100
```

### `decode <word> [--addr <a>]`
Decode one 32-bit AArch64 word. `word` is hex; `addr` (default `0`)
matters for PC-relative branches. No bundle required.

```sh
glass decode 0x52800000        # mov w0, #0
glass decode 0x94000003 --addr 0x100000
```

## Control-flow graph

### `cfg-of <path> --artifact <ref> --func <ref>`
Block list + edges + layout for one function. `--func` accepts a
hex address or an exact symbol name.

```sh
glass cfg-of ./libfoo.so --artifact libfoo.so --func "glass::main"
```

Returns:
- `entry_address`, `end_address`
- `blocks[]` — id, start/end address, instruction count, call
  count, rank, x-coordinate (for layout), `exits_function` flag
- `edges[]` — from / to block id, kind (`Fallthrough` /
  `ConditionalTaken` / `Unconditional` / `Call` / `Return`)

### `calls-from <path> --artifact <ref> --func <ref>`
Every call site inside a function. Lighter than `cfg-of` if you
only want the outbound call list.

```sh
glass calls-from ./libfoo.so --artifact libfoo.so --func _main --text
```

## DEX / smali (APK only)

### `classes <path> [--package <prefix>]`
All DEX classes. `--package` filters by JNI or Java prefix.

```sh
glass classes ./app.apk --package androidx.annotation. --text
```

### `types <path> [--artifact <ref>] [--package <prefix>] [--kind <kind>] [--limit <n>]`
List ObjC + Swift class-like entities (classes, categories, structs,
enums) across an iOS bundle's Mach-O artifacts. APKs / ELFs return
empty. `--kind` is one of `objc-class`, `objc-category`,
`swift-class`, `swift-struct`, `swift-enum`. `--package` is a prefix
filter on the **demangled** name. Default `--limit 200`.

```sh
glass types ./blackjack.ipa --kind swift-class --text
```

JSON shape:
```json
{
  "total": 42,
  "shown": 42,
  "entries": [
    {
      "kind": "swift-class",
      "name": "blackjack.ContentView",
      "raw_name": "_$s9blackjack11ContentViewC",
      "artifact": "blackjack",
      "vaddr": "0x100012abc",
      "method_count": 5,
      "field_count": 3,
      "category_for": null
    }
  ]
}
```

### `type <path> --artifact <ref> --name <name> [--raw]`
Detail view for one ObjC class / category or Swift type. Looks up
by pretty (demangled) name first, falling back to the raw mangled
form. Pass `--raw` to skip pretty-name conversion. The response is
a tagged enum keyed by `kind`:

```json
{ "kind": "objc-class", "name": "...", "instance_methods": [...] }
{ "kind": "swift-class", "name": "...", "fields": [...], "vtable": [...] }
```

```sh
glass type ./blackjack.ipa --artifact blackjack --name blackjack.ContentView --text
```

### `smali <path> --class <ref>`
Full smali source for one class.

```sh
glass smali ./app.apk --class com.example.MainActivity --text
```

### `smali-set <path> --class <ref> [--body STR | --file PATH] --patches FILE`
Stage a typed rewrite of one DEX class. The body is the full smali
text (same shape `smali` returns); the `.class` line in the body
must declare the same class as `--class` (we cross-check to avoid
silently overwriting the wrong slot).

Exactly one of `--body` (inline string), `--file` (path to a
`.smali` file), or stdin (neither flag given) supplies the body.

Smali edits accumulate in the same patch file as byte-level
`patch` edits — `export-patched` writes both. Per-`(artifact,
class_jni)` upsert: re-staging the same class replaces the prior
body.

```sh
# Round-trip via stdin
glass smali ./app.apk --class com.example.Foo \
  | sed 's/old-name/new-name/g' \
  | glass smali-set ./app.apk --class com.example.Foo --patches edits.json

# Or read from disk
glass smali-set ./app.apk --class com.example.Foo \
  --file new_foo.smali --patches edits.json
```

### `methods <path> --class <ref>`
Methods declared by a class (name, descriptor, modifiers, op count,
constructor flag).

### `fields <path> --class <ref>`
Fields declared by a class (name, type, modifiers).

### `method-calls <path> --class <ref> --method <ref>`
Every `invoke-*` call site inside a method. `--method` is either a
bare name (first match) or `name(descriptor)` for unambiguous lookup.

```sh
glass method-calls ./app.apk --class com.example.Foo --method 'bar(Ljava/lang/String;)V'
```

## Frida scripts

A small per-user library of Frida JS scripts. Bodies are plain `.js`
files in `~/Library/Application Support/Glass/scripts/` (or the
platform equivalent); descriptions / tags / timestamps live in
glass-db. A per-bundle "enabled" flag (also in glass-db) drives which
scripts the GUI auto-loads when it attaches a Frida session.

### `scripts [--bundle <path>]`

List every script in the library. With `--bundle`, each row's
`enabled_for_bundle` reflects the toggle state for that bundle.

```sh
glass scripts --bundle ./app.apk --text
```

### `script-read <name>`

Read one script's body + metadata. The `.js` suffix is optional.

```sh
glass script-read anti-root
```

### `script-write <name> [--body STR | --body-file PATH] [--description STR] [--tag T]...`

Create or overwrite a script. `--description` and `--tag` are
optional; omitting them leaves the existing metadata alone.

```sh
glass script-write anti-root --body-file ./anti-root.js \
  --description "Bypasses Magisk detection" --tag anti-root --tag tls
```

### `script-delete <name>`

Remove the `.js` file, the metadata row, and every per-bundle
enabled-row that referenced it. Idempotent.

### `script-enable <bundle> <name>` / `script-disable <bundle> <name>`

Toggle a script's enabled state for one bundle. The GUI's Frida
session auto-loads enabled scripts on attach.

```sh
glass script-enable ./app.apk anti-root
glass script-disable ./app.apk anti-root
```

### `enabled-scripts <bundle>`

List the script names currently enabled for the given bundle.

```sh
glass enabled-scripts ./app.apk
```

## Cross-references

The xref verbs build their indices inline for each query — the CLI
is one-shot, so there's no cache to amortise. For sustained
interactive use, the GUI's incremental indices are faster.

### `xref-addr <path> --artifact <ref> <addr>`
Native callers and address-takes pointing at `<addr>` inside one
artifact's text sections. Catches direct branches, ADRP+ADD pairs,
and other PC-relative references.

```sh
glass xref-addr ./libfoo.so --artifact libfoo.so 0x1000058d4
```

### `callers <path> --artifact <ref> --symbol <name>`
Same as `xref-addr`, but accepts a symbol name. Convenience wrapper.

```sh
glass callers ./libfoo.so --artifact libfoo.so --symbol "glass::main"
```

### `dex-callers <path> --method <key>`
DEX methods that `invoke-*` the given method key (in smali form,
`Lclass;->name(descriptor)return`).

```sh
glass dex-callers ./app.apk --method 'Lcom/example/Foo;->bar()V'
```

### `field-refs <path> --field <ref>`
DEX methods that read or write the given field
(`iget*` / `iput*` / `sget*` / `sput*`).

```sh
glass field-refs ./app.apk --field 'Ljava/lang/System;->out:Ljava/io/PrintStream;'
```

## Search & strings

### `search <path> <query> [--limit <n>]`
Case-insensitive substring search across native symbols and DEX
class / method / field names. Each hit records its `kind`, `label`,
`context`, and a `jump` target (hex address for native, JNI form
for DEX).

```sh
glass search ./app.apk "onCreate" --limit 20
```

### `strings <path> --artifact <ref> [--min <n>] [--limit <n>]`
Printable-ASCII NUL-terminated strings from a native artifact's
non-text non-debug sections. Default `--min` is 4.

```sh
glass strings ./libfoo.so --artifact libfoo.so --min 8 --limit 50
```

## Binary pattern search

### `bin-search --path P --artifact A --pattern '...' [--section S] [--limit N]`
Scan every text + data section of one artifact for a byte
pattern. Atoms are whitespace-separated; each is either a
2-character byte mask (`c0`, `0xc0`, `e?`, `?f`, `??`) or a
bounded gap (`*` = 0..=32 bytes default, `*(min..max)` to
override).

```sh
# `mov w0, #1 ; ret`  (returning-true stub finder)
glass bin-search ./libfoo.so --artifact libfoo.so \
  --pattern '20 00 80 52 c0 03 5f d6'

# any ADRP+ADD pair with no intervening bytes
glass bin-search ./libfoo.so --artifact libfoo.so \
  --pattern '?? ?? ?? 9? ?? ?? 4? 91'

# raw data: find embedded magic
glass bin-search ./libfoo.so --artifact libfoo.so --pattern 'de ad be ef'
```

Matches don't span sections. Each result carries a `preview`
column: two decoded AArch64 instructions joined with ` ; ` for
text sections (e.g. `mov x0, #0 ; ret x30`), or the first 8
bytes as space-separated hex for data sections.

Full pattern reference + worked examples: [`docs/BinSearch.md`](BinSearch.md).

### `insn-search --path P --artifact A --pattern '...' [--section S] [--limit N]`
Higher-level than `bin-search`: write the *assembly* and let
Glass compile it to bytes (with operand-bit masking for any
wildcards) before scanning. Mnemonics, register names,
immediates, and `;`-separated multi-instruction sequences are
supported. Wildcards let you express a code shape without
pinning every operand:

| Token  | Meaning                                              |
|--------|------------------------------------------------------|
| `*`    | any operand (kind inferred from the chosen opcode)   |
| `#*`   | any immediate (hints the opcode picker)              |
| `x`    | any X-class register                                 |
| `w`    | any W-class register                                 |
| `<*>`, `<X>`, `<W>`, `<R>`, `<imm>` | same as the shorthand forms, useful when nested inside other syntax (`[x, #*]`, etc.) |
| `r`    | any ARMv7 R-class register (`r0..r15`)               |

The pattern grammar dispatches on the target artifact's
architecture: AArch64 artifacts (`arm64-v8a`, `arm64`) accept
AArch64 syntax; ARMv7 artifacts (`armeabi-v7a`) accept ARMv7
syntax. Thumb is tried first per instruction; ARM mode (A32) is
the automatic fallback when no Thumb form matches.

```sh
# every `mov w0, #N` site, whatever N is (AArch64)
glass insn-search ./libfoo.so --artifact libfoo.so \
  --pattern 'mov w0, #*'

# any ADRP into x1 followed immediately by ADD into the same reg (AArch64)
glass insn-search ./libfoo.so --artifact libfoo.so \
  --pattern 'adrp x1, * ; add x1, x1, #*'

# every `ret x30` (AArch64 — concrete, no wildcards)
glass insn-search ./libfoo.so --artifact libfoo.so --pattern 'ret'

# ARMv7: every `mov r1, rX` for any X
glass insn-search ./libtool-checker.so --artifact libtool-checker.so \
  --pattern 'mov r1, <R>'

# ARMv7: every conditional `bxeq lr`
glass insn-search ./libtool-checker.so --artifact libtool-checker.so \
  --pattern 'bxeq lr'

# ARMv7: every push of {r4..r7, lr}
glass insn-search ./libtool-checker.so --artifact libtool-checker.so \
  --pattern 'push {r4-r7, lr}'
```

Known ARMv7 limitations (current scope): shifted-operand forms
(`r0, lsl #2`), pre/post-index addressing (`[rN, #imm]!`,
`[rN], #imm`), register-offset memory (`[rN, rM]`), and
bitmask-syntax register lists (`{0b00010010}`) aren't supported
yet. Register-list range syntax (`{r4-r7}`) works.

The response includes `bytes_hex` showing the compiled
byte-mask atoms (e.g. `01/1f ?? ?? 90/9f` for `adrp x1, *`) so
you can see exactly which bits are pinned vs wildcarded. Match
rows reuse the `bin-search` shape — section, address, length,
preview.

Captures (`<name:kind>` cross-referencing the same wildcard
later in the pattern) are designed but not yet implemented;
track on the roadmap.

Full design + phasing: [`docs/InsnPattern.md`](InsnPattern.md).

## Annotations & persistence

Glass persists window state, open tabs, and user annotations in a
content-addressed `redb` database. Annotations follow the artifact
(blake3 hash of the bytes), so the same `libfoo.so` shipped in two
different APKs shares analysis state.

Each annotation slot — keyed by `(artifact, key)` — carries up to
three independent facets: a **rename** (display name override), a
**comment** (free-form note), and a **colour** (RGBA tint). Writes
merge: setting a comment on a key that already has a rename leaves
the rename intact.

### `annotations <path>`
Read all annotations for the artifact identified by content-hashing
`<path>`. Each entry shows the populated facets — `rename` /
`comment` / `colour` (any combination).

### `set-rename --path P --key-kind K --key V [--method M] --name N`
Persist a display name. `--key-kind` is one of:
- `address` — `V` is a hex VA, e.g. `0x1000058d4`. Most specific.
- `symbol` — `V` is the symbol display name (`glass::main`).
- `class` — `V` is a class JNI (`Lcom/example/Foo;`).
- `method` — `V` is the class JNI; `--method` is the
  `name(descriptor)return` part, e.g. `bar(Ljava/lang/String;)V`.
- `method-line` — `V` is the class JNI; `--method` is
  `name(descriptor)return#<line_offset>` (line offset is
  0-indexed from the `.method` directive, so `0` targets the
  header itself, `1`+ targets a body line). This is the key
  the GUI writes when you right-click a specific line inside
  a smali method body.

```sh
glass set-rename ./libfoo.so --key-kind address --key 0x1000058d4 --name decode_packet
```

### `set-comment --path P --key-kind K --key V [--method M] --body B`
Free-form note on the same key. `--body` is multi-line OK.

```sh
glass set-comment ./libfoo.so --key-kind symbol --key "glass::main" \
  --body "entrypoint after rustc demangle"
```

### `set-colour --path P --key-kind K --key V [--method M] --rgba HEX`
RGBA hex (8 digits, with or without `0x`). UI renders this as a row /
node tint.

```sh
glass set-colour ./libfoo.so --key-kind address --key 0x1000058d4 --rgba ff0000aa
```

### `clear-annotation --path P --key-kind K --key V [--method M]`
Remove every facet hung off the key. No-op if nothing's stored.

### `db-dump <path>`
Reads the bundle-level record for the file at `<path>`: label,
schema version, last-opened time, artifact count, open tabs,
expanded paths, and the source path. Returns `record: null` when
the bundle has never been opened.

## Patching & re-serialisation

Glass can edit instructions and bytes inside a loaded artifact and
re-pack the whole bundle. The CLI/MCP path uses a JSON **patch
file** that accumulates edits across calls, mirroring the GUI's
in-memory edit registry.

### `patch <path> --artifact A --addr 0x... (--insn '...' | --bytes 'aa bb cc dd') --patches FILE`

Stage one edit. `--insn` compiles AArch64 assembly with PC-relative
encoding at `--addr` (no symbol lookup yet — pass hex for branch
targets). `--bytes` writes raw hex pairs of the same length as the
original at the address. Same `(artifact, addr)` appearing twice
replaces the earlier edit.

```sh
# Replace `svc #0` at 0x100000f7c with `nop`.
glass patch ./libfoo.so --artifact libfoo.so \
  --addr 0x100000f7c --insn 'nop' --patches /tmp/p.json

# Set the first 4 bytes at 0x100001000 to a NOP.
glass patch ./libfoo.so --artifact libfoo.so \
  --addr 0x100001000 --bytes '1f 20 03 d5' --patches /tmp/p.json
```

### `export-patched <path> --patches FILE --out OUT`

Apply the patch file to the bundle. Mach-O / ELF / `.so`
standalone binaries are written directly; APK/AAB get re-packed via
the smali zip writer; IPA gets re-streamed via the `zip` crate.
Empty patch files are rejected.

```sh
glass export-patched ./libfoo.so --patches /tmp/p.json --out ./libfoo-patched.so
```

### `patch-schema`

Print the JSON Schema (draft 2020-12) describing the patch file
format. Useful when consuming the file from another tool.

```sh
glass patch-schema | jq .
```

### Patch file format

```json
{
  "version": 1,
  "source_path": "/abs/path/to/bundle.so",
  "edits": [
    {
      "artifact": "<64-char hex artifact id from `glass inspect`>",
      "vaddr": 4294971260,
      "kind": "Instruction",
      "new_bytes": [31, 32, 3, 213],
      "original_bytes": [],
      "source_text": "nop"
    }
  ]
}
```

`kind` is display-only (one of `Instruction`, `Bytes`, `String`);
the splice writes `new_bytes` regardless. `original_bytes` and
`source_text` are optional and informational. See `glass
patch-schema` for the authoritative description.

## Piping & composition

The JSON shape is stable and addresses-as-strings are safe for
`jq`. Some patterns:

```sh
# Extract just the addresses of all `init`-named symbols:
glass symbols ./libfoo.so --filter init --limit 20 \
  | jq -r '.data[].symbols[].address'

# Every basic block of glass::main in one line per block:
glass cfg-of ./libfoo.so --artifact libfoo.so --func "glass::main" \
  | jq -c '.data.blocks[]'

# Strings ≥ 16 chars, sorted by section:
glass strings ./libfoo.so --artifact libfoo.so --min 16 \
  | jq -r '.data.strings[] | "\(.section)\t\(.address)\t\(.value)"'

# Find DEX callers of every onCreate override:
for m in $(glass search ./app.apk onCreate \
             | jq -r '.data.hits[] | select(.kind=="method") | .jump'); do
  glass dex-callers ./app.apk --method "$m" --text
done
```

## Errors & exit codes

Failures emit a JSON object on **stderr** and exit with code 1:

```json
{"error":{"message":"no artifact matches \"libnope.so\""}}
```

With `--text`, the same message goes to stderr as `error: <msg>`.
Stdout is empty on failure, so `glass ... | jq` will simply produce
no output rather than swallowing a malformed line.

## Skill catalog & MCP

Two helper verbs expose the automation API to LLM tooling:

### `skills`
Prints the machine-readable catalog: one entry per verb with name,
description, JSON Schema for arguments, and an example invocation.
Useful for generating prompts, building external clients, or
verifying the surface programmatically.

```sh
glass skills | jq '.skills[] | {name, example}'
```

### `mcp`
Runs an MCP (Model Context Protocol) stdio server. Every verb in
this document becomes an LLM-callable tool with the schema shown
by `glass skills`. Plug into Claude Desktop, Cursor, Zed, or any
other MCP host.

```sh
glass mcp                 # speak JSON-RPC over stdin/stdout
```

For Claude Desktop, add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "glass": { "command": "/usr/local/bin/glass", "args": ["mcp"] }
  }
}
```

Tool results come back as a single text content block whose body
is the same `{ data, meta }` JSON envelope the CLI emits — parse
the `.content[0].text` field as JSON.

## See also

- [`docs/AutomationAPI.md`](AutomationAPI.md) — design notes for the
  capability surface (`glass-api` crate) that backs every verb.
- [`docs/Roadmap.md`](Roadmap.md) — what's planned next.
