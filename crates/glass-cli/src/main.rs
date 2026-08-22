use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod output;
mod scripts_verbs;
mod verbs;

use output::Format;

/// Clap-friendly mirror of `glass_api::SymbolKindName`. Kept here
/// so glass-api stays free of clap.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
enum SymbolKindArg {
    Function,
    Object,
    Other,
}

impl From<SymbolKindArg> for glass_api::SymbolKindName {
    fn from(k: SymbolKindArg) -> Self {
        match k {
            SymbolKindArg::Function => glass_api::SymbolKindName::Function,
            SymbolKindArg::Object => glass_api::SymbolKindName::Object,
            SymbolKindArg::Other => glass_api::SymbolKindName::Other,
        }
    }
}

/// Returns Some(result) for automation verbs that handle their own
/// emission, None for legacy text-output subcommands that the
/// regular match below dispatches.
fn automation_dispatch(cmd: &Cmd, format: Format) -> Option<Result<()>> {
    match cmd {
        Cmd::BundleOpen { .. } | Cmd::BundleClose | Cmd::BundleStatus => {
            Some(Err(anyhow::anyhow!(
                "bundle-open / bundle-close / bundle-status are MCP-only verbs — \
                 the CLI is stateless and re-opens per call. Run `glass mcp` and \
                 use them through an MCP client.",
            )))
        }
        Cmd::FridaSpawn { .. }
        | Cmd::FridaAttach { .. }
        | Cmd::FridaDetach
        | Cmd::FridaStatus
        | Cmd::FridaLoadScript { .. }
        | Cmd::FridaUnloadScript { .. }
        | Cmd::FridaPostMessage { .. }
        | Cmd::FridaPollEvents
        | Cmd::FridaResume { .. }
        | Cmd::StalkerCoverage { .. } => Some(Err(anyhow::anyhow!(
            "frida-* verbs are MCP-only — Frida sessions can't survive the CLI's \
             one-shot lifecycle. Run `glass mcp` and use them through an MCP client.",
        ))),
        Cmd::DeviceList => Some(verbs::device_list(format)),
        Cmd::DevicePidof { serial, name } => {
            Some(verbs::device_pidof(serial.clone(), name.clone(), format))
        }
        Cmd::DeviceLaunch { serial, package } => Some(verbs::device_launch(
            serial.clone(),
            package.clone(),
            format,
        )),
        Cmd::DeviceForceStop { serial, package } => Some(verbs::device_force_stop(
            serial.clone(),
            package.clone(),
            format,
        )),
        Cmd::DevicePull { serial, remote, local } => Some(verbs::device_pull(
            serial.clone(),
            remote.clone(),
            local.clone(),
            format,
        )),
        Cmd::DevicePush { serial, local, remote } => Some(verbs::device_push(
            serial.clone(),
            local.clone(),
            remote.clone(),
            format,
        )),
        Cmd::DeviceShell { serial, args } => {
            Some(verbs::device_shell(serial.clone(), args.clone(), format))
        }
        Cmd::Inspect { path } => Some(verbs::inspect(path.clone(), format)),
        Cmd::Artifacts { path } => Some(verbs::artifacts(path.clone(), format)),
        Cmd::Sections { path, artifact } => {
            Some(verbs::sections(path.clone(), artifact.clone(), format))
        }
        Cmd::BinaryInfo { path } => Some(verbs::binary_info(path.clone(), format)),
        Cmd::Hash { path } => Some(verbs::hash(path.clone(), format)),
        Cmd::Symbols { path, artifact, filter, kind, limit } => {
            Some(verbs::symbols(
                path.clone(),
                artifact.clone(),
                filter.clone(),
                kind.map(Into::into),
                *limit,
                format,
            ))
        }
        Cmd::SymbolAt { path, addr, artifact } => Some(verbs::symbol_at(
            path.clone(),
            addr.clone(),
            artifact.clone(),
            format,
        )),
        Cmd::Demangle { name } => Some(verbs::demangle(name.clone(), format)),
        Cmd::Disasm { path, artifact, section, limit } => Some(verbs::disasm(
            path.clone(),
            artifact.clone(),
            section.clone(),
            *limit,
            format,
        )),
        Cmd::Decode { word, addr } => {
            Some(verbs::decode(word.clone(), addr.clone(), format))
        }
        Cmd::CfgOf { path, artifact, func } => Some(verbs::cfg_of(
            path.clone(),
            artifact.clone(),
            func.clone(),
            format,
        )),
        Cmd::CallsFrom { path, artifact, func } => Some(verbs::calls_from(
            path.clone(),
            artifact.clone(),
            func.clone(),
            format,
        )),
        Cmd::Classes { path, package } => {
            Some(verbs::classes(path.clone(), package.clone(), format))
        }
        Cmd::Types { path, artifact, package, kind, limit } => Some(verbs::types(
            path.clone(),
            artifact.clone(),
            package.clone(),
            kind.clone(),
            *limit,
            format,
        )),
        Cmd::Type { path, artifact, name, raw } => Some(verbs::type_detail(
            path.clone(),
            artifact.clone(),
            name.clone(),
            *raw,
            format,
        )),
        Cmd::Scripts { bundle } => {
            Some(scripts_verbs::scripts(bundle.clone(), format))
        }
        Cmd::ScriptRead { name } => {
            Some(scripts_verbs::script_read(name.clone(), format))
        }
        Cmd::ScriptWrite { name, body, body_file, description, tags } => {
            let tags_opt = if tags.is_empty() { None } else { Some(tags.clone()) };
            Some(scripts_verbs::script_write(
                name.clone(),
                body.clone(),
                body_file.clone(),
                description.clone(),
                tags_opt,
                format,
            ))
        }
        Cmd::ScriptDelete { name } => {
            Some(scripts_verbs::script_delete(name.clone(), format))
        }
        Cmd::ScriptEnable { bundle, name } => Some(
            scripts_verbs::script_enable(bundle.clone(), name.clone(), format),
        ),
        Cmd::ScriptDisable { bundle, name } => Some(
            scripts_verbs::script_disable(bundle.clone(), name.clone(), format),
        ),
        Cmd::EnabledScripts { bundle } => {
            Some(scripts_verbs::enabled_scripts(bundle.clone(), format))
        }
        Cmd::Smali { path, class } => {
            Some(verbs::smali(path.clone(), class.clone(), format))
        }
        Cmd::SmaliSet { path, class, body, file, patches } => {
            let source = match (body.clone(), file.clone()) {
                (Some(s), None) => verbs::SmaliBodySource::Inline(s),
                (None, Some(p)) => verbs::SmaliBodySource::File(p),
                (None, None) => verbs::SmaliBodySource::Stdin,
                (Some(_), Some(_)) => {
                    return Some(Err(anyhow::anyhow!(
                        "--body and --file are mutually exclusive"
                    )));
                }
            };
            Some(verbs::smali_set(
                path.clone(),
                class.clone(),
                source,
                patches.clone(),
                format,
            ))
        }
        Cmd::Methods { path, class } => {
            Some(verbs::methods(path.clone(), class.clone(), format))
        }
        Cmd::Fields { path, class } => {
            Some(verbs::fields(path.clone(), class.clone(), format))
        }
        Cmd::MethodCalls { path, class, method } => Some(verbs::method_calls(
            path.clone(),
            class.clone(),
            method.clone(),
            format,
        )),
        Cmd::XrefAddr { path, artifact, addr } => Some(verbs::xref_addr(
            path.clone(),
            artifact.clone(),
            addr.clone(),
            format,
        )),
        Cmd::Callers { path, artifact, symbol } => Some(verbs::callers(
            path.clone(),
            artifact.clone(),
            symbol.clone(),
            format,
        )),
        Cmd::DexCallers { path, method_key } => Some(verbs::dex_callers(
            path.clone(),
            method_key.clone(),
            format,
        )),
        Cmd::FieldRefs { path, field_ref } => Some(verbs::field_refs(
            path.clone(),
            field_ref.clone(),
            format,
        )),
        Cmd::Search { path, query, limit } => Some(verbs::search(
            path.clone(),
            query.clone(),
            *limit,
            format,
        )),
        Cmd::Strings { path, artifact, min, limit } => Some(verbs::strings(
            path.clone(),
            artifact.clone(),
            *min,
            *limit,
            format,
        )),
        Cmd::BinSearch { path, artifact, pattern, section, limit } => Some(verbs::bin_search(
            path.clone(),
            artifact.clone(),
            pattern.clone(),
            section.clone(),
            *limit,
            format,
        )),
        Cmd::InsnSearch { path, artifact, pattern, section, limit } => Some(verbs::insn_search(
            path.clone(),
            artifact.clone(),
            pattern.clone(),
            section.clone(),
            *limit,
            format,
        )),
        Cmd::Patch { path, artifact, addr, insn, bytes, patches } => Some(verbs::patch(
            path.clone(),
            artifact.clone(),
            addr.clone(),
            insn.clone(),
            bytes.clone(),
            patches.clone(),
            format,
        )),
        Cmd::ExportPatched { path, patches, out } => Some(verbs::export_patched(
            path.clone(),
            patches.clone(),
            out.clone(),
            format,
        )),
        Cmd::PatchSchema => Some(verbs::patch_schema(format)),
        Cmd::Annotations { path } => Some(verbs::annotations(path.clone(), format)),
        Cmd::DbDump { path } => Some(verbs::db_dump_v2(path.clone(), format)),
        Cmd::SetRename { path, key_kind, key, method, name } => Some(verbs::set_rename(
            path.clone(),
            key_kind.clone(),
            key.clone(),
            method.clone(),
            name.clone(),
            format,
        )),
        Cmd::SetComment { path, key_kind, key, method, body } => Some(verbs::set_comment(
            path.clone(),
            key_kind.clone(),
            key.clone(),
            method.clone(),
            body.clone(),
            format,
        )),
        Cmd::SetColour { path, key_kind, key, method, rgba } => Some(verbs::set_colour(
            path.clone(),
            key_kind.clone(),
            key.clone(),
            method.clone(),
            rgba.clone(),
            format,
        )),
        Cmd::ClearAnnotation { path, key_kind, key, method } => Some(verbs::clear_annotation(
            path.clone(),
            key_kind.clone(),
            key.clone(),
            method.clone(),
            format,
        )),
        _ => None,
    }
}

#[derive(Parser)]
#[command(name = "glass", about = "Glass mobile interactive disassembler")]
struct Cli {
    /// Bundle / binary to open when no subcommand is given. With no
    /// path either, opens an empty Glass window.
    path: Option<PathBuf>,
    /// Ignore any previously-saved tabs / expansion state on this
    /// launch. Only meaningful when running the GUI (no subcommand).
    #[arg(long)]
    fresh: bool,
    /// Render automation-API verbs as human-readable text instead
    /// of JSON. Ignored by the GUI and the legacy subcommands
    /// (arm64, bundle, cfg).
    #[arg(long, global = true)]
    text: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    // ----- MCP-only verbs (no CLI semantic) --------------------------
    // These three exist in the skill catalog so MCP clients see them,
    // but they're inherently stateful — the CLI is one-shot. Stubs
    // here print a clear pointer so users who try them get redirected
    // to `glass mcp`.
    /// (MCP-only) Open a bundle and cache it for subsequent calls.
    BundleOpen { path: PathBuf },
    /// (MCP-only) Drop the cached bundle.
    BundleClose,
    /// (MCP-only) Report what bundle (if any) is currently cached.
    BundleStatus,

    /// (MCP-only) Spawn a target paused and attach to it.
    FridaSpawn {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        program: String,
    },
    /// (MCP-only) Attach to a Frida-instrumented process.
    FridaAttach {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        pid: u32,
    },
    /// (MCP-only) Detach the current Frida session.
    FridaDetach,
    /// (MCP-only) Report the current Frida session, if any.
    FridaStatus,
    /// (MCP-only) Load JS source into the attached session.
    FridaLoadScript {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        source: String,
    },
    /// (MCP-only) Unload a previously-loaded script by id.
    FridaUnloadScript {
        #[arg(long)]
        script_id: u32,
    },
    /// (MCP-only) Forward a JSON message to a loaded script.
    FridaPostMessage {
        #[arg(long)]
        script_id: u32,
        #[arg(long)]
        message: String,
    },
    /// (MCP-only) Drain accumulated session events.
    FridaPollEvents,
    /// (MCP-only) Unblock a gadget loaded with `on_load: wait`.
    FridaResume {
        #[arg(long)]
        pid: u32,
    },
    /// (MCP-only) One-shot Stalker basic-block coverage.
    StalkerCoverage {
        #[arg(long, value_delimiter = ',')]
        tids: Vec<u32>,
        #[arg(long, value_delimiter = ',')]
        modules: Vec<String>,
        #[arg(long, default_value_t = 1000)]
        duration_ms: u64,
    },

    /// List reachable devices (Android via adb, iOS via libimobiledevice).
    DeviceList,
    /// Resolve a process / package name to live PIDs on an Android device.
    DevicePidof {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        name: String,
    },
    /// Launch an Android app by package name.
    DeviceLaunch {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        package: String,
    },
    /// Force-stop every process belonging to an Android package.
    DeviceForceStop {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        package: String,
    },
    /// Pull a file from an Android device to the host.
    DevicePull {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
    /// Push a local file to an Android device.
    DevicePush {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    /// Run an arbitrary `adb shell` command on a device.
    DeviceShell {
        #[arg(long)]
        serial: String,
        #[arg(last = true)]
        args: Vec<String>,
    },

    // ----- Automation verbs (structured JSON output) -----------------
    /// Inspect a bundle: kind, label, content hash, artifact list.
    Inspect { path: PathBuf },
    /// List the artifacts in a bundle.
    Artifacts { path: PathBuf },
    /// Per-artifact section table.
    Sections {
        path: PathBuf,
        /// Limit to one artifact (label or hex-prefix of its id).
        #[arg(long)]
        artifact: Option<String>,
    },
    /// Per-artifact binary info: format, architecture, raw counts.
    BinaryInfo { path: PathBuf },
    /// Content-hash a file (replaces hash-bench).
    Hash { path: PathBuf },
    /// List symbols across one or all artifacts.
    Symbols {
        path: PathBuf,
        /// Limit to one artifact (label or hex-prefix of its id).
        #[arg(long)]
        artifact: Option<String>,
        /// Substring filter (case-insensitive) on the demangled name.
        #[arg(long)]
        filter: Option<String>,
        /// Only return symbols of this kind.
        #[arg(long, value_enum)]
        kind: Option<SymbolKindArg>,
        /// Cap results per artifact.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Look up the symbol covering / at an address.
    SymbolAt {
        path: PathBuf,
        /// Hex address (with or without 0x prefix).
        addr: String,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
    },
    /// Demangle a single symbol name (no bundle required).
    Demangle { name: String },
    /// Linear-sweep disassembly of a text section.
    Disasm {
        path: PathBuf,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
        /// Section name (e.g. `.text`, `__text`). When omitted,
        /// picks the first text section in the artifact.
        #[arg(long)]
        section: Option<String>,
        /// Cap on returned rows.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Decode one 32-bit AArch64 instruction word (no bundle
    /// required). `word` is hex; `addr` defaults to 0.
    Decode {
        word: String,
        #[arg(long, default_value = "0")]
        addr: String,
    },
    /// Build the CFG for a function (block list, edges, layout).
    CfgOf {
        path: PathBuf,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
        /// Function entry — hex address or exact symbol name.
        #[arg(long)]
        func: String,
    },
    /// List every call site inside a function.
    CallsFrom {
        path: PathBuf,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
        /// Function entry — hex address or exact symbol name.
        #[arg(long)]
        func: String,
    },
    /// List DEX classes (APK only). Use `--package` to filter by
    /// JNI or Java prefix (e.g. `--package Lkotlin/` or `--package
    /// kotlin.`).
    Classes {
        path: PathBuf,
        #[arg(long)]
        package: Option<String>,
    },
    /// List ObjC + Swift class-like entities across the bundle's
    /// Mach-O artifacts. APKs / ELFs return empty.
    Types {
        path: PathBuf,
        /// Restrict to one artifact (label or hex-prefix of its id).
        #[arg(long)]
        artifact: Option<String>,
        /// Prefix filter on the demangled (pretty) name.
        #[arg(long)]
        package: Option<String>,
        /// Filter by kind: `objc-class`, `objc-category`,
        /// `swift-class`, `swift-struct`, `swift-enum`.
        #[arg(long)]
        kind: Option<String>,
        /// Cap on entries. Default 200.
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Detail view for one ObjC class / category or Swift type.
    /// Looks up by pretty (demangled) name first, falling back to
    /// the raw mangled form.
    Type {
        path: PathBuf,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
        /// Class / type name — pretty form or raw mangled.
        #[arg(long)]
        name: String,
        /// Emit raw mangled names unchanged (no demangle attempt
        /// on field types / superclass).
        #[arg(long)]
        raw: bool,
    },
    /// List the Frida scripts in the user's library. With
    /// `--bundle`, marks which are enabled for that bundle.
    Scripts {
        /// Optional bundle path; when given, each row carries an
        /// `enabled_for_bundle` flag for that bundle.
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
    /// Print one script's body + metadata.
    ScriptRead {
        /// Script name (with or without `.js`).
        name: String,
    },
    /// Create or overwrite a script.
    ScriptWrite {
        /// Script name (with or without `.js`).
        name: String,
        /// Inline script body. Mutually exclusive with --body-file.
        #[arg(long, conflicts_with = "body_file")]
        body: Option<String>,
        /// Read the body from this path.
        #[arg(long, conflicts_with = "body")]
        body_file: Option<PathBuf>,
        /// Replace the description. Omit to leave it unchanged.
        #[arg(long)]
        description: Option<String>,
        /// Replace the tag set. Pass `--tag` multiple times.
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Delete a script (both the `.js` file and its metadata) and
    /// every per-bundle enabled row that referenced it.
    ScriptDelete {
        name: String,
    },
    /// Mark a script as enabled for the given bundle. Idempotent.
    ScriptEnable {
        bundle: PathBuf,
        name: String,
    },
    /// Mark a script as disabled for the given bundle. Idempotent.
    ScriptDisable {
        bundle: PathBuf,
        name: String,
    },
    /// List the script names currently enabled for the given bundle.
    EnabledScripts {
        bundle: PathBuf,
    },
    /// Print the full smali body of a class.
    Smali {
        path: PathBuf,
        /// Class — JNI (`Lcom/foo/Bar;`) or Java (`com.foo.Bar`).
        #[arg(long)]
        class: String,
    },
    /// Stage a typed rewrite of one DEX class. The body is the
    /// full smali text — same shape `glass smali` returns.
    /// Reuses the patch file used by `glass patch` so byte and
    /// smali edits coexist; `glass export-patched` applies both.
    SmaliSet {
        path: PathBuf,
        /// Class to replace — JNI (`Lcom/foo/Bar;`) or Java
        /// (`com.foo.Bar`).
        #[arg(long)]
        class: String,
        /// Inline smali body. Mutually exclusive with `--file`.
        /// If neither is given, the body is read from stdin.
        #[arg(long, conflicts_with = "file")]
        body: Option<String>,
        /// Path to a `.smali` file containing the body. Mutually
        /// exclusive with `--body`.
        #[arg(long, conflicts_with = "body")]
        file: Option<PathBuf>,
        /// Patch file to read / write. Created if absent.
        #[arg(long)]
        patches: PathBuf,
    },
    /// List methods declared by a class.
    Methods {
        path: PathBuf,
        #[arg(long)]
        class: String,
    },
    /// List fields declared by a class.
    Fields {
        path: PathBuf,
        #[arg(long)]
        class: String,
    },
    /// List every `invoke-*` call site inside a method. `--method`
    /// is `name` (first match) or `name(descriptor)`.
    MethodCalls {
        path: PathBuf,
        #[arg(long)]
        class: String,
        #[arg(long)]
        method: String,
    },
    /// Native callers / address-takes for a given address.
    XrefAddr {
        path: PathBuf,
        /// Artifact label or hex-prefix of its id.
        #[arg(long)]
        artifact: String,
        /// Hex address (with or without 0x prefix).
        addr: String,
    },
    /// Native callers of a symbol by name.
    Callers {
        path: PathBuf,
        #[arg(long)]
        artifact: String,
        /// Symbol display name or raw name.
        #[arg(long)]
        symbol: String,
    },
    /// DEX methods that `invoke-*` the given method key
    /// (`Lclass;->name(descriptor)return`).
    DexCallers {
        path: PathBuf,
        #[arg(long = "method")]
        method_key: String,
    },
    /// DEX methods that touch the given field reference
    /// (`Lclass;->name:Ltype;`).
    FieldRefs {
        path: PathBuf,
        #[arg(long = "field")]
        field_ref: String,
    },
    /// Substring-search across native symbols + DEX class /
    /// method / field names. Case-insensitive.
    Search {
        path: PathBuf,
        query: String,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Extract printable-ASCII NUL-terminated strings from a
    /// native artifact's data sections.
    Strings {
        path: PathBuf,
        #[arg(long)]
        artifact: String,
        /// Minimum string length. Default 4.
        #[arg(long)]
        min: Option<usize>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Search native sections for a byte pattern. See
    /// docs/BinSearch.md for the grammar. Examples:
    ///   --pattern '20 00 80 d2 c0 03 5f d6'      # mov w0,#1 ; ret
    ///   --pattern 'e? ?? ff * c0'                # nibble + gap
    BinSearch {
        path: PathBuf,
        #[arg(long)]
        artifact: String,
        /// Pattern string: space-separated byte masks and gap
        /// atoms. Wrap in single quotes to keep your shell from
        /// expanding `?`.
        #[arg(long)]
        pattern: String,
        /// Narrow to a single section by name (e.g. `__text`).
        /// Otherwise scans every text + data section.
        #[arg(long)]
        section: Option<String>,
        /// Cap on returned matches across all sections.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Search native sections for an AArch64 instruction
    /// sequence written in assembly. The pattern is a `;`-
    /// separated list of concrete instructions; each compiles
    /// to 4 bytes and the result feeds the bin-search engine.
    /// Phase A: concrete operands only — no wildcards or
    /// captures (see docs/InsnPattern.md for the full plan).
    /// Examples:
    ///   --pattern 'mov w0, #1 ; ret'
    ///   --pattern 'mov x0, #0 ; ret'
    InsnSearch {
        path: PathBuf,
        #[arg(long)]
        artifact: String,
        /// Assembly text: `mnemonic op1, op2; mnemonic …`.
        #[arg(long)]
        pattern: String,
        #[arg(long)]
        section: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Stage one instruction or byte edit in a patch file.
    /// The file accumulates edits across calls. Use
    /// `export-patched` to write a patched bundle.
    /// Provide exactly one of `--insn` or `--bytes`.
    Patch {
        /// Bundle (apk/aab/ipa) or standalone binary.
        path: PathBuf,
        /// Artifact label or hex-prefix id (see `glass artifacts`).
        #[arg(long)]
        artifact: String,
        /// Virtual address as hex, with or without 0x prefix.
        #[arg(long)]
        addr: String,
        /// AArch64 assembly source (single instruction). Mutually
        /// exclusive with --bytes.
        #[arg(long, conflicts_with = "bytes")]
        insn: Option<String>,
        /// Raw replacement bytes, space-separated hex (e.g.
        /// `'20 00 80 52'`). Length must match the original
        /// item at addr (typically 4 for instructions).
        #[arg(long)]
        bytes: Option<String>,
        /// Patch file to read/write. Created if absent.
        #[arg(long)]
        patches: PathBuf,
    },
    /// Apply a patch file to a bundle and write the patched
    /// output.
    ExportPatched {
        path: PathBuf,
        #[arg(long)]
        patches: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the JSON Schema for the patch file format. Useful
    /// for external validators / tooling.
    PatchSchema,
    /// Read user-set annotations (rename / comment / colour) for
    /// the artifact identified by content-hashing `path`.
    Annotations { path: PathBuf },
    /// Persist a user-chosen display name for an address / symbol /
    /// class / method. Re-using the same key overwrites.
    SetRename {
        path: PathBuf,
        /// `address` | `symbol` | `class` | `method`.
        #[arg(long = "key-kind")]
        key_kind: String,
        /// Kind-specific identifier (hex VA / display name / JNI).
        #[arg(long)]
        key: String,
        /// Method name+descriptor; required when `--key-kind method`.
        #[arg(long)]
        method: Option<String>,
        /// New display name.
        #[arg(long)]
        name: String,
    },
    /// Attach a free-text comment to an address / symbol / class / method.
    SetComment {
        path: PathBuf,
        #[arg(long = "key-kind")]
        key_kind: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        method: Option<String>,
        /// Comment body. `--text` would clash with the global format
        /// flag, so the body parameter is `--body`.
        #[arg(long)]
        body: String,
    },
    /// Tag with an RGBA hex colour (8 hex digits).
    SetColour {
        path: PathBuf,
        #[arg(long = "key-kind")]
        key_kind: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        rgba: String,
    },
    /// Remove any annotation hung off the given key.
    ClearAnnotation {
        path: PathBuf,
        #[arg(long = "key-kind")]
        key_kind: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        method: Option<String>,
    },
    /// Print the skill catalog — one JSON object listing every
    /// automation verb, its description, input schema, and example
    /// invocation. Use this to generate prompts, docs, or to drive
    /// an external MCP client.
    Skills,
    /// Run as an MCP (Model Context Protocol) stdio server. Each
    /// CLI verb becomes an LLM-callable tool. Plug into Claude
    /// Desktop / Cursor / any MCP host.
    Mcp,

    // ----- Legacy text-output commands -------------------------------
    /// Disassemble AArch64 code from an ELF or thin Mach-O.
    Arm64 {
        path: PathBuf,
        #[arg(short, long, default_value_t = 100)]
        limit: usize,
    },
    /// Inspect an APK / IPA bundle: list DEX files, native libs, etc.
    Bundle { path: PathBuf },
    /// Open the interactive GUI. Optional bundle/binary path.
    Gui {
        path: Option<PathBuf>,
        /// Ignore any previously-saved tabs / expansion state for this
        /// launch. Writes still happen, so subsequent (non-`--fresh`)
        /// launches will pick up where you leave off.
        #[arg(long)]
        fresh: bool,
    },
    /// Show what's stored in the persistence DB for a given bundle path.
    DbDump {
        path: PathBuf,
    },
    /// Inject a fake open-tab record into the DB. Used to test restore.
    DbInjectTab {
        path: PathBuf,
        /// JNI signature, e.g. "Lcom/example/Foo;"
        class_jni: String,
    },
    /// Run build_listing_rows on a native lib's .text section and print
    /// any rows that got a string-literal comment. Helps verify adrp+add
    /// pair detection without driving the GUI.
    StringComments {
        path: PathBuf,
        /// Section name (default: ".text" or "__text" — try both).
        #[arg(long)]
        section: Option<String>,
        /// Max comments to print.
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
    },
    /// Dump PLT-related sections and relocations from a native lib.
    PltProbe { path: PathBuf },
    /// Benchmark how long ArtifactId hashing of a file takes.
    HashBench { path: PathBuf },
    /// Build a CFG for the function at `entry_hex` (e.g. 0x100051e8)
    /// and print block / edge counts plus the layout summary.
    Cfg {
        path: PathBuf,
        /// Function entry address in hex (with or without 0x prefix).
        entry_hex: String,
    },
}

fn main() -> Result<()> {
    // Logs go to stderr so they never corrupt the JSON / NDJSON
    // output on stdout (automation verbs + the MCP server both
    // need stdout to be machine-clean). Default level is `warn`
    // — set `RUST_LOG=info` (or any envfilter expression) to
    // see the noisier per-load progress lines.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let cmd = match cli.cmd {
        Some(c) => c,
        // No subcommand → fall back to GUI. Honour any positional
        // path + the top-level --fresh flag.
        None => Cmd::Gui { path: cli.path, fresh: cli.fresh },
    };
    let format = Format::from_flag(cli.text);
    // Top-level verbs that don't fit the verb-table pattern.
    match &cmd {
        Cmd::Skills => {
            let cat = glass_api::skill_catalog();
            println!("{}", serde_json::to_string_pretty(&cat)?);
            return Ok(());
        }
        Cmd::Mcp => {
            return glass_mcp::serve_stdio();
        }
        _ => {}
    }
    // Automation verbs handle their own JSON / text emission and
    // exit with a structured error on failure.
    if let Some(handler) = automation_dispatch(&cmd, format) {
        if let Err(e) = handler {
            std::process::exit(output::emit_error(&e, format));
        }
        return Ok(());
    }
    // Legacy text-output subcommands fall through to here.
    match cmd {
        Cmd::Arm64 { path, limit } => dump_arm64(path, limit),
        Cmd::Bundle { path } => dump_bundle(path),
        Cmd::Gui { path, fresh } => run_gui(path, fresh),
        Cmd::DbInjectTab { path, class_jni } => db_inject_tab(path, class_jni),
        Cmd::StringComments { path, section, limit } => {
            dump_string_comments(path, section, limit)
        }
        Cmd::PltProbe { path } => plt_probe(path),
        Cmd::Cfg { path, entry_hex } => {
            let entry = u64::from_str_radix(entry_hex.trim_start_matches("0x"), 16)?;
            let bin = glass_arch_arm::Arm64Binary::open(&path)?;
            let symbols = glass_arch_arm::SymbolMap::build(&bin.container);
            let Some(cfg) =
                glass_arch_arm::build_function_cfg(&bin.container, &symbols, entry)
            else {
                anyhow::bail!("no function at 0x{entry:x}");
            };
            println!(
                "function @ 0x{:x}-0x{:x}  ({} blocks, {} edges)",
                cfg.entry_addr,
                cfg.end_addr,
                cfg.blocks.len(),
                cfg.edges.len(),
            );
            let max_rank = cfg.layout.iter().map(|l| l.rank).max().unwrap_or(0);
            let total_calls: usize = cfg.blocks.iter().map(|b| b.calls.len()).sum();
            let exits = cfg.blocks.iter().filter(|b| b.exits_function).count();
            println!(
                "max_rank={max_rank}  total_calls={total_calls}  exit_blocks={exits}",
            );
            for (block, layout) in cfg.blocks.iter().zip(cfg.layout.iter()).take(10) {
                println!(
                    "  block {:>2} rank={} pos=({:.1},{:.1}) addr=0x{:x}..0x{:x} ({} insns, {} calls){}",
                    block.id.0,
                    layout.rank,
                    layout.x,
                    layout.y,
                    block.start_addr,
                    block.end_addr,
                    block.instructions.len(),
                    block.calls.len(),
                    if block.exits_function { " EXIT" } else { "" },
                );
            }
            if cfg.blocks.len() > 10 {
                println!("  … ({} more)", cfg.blocks.len() - 10);
            }
            Ok(())
        }
        Cmd::HashBench { path } => {
            use std::time::Instant;
            let t = Instant::now();
            let bytes = std::fs::read(&path)?;
            println!("read {} MB in {:?}", bytes.len() / 1_000_000, t.elapsed());
            let t = Instant::now();
            let id = glass_db::ArtifactId::from_bytes(&bytes);
            println!("hash {} MB in {:?} -> {}", bytes.len() / 1_000_000, t.elapsed(), id);
            Ok(())
        }
        // Automation verbs are already handled by automation_dispatch
        // above; this arm exists only so the match is exhaustive.
        Cmd::BundleOpen { .. }
        | Cmd::BundleClose
        | Cmd::BundleStatus
        | Cmd::FridaAttach { .. }
        | Cmd::FridaDetach
        | Cmd::FridaStatus
        | Cmd::FridaLoadScript { .. }
        | Cmd::FridaUnloadScript { .. }
        | Cmd::FridaPostMessage { .. }
        | Cmd::FridaPollEvents
        | Cmd::FridaResume { .. }
        | Cmd::FridaSpawn { .. }
        | Cmd::StalkerCoverage { .. }
        | Cmd::DeviceList
        | Cmd::DevicePidof { .. }
        | Cmd::DeviceLaunch { .. }
        | Cmd::DeviceForceStop { .. }
        | Cmd::DevicePull { .. }
        | Cmd::DevicePush { .. }
        | Cmd::DeviceShell { .. }
        | Cmd::Inspect { .. }
        | Cmd::Artifacts { .. }
        | Cmd::Sections { .. }
        | Cmd::BinaryInfo { .. }
        | Cmd::Hash { .. }
        | Cmd::Symbols { .. }
        | Cmd::SymbolAt { .. }
        | Cmd::Demangle { .. }
        | Cmd::Disasm { .. }
        | Cmd::Decode { .. }
        | Cmd::CfgOf { .. }
        | Cmd::CallsFrom { .. }
        | Cmd::Classes { .. }
        | Cmd::Types { .. }
        | Cmd::Type { .. }
        | Cmd::Scripts { .. }
        | Cmd::ScriptRead { .. }
        | Cmd::ScriptWrite { .. }
        | Cmd::ScriptDelete { .. }
        | Cmd::ScriptEnable { .. }
        | Cmd::ScriptDisable { .. }
        | Cmd::EnabledScripts { .. }
        | Cmd::Smali { .. }
        | Cmd::SmaliSet { .. }
        | Cmd::Methods { .. }
        | Cmd::Fields { .. }
        | Cmd::MethodCalls { .. }
        | Cmd::XrefAddr { .. }
        | Cmd::Callers { .. }
        | Cmd::DexCallers { .. }
        | Cmd::FieldRefs { .. }
        | Cmd::Search { .. }
        | Cmd::Strings { .. }
        | Cmd::BinSearch { .. }
        | Cmd::InsnSearch { .. }
        | Cmd::Patch { .. }
        | Cmd::ExportPatched { .. }
        | Cmd::PatchSchema
        | Cmd::Annotations { .. }
        | Cmd::DbDump { .. }
        | Cmd::SetRename { .. }
        | Cmd::SetComment { .. }
        | Cmd::SetColour { .. }
        | Cmd::ClearAnnotation { .. } => unreachable!("handled by automation_dispatch"),
        Cmd::Skills | Cmd::Mcp => unreachable!("handled above the verb-table dispatch"),
    }
}

fn plt_probe(path: PathBuf) -> Result<()> {
    let bin = glass_arch_arm::Arm64Binary::open(&path)?;
    let c = &bin.container;
    println!("=== plt-like sections ===");
    for s in &c.sections {
        if s.name.contains("plt") || s.name.contains("got") {
            println!(
                "  {:30} addr=0x{:08x} size=0x{:08x} bytes={}",
                s.name,
                s.address,
                s.size,
                s.bytes.len(),
            );
        }
    }
    // Group relocations by section name.
    use std::collections::HashMap;
    let mut by_sec: HashMap<&str, Vec<&armv8_encode::container::Relocation>> =
        HashMap::new();
    for r in &c.relocations {
        let name = c.sections.get(r.section.0).map(|s| s.name.as_str()).unwrap_or("?");
        by_sec.entry(name).or_default().push(r);
    }
    println!("=== relocation counts by target section ===");
    let mut names: Vec<&&str> = by_sec.keys().collect();
    names.sort();
    for n in names {
        println!("  {} : {}", n, by_sec[n].len());
    }
    for target in [".got.plt", ".got", ".rela.plt"] {
        if let Some(relocs) = by_sec.get(target) {
            println!("=== first 10 relocations targeting {} ===", target);
            for r in relocs.iter().take(10) {
                let sym_name = r
                    .symbol
                    .and_then(|id| c.symbols.get(id.0).map(|s| s.name.as_str()))
                    .unwrap_or("(no sym)");
                println!(
                    "  offset=0x{:08x} kind={:?} addend={} sym={}",
                    r.offset, r.kind, r.addend, sym_name,
                );
            }
        }
    }
    Ok(())
}

fn dump_string_comments(
    path: PathBuf,
    section_arg: Option<String>,
    limit: usize,
) -> Result<()> {
    use std::sync::Arc;
    let bin = glass_arch_arm::Arm64Binary::open(&path)?;
    let symbols = glass_arch_arm::SymbolMap::build(&bin.container);

    // Find the requested text section (keeping its index for the
    // precompute call below).
    let pick = section_arg.as_deref();
    let (section_index, text_sec) = bin
        .container
        .sections
        .iter()
        .enumerate()
        .find(|(_, s)| {
            matches!(s.kind, armv8_encode::container::SectionKind::Text)
                && pick.map(|p| p == s.name).unwrap_or(true)
        })
        .ok_or_else(|| anyhow::anyhow!("no matching text section"))?;
    println!(
        "# Disassembling {} ({} bytes)",
        text_sec.name,
        text_sec.bytes.len()
    );

    // Variable-length ISAs (ARMv7 Thumb, x86/x86_64) must be
    // precomputed so the listing renderer doesn't chunk by 4 bytes;
    // AArch64 decodes on demand and leaves the slot empty. Mirrors
    // `glass_ui::loader::build_text_section_bytes`.
    let symbol_addresses: Vec<u64> = symbols.iter().map(|s| s.address).collect();
    let precomputed = glass_arch_arm::precompute_section_insns(
        &bin.container,
        section_index,
        &symbol_addresses,
    )
    .map(Arc::new);

    let text = glass_ui::TextSectionBytes {
        base: text_sec.address,
        bytes: Arc::new(text_sec.bytes.clone()),
        precomputed,
        arch: bin.container.architecture,
    };
    // Build a DataPeek from non-text non-debug non-zero-base sections.
    // See LoadedBundle::data_sections loader for matching filter.
    let mut data_sections = Vec::new();
    let mut section_meta = Vec::new();
    for s in &bin.container.sections {
        if matches!(s.kind, armv8_encode::container::SectionKind::Text)
            || matches!(s.kind, armv8_encode::container::SectionKind::Debug)
            || s.bytes.is_empty()
            || s.address == 0
        {
            continue;
        }
        data_sections.push((s.address, Arc::new(s.bytes.clone())));
        section_meta.push(glass_ui::DataSectionMeta {
            name: s.name.clone(),
            base: s.address,
            size: s.bytes.len() as u64,
        });
    }
    let data = glass_ui::DataPeek {
        sections: data_sections,
        code_sections: Vec::new(),
        section_meta,
    };
    println!("# DataPeek has {} sections", data.sections.len());
    for (b, bytes) in &data.sections {
        println!("#   0x{:x}  ({} bytes)", b, bytes.len());
    }

    let rows = glass_ui::build_listing_rows(&text, &symbols, &data, None);
    let mut found = 0usize;
    let mut rows_with_arrows = 0usize;
    let mut total_segments = 0usize;
    let mut max_lane = 0u8;
    let mut solid = 0usize;
    let mut dotted = 0usize;
    for r in &rows {
        if let glass_ui::ListingRow::Instruction { address, comment, mnemonic, arrows, .. } = r {
            if comment.contains('"') {
                found += 1;
                if found <= limit {
                    println!("0x{:016x}  {}  {}", address, mnemonic, comment);
                }
            }
            if !arrows.is_empty() {
                rows_with_arrows += 1;
                total_segments += arrows.len();
                for s in arrows.iter() {
                    if s.lane > max_lane { max_lane = s.lane; }
                    match s.style {
                        glass_ui::ArrowStyle::Solid => solid += 1,
                        glass_ui::ArrowStyle::Dotted => dotted += 1,
                    }
                }
            }
        }
    }
    println!("# Total string comments: {found}");
    println!(
        "# Arrow rows: {rows_with_arrows}  segments: {total_segments}  max_lane: {max_lane}  solid_segs: {solid}  dotted_segs: {dotted}"
    );
    Ok(())
}

fn db_inject_tab(path: PathBuf, class_jni: String) -> Result<()> {
    let bytes = std::fs::read(&path)?;
    let id = glass_db::BundleId::from_bytes(&bytes);
    let db = glass_db::Database::open(false)?;
    let mut rec = db.load_bundle(&id)?.unwrap_or(glass_db::BundleRecord {
        schema_version: 1,
        label: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        last_opened_unix: 0,
        artifacts: vec![],
        open_tabs: vec![],
        active_tab: None,
        expanded_paths: vec![],
        source_path: None,
        annotations_pane_open: false,
        window_tint: 0,
    });
    rec.open_tabs.push(glass_db::TabState::SmaliClass { class_jni, scroll_line: 0 });
    rec.active_tab = Some(rec.open_tabs.len() - 1);
    db.save_bundle(id, rec);
    db.flush()?;
    println!("injected tab; relaunch `glass gui {}` to restore", path.display());
    Ok(())
}

fn run_gui(path: Option<PathBuf>, fresh: bool) -> Result<()> {
    // The UI handles loading itself (background + progress bar). All we do
    // here is hand it the path.
    glass_ui::launch(path, fresh)
}

fn dump_arm64(path: PathBuf, limit: usize) -> Result<()> {
    let binary = glass_arch_arm::Arm64Binary::open(&path)?;
    let rows = glass_arch_arm::linear_sweep(&binary.container)?;
    println!("# {} ({} bytes) — {} rows", path.display(), binary.bytes.len(), rows.len());
    for row in rows.iter().take(limit) {
        println!(
            "0x{:016x}  {:02x} {:02x} {:02x} {:02x}  {}",
            row.address, row.bytes[0], row.bytes[1], row.bytes[2], row.bytes[3], row.text,
        );
    }
    Ok(())
}

fn dump_bundle(path: PathBuf) -> Result<()> {
    use glass_mobile::Bundle;
    match Bundle::open(&path)? {
        Bundle::Apk(apk) => {
            println!("APK: {}", apk.path.display());
            println!("  DEX files: {}", apk.dex_files.len());
            for d in &apk.dex_files {
                println!("    {}", d.name);
            }
            println!("  Native libs: {}", apk.native_libs.len());
            for lib in &apk.native_libs {
                let sm = glass_arch_arm::SymbolMap::build(&lib.binary.container);
                println!("    {}/{}  ({} symbols)", lib.abi, lib.name, sm.len());
                let mut plt_examples: Vec<&glass_arch_arm::Symbol> = sm
                    .iter()
                    .filter(|s| s.display_name.ends_with("@plt"))
                    .take(5)
                    .collect();
                for sym in sm.iter().take(5) {
                    println!(
                        "      {:016x}  size={:#x}  src={:?}  {}",
                        sym.address, sym.size, sym.sources, sym.display_name,
                    );
                }
                if sm.len() > 5 {
                    println!("      … ({} more)", sm.len() - 5);
                }
                if !plt_examples.is_empty() {
                    println!("      sample @plt:");
                    while let Some(sym) = plt_examples.pop() {
                        println!(
                            "        {:016x}  size={:#x}  {}",
                            sym.address, sym.size, sym.display_name,
                        );
                    }
                }
            }
        }
        Bundle::Ipa(ipa) => {
            println!("IPA: {}", ipa.path.display());
            println!("  app dir       : {}", ipa.app_dir);
            println!("  bundle id     : {:?}", ipa.info.bundle_id);
            println!("  display name  : {:?}", ipa.info.display_name);
            println!("  executable    : {:?}", ipa.info.executable);
            println!("  version       : {:?} (build {:?})", ipa.info.short_version, ipa.info.build_version);
            println!("  min iOS       : {:?}", ipa.info.min_os);
            println!("  platform      : {:?}", ipa.info.platform);
            match &ipa.main_executable {
                Some(bin) => {
                    let sm = glass_arch_arm::SymbolMap::build(&bin.container);
                    println!("  main exec     : loaded ({} bytes, {} symbols)", bin.bytes.len(), sm.len());
                    for sym in sm.iter().take(5) {
                        println!("      {:016x}  {}", sym.address, sym.display_name);
                    }
                    if sm.len() > 5 {
                        println!("      … ({} more)", sm.len() - 5);
                    }
                    let stub_examples: Vec<&glass_arch_arm::Symbol> = sm
                        .iter()
                        .filter(|s| s.display_name.ends_with("@stubs"))
                        .take(5)
                        .collect();
                    let total_stubs = sm
                        .iter()
                        .filter(|s| s.display_name.ends_with("@stubs"))
                        .count();
                    if !stub_examples.is_empty() {
                        println!("      sample @stubs ({} total):", total_stubs);
                        for sym in &stub_examples {
                            println!(
                                "        {:016x}  size={:#x}  {}",
                                sym.address, sym.size, sym.display_name,
                            );
                        }
                    }
                }
                None => println!("  main exec     : (not loaded)"),
            }
            println!("  frameworks    : {}", ipa.frameworks.len());
            for fw in &ipa.frameworks {
                println!("      {}  ({} bytes)  {}", fw.name, fw.bytes.len(), fw.archive_path);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod parity_tests {
    //! Guards the catalog ↔ CLI half of the four-way parity rule in
    //! CLAUDE.md. Every automation verb in `glass_api::skill_catalog()`
    //! must be reachable as a CLI subcommand (MCP-only verbs appear as
    //! stub variants). The CLI may carry extra non-catalog subcommands
    //! — legacy verbs, the GUI launcher, `mcp`, `skills` — so the
    //! catalog is a *subset* of the CLI, and any surplus must be an
    //! explicitly acknowledged entry in `NON_CATALOG` below.
    use super::Cli;
    use clap::CommandFactory;
    use std::collections::BTreeSet;

    /// CLI subcommands that intentionally have no skill-catalog entry:
    /// legacy one-offs, the GUI/server launchers, catalog/dev helpers,
    /// and clap's auto-generated `help`. A new subcommand that lands
    /// here without being an automation verb must be added to this list
    /// consciously — which is the prompt to ask "should this be a
    /// catalog verb + MCP arm instead?".
    const NON_CATALOG: &[&str] = &[
        "arm64",           // legacy raw-disassembly subcommand
        "bundle",          // legacy bundle-inspect subcommand
        "cfg",             // legacy CFG dump, superseded by the `cfg-of` verb
        "gui",             // launches the GPUI app, not an analysis verb
        "mcp",             // runs the MCP server
        "skills",          // prints the catalog itself
        "db-inject-tab",   // dev/debug helper
        "hash-bench",      // benchmark: time ArtifactId hashing
        "plt-probe",       // diagnostic: dump PLT sections + relocations
        "string-comments", // dev: verify adrp+add string-literal detection
        "help",            // clap-generated
    ];

    fn cli_subcommands() -> BTreeSet<String> {
        Cli::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect()
    }

    fn catalog_verbs() -> BTreeSet<String> {
        glass_api::skill_catalog()
            .skills
            .iter()
            .map(|s| s.name.to_string())
            .collect()
    }

    #[test]
    fn every_catalog_verb_has_a_cli_subcommand() {
        let cli = cli_subcommands();
        let catalog = catalog_verbs();
        let missing: Vec<&String> = catalog.difference(&cli).collect();
        assert!(
            missing.is_empty(),
            "skill catalog lists verb(s) with no CLI subcommand: {missing:?}\n\
             Add a `Cmd` variant + dispatch arm in glass-cli (a stub for MCP-only verbs; \
             see CLAUDE.md skill-catalog parity)."
        );
    }

    #[test]
    fn no_unaccounted_cli_subcommand() {
        let catalog = catalog_verbs();
        let allow: BTreeSet<String> = NON_CATALOG.iter().map(|s| s.to_string()).collect();
        let unexpected: Vec<String> = cli_subcommands()
            .into_iter()
            .filter(|c| !catalog.contains(c) && !allow.contains(c))
            .collect();
        assert!(
            unexpected.is_empty(),
            "CLI subcommand(s) that are neither a catalog verb nor a known non-catalog command: \
             {unexpected:?}\n\
             If this is a new automation verb, add it to the skill catalog + MCP dispatcher too; \
             if it's intentionally CLI-only, add it to NON_CATALOG in this test."
        );
    }
}
