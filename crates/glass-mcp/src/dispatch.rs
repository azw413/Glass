//! Tool-name → `glass_api` dispatch.
//!
//! One arm per verb. Each arm pulls typed args out of the JSON
//! object the MCP client sent, calls the matching `glass_api`
//! function, and serialises the result back to a JSON string for
//! the `text` content block.
//!
//! Every arm goes through the same envelope as the CLI:
//! `{ "data": ..., "meta": { "duration_ms": ... } }`. Keeping the
//! shape consistent between CLI and MCP means a single piece of
//! downstream tooling (jq filter, schema, prompt example) can
//! consume either source.

use std::path::PathBuf;
use std::time::Instant;

use serde_json::{json, Value};

use crate::DispatchError;

type Result<T> = std::result::Result<T, DispatchError>;

pub(crate) fn call(
    name: &str,
    args: &Value,
    state: &crate::state::StateHandle,
) -> Result<String> {
    let start = Instant::now();
    let data: Value = match name {
        // ---- Stateful bundle lifecycle ----------------------------
        "bundle-open" => {
            // Open and cache a bundle for subsequent calls.
            // Returns a small summary (kind + label + source_path
            // + artifact count) — the full inspect data is one
            // verb away. Replaces any previously-open bundle.
            let path = require_path(args)?;
            let bundle = std::sync::Arc::new(glass_api::open(&path)?);
            let inspection = bundle.inspect();
            {
                let mut st = state.lock();
                st.bundle = Some(crate::state::OpenBundle {
                    source_path: path.clone(),
                    bundle,
                });
            }
            json!({
                "source_path": path.display().to_string(),
                "kind": inspection.kind,
                "label": inspection.label,
                "artifact_count": inspection.artifacts.len(),
                "bundle_id": inspection.bundle_id,
            })
        }
        "bundle-close" => {
            // Drop the cached bundle. Subsequent path-bearing verbs
            // re-parse fresh. No-op when nothing is open.
            let had = {
                let mut st = state.lock();
                let had = st.bundle.is_some();
                st.bundle = None;
                had
            };
            json!({ "closed": had })
        }
        "bundle-status" => {
            // Report what (if anything) is currently open. Useful
            // for an LLM to check before issuing path-less follow-up
            // verbs once those land.
            let st = state.lock();
            match st.bundle.as_ref() {
                Some(b) => json!({
                    "open": true,
                    "source_path": b.source_path.display().to_string(),
                    "label": b.bundle.label(),
                }),
                None => json!({ "open": false }),
            }
        }

        "inspect" => {
            let bundle = open(args, state)?;
            json_of(&bundle.inspect())?
        }
        "artifacts" => {
            let bundle = open(args, state)?;
            json_of(&bundle.artifacts())?
        }
        "sections" => {
            let bundle = open(args, state)?;
            let artifact = opt_str(args, "artifact");
            json_of(&bundle.sections(artifact.as_deref()))?
        }
        "binary-info" => {
            let bundle = open(args, state)?;
            json_of(&bundle.binary_info())?
        }
        "hash" => {
            let path = require_path(args)?;
            json_of(&glass_api::hash_file(&path)?)?
        }
        "symbols" => {
            let bundle = open(args, state)?;
            let artifact = opt_str(args, "artifact");
            let filter = opt_str(args, "filter");
            let kind = opt_str(args, "kind").as_deref().and_then(parse_kind);
            let limit = opt_usize(args, "limit");
            let query = glass_api::SymbolQuery {
                artifact: artifact.as_deref(),
                filter: filter.as_deref(),
                kind,
                limit,
            };
            json_of(&bundle.symbols(query))?
        }
        "symbol-at" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let addr = require_hex_u64(args, "addr")?;
            json_of(&bundle.symbol_at(&artifact, addr))?
        }
        "demangle" => {
            let name = require_str(args, "name")?;
            json_of(&glass_api::demangle(&name))?
        }
        "disasm" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let section = opt_str(args, "section");
            let limit = opt_usize(args, "limit");
            json_of(&bundle.disasm(&artifact, section.as_deref(), limit)?)?
        }
        "decode" => {
            let word_s = require_str(args, "word")?;
            let word = u32::from_str_radix(word_s.trim_start_matches("0x"), 16)
                .map_err(|e| DispatchError::Other(format!("bad word {word_s:?}: {e}")))?;
            let addr = match opt_str(args, "addr") {
                Some(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16)
                    .map_err(|e| DispatchError::Other(format!("bad addr {s:?}: {e}")))?,
                None => 0,
            };
            json_of(&glass_api::decode_word(word, addr))?
        }
        "cfg-of" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let func = require_str(args, "func")?;
            json_of(&bundle.cfg(&artifact, &func)?)?
        }
        "calls-from" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let func = require_str(args, "func")?;
            json_of(&bundle.calls_from(&artifact, &func)?)?
        }
        "classes" => {
            let bundle = open(args, state)?;
            let package = opt_str(args, "package");
            json_of(&bundle.classes(package.as_deref()))?
        }
        "types" => {
            let bundle = open(args, state)?;
            let artifact = opt_str(args, "artifact");
            let package = opt_str(args, "package");
            let kind = match opt_str(args, "kind") {
                Some(s) => match glass_api::TypeKind::parse(&s) {
                    Some(k) => Some(k),
                    None => {
                        return Err(DispatchError::Other(format!(
                            "unknown kind {s:?}: expected objc-class, objc-category, swift-class, swift-struct, swift-enum"
                        )))
                    }
                },
                None => None,
            };
            let limit = opt_usize(args, "limit").or(Some(200));
            json_of(&bundle.types(
                artifact.as_deref(),
                kind,
                package.as_deref(),
                limit,
            )?)?
        }
        "type" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let name = require_str(args, "name")?;
            let raw = args
                .get("raw")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            json_of(&bundle.type_detail(&artifact, &name, raw)?)?
        }
        "scripts" => {
            // Optional `path` scopes to a bundle so each row carries
            // `enabled_for_bundle`. Without it the listing is global.
            match opt_str(args, "path") {
                Some(p) => json_of(&glass_api::scripts_for_bundle(&p)?)?,
                None => json_of(&glass_api::scripts()?)?,
            }
        }
        "script-read" => {
            let name = require_str(args, "name")?;
            json_of(&glass_api::read_script(&name)?)?
        }
        "script-write" => {
            let name = require_str(args, "name")?;
            let body = require_str(args, "body")?;
            let description = opt_str(args, "description");
            let tags = args
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                });
            json_of(&glass_api::write_script(
                &name,
                &body,
                description.as_deref(),
                tags,
            )?)?
        }
        "script-delete" => {
            let name = require_str(args, "name")?;
            json_of(&glass_api::delete_script(&name)?)?
        }
        "script-enable" => {
            let path = require_path(args)?;
            let name = require_str(args, "name")?;
            json_of(&glass_api::set_script_enabled(&path, &name, true)?)?
        }
        "script-disable" => {
            let path = require_path(args)?;
            let name = require_str(args, "name")?;
            json_of(&glass_api::set_script_enabled(&path, &name, false)?)?
        }
        "enabled-scripts" => {
            let path = require_path(args)?;
            json_of(&glass_api::enabled_scripts(&path)?)?
        }
        "smali" => {
            let bundle = open(args, state)?;
            let class = require_str(args, "class")?;
            json_of(&bundle.smali(&class)?)?
        }
        "methods" => {
            let bundle = open(args, state)?;
            let class = require_str(args, "class")?;
            json_of(&bundle.methods(&class)?)?
        }
        "fields" => {
            let bundle = open(args, state)?;
            let class = require_str(args, "class")?;
            json_of(&bundle.fields(&class)?)?
        }
        "method-calls" => {
            let bundle = open(args, state)?;
            let class = require_str(args, "class")?;
            let method = require_str(args, "method")?;
            json_of(&bundle.method_calls(&class, &method)?)?
        }
        "xref-addr" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let addr = require_hex_u64(args, "addr")?;
            json_of(&bundle.xref_addr(&artifact, addr)?)?
        }
        "callers" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let symbol = require_str(args, "symbol")?;
            json_of(&bundle.callers(&artifact, &symbol)?)?
        }
        "dex-callers" => {
            let bundle = open(args, state)?;
            let method = require_str(args, "method")?;
            json_of(&bundle.dex_callers(&method))?
        }
        "field-refs" => {
            let bundle = open(args, state)?;
            let field = require_str(args, "field")?;
            json_of(&bundle.field_refs(&field))?
        }
        "search" => {
            let bundle = open(args, state)?;
            let query = require_str(args, "query")?;
            let limit = opt_usize(args, "limit");
            json_of(&bundle.search(&query, limit))?
        }
        "strings" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let min = opt_usize(args, "min");
            let limit = opt_usize(args, "limit");
            json_of(&bundle.strings(&artifact, min, limit)?)?
        }
        "annotations" => {
            let path = require_path(args)?;
            json_of(&glass_api::annotations(&path)?)?
        }
        "db-dump" => {
            let path = require_path(args)?;
            json_of(&glass_api::db_dump(&path)?)?
        }
        "set-rename" => {
            let path = require_path(args)?;
            let key_kind = require_str(args, "key_kind")?;
            let key = require_str(args, "key")?;
            let method = opt_str(args, "method");
            let name = require_str(args, "name")?;
            let key_args = glass_api::AnnotationKeyArgs {
                kind: &key_kind,
                key: &key,
                method: method.as_deref(),
            };
            json_of(&glass_api::set_rename(&path, key_args, &name)?)?
        }
        "set-comment" => {
            let path = require_path(args)?;
            let key_kind = require_str(args, "key_kind")?;
            let key = require_str(args, "key")?;
            let method = opt_str(args, "method");
            let body = require_str(args, "body")?;
            let key_args = glass_api::AnnotationKeyArgs {
                kind: &key_kind,
                key: &key,
                method: method.as_deref(),
            };
            json_of(&glass_api::set_comment(&path, key_args, &body)?)?
        }
        "set-colour" => {
            let path = require_path(args)?;
            let key_kind = require_str(args, "key_kind")?;
            let key = require_str(args, "key")?;
            let method = opt_str(args, "method");
            let rgba = require_str(args, "rgba")?;
            let key_args = glass_api::AnnotationKeyArgs {
                kind: &key_kind,
                key: &key,
                method: method.as_deref(),
            };
            json_of(&glass_api::set_colour(&path, key_args, &rgba)?)?
        }
        "clear-annotation" => {
            let path = require_path(args)?;
            let key_kind = require_str(args, "key_kind")?;
            let key = require_str(args, "key")?;
            let method = opt_str(args, "method");
            let key_args = glass_api::AnnotationKeyArgs {
                kind: &key_kind,
                key: &key,
                method: method.as_deref(),
            };
            json_of(&glass_api::clear_annotation(&path, key_args)?)?
        }
        "bin-search" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let pattern = require_str(args, "pattern")?;
            let section = opt_str(args, "section");
            let limit = opt_usize(args, "limit");
            json_of(&bundle.bin_search(&artifact, &pattern, section.as_deref(), limit)?)?
        }
        "insn-search" => {
            let bundle = open(args, state)?;
            let artifact = require_str(args, "artifact")?;
            let pattern = require_str(args, "pattern")?;
            let section = opt_str(args, "section");
            let limit = opt_usize(args, "limit");
            json_of(&bundle.insn_search(&artifact, &pattern, section.as_deref(), limit)?)?
        }
        "patch" => {
            // Reuses the same code path as the CLI verb by
            // calling glass_api::PatchFile + compile_insn_at.
            let path = require_path(args)?;
            let artifact_ref = require_str(args, "artifact")?;
            let addr_str = require_str(args, "addr")?;
            let patches_path = std::path::PathBuf::from(require_str(args, "patches")?);
            let insn = opt_str(args, "insn");
            let bytes = opt_str(args, "bytes");

            let bundle = glass_api::open(&path)?;
            let artifact_id = bundle
                .resolve_artifact(&artifact_ref)
                .ok_or_else(|| {
                    DispatchError::Other(format!(
                        "no artifact matches {artifact_ref:?}"
                    ))
                })?
                .clone();
            let vaddr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                .map_err(|e| {
                    DispatchError::Other(format!(
                        "bad hex address {addr_str:?}: {e}"
                    ))
                })?;
            let (new_bytes, kind, source_text) = match (insn, bytes) {
                (Some(insn_src), None) => {
                    let bytes_vec = glass_api::compile_insn_at(&insn_src, vaddr, None)?;
                    (bytes_vec, glass_api::PatchKind::Instruction, insn_src)
                }
                (None, Some(hex_src)) => {
                    let bytes_vec = parse_hex_bytes(&hex_src)?;
                    let display = bytes_vec
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    (bytes_vec, glass_api::PatchKind::Bytes, display)
                }
                (Some(_), Some(_)) => {
                    return Err(DispatchError::Other("provide either `insn` or `bytes`, not both".to_string()))
                }
                (None, None) => {
                    return Err(DispatchError::Other("provide `insn` or `bytes`".to_string()))
                }
            };
            let mut pf = glass_api::PatchFile::read_or_default(&patches_path)?;
            if pf.source_path.is_none() {
                pf.source_path = Some(path.clone());
            }
            pf.upsert(glass_api::PatchEntry {
                artifact: artifact_id.to_hex(),
                vaddr,
                kind,
                new_bytes: new_bytes.clone(),
                original_bytes: Vec::new(),
                source_text,
            });
            pf.write(&patches_path)?;
            let new_bytes_hex = new_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            json_of(&serde_json::json!({
                "patches": patches_path,
                "artifact": artifact_id.to_hex(),
                "vaddr": format!("0x{vaddr:x}"),
                "new_bytes_hex": new_bytes_hex,
                "total_edits": pf.edits.len(),
            }))?
        }
        "smali-set" => {
            let path = require_path(args)?;
            let class_ref = require_str(args, "class")?;
            let body = require_str(args, "body")?;
            let patches_path = std::path::PathBuf::from(require_str(args, "patches")?);
            if body.trim().is_empty() {
                return Err(DispatchError::Other("smali body is empty".to_string()));
            }
            let parsed = glass_api::parse_smali_class(&body)?;
            let bundle = glass_api::open(&path)?;
            let (artifact_id, class_jni) =
                bundle.resolve_smali_class(&class_ref)?;
            let body_jni = glass_api::smali_class_jni(&parsed);
            if body_jni != class_jni {
                return Err(DispatchError::Other(format!(
                    "smali body declares class {body_jni:?} but `class` resolves to {class_jni:?}"
                )));
            }
            let mut pf = glass_api::PatchFile::read_or_default(&patches_path)?;
            if pf.source_path.is_none() {
                pf.source_path = Some(path.clone());
            }
            let body_bytes = body.len();
            pf.upsert_smali(glass_api::SmaliPatchEntry {
                artifact: artifact_id.to_hex(),
                class_jni: class_jni.clone(),
                body,
            });
            pf.write(&patches_path)?;
            json_of(&serde_json::json!({
                "patches": patches_path,
                "artifact": artifact_id.to_hex(),
                "class_jni": class_jni,
                "body_bytes": body_bytes,
                "total_smali_edits": pf.smali_edits.len(),
            }))?
        }
        "export-patched" => {
            let path = require_path(args)?;
            let patches = std::path::PathBuf::from(require_str(args, "patches")?);
            let out = std::path::PathBuf::from(require_str(args, "out")?);
            let pf = glass_api::PatchFile::read_or_default(&patches)?;
            if pf.edits.is_empty() && pf.smali_edits.is_empty() {
                return Err(DispatchError::Other(format!(
                    "patch file {} contains no edits",
                    patches.display()
                )));
            }
            let edits_applied = pf.edits.len() + pf.smali_edits.len();
            let bundle = glass_api::open(&path)?;
            let edit_map = pf.to_edit_map();
            let smali_map = pf.to_smali_edit_map()?;
            // MCP export carries no additions today — same shape
            // as the CLI verb; the gadget-injection flow lives
            // in the GUI.
            let additions = glass_api::ApkAdditions::new();
            glass_api::export_to_path_with_smali(
                &bundle, &edit_map, &smali_map, &additions, &out,
            )?;
            json_of(&serde_json::json!({
                "out": out,
                "edits_applied": edits_applied,
            }))?
        }
        "patch-schema" => json_of(&glass_api::patch_file_schema())?,

        // ---- Frida session lifecycle -----------------------------
        "frida-attach" => {
            // Attach to a Frida-instrumented process. `host` is a
            // `host:port` reachable from the dev machine — for
            // gadget mode this is typically `127.0.0.1:27042`
            // after `adb forward tcp:27042 tcp:27042`. For
            // frida-server mode `frida-ls-devices` shows the
            // remote endpoint. Replaces any existing session.
            let host = opt_str(args, "host")
                .unwrap_or_else(|| "127.0.0.1:27042".to_string());
            let pid = args
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| DispatchError::Other(
                    "missing required u32 arg \"pid\"".into(),
                ))? as u32;
            // Drop any prior session before spawning a new actor.
            {
                let mut st = state.lock();
                if let Some(prev) = st.frida.take() {
                    let _ = prev.session.detach();
                    prev.session.shutdown();
                }
            }
            let session = glass_frida::Session::spawn();
            let report = session
                .attach_remote(host.clone(), pid)
                .map_err(DispatchError::Other)?;
            let agent_version = report.agent_version.clone();
            let os = report.os.clone();
            {
                let mut st = state.lock();
                st.frida = Some(crate::state::FridaAttached {
                    session,
                    host: host.clone(),
                    pid,
                    agent_version: agent_version.clone(),
                    os: os.clone(),
                });
            }
            json!({
                "attached": true,
                "host": host,
                "pid": pid,
                "agent_version": agent_version,
                "os": os,
            })
        }
        "frida-spawn" => {
            // Spawn a target by program name (package on Android)
            // and attach to it paused. Returns the new pid; call
            // `frida-load-script` to set up instrumentation, then
            // `frida-resume` with the same pid to let it run.
            let host = opt_str(args, "host")
                .unwrap_or_else(|| "127.0.0.1:27042".to_string());
            let program = require_str(args, "program")?;
            // Tear down any prior session first.
            {
                let mut st = state.lock();
                if let Some(prev) = st.frida.take() {
                    let _ = prev.session.detach();
                    prev.session.shutdown();
                }
            }
            let session = glass_frida::Session::spawn();
            let report = session
                .spawn_remote(host.clone(), program.clone())
                .map_err(DispatchError::Other)?;
            let pid = report.pid;
            {
                let mut st = state.lock();
                st.frida = Some(crate::state::FridaAttached {
                    session,
                    host: host.clone(),
                    pid,
                    agent_version: None,
                    os: None,
                });
            }
            json!({
                "spawned": true,
                "host": host,
                "program": program,
                "pid": pid,
                "paused": true,
            })
        }
        "frida-detach" => {
            let prev = { state.lock().frida.take() };
            let had = prev.is_some();
            if let Some(p) = prev {
                let _ = p.session.detach();
                p.session.shutdown();
            }
            json!({ "detached": had })
        }
        "frida-status" => {
            let st = state.lock();
            match st.frida.as_ref() {
                Some(f) => json!({
                    "attached": true,
                    "host": f.host,
                    "pid": f.pid,
                    "agent_version": f.agent_version,
                    "os": f.os,
                }),
                None => json!({ "attached": false }),
            }
        }
        "frida-load-script" => {
            // Load JS source into the attached session. `name` is
            // a short tag for diagnostics; `source` is the literal
            // JS (use frida's repl semantics). Returns a
            // `script_id` to use for unload / post-message / event
            // routing.
            let name_arg = opt_str(args, "name")
                .unwrap_or_else(|| "mcp-script".to_string());
            let source = require_str(args, "source")?;
            let session = clone_frida(state)?;
            let id = session.alloc_script_id();
            session
                .create_script(id, name_arg.clone(), source)
                .map_err(DispatchError::Other)?;
            json!({ "script_id": id, "name": name_arg })
        }
        "frida-unload-script" => {
            let id = args
                .get("script_id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| DispatchError::Other(
                    "missing required u32 arg \"script_id\"".into(),
                ))? as u32;
            let session = clone_frida(state)?;
            session.unload_script(id).map_err(DispatchError::Other)?;
            json!({ "unloaded": id })
        }
        "frida-post-message" => {
            // Forward a JSON value to the running script — the
            // script observes it via `recv(...)`. Accepts either
            // a JSON string (passed through) or any other JSON
            // value (serialised here so the LLM doesn't have to
            // double-encode).
            let id = args
                .get("script_id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| DispatchError::Other(
                    "missing required u32 arg \"script_id\"".into(),
                ))? as u32;
            let message_value = args
                .get("message")
                .ok_or_else(|| DispatchError::Other(
                    "missing required arg \"message\"".into(),
                ))?;
            let payload = match message_value {
                Value::String(s) => s.clone(),
                other => serde_json::to_string(other)?,
            };
            let session = clone_frida(state)?;
            session
                .post_message(id, payload)
                .map_err(DispatchError::Other)?;
            json!({ "posted": id })
        }
        "frida-poll-events" => {
            // Non-blocking drain of accumulated events. Each
            // event is rendered as a `{kind, ...}` object. Call
            // this on a tick to surface `send(...)` from scripts.
            let session = clone_frida(state)?;
            let events = session.poll_events();
            let rendered: Vec<Value> = events
                .into_iter()
                .map(render_session_event)
                .collect();
            json!({ "events": rendered })
        }
        // ---- Devices ------------------------------------------------
        "device-list" => {
            // Snapshot all reachable devices (Android via adb,
            // iOS via libimobiledevice).
            let mgr = glass_device::DeviceManager::new();
            let devices: Vec<Value> = mgr
                .list()
                .into_iter()
                .map(|d| {
                    json!({
                        "platform": d.id.platform.label(),
                        "serial": d.id.serial,
                        "model": d.model,
                        "os_version": d.os_version,
                        "state": format!("{:?}", d.state),
                    })
                })
                .collect();
            json!({ "devices": devices })
        }
        "device-pidof" => {
            // Resolve a process name (or package name) to PIDs
            // on an Android device. Use the first PID as
            // `frida-attach`'s `pid` arg.
            let serial = require_str(args, "serial")?;
            let name = require_str(args, "name")?;
            let mgr = glass_device::DeviceManager::new();
            let pids = mgr
                .android_pidof(&serial, &name)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "pids": pids })
        }
        "device-launch" => {
            // Launch an Android app by package name (`monkey
            // -p <pkg>`). Returns combined stdout+stderr.
            let serial = require_str(args, "serial")?;
            let package = require_str(args, "package")?;
            let mgr = glass_device::DeviceManager::new();
            let out = mgr
                .android_launch(&serial, &package)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "output": out })
        }
        "device-force-stop" => {
            // Force-stop every process belonging to an Android
            // package (`am force-stop <pkg>`).
            let serial = require_str(args, "serial")?;
            let package = require_str(args, "package")?;
            let mgr = glass_device::DeviceManager::new();
            let out = mgr
                .android_force_stop(&serial, &package)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "output": out })
        }
        "device-pull" => {
            // `adb pull <remote> <local>`. Note paths under
            // `/data/data/<pkg>/` need root or a debuggable
            // package; this verb doesn't try to elevate.
            let serial = require_str(args, "serial")?;
            let remote = require_str(args, "remote")?;
            let local = PathBuf::from(require_str(args, "local")?);
            let mgr = glass_device::DeviceManager::new();
            let out = mgr
                .android_pull(&serial, &remote, &local)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "output": out, "local": local.display().to_string() })
        }
        "device-push" => {
            let serial = require_str(args, "serial")?;
            let local = PathBuf::from(require_str(args, "local")?);
            let remote = require_str(args, "remote")?;
            let mgr = glass_device::DeviceManager::new();
            let out = mgr
                .android_push(&serial, &local, &remote)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "output": out, "remote": remote })
        }
        "device-shell" => {
            // Run an arbitrary `adb shell` command. `args` is
            // the array passed after `adb -s <serial> shell …`.
            let serial = require_str(args, "serial")?;
            let cmd_args: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .ok_or_else(|| DispatchError::Other(
                    "missing required string-array arg \"args\"".into(),
                ))?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect();
            let refs: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
            let mgr = glass_device::DeviceManager::new();
            let out = mgr
                .android_shell(&serial, &refs)
                .map_err(|e| DispatchError::Other(e.to_string()))?;
            json!({ "stdout": out })
        }

        "frida-resume" => {
            // Unblock a gadget loaded with `on_load: wait`. Cheap
            // no-op once already resumed.
            let pid = args
                .get("pid")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| DispatchError::Other(
                    "missing required u32 arg \"pid\"".into(),
                ))? as u32;
            let session = clone_frida(state)?;
            session.resume(pid).map_err(DispatchError::Other)?;
            json!({ "resumed": pid })
        }
        "stalker-coverage" => stalker_coverage(args, state)?,

        other => return Err(DispatchError::UnknownTool(other.to_string())),
    };
    let duration_ms = start.elapsed().as_millis();
    let envelope = json!({ "data": data, "meta": { "duration_ms": duration_ms } });
    serde_json::to_string(&envelope).map_err(DispatchError::from)
}

// ---- argument helpers ----------------------------------------------------

/// Resolve the bundle for a path-bearing verb. Checks the
/// stateful cache first — returning the shared `Arc<Bundle>`
/// when the same path is already open — and falls back to a
/// fresh `glass_api::open` otherwise. Newly-opened bundles are
/// cached in state so the next path-using verb reuses them.
fn open(
    args: &Value,
    state: &crate::state::StateHandle,
) -> Result<std::sync::Arc<glass_api::Bundle>> {
    let path = require_path(args)?;
    // Quick check: bundle for this path already cached?
    if let Some(open) = state.lock().bundle_for(&path) {
        return Ok(open.bundle);
    }
    // Otherwise open afresh and cache it. Multiple concurrent
    // calls could race here; the loser's open is discarded but
    // no soundness issue since `glass_api::open` is pure work
    // on a file. Cheaper than holding the mutex across the open.
    let bundle = std::sync::Arc::new(glass_api::open(&path)?);
    let mut st = state.lock();
    st.bundle = Some(crate::state::OpenBundle {
        source_path: path,
        bundle: bundle.clone(),
    });
    Ok(bundle)
}

fn require_path(args: &Value) -> Result<PathBuf> {
    Ok(PathBuf::from(require_str(args, "path")?))
}

fn require_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| DispatchError::Other(format!("missing required string arg {key:?}")))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(str::to_owned)
}

fn opt_usize(args: &Value, key: &str) -> Option<usize> {
    args.get(key).and_then(|v| v.as_u64()).map(|n| n as usize)
}

fn require_hex_u64(args: &Value, key: &str) -> Result<u64> {
    let s = require_str(args, key)?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|e| DispatchError::Other(format!("bad hex {key} {s:?}: {e}")))
}

fn json_of<T: serde::Serialize>(v: &T) -> Result<Value> {
    Ok(serde_json::to_value(v)?)
}

/// Run a one-shot Stalker coverage session.
///
/// Composes existing primitives: load a coverage script,
/// wait for it to deliver, unload. The script does its own
/// dedup so we ship one summary back, not millions of
/// per-block events. When a bundle is open in state and the
/// caller asks for `symbolise: true`, each coverage row gets
/// a `symbol` field via `bundle.symbol_at(module, offset)`.
fn stalker_coverage(
    args: &Value,
    state: &crate::state::StateHandle,
) -> Result<Value> {
    let modules: Vec<String> = args
        .get("modules")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let duration_ms = args
        .get("duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000);
    let tids: Vec<u32> = args
        .get("tids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default();
    let symbolise = args
        .get("symbolise")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let session = clone_frida(state)?;
    let source = glass_frida::render_coverage_script(&tids, &modules, duration_ms);
    let id = session.alloc_script_id();
    session
        .create_script(id, "stalker-coverage", source)
        .map_err(DispatchError::Other)?;

    // Wait for the script's `send`. Poll on a small interval
    // so we react as soon as the table arrives — Stalker
    // teardown after `unfollow` can be slow on large module
    // sets, so giving ourselves up to ~10s past `duration_ms`
    // for the result avoids spurious timeouts.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_millis(duration_ms.saturating_add(10_000));
    let mut rows: Option<Value> = None;
    let mut followed_tids: Option<Value> = None;
    let mut init_report: Option<Value> = None;
    let mut script_errors: Vec<String> = Vec::new();
    'wait: loop {
        for ev in session.poll_events() {
            match &ev {
                glass_frida::SessionEvent::ScriptMessage {
                    script_id,
                    payload,
                } if *script_id == id => {
                    match payload.get("kind").and_then(|v| v.as_str()) {
                        Some("stalker-coverage-init") => {
                            init_report = Some(payload.clone());
                        }
                        Some("stalker-coverage") => {
                            followed_tids =
                                payload.get("followed_tids").cloned();
                            rows = payload.get("rows").cloned();
                            break 'wait;
                        }
                        _ => {}
                    }
                }
                glass_frida::SessionEvent::ScriptError {
                    script_id,
                    description,
                } if *script_id == id => {
                    script_errors.push(description.clone());
                }
                _ => {}
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Best-effort unload — the script has already done its
    // work, and frida-core's unload can hang briefly after
    // Stalker teardown. Leaving it loaded is a minor leak
    // we'd rather take than fail the verb on.
    let _ = session.unload_script(id);

    let rows = rows.ok_or_else(|| {
        DispatchError::Other(format!(
            "stalker coverage script produced no result within {}ms. \
             init={init_report:?} errors={script_errors:?}",
            duration_ms.saturating_add(10_000)
        ))
    })?;

    let final_rows = if symbolise {
        symbolise_coverage(&rows, state)
    } else {
        rows
    };

    Ok(json!({
        "followed_tids": followed_tids,
        "row_count": final_rows.as_array().map(|a| a.len()).unwrap_or(0),
        "rows": final_rows,
        "init": init_report,
        "script_errors": script_errors,
    }))
}

/// Walk the coverage rows and attach `{artifact, symbol?}`
/// when the open bundle has the module. Module → artifact is
/// by basename (`libfoo.so`) so APK paths like
/// `arm64-v8a/libfoo.so` still match. Rows whose module isn't
/// in the bundle (libc, app_process, etc.) pass through
/// unchanged.
fn symbolise_coverage(
    rows: &Value,
    state: &crate::state::StateHandle,
) -> Value {
    let arr = match rows.as_array() {
        Some(a) => a,
        None => return rows.clone(),
    };
    let bundle = match state.lock().bundle.as_ref() {
        Some(b) => b.bundle.clone(),
        None => return rows.clone(),
    };
    // Index artifacts by basename so a coverage row with
    // module "libsqliteX.so" can locate the bundle's
    // "arm64-v8a/libsqliteX.so" artifact.
    let inspection = bundle.inspect();
    let mut by_basename: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for a in &inspection.artifacts {
        if let Some(base) = a.label.rsplit('/').next() {
            by_basename.insert(base.to_string(), a.label.clone());
        }
    }

    let mut out = Vec::with_capacity(arr.len());
    for row in arr {
        let mut enriched = row.clone();
        let (Some(module), Some(offset_str)) = (
            row.get("module").and_then(|v| v.as_str()),
            row.get("offset").and_then(|v| v.as_str()),
        ) else {
            out.push(enriched);
            continue;
        };
        let basename = module.rsplit('/').next().unwrap_or(module);
        let Some(artifact_label) = by_basename.get(basename) else {
            out.push(enriched);
            continue;
        };
        let Ok(addr) = u64::from_str_radix(
            offset_str.trim_start_matches("0x"),
            16,
        ) else {
            out.push(enriched);
            continue;
        };
        if let Some(sym) = bundle.symbol_at(artifact_label, addr) {
            if let Some(obj) = enriched.as_object_mut() {
                obj.insert("artifact".to_string(), json!(artifact_label));
                obj.insert(
                    "symbol".to_string(),
                    json!({
                        "name": sym.demangled,
                        "address": sym.address,
                    }),
                );
            }
        }
        out.push(enriched);
    }
    Value::Array(out)
}

/// Pull a clone of the attached Frida session out of state, or
/// fail with a useful error pointing the caller at `frida-attach`.
fn clone_frida(state: &crate::state::StateHandle) -> Result<glass_frida::Session> {
    state
        .lock()
        .frida
        .as_ref()
        .map(|f| f.session.clone())
        .ok_or_else(|| DispatchError::Other(
            "no Frida session attached — call frida-attach first".into(),
        ))
}

fn render_session_event(ev: glass_frida::SessionEvent) -> Value {
    use glass_frida::SessionEvent::*;
    match ev {
        ScriptMessage { script_id, payload } => json!({
            "kind": "message",
            "script_id": script_id,
            "payload": payload,
        }),
        ScriptError { script_id, description } => json!({
            "kind": "error",
            "script_id": script_id,
            "description": description,
        }),
        ScriptLog { script_id, level, message } => json!({
            "kind": "log",
            "script_id": script_id,
            "level": level,
            "message": message,
        }),
        Detached { reason } => json!({
            "kind": "detached",
            "reason": reason,
        }),
    }
}

fn parse_kind(s: &str) -> Option<glass_api::SymbolKindName> {
    match s {
        "function" => Some(glass_api::SymbolKindName::Function),
        "object" => Some(glass_api::SymbolKindName::Object),
        "other" => Some(glass_api::SymbolKindName::Other),
        _ => None,
    }
}


/// Parse a hex byte string like `"20 00 80 52"` (whitespace
/// optional) into a Vec<u8>. Mirrors the CLI's helper.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err(DispatchError::Other(format!(
            "hex byte string has odd length: {s:?}"
        )));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let pair = &cleaned[i..i + 2];
        let byte = u8::from_str_radix(pair, 16).map_err(|e| {
            DispatchError::Other(format!("non-hex pair {pair:?}: {e}"))
        })?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod parity_tests {
    //! Guards the catalog ↔ MCP-dispatcher half of the four-way
    //! parity rule in CLAUDE.md. `glass_api::skill_catalog()` is the
    //! single source of truth for the automation surface; every entry
    //! must have a `match` arm in `call()` above, and every arm must
    //! correspond to a catalog entry (an orphan arm is a verb an MCP
    //! client can never reach, since the tool list comes from the
    //! catalog). This test parses the *actual* arms out of this file's
    //! source so it cannot drift from a hand-maintained list.
    use std::collections::BTreeSet;

    /// Verb names dispatched by `call()`, parsed from the `match name`
    /// block in this file's own source. We read the source rather than
    /// exercise `call()` because the arms are string patterns with no
    /// runtime handle. Bounded to the region between `match name {` and
    /// the `UnknownTool` fall-through so unrelated string-pattern
    /// matches elsewhere in the file (e.g. `parse_kind`) can't leak in.
    fn dispatched_verbs() -> BTreeSet<String> {
        const SRC: &str = include_str!("dispatch.rs");
        let start = SRC
            .find("match name {")
            .expect("dispatch `match name {` not found — did call() change shape?");
        let region = &SRC[start..];
        let end = region
            .find("DispatchError::UnknownTool")
            .expect("dispatch fall-through `UnknownTool` arm not found");
        let body = &region[..end];

        // Collect (indent, name) for every `"…" =>` line, then keep
        // only the shallowest indent. Top-level arms share one indent;
        // any deeper string-pattern match nested inside an arm body
        // sits further right and is dropped.
        let mut candidates: Vec<(usize, String)> = Vec::new();
        for line in body.lines() {
            let indent = line.len() - line.trim_start().len();
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix('"') else {
                continue;
            };
            let Some(qend) = rest.find('"') else { continue };
            let name = &rest[..qend];
            let after = rest[qend + 1..].trim_start();
            let looks_like_verb = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if after.starts_with("=>") && looks_like_verb {
                candidates.push((indent, name.to_string()));
            }
        }
        let min_indent = candidates
            .iter()
            .map(|(i, _)| *i)
            .min()
            .expect("no dispatch arms parsed");
        candidates
            .into_iter()
            .filter(|(i, _)| *i == min_indent)
            .map(|(_, n)| n)
            .collect()
    }

    #[test]
    fn catalog_and_dispatcher_agree() {
        let catalog: BTreeSet<String> = glass_api::skill_catalog()
            .skills
            .iter()
            .map(|s| s.name.to_string())
            .collect();
        let dispatched = dispatched_verbs();

        let missing: Vec<&String> = catalog.difference(&dispatched).collect();
        let orphan: Vec<&String> = dispatched.difference(&catalog).collect();

        assert!(
            missing.is_empty(),
            "skill catalog lists verb(s) with no MCP dispatch arm in call(): {missing:?}\n\
             Add a `match name` arm in dispatch.rs for each (see CLAUDE.md skill-catalog parity)."
        );
        assert!(
            orphan.is_empty(),
            "dispatch.rs handles verb(s) absent from the skill catalog: {orphan:?}\n\
             These are unreachable (the MCP tool list comes from the catalog). Add a Skill entry \
             in glass-api/src/skills.rs or remove the arm."
        );
    }

    #[test]
    fn parser_finds_expected_arm_count() {
        // Sanity check on the source parser itself: if it silently
        // matched zero (or nearly zero) arms, `catalog_and_dispatcher_agree`
        // would report every catalog verb as "missing" — a confusing
        // failure. Assert we parsed a plausible number instead.
        let n = dispatched_verbs().len();
        assert!(
            n >= 50,
            "source parser found only {n} dispatch arms — the parse likely broke, \
             not the catalog. Check the `match name {{` / `UnknownTool` anchors."
        );
    }
}
