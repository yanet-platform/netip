//! Pins the Rust items that the Lean transcriptions in `proofs/` follow.
//!
//! `proofs/pins.txt` lists each such item with a hash of its tokens and the
//! Lean declarations that transcribe it. Comments, doc comments and formatting
//! are not tokens, so they do not count. Any other change to a pinned item
//! changes its hash, and the check fails until someone has re-read the
//! transcriptions against the new code and re-pinned the item with `bless`.
//!
//! Run it from anywhere in the repository:
//!
//! ```text
//! cargo run --manifest-path proofs/drift/Cargo.toml              # check the pins
//! cargo run --manifest-path proofs/drift/Cargo.toml -- bless     # re-pin changed items
//! cargo run --manifest-path proofs/drift/Cargo.toml -- list      # every item of src/
//! cargo run --manifest-path proofs/drift/Cargo.toml -- unpinned  # items no pin names
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use syn::{Attribute, ImplItem, Item};

const PINS: &str = "proofs/pins.txt";
const BLESS: &str = "cargo run --manifest-path proofs/drift/Cargo.toml -- bless";

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mode = env::args().nth(1).unwrap_or_default();
    let result = match mode.as_str() {
        "" | "check" => check(&root, false),
        "bless" => check(&root, true),
        "list" => list(&root, false),
        "unpinned" => list(&root, true),
        _ => Err(format!(
            "unknown mode `{mode}`, expected check, bless, list or unpinned"
        )),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// An item of `src/` that a pin can name.
struct RustItem {
    /// The line of the item's name.
    line: usize,
    /// The hash of the item's tokens.
    pin: String,
}

/// The items of `src/` by `(file, key)`. The file is relative to the
/// repository root. The key is the item's path inside the file: `name` for a
/// free item, `Type::name` for an inherent associated one, `Type::Trait::name`
/// for a trait implementation's, with inline modules prepended and all
/// whitespace removed.
type Items = BTreeMap<(String, String), RustItem>;

fn collect(root: &Path) -> Result<Items, String> {
    let mut paths = Vec::new();
    rust_files(&root.join("src"), &mut paths)?;
    paths.sort();
    let mut items = Items::new();
    for path in paths {
        let file = relative(root, &path);
        let text = fs::read_to_string(&path).map_err(|e| format!("{file}: {e}"))?;
        let ast = syn::parse_file(&text).map_err(|e| format!("{file}: {e}"))?;
        walk(&file, "", &ast.items, &mut items);
    }
    Ok(items)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    path.strip_prefix(&root)
        .unwrap_or(&path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn walk(file: &str, prefix: &str, items: &[Item], out: &mut Items) {
    for item in items {
        let (ident, attrs) = match item {
            Item::Const(x) => (&x.ident, &x.attrs),
            Item::Enum(x) => (&x.ident, &x.attrs),
            Item::Fn(x) => (&x.sig.ident, &x.attrs),
            Item::Static(x) => (&x.ident, &x.attrs),
            Item::Struct(x) => (&x.ident, &x.attrs),
            Item::Trait(x) => (&x.ident, &x.attrs),
            Item::Type(x) => (&x.ident, &x.attrs),
            Item::Union(x) => (&x.ident, &x.attrs),
            Item::Mod(x) => {
                if let Some((_, inner)) = &x.content
                    && !is_test(&x.attrs)
                {
                    walk(file, &format!("{prefix}{}::", x.ident), inner, out);
                }
                continue;
            }
            Item::Impl(x) => {
                if is_test(&x.attrs) {
                    continue;
                }
                let ty = compact(x.self_ty.to_token_stream());
                let owner = match &x.trait_ {
                    Some((_, path, _)) => format!("{ty}::{}", compact(path.to_token_stream())),
                    None => ty,
                };
                // The `impl` line, its bounds and its attributes count towards
                // every item of the block: a changed `cfg` or bound changes
                // which code runs.
                let mut header = x.clone();
                header.items.clear();
                let header = header.to_token_stream();
                for inner in &x.items {
                    let (ident, attrs) = match inner {
                        ImplItem::Const(x) => (&x.ident, &x.attrs),
                        ImplItem::Fn(x) => (&x.sig.ident, &x.attrs),
                        ImplItem::Type(x) => (&x.ident, &x.attrs),
                        _ => continue,
                    };
                    if !is_test(attrs) {
                        let key = format!("{prefix}{owner}::{ident}");
                        let mut tokens = header.clone();
                        tokens.extend(inner.to_token_stream());
                        add(out, file, key, ident, tokens);
                    }
                }
                continue;
            }
            _ => continue,
        };
        if !is_test(attrs) {
            add(out, file, format!("{prefix}{ident}"), ident, item.to_token_stream());
        }
    }
}

fn add(out: &mut Items, file: &str, key: String, ident: &syn::Ident, tokens: TokenStream) {
    let item = RustItem {
        line: ident.span().start().line,
        pin: pin(tokens),
    };
    // Items that share a key, such as two `impl` blocks under different
    // `cfg`s, are told apart by their order in the file.
    let mut unique = key.clone();
    let mut n = 1;
    while out.contains_key(&(file.to_owned(), unique.clone())) {
        n += 1;
        unique = format!("{key}#{n}");
    }
    out.insert((file.to_owned(), unique), item);
}

/// Whether the attributes hold `#[cfg(test)]`.
fn is_test(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("cfg") && a.meta.require_list().is_ok_and(|l| l.tokens.to_string() == "test"))
}

fn compact(tokens: TokenStream) -> String {
    tokens.to_string().split_whitespace().collect()
}

/// A 64-bit FNV-1a hash of the tokens, doc attributes left out.
fn pin(tokens: TokenStream) -> String {
    let mut hash = Fnv(0xcbf2_9ce4_8422_2325);
    hash.tokens(tokens);
    format!("{:016x}", hash.0)
}

struct Fnv(u64);

impl Fnv {
    fn bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }

    /// Feeds the tokens with a tag per kind, so that the hash depends only on
    /// the token sequence, not on how a library prints it.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut it = tokens.into_iter().peekable();
        while let Some(tree) = it.next() {
            match tree {
                TokenTree::Group(g) => {
                    let (open, close) = match g.delimiter() {
                        Delimiter::Parenthesis => (b'(', b')'),
                        Delimiter::Brace => (b'{', b'}'),
                        Delimiter::Bracket => (b'[', b']'),
                        Delimiter::None => (b'<', b'>'),
                    };
                    self.bytes(&[b'G', open]);
                    self.tokens(g.stream());
                    self.bytes(&[b'G', close]);
                }
                TokenTree::Ident(i) => {
                    self.bytes(b"I");
                    self.bytes(i.to_string().as_bytes());
                    self.bytes(b"\0");
                }
                TokenTree::Punct(p) => {
                    if p.as_char() == '#' {
                        // `#[doc = ".."]`, which a doc comment becomes, or the
                        // inner `#![doc = ".."]`.
                        let mut ahead = it.clone();
                        let inner = matches!(ahead.peek(), Some(TokenTree::Punct(q)) if q.as_char() == '!');
                        if inner {
                            ahead.next();
                        }
                        if let Some(TokenTree::Group(g)) = ahead.next()
                            && g.delimiter() == Delimiter::Bracket
                            && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(i)) if i == "doc")
                        {
                            it = ahead;
                            continue;
                        }
                    }
                    let spacing = match p.spacing() {
                        Spacing::Joint => b'j',
                        Spacing::Alone => b'a',
                    };
                    self.bytes(b"P");
                    self.bytes(p.as_char().to_string().as_bytes());
                    self.bytes(&[spacing]);
                }
                TokenTree::Literal(l) => {
                    self.bytes(b"L");
                    self.bytes(l.to_string().as_bytes());
                    self.bytes(b"\0");
                }
            }
        }
    }
}

/// An item line of `proofs/pins.txt`: `<item> <pin> <lean>...` under a `[file]`
/// line, where each `<lean>` is a file under `proofs/`, optionally followed by
/// `:<declaration>`.
struct Pin {
    line: usize,
    file: String,
    key: String,
    pin: String,
    /// Where the pin sits in the line, for `bless` to replace.
    pin_at: core::ops::Range<usize>,
    lean: Vec<String>,
}

fn read_pins(text: &str) -> Result<Vec<Pin>, String> {
    let mut pins = Vec::new();
    let mut file = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            file = Some(name.to_owned());
            continue;
        }
        let Some(file) = &file else {
            return Err(format!("{PINS}:{}: an item before the first `[file]` line", i + 1));
        };
        let fields = fields(raw);
        if fields.len() < 3 {
            return Err(format!("{PINS}:{}: expected `<item> <pin> <lean>...`", i + 1));
        }
        pins.push(Pin {
            line: i + 1,
            file: file.clone(),
            key: raw[fields[0].clone()].to_owned(),
            pin: raw[fields[1].clone()].to_owned(),
            pin_at: fields[1].clone(),
            lean: fields[2..].iter().map(|f| raw[f.clone()].to_owned()).collect(),
        });
    }
    Ok(pins)
}

/// The byte ranges of the whitespace-separated fields of a line.
fn fields(line: &str) -> Vec<core::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices().chain([(line.len(), ' ')]) {
        match (c.is_whitespace(), start) {
            (true, Some(s)) => {
                out.push(s..i);
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    out
}

fn check(root: &Path, bless: bool) -> Result<bool, String> {
    let items = collect(root)?;
    let text = fs::read_to_string(root.join(PINS)).map_err(|e| format!("{PINS}: {e}"))?;
    let pins = read_pins(&text)?;
    let mut lean = LeanIndex::default();
    let mut ok = true;
    let mut seen = BTreeSet::new();
    let mut repinned = BTreeMap::new();
    for p in &pins {
        let where_ = p
            .lean
            .iter()
            .map(|l| format!("proofs/{l}"))
            .collect::<Vec<_>>()
            .join(", ");
        if !seen.insert((&p.file, &p.key)) {
            report(PINS, p.line, &format!("`{}` in {} is pinned twice", p.key, p.file));
            ok = false;
        }
        match items.get(&(p.file.clone(), p.key.clone())) {
            None => {
                report(
                    PINS,
                    p.line,
                    &format!(
                        "`{}` is not in {} any more. If it was renamed or moved, update its line here; if it was \
                     removed, check what the transcription in {where_} stands for now",
                        p.key, p.file
                    ),
                );
                ok = false;
            }
            Some(item) if item.pin != p.pin => {
                if bless {
                    println!("re-pinned {} {}: {} -> {}", p.file, p.key, p.pin, item.pin);
                    repinned.insert(p.line, item.pin.clone());
                } else {
                    report(
                        &p.file,
                        item.line,
                        &format!(
                            "`{}` changed since it was pinned. The Lean transcription in {where_} follows it: check that \
                         it still does, fix it and the proofs if not, then re-pin with `{BLESS}`",
                            p.key
                        ),
                    );
                    ok = false;
                }
            }
            Some(_) => {}
        }
        for l in &p.lean {
            if let Err(e) = lean.has(root, l) {
                report(PINS, p.line, &e);
                ok = false;
            }
        }
    }
    if !repinned.is_empty() {
        let mut out = String::with_capacity(text.len());
        for (i, line) in text.split_inclusive('\n').enumerate() {
            match (repinned.get(&(i + 1)), pins.iter().find(|p| p.line == i + 1)) {
                (Some(new), Some(p)) => {
                    out.push_str(&line[..p.pin_at.start]);
                    out.push_str(new);
                    out.push_str(&line[p.pin_at.end..]);
                }
                _ => out.push_str(line),
            }
        }
        fs::write(root.join(PINS), out).map_err(|e| format!("{PINS}: {e}"))?;
    }
    if ok {
        println!("{} pins match src/", pins.len());
    }
    Ok(ok)
}

fn list(root: &Path, unpinned_only: bool) -> Result<bool, String> {
    let items = collect(root)?;
    let pinned: BTreeSet<(String, String)> = match fs::read_to_string(root.join(PINS)) {
        Ok(text) => read_pins(&text)?.into_iter().map(|p| (p.file, p.key)).collect(),
        Err(_) => BTreeSet::new(),
    };
    for ((file, key), item) in &items {
        let is_pinned = pinned.contains(&(file.clone(), key.clone()));
        if !(unpinned_only && is_pinned) {
            let mark = if is_pinned { "pinned" } else { "-" };
            println!("{file}:{}\t{key}\t{}\t{mark}", item.line, item.pin);
        }
    }
    Ok(true)
}

/// Prints a problem, as a GitHub annotation inside a workflow.
fn report(file: &str, line: usize, msg: &str) {
    if env::var_os("GITHUB_ACTIONS").is_some() {
        println!("::error file={file},line={line},title=Transcription drift::{msg}");
    } else {
        eprintln!("{file}:{line}: {msg}");
    }
}

/// The declarations of the Lean files that pins name, by file.
#[derive(Default)]
struct LeanIndex(BTreeMap<String, Vec<String>>);

impl LeanIndex {
    /// Checks that `reference`, `<file>` or `<file>:<name>`, names a Lean file
    /// and, with a name, a declaration in it whose full name is `name` or ends
    /// with `.name`.
    fn has(&mut self, root: &Path, reference: &str) -> Result<(), String> {
        let (file, name) = match reference.split_once(':') {
            Some((file, name)) => (file, Some(name)),
            None => (reference, None),
        };
        if !self.0.contains_key(file) {
            let text = fs::read_to_string(root.join("proofs").join(file)).map_err(|e| format!("proofs/{file}: {e}"))?;
            self.0.insert(file.to_owned(), lean_declarations(&text));
        }
        let Some(name) = name else {
            return Ok(());
        };
        let dotted = format!(".{name}");
        if self.0[file].iter().any(|d| d == name || d.ends_with(&dotted)) {
            Ok(())
        } else {
            Err(format!("proofs/{file} declares no `{name}`"))
        }
    }
}

/// The full names of the declarations in a Lean file. It reads only what a
/// pin needs: `namespace`, `section`, `mutual` and `end` for the scope, and a
/// declaration keyword after attributes and modifiers at the start of a line.
fn lean_declarations(text: &str) -> Vec<String> {
    const MODIFIERS: &[&str] = &["private", "protected", "noncomputable", "partial", "nonrec", "unsafe"];
    const KEYWORDS: &[&str] = &[
        "def",
        "abbrev",
        "theorem",
        "lemma",
        "structure",
        "inductive",
        "class",
        "instance",
        "opaque",
    ];
    let mut scopes: Vec<Vec<String>> = Vec::new();
    let mut decls = Vec::new();
    let mut depth = 0usize;
    for raw in text.lines() {
        let code = strip_comments(raw, &mut depth);
        let mut words = code.split_whitespace().peekable();
        // Attributes, which may span several words: `@[simp, grind]`.
        while words.peek().is_some_and(|w| w.starts_with("@[")) {
            for w in words.by_ref() {
                if w.ends_with(']') {
                    break;
                }
            }
        }
        while words.peek().is_some_and(|w| MODIFIERS.contains(w)) {
            words.next();
        }
        match (words.next(), words.next()) {
            (Some("namespace"), Some(ns)) => scopes.push(ns.split('.').map(str::to_owned).collect()),
            (Some("section" | "mutual"), _) => scopes.push(Vec::new()),
            (Some("end"), _) => {
                scopes.pop();
            }
            (Some(k), Some(name)) if KEYWORDS.contains(&k) => {
                let name = name.trim_matches(|c| c == '«' || c == '»');
                let mut full: Vec<&str> = scopes.iter().flatten().map(String::as_str).collect();
                full.push(name);
                decls.push(full.join("."));
            }
            _ => {}
        }
    }
    decls
}

/// The part of a line outside comments, given the nesting depth of `/- -/`
/// comments at its start, which it updates.
fn strip_comments(line: &str, depth: &mut usize) -> String {
    let mut code = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('/', Some('-')) => {
                chars.next();
                *depth += 1;
            }
            ('-', Some('/')) if *depth > 0 => {
                chars.next();
                *depth -= 1;
            }
            ('-', Some('-')) if *depth == 0 => break,
            _ if *depth == 0 => code.push(c),
            _ => {}
        }
    }
    code
}
