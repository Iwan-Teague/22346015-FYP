//! The research session's own loop state (P-46): the live web transport a
//! research run hands the loop, every fetched source the loop saw (for the
//! report's citations and its quarantined note), and the note sink. A
//! coding session touches none of it: `WebSources` never exists there, and
//! `NoteSink` is `None`, so a coding submit journals exactly as before.
//!
//! Everything here is replay discipline (design §2.9, §6): the web field a
//! `ToolFinished` carries names every hop (its Egress records, its frame
//! digest) so an audit can recompute the whole call offline, and a note is
//! built only from what the journal itself holds — the question from the
//! re-fed user turn, the answer from the re-fed submit call, the sources
//! from the recomputed fetch results.

use std::collections::BTreeSet;
use std::path::PathBuf;

use gate_outcome::Digest;
use harness_core::{sha256, Source, Untrusted};
use harness_journal::{
    BlobSink, Clock, Event, EventKind, Ident, JournalError, JournalFile, JournalWriter, Trusted,
};
use harness_model::endpoint::Endpoint;
use harness_tools::{FetcherPin, HopRunner, WebBudgets, WebRecord, WebTools};

/// Which web capabilities this loop serves (P-46): the provider refuses a
/// call with no egress door, so the loop only opens the door for these.
pub(crate) fn is_web_call(tool: &str) -> bool {
    tool == harness_policy::WEB_FETCH_ID || tool == harness_policy::WEB_SEARCH_ID
}

/// The wire prefix of the one error message whose text the environment
/// chooses (§3: the resolver's failure reason). A replay must re-feed that
/// reason, so the loop records it on the `ToolFinished` it belongs to; a
/// journal that failed any other way carries no such field.
pub(crate) const DNS_FAIL_PREFIX: &str = "error: dns resolution refused: ";

/// The live web transport of a research run (P-46): the pinned fetcher the
/// confined hop runner spawns, the egress door (its mode, resolver and
/// connector) every hop goes through, the optional search endpoint, and
/// the optional in-process runner (a test seam; the production path always
/// runs the pinned fetcher under the session's confinement).
pub(crate) struct WebSources<'a> {
    /// The pinned fetcher binary (§3 step 6): its bytes' digest is
    /// verified before the first hop.
    pub(crate) fetcher: FetcherPin,
    /// The session's search endpoint, exactly when the grant said search.
    pub(crate) search: Option<Endpoint>,
    /// The egress door (§3 step 5): mode, resolver, connector.
    pub(crate) egress: harness_tools::Egress,
    /// The session's web budgets (§4): P-46 keeps the defaults; a slice
    /// that makes them configurable must also journal them.
    pub(crate) budgets: WebBudgets,
    /// The in-process hop runner (a test seam). `None` in production: the
    /// tools spawn the pinned fetcher under the confinement witness.
    pub(crate) runner: Option<Box<dyn HopRunner + 'a>>,
}

impl<'a> WebSources<'a> {
    /// Build the live provider for a research loop: `WebTools::new` under
    /// the confinement witness, or `new_with_runner` behind the seam.
    pub(crate) fn tools(
        self,
        scratch: &std::path::Path,
        allowlist: harness_policy::web::Allowlist,
        confinement: &dyn harness_sandbox::Confinement,
        witness: harness_sandbox::Conformed,
    ) -> Result<WebTools<'a>, harness_tools::WebSetupError> {
        match self.runner {
            Some(runner) => WebTools::new_with_runner(
                scratch,
                allowlist,
                self.budgets,
                self.fetcher,
                self.search,
                runner,
                self.egress,
            ),
            None => WebTools::new(
                scratch,
                allowlist,
                self.budgets,
                self.fetcher,
                self.search,
                confinement,
                witness,
                self.egress,
            ),
        }
    }
}

/// Where an accepted research submit's note goes (P-46 §6). `Live` writes
/// the quarantined note files under the state root's research notes
/// directory (journal first, then the files); `Compute` is an audit
/// replay's: the note is recomputed and journalled, but nothing is written
/// — an audit never writes outside its replay journal.
pub(crate) enum NoteSink {
    Live { dir: PathBuf },
    Compute,
}

/// One fetched source the loop saw (P-46 §6): a successful, uncached
/// fetch, deduplicated by final URL at note time. Every field but the
/// step comes from the journaled `ToolFinished` web record, so an audit
/// rebuilds the same list as it recomputes the calls.
#[derive(Debug, Clone)]
pub(crate) struct WebSourceRec {
    /// The URL the call asked for (the first hop's).
    pub(crate) url: String,
    /// The URL the last hop ended on.
    pub(crate) final_url: String,
    /// The frame status.
    pub(crate) status: Option<u16>,
    /// The frame content type.
    pub(crate) content_type: Option<String>,
    /// The frame body's digest (absent only when a record has no hop, which
    /// an ok fetch never is — kept as an `Option` so the note builder
    /// cannot guess).
    pub(crate) body_sha256: Option<Digest>,
    /// The extracted text's digest: the citation currency.
    pub(crate) text_sha256: Digest,
    /// Whether the frame body was truncated by the body budget.
    pub(crate) truncated: bool,
    /// The step the fetch ran at (the note cites it so a reviewer can walk
    /// back to the exact journal records).
    pub(crate) step: u64,
    /// How many hops the fetch took (the Egress records between the call's
    /// intent and its result).
    pub(crate) hops: usize,
}

/// Journal one runtime string in its typed home, with the web source it
/// came from (P-46: every URL, header value and error reason a hop
/// carried is network text — never harness-authored, so never a trusted
/// `Text` field).
fn web_text<F: JournalFile, B: BlobSink, K: Clock>(
    w: &mut JournalWriter<F, B, K>,
    text: &str,
    from: &str,
) -> Result<Trusted, JournalError> {
    let home = w.untrusted(&Untrusted::new(
        text.to_owned(),
        Source::Web(from.to_owned()),
    ))?;
    Ok(Trusted::Untrusted(home))
}

/// The `web` object a web call's `ToolFinished` carries (P-46): the flat,
/// mcp-style record of what the airlock did — the final URL, the extracted
/// text's digest, every hop with its measured pump outcome and its frame's
/// blob home, and the recorded resolver failure when the environment chose
/// one. Frames go to the blob store (network bytes are never journal
/// text), so an audit re-feeds them and recomputes the whole call offline.
pub(crate) fn web_field<F: JournalFile, B: BlobSink, K: Clock>(
    w: &mut JournalWriter<F, B, K>,
    web: &WebRecord,
    dns_fail: Option<&str>,
) -> Result<Trusted, JournalError> {
    let mut hops = Vec::with_capacity(web.hops.len());
    for h in &web.hops {
        let mut hop = vec![
            ("hop", Trusted::U64(h.hop)),
            ("url", web_text(w, &h.url, &web.final_url)?),
            ("body_len", Trusted::U64(h.body_len)),
            ("body_sha256", Trusted::Digest(h.body_sha256)),
            ("truncated", Trusted::Bool(h.truncated)),
            ("bytes_up", Trusted::U64(h.bytes_up)),
            ("bytes_down", Trusted::U64(h.bytes_down)),
            ("elapsed_ms", Trusted::U64(h.elapsed_ms)),
            // Hop outcomes and egress modes are the airlock's own closed
            // vocabularies: harness-authored constants, safe as text.
            ("ended", Trusted::Text(h.ended)),
            ("mode", Trusted::Text(h.mode)),
        ];
        if let Some(s) = h.status {
            hop.push(("status", Trusted::U64(u64::from(s))));
        }
        if let Some(t) = &h.content_type {
            hop.push(("content_type", web_text(w, t, &web.final_url)?));
        }
        if let Some(ip) = h.ip {
            hop.push(("ip", Trusted::Ip(ip)));
        }
        if let Some(loc) = &h.location {
            hop.push(("location", web_text(w, loc, &web.final_url)?));
        }
        if let Some(frame) = &h.frame {
            let home = w.untrusted_stored(&Untrusted::new(
                frame.clone(),
                Source::Web(web.final_url.clone()),
            ))?;
            hop.push(("frame", Trusted::Untrusted(home)));
        }
        hops.push(Trusted::Obj(hop));
    }
    let mut obj = vec![
        ("final_url", web_text(w, &web.final_url, &web.final_url)?),
        ("text_sha256", Trusted::Digest(web.text_sha256)),
        ("cached", Trusted::Bool(web.cached)),
        ("hops", Trusted::List(hops)),
    ];
    if let Some(why) = dns_fail {
        obj.push(("dns_fail", web_text(w, why, &web.final_url)?));
    }
    Ok(Trusted::Obj(obj))
}

/// Every citation token in a report (P-46): the `sha256:<64 hex>` texts
/// the report cites, deduplicated and sorted. This scan is the only thing
/// that stands between a cited passage and a phantom one, so it is exact:
/// `sha256:` followed by exactly 64 lowercase hex digits, then a character
/// that cannot extend the digest.
pub(crate) fn scan_citations(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = BTreeSet::new();
    let mut i = 0;
    while i + 7 + 64 <= bytes.len() {
        if &bytes[i..i + 7] == b"sha256:" {
            let candidate = &text[i + 7..i + 7 + 64];
            let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
            if candidate.bytes().all(lower_hex)
                && bytes[i + 7 + 64..].first().map_or(true, |b| !lower_hex(*b))
            {
                found.insert(candidate.to_owned());
                i += 7 + 64;
                continue;
            }
        }
        i += 1;
    }
    found.into_iter().collect()
}

/// The citation verdict a research submit carries (P-46), in the form both
/// its journal field and its note entry are built from: how many distinct
/// passages the report cites, which cited digests match no fetched source
/// ("phantom"), and which fetched sources the report never cites
/// ("uncited"). The lists hold digests, sorted and deduplicated, so a
/// replay recomputes byte-identical values from the same records.
pub(crate) struct Citations {
    pub(crate) cited: u64,
    pub(crate) phantom: Vec<String>,
    pub(crate) uncited: Vec<String>,
}

pub(crate) fn citations_of(sources: &[WebSourceRec], note: &str) -> Citations {
    let cited = scan_citations(note);
    let known: BTreeSet<String> = sources.iter().map(|s| s.text_sha256.to_string()).collect();
    Citations {
        cited: cited.len() as u64,
        phantom: cited
            .iter()
            .filter(|c| !known.contains(*c))
            .cloned()
            .collect(),
        uncited: known
            .into_iter()
            .filter(|k| !cited.iter().any(|c| c == k))
            .collect(),
    }
}

impl Citations {
    /// The journal field. The scan only ever produces 64 lowercase hex
    /// digits, so each entry parses as a digest (a non-parsing entry would
    /// be dropped, never guessed).
    pub(crate) fn trusted(&self) -> Trusted {
        let d = |list: &[String]| {
            Trusted::List(
                list.iter()
                    .filter_map(|p| p.parse::<Digest>().ok())
                    .map(Trusted::Digest)
                    .collect(),
            )
        };
        Trusted::Obj(vec![
            ("cited", Trusted::U64(self.cited)),
            ("phantom", d(&self.phantom)),
            ("uncited", d(&self.uncited)),
        ])
    }

    /// The note.json entry (sorted digest strings, the same verdict).
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "cited": self.cited,
            "phantom": self.phantom,
            "uncited": self.uncited,
        })
    }
}

/// The label block every note carries (§6): third-party web content,
/// quarantined until a human imports it.
fn labels_json() -> serde_json::Value {
    serde_json::json!({
        "content": "third_party",
        "origin": "web",
        "untrusted": true,
    })
}

/// The canonical note bytes (P-46 §6): the question and the answer with
/// their digests, the labels, the citation verdict, and the sources in the
/// order the loop fetched them. The note file itself is the untrusted
/// payload's home here (the journal carries only the `NoteSaved` counts
/// and the id); it is quarantined under the state root and imported only
/// by an explicit human action. The note's id is the SHA-256 of exactly
/// these bytes — the JSON is written with sorted keys (`serde_json`
/// BTreeMap order), so the same facts always build the same note.
pub(crate) fn build_note(
    question: &str,
    answer: &str,
    sources: &[WebSourceRec],
    citations: &Citations,
) -> Option<(Vec<u8>, String, u64)> {
    let sources_list: Vec<serde_json::Value> = sources
        .iter()
        .map(|s| {
            let mut o = serde_json::json!({
                "final_url": s.final_url,
                "hops": s.hops,
                "step": s.step,
                "text_sha256": s.text_sha256.to_string(),
                "truncated": s.truncated,
                "url": s.url,
            });
            let m = o.as_object_mut()?;
            if let Some(st) = s.status {
                m.insert("status".into(), serde_json::Value::from(st));
            }
            if let Some(ct) = &s.content_type {
                m.insert("content_type".into(), serde_json::Value::from(ct));
            }
            if let Some(b) = s.body_sha256 {
                m.insert("body_sha256".into(), serde_json::Value::from(b.to_string()));
            }
            Some(o)
        })
        .collect::<Option<_>>()?;
    let note = serde_json::json!({
        "answer": {
            "sha256": sha256(answer.as_bytes()).to_string(),
            "text": answer,
        },
        "citations": citations.json(),
        "labels": labels_json(),
        "note_version": "1",
        "question": {
            "sha256": sha256(question.as_bytes()).to_string(),
            "text": question,
        },
        "sources": sources_list,
    });
    let bytes = note.to_string().into_bytes();
    let id = sha256(&bytes).to_string();
    Some((bytes, id, sources.len() as u64))
}

/// The journal record of a saved note (§6): journalled BEFORE the files
/// are written, fsynced with the journal like every record. `turn` is the
/// 1-based number of the turn that submitted. The id travels as an
/// `Ident` — trusted text must be compile-time, and a validated
/// identifier is the harness's one runtime-text carrier.
pub(crate) fn note_saved_event(
    note: &str,
    bytes: u64,
    sources: u64,
    turn: u64,
) -> Result<Event, JournalError> {
    let id = Ident::of(note)
        .map_err(|_| JournalError::InvalidEvent("a note id is not a valid identifier"))?;
    Ok(Event::new(EventKind::NoteSaved)
        .field("bytes", Trusted::U64(bytes))
        .field("note", Trusted::Id(id))
        .field("sources", Trusted::U64(sources))
        .field("turn", Trusted::U64(turn)))
}

/// Why writing a note failed: journal trouble already poisoned the writer;
/// a file error is the state root's (refuse the run, fail closed).
pub(crate) enum NoteWriteError {
    Journal(JournalError),
    Io(std::io::Error),
}

/// Write a quarantined note (P-46 §6): `<notes>/<id>/note.json` (the
/// canonical bytes the id digests) and `note.md` (the banner, the question
/// and the answer), 0700 directories and 0600 files, created atomically —
/// temp names, fsynced, renamed. An existing note id is left untouched:
/// notes are immutable, and a repeated save (a resume's catch-up) must not
/// disturb the file a reviewer may already be reading. The journal record
/// was written before this runs (§6), so a crash here leaves the note
/// journaled but absent: a re-drive rewrites the same bytes.
pub(crate) fn write_note(
    dir: &std::path::Path,
    id: &str,
    json: &[u8],
    question: &str,
    answer: &str,
) -> Result<(), NoteWriteError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let note_dir = dir.join(id);
    if note_dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(&note_dir).map_err(NoteWriteError::Io)?;
    std::fs::set_permissions(&note_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(NoteWriteError::Io)?;
    // note.json: the canonical bytes, so `sha256(note.json) == <id>`.
    let tmp = note_dir.join(".note.json.tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(NoteWriteError::Io)?;
        f.write_all(json).map_err(NoteWriteError::Io)?;
        f.sync_all().map_err(NoteWriteError::Io)?;
    }
    std::fs::rename(&tmp, note_dir.join("note.json")).map_err(NoteWriteError::Io)?;
    // note.md: the banner first (§6), then the report a human reviews.
    let mut md = String::new();
    md.push_str("# UNTRUSTED RESEARCH NOTE (third_party web content)\n\n");
    md.push_str("Quarantined: import into a coding session only by an explicit typed action.\n\n## Question\n\n");
    md.push_str(question);
    md.push_str("\n\n## Answer\n\n");
    md.push_str(answer);
    md.push('\n');
    let tmp = note_dir.join(".note.md.tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(NoteWriteError::Io)?;
        f.write_all(md.as_bytes()).map_err(NoteWriteError::Io)?;
        f.sync_all().map_err(NoteWriteError::Io)?;
    }
    std::fs::rename(&tmp, note_dir.join("note.md")).map_err(NoteWriteError::Io)?;
    Ok(())
}
