//! HTML renderer.
//!
//! Standalone HTML document with inlined CSS. Color-coded sections
//! — green for added, red for removed, amber for modified, neutral
//! for schema-version pin change and behavioural section. Cedar
//! policy bodies and engine-config JSON blocks render inside
//! `<details>` so the page stays scannable even with many entries.
//!
//! Same section order as the Markdown renderer (title → summary →
//! schema → cedar → named predicates → scoring rules → procedures →
//! enforcement rules → behavioural). Empty sections render as a
//! `(no changes)` paragraph rather than being elided.
//!
//! ## HTML escaping
//!
//! Every operator-supplied string (entry names, Cedar source text,
//! JSON-serialised engine-config values, behavioural identifiers)
//! is run through [`escape_html`] before being written. The escape
//! covers the minimal entity set `& < > " '` — enough to prevent
//! injection from any input that would parse through
//! `yutha_cedar_plus::ConstitutionLoader`.

use std::io::Write;

use crate::behavioural::BehaviouralDiff;
use crate::cedar::{has_unannotated_policies, CedarPolicyEntry};
use crate::error::Result;
use crate::model::{ConstitutionDiff, NamedItemChange, NamedItemsDiff};

/// Inlined stylesheet. Kept lean — no fonts, no external links, no
/// JavaScript. The page MUST work offline + render the same in any
/// modern browser.
const STYLESHEET: &str = r#"
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.5;
    color: #24292e;
    max-width: 960px;
    margin: 2rem auto;
    padding: 0 1rem;
  }
  h1 { border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
  h2 { border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; margin-top: 2rem; }
  h3 { margin-top: 1.5rem; }
  h4 { margin-top: 1rem; }
  code { font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
         background: #f6f8fa; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.9em; }
  pre { background: #f6f8fa; padding: 0.75rem 1rem; border-radius: 6px; overflow-x: auto; }
  pre code { background: transparent; padding: 0; font-size: 0.875em; }
  details { margin: 0.5rem 0; }
  summary { cursor: pointer; color: #0366d6; font-weight: 500; }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0; }
  th, td { border: 1px solid #eaecef; padding: 0.4rem 0.75rem; text-align: left; }
  th { background: #f6f8fa; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .meta { color: #586069; font-size: 0.9em; }
  .none { color: #586069; font-style: italic; }
  .hint { background: #fff8c5; border-left: 4px solid #b08800; padding: 0.75rem 1rem;
          border-radius: 0 6px 6px 0; }
  article.added { border-left: 4px solid #22863a; padding-left: 0.75rem; margin: 0.5rem 0; }
  article.removed { border-left: 4px solid #cb2431; padding-left: 0.75rem; margin: 0.5rem 0; }
  article.modified { border-left: 4px solid #b08800; padding-left: 0.75rem; margin: 0.5rem 0; }
  .badge { display: inline-block; padding: 0.1em 0.5em; border-radius: 3px;
           font-size: 0.75em; font-weight: 600; margin-left: 0.5em; }
  .badge.permit { background: #22863a; color: white; }
  .badge.forbid { background: #cb2431; color: white; }
  .badge.annotated { background: #0366d6; color: white; }
  .badge.unannotated { background: #b08800; color: white; }
  .delta-pos { color: #22863a; font-weight: 600; }
  .delta-neg { color: #cb2431; font-weight: 600; }
  .delta-zero { color: #586069; }
"#;

pub(crate) fn render(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    write_prelude(diff, out)?;
    write_summary(diff, out)?;
    write_schema_version_change(diff, out)?;
    write_cedar_policies_section(&diff.cedar_policies, out)?;
    write_named_section(
        "Named predicates",
        &diff.named_predicates,
        |p| p.name.clone(),
        out,
    )?;
    write_named_section(
        "Scoring rules",
        &diff.scoring_rules,
        |r| r.name.clone(),
        out,
    )?;
    write_named_section("Procedures", &diff.procedures, |p| p.name.clone(), out)?;
    write_named_section(
        "Enforcement rules",
        &diff.enforcement_rules,
        |r| r.name.clone(),
        out,
    )?;
    if let Some(b) = &diff.behavioural {
        write_behavioural_section(b, out)?;
    }
    write_postlude(out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// section writers
// ---------------------------------------------------------------------------

fn write_prelude(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    writeln!(out, "<!doctype html>")?;
    writeln!(out, "<html lang=\"en\">")?;
    writeln!(out, "<head>")?;
    writeln!(out, "  <meta charset=\"utf-8\">")?;
    writeln!(
        out,
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    )?;
    writeln!(
        out,
        "  <title>Constitution diff ({} &rarr; {})</title>",
        escape_html(&diff.left_constitution_version),
        escape_html(&diff.right_constitution_version)
    )?;
    writeln!(out, "  <style>{STYLESHEET}</style>")?;
    writeln!(out, "</head>")?;
    writeln!(out, "<body>")?;
    writeln!(out, "<header>")?;
    writeln!(
        out,
        "  <h1>Constitution diff ({} &rarr; {})</h1>",
        escape_html(&diff.left_constitution_version),
        escape_html(&diff.right_constitution_version)
    )?;
    writeln!(
        out,
        "  <p class=\"meta\">Generated by yutha-diff (schema {}). \
         Empty sections render as <em>(no changes)</em>.</p>",
        escape_html(&diff.diff_schema_version)
    )?;
    writeln!(out, "</header>")?;
    Ok(())
}

fn write_postlude(out: &mut impl Write) -> Result<()> {
    writeln!(out, "</body>")?;
    writeln!(out, "</html>")?;
    Ok(())
}

fn write_summary(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    writeln!(out, "<section class=\"summary\">")?;
    writeln!(out, "<h2>Summary</h2>")?;
    if diff.is_empty_structurally() && diff.behavioural.is_none() {
        writeln!(out, "<p class=\"none\">(no changes)</p>")?;
        writeln!(out, "</section>")?;
        return Ok(());
    }

    writeln!(out, "<ul>")?;
    if let Some((from, to)) = &diff.schema_version_change {
        writeln!(
            out,
            "  <li>Schema version: <code>{}</code> &rarr; <code>{}</code></li>",
            escape_html(from),
            escape_html(to)
        )?;
    }
    writeln!(
        out,
        "  <li>Cedar policies: {}</li>",
        escape_html(&summarise_counts(&diff.cedar_policies))
    )?;
    writeln!(
        out,
        "  <li>Named predicates: {}</li>",
        escape_html(&summarise_counts(&diff.named_predicates))
    )?;
    writeln!(
        out,
        "  <li>Scoring rules: {}</li>",
        escape_html(&summarise_counts(&diff.scoring_rules))
    )?;
    writeln!(
        out,
        "  <li>Procedures: {}</li>",
        escape_html(&summarise_counts(&diff.procedures))
    )?;
    writeln!(
        out,
        "  <li>Enforcement rules: {}</li>",
        escape_html(&summarise_counts(&diff.enforcement_rules))
    )?;
    if let Some(b) = &diff.behavioural {
        writeln!(
            out,
            "  <li>Behavioural: {} receipt-count deltas, {} chain divergences \
             (window {} &rarr; {})</li>",
            b.receipt_count_deltas.len(),
            b.chain_divergences.len(),
            b.window_from_unix_ns,
            b.window_to_unix_ns
        )?;
    }
    writeln!(out, "</ul>")?;
    writeln!(out, "</section>")?;
    Ok(())
}

fn summarise_counts<T>(section: &NamedItemsDiff<T>) -> String {
    if section.is_empty() {
        return "(no changes)".to_string();
    }
    format!(
        "{} added, {} removed, {} modified",
        section.added.len(),
        section.removed.len(),
        section.modified.len()
    )
}

fn write_schema_version_change(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    writeln!(out, "<section class=\"schema-version\">")?;
    writeln!(out, "<h2>Schema version</h2>")?;
    match &diff.schema_version_change {
        Some((from, to)) => writeln!(
            out,
            "<p>Pin changed: <code>{}</code> &rarr; <code>{}</code>.</p>",
            escape_html(from),
            escape_html(to)
        )?,
        None => writeln!(out, "<p class=\"none\">(no changes)</p>")?,
    }
    writeln!(out, "</section>")?;
    Ok(())
}

fn write_cedar_policies_section(
    section: &NamedItemsDiff<CedarPolicyEntry>,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "<section class=\"cedar-policies\">")?;
    writeln!(out, "<h2>Cedar policies</h2>")?;

    let any_unannotated = has_unannotated_policies(&section.added)
        || has_unannotated_policies(&section.removed)
        || section
            .modified
            .iter()
            .any(|m| !m.left.annotated || !m.right.annotated);
    if any_unannotated {
        writeln!(
            out,
            "<p class=\"hint\"><strong>Note:</strong> un-annotated Cedar policies were \
             encountered. Consider adding <code>@id(\"...\")</code> annotations so diffs \
             key on the operator-supplied name rather than a structural fingerprint.</p>"
        )?;
    }

    write_cedar_subsection("Added", "added", &section.added, out)?;
    write_cedar_subsection("Removed", "removed", &section.removed, out)?;
    write_cedar_modified(&section.modified, out)?;

    writeln!(out, "</section>")?;
    Ok(())
}

fn write_cedar_subsection(
    label: &str,
    article_class: &str,
    entries: &[CedarPolicyEntry],
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "<h3>{} ({})</h3>", escape_html(label), entries.len())?;
    if entries.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
        return Ok(());
    }
    for entry in entries {
        writeln!(out, "<article class=\"{article_class}\">")?;
        writeln!(
            out,
            "  <h4><code>{}</code>{}{}</h4>",
            escape_html(&entry.name),
            effect_badge(entry.effect),
            annotation_badge(entry.annotated)
        )?;
        write_collapsible_source("cedar", &entry.source, out)?;
        writeln!(out, "</article>")?;
    }
    Ok(())
}

fn write_cedar_modified(
    entries: &[NamedItemChange<CedarPolicyEntry>],
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "<h3>Modified ({})</h3>", entries.len())?;
    if entries.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
        return Ok(());
    }
    for change in entries {
        writeln!(out, "<article class=\"modified\">")?;
        writeln!(
            out,
            "  <h4><code>{}</code>{}</h4>",
            escape_html(&change.name),
            effect_badge(change.right.effect)
        )?;
        writeln!(out, "  <p><strong>Before:</strong></p>")?;
        write_collapsible_source("cedar", &change.left.source, out)?;
        writeln!(out, "  <p><strong>After:</strong></p>")?;
        write_collapsible_source("cedar", &change.right.source, out)?;
        writeln!(out, "</article>")?;
    }
    Ok(())
}

fn write_named_section<T, KeyFn>(
    title: &str,
    section: &NamedItemsDiff<T>,
    name_of: KeyFn,
    out: &mut impl Write,
) -> Result<()>
where
    T: serde::Serialize,
    KeyFn: Fn(&T) -> String,
{
    writeln!(out, "<section>")?;
    writeln!(out, "<h2>{}</h2>", escape_html(title))?;
    if section.is_empty() {
        writeln!(out, "<p class=\"none\">(no changes)</p>")?;
        writeln!(out, "</section>")?;
        return Ok(());
    }

    write_named_subsection("Added", "added", &section.added, &name_of, out)?;
    write_named_subsection("Removed", "removed", &section.removed, &name_of, out)?;
    write_named_modified(&section.modified, out)?;
    writeln!(out, "</section>")?;
    Ok(())
}

fn write_named_subsection<T, KeyFn>(
    label: &str,
    article_class: &str,
    entries: &[T],
    name_of: &KeyFn,
    out: &mut impl Write,
) -> Result<()>
where
    T: serde::Serialize,
    KeyFn: Fn(&T) -> String,
{
    writeln!(out, "<h3>{} ({})</h3>", escape_html(label), entries.len())?;
    if entries.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
        return Ok(());
    }
    for entry in entries {
        let name = name_of(entry);
        let pretty = serde_json::to_string_pretty(entry)?;
        writeln!(out, "<article class=\"{article_class}\">")?;
        writeln!(out, "  <h4><code>{}</code></h4>", escape_html(&name))?;
        write_collapsible_source("json", &pretty, out)?;
        writeln!(out, "</article>")?;
    }
    Ok(())
}

fn write_named_modified<T>(entries: &[NamedItemChange<T>], out: &mut impl Write) -> Result<()>
where
    T: serde::Serialize,
{
    writeln!(out, "<h3>Modified ({})</h3>", entries.len())?;
    if entries.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
        return Ok(());
    }
    for change in entries {
        let pretty_left = serde_json::to_string_pretty(&change.left)?;
        let pretty_right = serde_json::to_string_pretty(&change.right)?;
        writeln!(out, "<article class=\"modified\">")?;
        writeln!(out, "  <h4><code>{}</code></h4>", escape_html(&change.name))?;
        writeln!(out, "  <p><strong>Before:</strong></p>")?;
        write_collapsible_source("json", &pretty_left, out)?;
        writeln!(out, "  <p><strong>After:</strong></p>")?;
        write_collapsible_source("json", &pretty_right, out)?;
        writeln!(out, "</article>")?;
    }
    Ok(())
}

fn write_behavioural_section(b: &BehaviouralDiff, out: &mut impl Write) -> Result<()> {
    writeln!(out, "<section class=\"behavioural\">")?;
    writeln!(
        out,
        "<h2>Behavioural diff (window {} &rarr; {})</h2>",
        b.window_from_unix_ns, b.window_to_unix_ns
    )?;
    writeln!(
        out,
        "<p class=\"meta\">Replay session id: <code>{}</code>. Counts compare the \
         production receipt store against the candidate's session-scoped store over \
         the same window.</p>",
        escape_html(&b.replay_session_id)
    )?;

    writeln!(out, "<h3>Receipt count deltas</h3>")?;
    if b.receipt_count_deltas.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
    } else {
        writeln!(out, "<table>")?;
        writeln!(
            out,
            "  <thead><tr><th>action_kind</th><th>subject_agent_id</th>\
             <th>production</th><th>candidate</th><th>delta</th></tr></thead>"
        )?;
        writeln!(out, "  <tbody>")?;
        for d in &b.receipt_count_deltas {
            let subject = if d.subject_agent_id.is_empty() {
                "(none)".to_string()
            } else {
                d.subject_agent_id.clone()
            };
            writeln!(
                out,
                "  <tr><td><code>{}</code></td><td><code>{}</code></td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num {}\">{}</td></tr>",
                escape_html(&d.action_kind),
                escape_html(&subject),
                d.production_count,
                d.candidate_count,
                delta_class(d.delta()),
                format_signed_delta(d.delta()),
            )?;
        }
        writeln!(out, "  </tbody>")?;
        writeln!(out, "</table>")?;
    }

    writeln!(out, "<h3>Enforcement chain divergences</h3>")?;
    if b.chain_divergences.is_empty() {
        writeln!(out, "<p class=\"none\">(none)</p>")?;
    } else {
        writeln!(out, "<table>")?;
        writeln!(
            out,
            "  <thead><tr><th>target_agent_id</th><th>enforcement_rule_id</th>\
             <th>stage</th><th>production</th><th>candidate</th><th>delta</th></tr></thead>"
        )?;
        writeln!(out, "  <tbody>")?;
        for c in &b.chain_divergences {
            writeln!(
                out,
                "  <tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td>\
                 <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                 <td class=\"num {}\">{}</td></tr>",
                escape_html(&c.target_agent_id),
                escape_html(&c.enforcement_rule_id),
                escape_html(&c.stage),
                c.production_count,
                c.candidate_count,
                delta_class(c.delta()),
                format_signed_delta(c.delta()),
            )?;
        }
        writeln!(out, "  </tbody>")?;
        writeln!(out, "</table>")?;
    }

    writeln!(out, "</section>")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn effect_badge(effect: crate::cedar::CedarPolicyEffect) -> String {
    let class = match effect {
        crate::cedar::CedarPolicyEffect::Permit => "permit",
        crate::cedar::CedarPolicyEffect::Forbid => "forbid",
    };
    format!(" <span class=\"badge {class}\">{class}</span>")
}

fn annotation_badge(annotated: bool) -> String {
    if annotated {
        " <span class=\"badge annotated\">annotated</span>".into()
    } else {
        " <span class=\"badge unannotated\">un-annotated</span>".into()
    }
}

fn delta_class(d: i64) -> &'static str {
    match d.cmp(&0) {
        std::cmp::Ordering::Greater => "delta-pos",
        std::cmp::Ordering::Less => "delta-neg",
        std::cmp::Ordering::Equal => "delta-zero",
    }
}

fn format_signed_delta(d: i64) -> String {
    if d >= 0 {
        format!("+{d}")
    } else {
        format!("{d}")
    }
}

/// Emit a `<details>`-wrapped `<pre><code class="language-...">` block
/// for `source`. The summary is the language tag (`cedar`, `json`)
/// so operators can collapse the body to reduce visual noise on
/// large pages.
fn write_collapsible_source(language: &str, source: &str, out: &mut impl Write) -> Result<()> {
    writeln!(out, "  <details>")?;
    writeln!(
        out,
        "    <summary>{} source</summary>",
        escape_html(language)
    )?;
    writeln!(
        out,
        "    <pre><code class=\"language-{}\">{}</code></pre>",
        escape_html(language),
        escape_html(source)
    )?;
    writeln!(out, "  </details>")?;
    Ok(())
}

/// HTML-escape the minimal entity set: `& < > " '`. Used on every
/// operator-supplied string before write so injection from
/// Constitution-loadable input is impossible.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavioural::{ChainDivergence, ReceiptCountDelta};
    use crate::cedar::CedarPolicyEffect;
    use crate::diff::DIFF_SCHEMA_VERSION;

    fn empty_diff() -> ConstitutionDiff {
        ConstitutionDiff {
            diff_schema_version: DIFF_SCHEMA_VERSION.to_string(),
            left_constitution_version: "1.0.0".into(),
            right_constitution_version: "1.0.0".into(),
            schema_version_change: None,
            cedar_policies: NamedItemsDiff::default(),
            named_predicates: NamedItemsDiff::default(),
            scoring_rules: NamedItemsDiff::default(),
            procedures: NamedItemsDiff::default(),
            enforcement_rules: NamedItemsDiff::default(),
            behavioural: None,
        }
    }

    fn render_to_string(diff: &ConstitutionDiff) -> String {
        let mut buf = Vec::new();
        render(diff, &mut buf).expect("render");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn empty_diff_is_valid_standalone_document() {
        let s = render_to_string(&empty_diff());
        // Standalone document framing.
        assert!(s.starts_with("<!doctype html>"));
        assert!(s.contains("<html lang=\"en\">"));
        assert!(s.contains("<meta charset=\"utf-8\">"));
        assert!(s.contains("<style>"));
        assert!(s.contains("</style>"));
        assert!(s.contains("</body>"));
        assert!(s.contains("</html>"));
        // Title with the version transition (HTML entities for arrow).
        assert!(s.contains("Constitution diff (1.0.0 &rarr; 1.0.0)"));
        // All five section headers render even when empty.
        for h in [
            "Cedar policies",
            "Named predicates",
            "Scoring rules",
            "Procedures",
            "Enforcement rules",
        ] {
            assert!(
                s.contains(&format!("<h2>{h}</h2>")),
                "missing h2 {h:?}:\n{s}"
            );
        }
        // No behavioural section.
        assert!(
            !s.contains("class=\"behavioural\""),
            "behavioural section MUST be elided for static-only diffs"
        );
    }

    #[test]
    fn escapes_html_in_operator_inputs() {
        let mut diff = empty_diff();
        // Inject a `<script>` tag in a Cedar policy name. The
        // escape MUST neutralise it.
        diff.cedar_policies.added.push(CedarPolicyEntry::new(
            "<script>alert(1)</script>",
            true,
            CedarPolicyEffect::Forbid,
            "forbid (principal, action, resource);",
        ));
        let s = render_to_string(&diff);
        assert!(!s.contains("<script>alert(1)</script>"));
        assert!(s.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn cedar_source_is_collapsible() {
        let mut diff = empty_diff();
        diff.cedar_policies.added.push(CedarPolicyEntry::new(
            "no-x",
            true,
            CedarPolicyEffect::Forbid,
            "forbid (principal, action, resource);",
        ));
        let s = render_to_string(&diff);
        // Source is wrapped in <details><summary>cedar source</summary>...
        assert!(s.contains("<details>"));
        assert!(s.contains("<summary>cedar source</summary>"));
        assert!(s.contains("<code class=\"language-cedar\">"));
        // Effect + annotation badges render.
        assert!(s.contains("<span class=\"badge forbid\">forbid</span>"));
        assert!(s.contains("<span class=\"badge annotated\">annotated</span>"));
    }

    #[test]
    fn unannotated_hint_renders_with_callout() {
        let mut diff = empty_diff();
        diff.cedar_policies.added.push(CedarPolicyEntry::new(
            "permit:fingerprint",
            false,
            CedarPolicyEffect::Permit,
            "permit (principal, action, resource);",
        ));
        let s = render_to_string(&diff);
        assert!(s.contains("<p class=\"hint\">"));
        assert!(s.contains("un-annotated Cedar policies"));
        assert!(s.contains("<span class=\"badge unannotated\">un-annotated</span>"));
    }

    #[test]
    fn behavioural_section_renders_tables_with_delta_classes() {
        let mut diff = empty_diff();
        diff.behavioural = Some(BehaviouralDiff {
            window_from_unix_ns: 1_000,
            window_to_unix_ns: 2_000,
            replay_session_id: "session-uuid".into(),
            receipt_count_deltas: vec![ReceiptCountDelta {
                action_kind: "constitution.evaluate.deny".into(),
                subject_agent_id: "alice".into(),
                production_count: 12,
                candidate_count: 18,
            }],
            chain_divergences: vec![ChainDivergence {
                target_agent_id: "alice".into(),
                enforcement_rule_id: "forbidden_payload_chain".into(),
                stage: "detect".into(),
                production_count: 0,
                candidate_count: 1,
            }],
        });
        let s = render_to_string(&diff);
        // Section heading + replay session id.
        assert!(s.contains("Behavioural diff (window 1000 &rarr; 2000)"));
        assert!(s.contains("session-uuid"));
        // Both tables.
        assert!(s.contains("<th>action_kind</th>"));
        assert!(s.contains("<th>target_agent_id</th>"));
        // Positive deltas use the positive class + signed display.
        assert!(s.contains("class=\"num delta-pos\""));
        assert!(s.contains(">+6<"));
        assert!(s.contains(">+1<"));
    }
}
