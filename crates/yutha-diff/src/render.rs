//! Render entry points for the three output formats.
//!
//! Each format's body lives in its own private submodule (filled in
//! at 3d-C / 3d-D / 3d-E). This module ties them together behind a
//! single [`OutputFormat`] enum + per-format function so 3d-F can
//! flip between renderers based on a CLI flag without reaching into
//! private state.
//!
//! Phase 3d-B ships scaffolding only — each renderer returns a
//! placeholder string until its dedicated sub-phase lands. The shape
//! is locked here so 3d-F can wire the CLI surface in parallel.

use std::io::Write;

use crate::error::Result;
use crate::model::ConstitutionDiff;

mod html;
mod json;
mod markdown;

/// Discriminator over the three output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Machine-readable JSON. Output schema marker
    /// `"yutha-diff/v1"` per [`crate::diff::DIFF_SCHEMA_VERSION`].
    Json,
    /// Human-readable Markdown. Pastable into PR review threads.
    Markdown,
    /// Standalone HTML document with inlined CSS, color-coded sections,
    /// `<details>` collapse for long Cedar sources.
    Html,
}

impl OutputFormat {
    /// Parse from a CLI flag value. Accepts the lower-case names
    /// `"json"` / `"markdown"` / `"html"`. Returns `None` for any
    /// other input so the CLI can render a helpful error.
    pub fn parse_flag(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "markdown" | "md" => Some(Self::Markdown),
            "html" => Some(Self::Html),
            _ => None,
        }
    }

    /// CLI-friendly name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
            Self::Html => "html",
        }
    }
}

/// Render `diff` in the supplied format directly to a `String`. The
/// CLI uses this when `--output-file` is unset.
pub fn render_to_string(diff: &ConstitutionDiff, format: OutputFormat) -> Result<String> {
    let mut buf = Vec::new();
    render_to(diff, format, &mut buf)?;
    // Renderers MUST emit valid UTF-8; treat any non-UTF-8 byte as a
    // rendering bug (would only fire if a renderer's str writes
    // misbehave).
    Ok(String::from_utf8(buf).expect("renderers emit valid UTF-8"))
}

/// Render `diff` to an arbitrary `Write` sink.
pub fn render_to(
    diff: &ConstitutionDiff,
    format: OutputFormat,
    out: &mut impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => render_json(diff, out),
        OutputFormat::Markdown => render_markdown(diff, out),
        OutputFormat::Html => render_html(diff, out),
    }
}

/// Render `diff` as JSON to a `Write` sink. See [`mod@json`] for the
/// JSON shape spec.
pub fn render_json(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    json::render(diff, out)
}

/// Render `diff` as Markdown to a `Write` sink. See [`mod@markdown`]
/// for the Markdown layout.
pub fn render_markdown(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    markdown::render(diff, out)
}

/// Render `diff` as HTML to a `Write` sink. See [`mod@html`] for the
/// HTML structure.
pub fn render_html(diff: &ConstitutionDiff, out: &mut impl Write) -> Result<()> {
    html::render(diff, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_parse_flag_round_trip() {
        for f in [
            OutputFormat::Json,
            OutputFormat::Markdown,
            OutputFormat::Html,
        ] {
            assert_eq!(OutputFormat::parse_flag(f.name()), Some(f));
        }
        assert_eq!(OutputFormat::parse_flag("md"), Some(OutputFormat::Markdown));
        assert!(OutputFormat::parse_flag("yaml").is_none());
    }
}
