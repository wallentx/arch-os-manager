//! Scanner findings for pending AUR updates and decisions about installing them.

use std::collections::BTreeMap;

use super::{
    Act, Block, Ctx, Detail, Does, Flow, Job, Key, Page, Source, Tone, Update, icon, op, recheck,
    start, t, tf,
};
use crate::data::screening::{Category, Policy, Report, Scanner, eligible, inspectable};
use crate::data::updates::Pending;
use crate::state::State;
use crate::ui::list::{Lead, List, Picked, Row};
use ratatui::{buffer::Buffer, layout::Rect};

fn disposition(ctx: &Ctx, pending: &Pending, u: &Update) -> (Category, Policy) {
    let category = pending
        .screens
        .get(&u.name)
        .filter(|r| r.category == Category::Malicious || (!u.new.is_empty() && r.version == u.new))
        .map_or(Category::Missing, |r| r.category);
    if ctx.state.aur_malicious.contains_key(&u.name) {
        return (Category::Malicious, Policy::Block);
    }
    let policy = ctx.settings.screening_policy(category);
    if policy != Policy::Block
        && (ctx.state.deferred(&u.name, &ctx.settings) || ctx.state.aur_holds.contains_key(&u.name))
    {
        return (category, Policy::Defer);
    }
    (category, policy)
}

/// Preserve package order within each category and distinguish effective dispositions
/// when a package remains deferred by an earlier decision.
pub(super) fn groups(
    ctx: &Ctx,
    pending: &Pending,
    visible: impl IntoIterator<Item = usize>,
) -> BTreeMap<Option<(Category, Policy)>, Vec<usize>> {
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for i in visible {
        let group = disposition(ctx, pending, &pending.updates[i]);
        groups
            .entry((!pending.screening || group.0 == Category::Malicious).then_some(group))
            .or_default()
            .push(i);
    }
    groups
}

pub(super) fn heading(category: Category, policy: Policy) -> String {
    let label = category.label();
    match policy {
        Policy::Allow => label.into(),
        Policy::Inspect => tf("Inspect: {category}", &[("category", &label)]),
        Policy::Defer => tf("Deferred: {category}", &[("category", &label)]),
        Policy::Block => tf("Blocked: {category}", &[("category", &label)]),
    }
}

pub(super) fn decision_label(ctx: &Ctx, pending: &Pending, u: &Update) -> Option<&'static str> {
    if !ctx.state.aur_malicious.contains_key(&u.name) && ctx.state.aur_holds.contains_key(&u.name) {
        return Some(t("Quarantined"));
    }
    pending
        .screens
        .get(&u.name)
        .filter(|r| {
            !pending.screening
                && r.version == u.new
                && r.category != Category::Clean
                && eligible(&u.name, r, &ctx.settings, &ctx.state)
        })
        .map(|_| t("Approved"))
}

pub(super) fn actions(ctx: &Ctx) -> Vec<Act> {
    let mut acts = Vec::new();
    let pending = ctx.shared.updates.ready();
    if pending
        .is_none_or(|p| p.updates.iter().any(|u| u.source != Source::Aur) || !p.failed.is_empty())
    {
        acts.push(
            Act::new(t("Update official packages and Flatpaks"), |ctx| {
                Flow::Push(start(Job::new(op::UPGRADE_RUN, vec!["system".into()]), ctx))
            })
            .icon(icon::UPDATE),
        );
    }
    if let Some(pending) = pending.filter(|p| p.updates.iter().any(|u| u.source == Source::Aur)) {
        let mut clean = BTreeMap::new();
        let mut approved = BTreeMap::new();
        for u in pending.updates.iter().filter(|u| u.source == Source::Aur) {
            if !pending.screening
                && let Some(report) = pending.screens.get(&u.name)
                && report.version == u.new
                && eligible(&u.name, report, &ctx.settings, &ctx.state)
            {
                let group = if report.category == Category::Clean {
                    &mut clean
                } else {
                    &mut approved
                };
                group.insert(u.name.clone(), report.clone());
            }
        }
        // The combined choice allows selected split packages to build in one transaction.
        let combined = if !clean.is_empty() && !approved.is_empty() {
            Some(
                clean
                    .iter()
                    .chain(&approved)
                    .map(|(n, r)| (n.clone(), r.clone()))
                    .collect(),
            )
        } else {
            None
        };
        if !clean.is_empty() {
            acts.push(install(t("Update clean AUR packages"), clean));
        }
        if !approved.is_empty() {
            acts.push(install(t("Update approved AUR packages"), approved));
        }
        if let Some(reports) = combined {
            acts.push(install(
                t("Update clean and approved AUR packages"),
                reports,
            ));
        }
        acts.push(
            Act::new(t("Inspect AUR findings"), |_| {
                Flow::Push(Box::new(Reports {
                    list: List::filterable(),
                }))
            })
            .icon(icon::CODE)
            .does(Does::Open),
        );
    }
    acts.push(recheck(ctx));
    acts
}

/// The action retains the reports that were on screen; a refresh may remove
/// authorization before the user presses Enter.
fn install(label: &str, reports: BTreeMap<String, Report>) -> Act {
    let count = reports.len();
    Act::new(label, move |ctx| {
        let Some(pending) = ctx.shared.updates.ready() else {
            return Flow::Stay;
        };
        if pending.screening
            || !reports.iter().all(|(name, report)| {
                pending.screens.get(name) == Some(report)
                    && pending.updates.iter().any(|u| {
                        u.source == Source::Aur && u.name == *name && u.new == report.version
                    })
                    && eligible(name, report, &ctx.settings, &ctx.state)
            })
        {
            return Flow::Stay;
        }
        Flow::Push(start(Job::screened(reports.clone()), ctx))
    })
    .icon(icon::UPDATE)
    .note(count.to_string(), Tone::Muted)
}

struct Reports {
    list: List<String>,
}

impl Page for Reports {
    fn title(&self) -> String {
        t("AUR findings").into()
    }

    fn draw(&mut self, area: Rect, buf: &mut Buffer, ctx: &mut Ctx) {
        let Some(pending) = crate::ui::detail::loaded(&ctx.shared.updates, area, buf, ctx) else {
            return;
        };
        let mut rows = Vec::new();
        let aur = pending
            .updates
            .iter()
            .enumerate()
            .filter_map(|(i, u)| (u.source == Source::Aur).then_some(i));
        for (group, packages) in groups(ctx, pending, aur) {
            let title = group.map_or_else(
                || t("Checking AUR scan sources").into(),
                |(c, policy)| heading(c, policy),
            );
            rows.push(Row::heading(format!("{title} ({})", packages.len())));
            for index in packages {
                let u = &pending.updates[index];
                let mut row = Row::new(u.name.clone(), u.name.clone())
                    .dot(group.map_or(Tone::Muted, |(c, _)| Tone::Screening(c)))
                    .detail(u.new.clone(), Tone::Muted);
                if let Some(label) = decision_label(ctx, pending, u) {
                    row = row.note(label);
                }
                rows.push(row);
            }
        }
        self.list.set(rows);
        self.list.draw(area, buf, ctx);
    }
    fn key(&mut self, key: Key, _ctx: &mut Ctx) -> Flow {
        match self.list.key(key) {
            Picked::Open(name) => Flow::Push(Box::new(PackageReport::new(name))),
            Picked::Used => Flow::Stay,
            Picked::Ignored => Flow::Ignored,
        }
    }
    fn hints(&self, _: &Ctx) -> Vec<(&'static str, Does)> {
        crate::ui::pages::list_hints(self.list.typing())
    }
    fn typing(&self) -> bool {
        self.list.typing()
    }
}

struct PackageReport {
    name: String,
    detail: Detail,
    save_error: Option<String>,
}

impl PackageReport {
    fn new(name: String) -> Self {
        Self {
            name,
            detail: Detail::default(),
            save_error: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Hold,
    Revoke,
    Release,
}

impl Decision {
    fn available(self, name: &str, report: &Report, ctx: &Ctx, state: &State) -> bool {
        match self {
            Self::Approve => {
                inspectable(name, report, &ctx.settings, state)
                    && state.aur_trust.get(name) != Some(report)
            }
            Self::Hold => inspectable(name, report, &ctx.settings, state),
            Self::Revoke => state.aur_trust.get(name) == Some(report),
            Self::Release => {
                report.category != Category::Malicious && state.aur_holds.contains_key(name)
            }
        }
    }

    fn action(self, name: &str, report: &Report) -> Act {
        let name = name.to_owned();
        let report = report.clone();
        let label = match self {
            Self::Approve => t("Approve this version and its findings"),
            Self::Hold => t("Quarantine until findings clear"),
            Self::Revoke => t("Revoke approval"),
            Self::Release => t("Release from quarantine"),
        };
        Act::new(label, move |ctx| {
            if !ctx.settings.aur_screening
                || !ctx.shared.updates.ready().is_some_and(|p| {
                    !p.screening
                        && p.screens.get(&name) == Some(&report)
                        && p.updates.iter().any(|u| {
                            u.source == Source::Aur && u.name == name && u.new == report.version
                        })
                })
            {
                return Flow::Stay;
            }
            match State::try_update(|state| {
                if !self.available(&name, &report, ctx, state) {
                    return;
                }
                match self {
                    Self::Approve => {
                        state.aur_trust.insert(name.clone(), report.clone());
                    }
                    Self::Hold => {
                        state.aur_trust.remove(&name);
                        state.aur_holds.insert(name.clone(), report.version.clone());
                    }
                    Self::Revoke => {
                        state.aur_trust.remove(&name);
                    }
                    Self::Release => {
                        state.aur_holds.remove(&name);
                    }
                }
            }) {
                Ok(state) => {
                    ctx.state.aur_trust = state.aur_trust;
                    ctx.state.aur_holds = state.aur_holds;
                    ctx.state.aur_malicious = state.aur_malicious;
                    ctx.state.aur_deferrals = state.aur_deferrals;
                    Flow::Pop
                }
                Err(error) => {
                    let mut page = PackageReport::new(name.clone());
                    page.save_error = Some(error.to_string());
                    Flow::Replace(Box::new(page))
                }
            }
        })
        .does(Does::Use)
    }
}

fn sources(body: &mut Vec<Block>, ctx: &Ctx, report: Option<&Report>, u: &Update) {
    for scanner in Scanner::ALL {
        let enabled = ctx.settings.aur_screening && ctx.settings.scanner_enabled(scanner);
        let mut evidence: Vec<_> = report
            .into_iter()
            .flat_map(|r| &r.evidence)
            .filter(|e| e.scanner == scanner && (enabled || e.category == Category::Malicious))
            .collect();
        if let Some(stored) = ctx
            .state
            .aur_malicious
            .get(&u.name)
            .and_then(|records| records.get(&scanner))
            && !evidence.iter().any(|e| e.category == Category::Malicious)
        {
            evidence.push(stored);
        }
        if evidence.is_empty() && !enabled {
            continue;
        }
        body.push(Block::Blank);
        body.push(Block::Heading(scanner.label().into()));
        if evidence.is_empty() {
            body.push(Block::Text(
                t("No report is available.").into(),
                Tone::Muted,
            ));
        }
        for e in evidence {
            let version = e.version.as_deref().unwrap_or(t("Unreported"));
            let tone = if e.version.as_deref() == Some(u.new.as_str()) {
                Tone::Normal
            } else {
                Tone::Warn
            };
            body.push(Block::Field(
                t("Scanned version").into(),
                version.into(),
                tone,
            ));
            body.push(Block::Text(e.summary.clone(), Tone::Normal));
            body.extend(
                e.findings
                    .iter()
                    .map(|f| Block::Note(Lead::Bullet, f.clone(), Tone::Normal)),
            );
            if !e.url.is_empty() {
                body.push(Block::Text(e.url.clone(), Tone::Accent));
            }
        }
    }
}

impl Page for PackageReport {
    fn title(&self) -> String {
        self.name.clone()
    }
    fn draw(&mut self, area: Rect, buf: &mut Buffer, ctx: &mut Ctx) {
        let Some(pending) = crate::ui::detail::loaded(&ctx.shared.updates, area, buf, ctx) else {
            self.detail.set(Vec::new(), Vec::new());
            return;
        };
        let Some(u) = pending
            .updates
            .iter()
            .find(|u| u.source == Source::Aur && u.name == self.name)
        else {
            self.detail.set(
                vec![Block::Text(
                    t("This update is no longer pending.").into(),
                    Tone::Muted,
                )],
                Vec::new(),
            );
            self.detail.draw(area, buf, ctx);
            return;
        };
        let (c, policy) = disposition(ctx, pending, u);
        let report = pending.screens.get(&self.name);
        let mut body = vec![Block::Field(
            t("Candidate version").into(),
            u.new.clone(),
            Tone::Normal,
        )];
        if pending.screening {
            body.push(Block::Text(
                t("Checking AUR scan sources").into(),
                Tone::Muted,
            ));
        }
        if !pending.screening || c == Category::Malicious {
            body.push(Block::Field(
                t("Group").into(),
                heading(c, policy),
                Tone::Screening(c),
            ));
        }
        if c != Category::Malicious && !ctx.settings.aur_screening {
            body.push(Block::Text(
                t("Enable AUR update screening to select other AUR updates.").into(),
                Tone::Muted,
            ));
        } else if ctx.settings.aur_screening
            && Scanner::ALL
                .into_iter()
                .all(|s| !ctx.settings.scanner_enabled(s))
        {
            body.push(Block::Text(
                t("No scan sources are enabled.").into(),
                Tone::Muted,
            ));
        }
        if let Some(status) = decision_label(ctx, pending, u) {
            body.push(Block::Text(status.into(), Tone::Normal));
        }
        if let Some(e) = &self.save_error {
            body.push(Block::Field(
                t("Could not save decision").into(),
                e.clone(),
                Tone::Error,
            ));
        }
        if !pending.screening || c == Category::Malicious {
            sources(&mut body, ctx, report, u);
        }
        let mut acts = Vec::new();
        if let Some(report) = report
            .filter(|r| !pending.screening && r.version == u.new && ctx.settings.aur_screening)
        {
            for decision in [
                Decision::Approve,
                Decision::Revoke,
                Decision::Release,
                Decision::Hold,
            ] {
                if c != Category::Malicious
                    && decision.available(&self.name, report, ctx, &ctx.state)
                {
                    acts.push(decision.action(&self.name, report));
                }
            }
            if eligible(&self.name, report, &ctx.settings, &ctx.state) {
                acts.push(install(
                    t("Install this AUR update"),
                    BTreeMap::from([(u.name.clone(), report.clone())]),
                ));
            }
        }
        self.detail.set(body, acts);
        self.detail.draw(area, buf, ctx);
    }
    fn key(&mut self, key: Key, ctx: &mut Ctx) -> Flow {
        self.detail.key(key, ctx)
    }
    fn hints(&self, _: &Ctx) -> Vec<(&'static str, Does)> {
        self.detail.hints()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::screening::Evidence;
    use crate::data::updates::parse;
    use crate::ui::Loaded;
    use crate::ui::app::tests::{app, open, press, screen};
    use crate::ui::pages::upgrade::UpgradePage;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn report(category: Category) -> Report {
        Report::new(
            "2-1",
            vec![
                Evidence {
                    scanner: Scanner::Wtako,
                    version: Some("2-1".into()),
                    category,
                    summary: "WTAKO fixture".into(),
                    findings: vec!["Check the recipe".into()],
                    url: "https://example.org/first".into(),
                },
                Evidence {
                    scanner: Scanner::Aurwatch,
                    version: None,
                    category: Category::Missing,
                    summary: "No analysis available".into(),
                    findings: vec![],
                    url: "https://example.org/second".into(),
                },
            ],
        )
    }

    fn configure(ctx: &mut Ctx) {
        ctx.settings.aur_screening = true;
        for s in Scanner::ALL {
            ctx.settings
                .set_scanner_enabled(s, matches!(s, Scanner::Wtako | Scanner::Aurwatch));
        }
    }

    fn example_reports(ctx: &mut Ctx) {
        configure(ctx);
        let packages = [
            ("some-safe-package", Category::Clean),
            ("simple-tool", Category::Clean),
            ("example-minor", Category::Minor),
            ("example-suspicious", Category::Suspicious),
            ("example-unscanned", Category::Missing),
            ("example-compromised", Category::Malicious),
        ];
        let mut pending = parse("repo\tlibexample\t1-1\t2-1\n");
        for (name, c) in packages {
            pending
                .updates
                .extend(parse(&format!("aur\t{name}\t1-1\t2-1\n")).updates);
            pending.screens.insert(name.into(), report(c));
        }
        ctx.shared.updates = Loaded::Ready(pending);
    }

    #[test]
    fn screen_groups_candidates_under_one_heading_with_five_distinct_colored_dots() {
        let (mut app, _) = app();
        example_reports(&mut app.ctx);
        open(&mut app, Box::new(UpgradePage::new()));
        let mut term = Terminal::new(TestBackend::new(90, 36)).unwrap();
        let shown = screen(&mut app, &mut term);
        let lines: Vec<_> = shown.lines().collect();
        assert_eq!(
            lines.iter().filter(|line| line.trim() == "AUR").count(),
            1,
            "{shown}"
        );
        let categories = [
            ("No findings (2)", Category::Clean),
            ("Inspect: Minor findings (1)", Category::Minor),
            ("Blocked: Suspicious findings (1)", Category::Suspicious),
            ("Inspect: Missing scan (1)", Category::Missing),
            ("Blocked: Confirmed malicious (1)", Category::Malicious),
        ];
        let mut last = 0;
        let mut colors = vec![];
        for (label, c) in categories {
            let (y, line) = lines
                .iter()
                .enumerate()
                .find(|(_, l)| l.contains(label))
                .unwrap_or_else(|| panic!("{shown}"));
            assert!(y > last);
            last = y;
            let x = line.chars().position(|c| c == '●').unwrap();
            let cell = &term.backend().buffer()[(x as u16, y as u16)];
            assert_eq!(cell.fg, app.ctx.style.color(Tone::Screening(c)));
            assert!(!colors.contains(&cell.fg));
            colors.push(cell.fg);
            assert!(lines[y + 1].chars().position(|c| c == '↑').unwrap() > x);
            assert!(lines[y + 1].contains("1-1  →  2-1"));
        }
        let labels: Vec<_> = actions(&app.ctx).into_iter().map(|a| a.label).collect();
        assert_eq!(
            labels,
            [
                "Update official packages and Flatpaks",
                "Update clean AUR packages",
                "Inspect AUR findings",
                "Check again"
            ]
        );
        app.ctx
            .settings
            .set_screening_policy(Category::Missing, Policy::Defer);
        assert!(screen(&mut app, &mut term).contains("Deferred: Missing scan (1)"));
        // Filtering narrows counts within each visible group and hides empty headings.
        press(&mut app, &[Key::Char('f')]);
        for c in "simple-tool".chars() {
            press(&mut app, &[Key::Char(c)]);
        }
        let filtered = screen(&mut app, &mut term);
        assert!(filtered.contains("No findings (1)") && filtered.contains("simple-tool"));
        assert!(!filtered.contains("Minor findings"));
    }

    #[test]
    fn report_shows_provenance_then_allows_inspection_only_approval() {
        let (mut app, _) = app();
        configure(&mut app.ctx);
        let name = "screen-ui-minor-example";
        let mut p = parse(&format!("aur\t{name}\t1-1\t2-1\n"));
        let mut r = report(Category::Minor);
        r.evidence[1].version = Some("1-1".into());
        r.evidence[1].summary = "Prior version assessed".into();
        p.screens.insert(name.into(), r.clone());
        app.ctx.shared.updates = Loaded::Ready(p);
        let mut term = Terminal::new(TestBackend::new(88, 42)).unwrap();
        open(&mut app, Box::new(PackageReport::new(name.into())));
        let shown = screen(&mut app, &mut term);
        for text in [
            "WTAKO fixture",
            "Prior version assessed",
            "2-1",
            "1-1",
            "WTAKO AUR Audit",
            "AURWatch",
            "Check the recipe",
            "https://example.org/first",
            "https://example.org/second",
            "Approve this version and its findings",
        ] {
            assert!(shown.contains(text), "{text}: {shown}");
        }
        press(&mut app, &[Key::Enter]);
        assert_eq!(State::load().aur_trust.get(name), Some(&r));
        let mut action = actions(&app.ctx)
            .into_iter()
            .find(|a| a.label == "Update approved AUR packages")
            .unwrap();
        app.ctx
            .settings
            .set_screening_policy(Category::Minor, Policy::Block);
        assert!(matches!((action.go)(&mut app.ctx), Flow::Stay));
        open(&mut app, Box::new(PackageReport::new(name.into())));
        let blocked = screen(&mut app, &mut term);
        assert!(
            blocked.contains("Blocked: Minor findings")
                && !blocked.contains("Install this AUR update")
        );
        assert!(!blocked.contains("Approve this version"));
        State::try_update(|s| {
            s.aur_trust.remove(name);
        })
        .unwrap();
    }

    #[test]
    fn confirmed_malicious_has_no_per_package_or_bulk_install_override() {
        let (mut app, mut term) = app();
        example_reports(&mut app.ctx);
        let name = "example-compromised";
        app.ctx
            .state
            .aur_trust
            .insert(name.into(), report(Category::Malicious));
        open(&mut app, Box::new(PackageReport::new(name.into())));
        let shown = screen(&mut app, &mut term);
        assert!(shown.contains("Blocked: Confirmed malicious"), "{shown}");
        for forbidden in [
            "Approve this version",
            "Install this AUR update",
            "Release from quarantine",
            "Revoke approval",
        ] {
            assert!(!shown.contains(forbidden), "{shown}");
        }
        let approved = actions(&app.ctx)
            .into_iter()
            .any(|a| a.label == "Update approved AUR packages");
        assert!(!approved);
    }

    #[test]
    fn lingering_deferral_is_distinct_from_other_findings_in_the_same_category() {
        let (mut app, _) = app();
        configure(&mut app.ctx);
        app.ctx
            .settings
            .set_screening_policy(Category::Suspicious, Policy::Defer);
        app.ctx
            .state
            .aur_deferrals
            .insert("wait".into(), Category::Suspicious);
        let mut p = parse("aur\twait\t1-1\t2-1\naur\treview\t1-1\t2-1\n");
        for u in &p.updates {
            p.screens.insert(u.name.clone(), report(Category::Minor));
        }
        let grouped = groups(&app.ctx, &p, [0, 1]);
        assert_eq!(grouped[&Some((Category::Minor, Policy::Defer))], [0]);
        assert_eq!(grouped[&Some((Category::Minor, Policy::Inspect))], [1]);
    }

    #[test]
    fn retained_malicious_finding_hides_install_all_when_screening_is_switched_off() {
        let (mut app, mut term) = app();
        example_reports(&mut app.ctx);
        let name = "example-compromised";
        let retained = report(Category::Malicious).evidence.remove(0);
        app.ctx
            .state
            .aur_malicious
            .insert(name.into(), BTreeMap::from([(Scanner::Wtako, retained)]));
        app.ctx.settings.aur_screening = false;
        app.ctx.settings.set_scanner_enabled(Scanner::Wtako, false);
        if let Loaded::Ready(p) = &mut app.ctx.shared.updates {
            p.screens.clear();
        }
        open(&mut app, Box::new(UpgradePage::new()));
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("Blocked: Confirmed malicious") && !shown.contains("Install now"),
            "{shown}"
        );
        assert!(shown.contains("Update official packages and Flatpaks"));
        assert!(!shown.contains("Update clean AUR packages"));
        open(&mut app, Box::new(PackageReport::new(name.into())));
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("WTAKO AUR Audit") && shown.contains("Check the recipe"),
            "{shown}"
        );
        assert!(
            !shown.contains("Approve this version") && !shown.contains("No report is available.")
        );
    }

    #[test]
    fn an_async_scan_keeps_system_updates_and_known_blocks_available() {
        let (mut app, mut term) = app();
        example_reports(&mut app.ctx);
        let mut stale_install = actions(&app.ctx)
            .into_iter()
            .find(|a| a.label == "Update clean AUR packages")
            .unwrap();
        let mut pending = app.ctx.shared.updates.ready().unwrap().clone();
        pending.screening = true;
        app.ctx.shared.updates = Loaded::Ready(pending);
        app.ctx.check = std::time::Duration::from_secs(60);
        app.ctx.recheck();
        let page = UpgradePage::new();
        assert!(!page.animating(&app.ctx));
        open(&mut app, Box::new(page));
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("Checking AUR scan sources")
                && shown.contains("Blocked: Confirmed malicious"),
            "{shown}"
        );
        assert!(!shown.contains("Update clean AUR packages") && !shown.contains("No findings"));
        assert!(matches!((stale_install.go)(&mut app.ctx), Flow::Stay));
        let mut system = actions(&app.ctx)
            .into_iter()
            .find(|a| a.label == "Update official packages and Flatpaks")
            .unwrap();
        assert!(system.unavailable.is_none());
        assert!(matches!((system.go)(&mut app.ctx), Flow::Push(_)));
    }

    /// Generate a local preview with the same painter used by the native window.
    #[test]
    #[ignore]
    fn screening_preview() {
        let (mut app, _) = app();
        example_reports(&mut app.ctx);
        open(&mut app, Box::new(UpgradePage::new()));
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/preview");
        std::fs::create_dir_all(&dir).unwrap();
        crate::window::tests::png(&mut app, 1600, 1200, 1.5, &dir.join("aur-screening.png"));
    }
}
