//! AUR update candidates, their scanner evidence and the user's version-specific decisions.

use std::collections::BTreeMap;

use super::{
    Act, Block, Ctx, Detail, Does, Flow, Job, Key, Page, Source, Tone, Update, icon, op, recheck,
    start, t,
};
use crate::data::screening::{Report, Status};
use crate::data::updates::Pending;
use crate::state::State;
use crate::ui::list::{Lead, List, Picked, Row};
use ratatui::{buffer::Buffer, layout::Rect};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Group {
    Clean,
    Flagged,
    Unknown,
    Held,
    Trusted,
}

impl Group {
    pub(super) const ALL: [Self; 5] = [
        Self::Clean,
        Self::Flagged,
        Self::Unknown,
        Self::Held,
        Self::Trusted,
    ];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Clean => t("AUR with no findings"),
            Self::Flagged => t("AUR with findings"),
            Self::Unknown => t("AUR without a current report"),
            Self::Held => t("Quarantined AUR updates"),
            Self::Trusted => t("Locally trusted AUR updates"),
        }
    }

    fn tone(self) -> Tone {
        match self {
            Self::Clean => Tone::Ok,
            Self::Trusted => Tone::Accent,
            Self::Flagged | Self::Held => Tone::Warn,
            Self::Unknown => Tone::Muted,
        }
    }
}

pub(super) fn group(ctx: &Ctx, pending: &Pending, update: &Update) -> Group {
    let report = pending
        .screens
        .get(&update.name)
        .filter(|report| !update.new.is_empty() && report.version == update.new);
    match report.map(|r| &r.status) {
        _ if ctx.state.aur_holds.contains_key(&update.name) => Group::Held,
        Some(Status::Clean) => Group::Clean,
        Some(_) if ctx.state.aur_trust.get(&update.name) == report => Group::Trusted,
        Some(Status::Flagged) => Group::Flagged,
        _ => Group::Unknown,
    }
}

/// Capture exactly the candidates the action showed. A subsequent update check can withdraw
/// authorization while the cursor is on the action, but cannot add packages to this run.
fn selection(ctx: &Ctx, pending: &Pending, wanted: Group) -> Vec<(String, String)> {
    pending
        .updates
        .iter()
        .filter(|u| u.source == Source::Aur && group(ctx, pending, u) == wanted)
        .map(|u| (u.name.clone(), u.new.clone()))
        .collect()
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
        acts.push(
            Act::new(t("Inspect AUR reports"), |_| {
                Flow::Push(Box::new(Reports {
                    list: List::filterable(),
                }))
            })
            .icon(icon::CODE)
            .does(Does::Open),
        );
        let mut eligible = BTreeMap::new();
        let mut both = true;
        for (wanted, label) in [
            (Group::Clean, t("Install AUR updates with no findings")),
            (Group::Trusted, t("Install locally trusted AUR updates")),
        ] {
            let selected: BTreeMap<_, _> = selection(ctx, pending, wanted)
                .into_iter()
                .map(|(name, _)| (name.clone(), pending.screens[&name].clone()))
                .collect();
            if selected.is_empty() {
                both = false;
            } else {
                eligible.extend(selected.clone());
                acts.push(install(label, selected, wanted.tone()));
            }
        }
        if both {
            acts.push(install(
                t("Install both eligible AUR groups"),
                eligible,
                Tone::Normal,
            ));
        }
    }
    acts.push(recheck(ctx));
    acts
}

fn install(label: &str, reports: BTreeMap<String, Report>, tone: Tone) -> Act {
    let count = reports.len();
    Act::new(label, move |ctx| {
        let Some(pending) = ctx.shared.updates.ready() else {
            return Flow::Stay;
        };
        if !ctx.settings.aur_screening
            || !reports.iter().all(|(name, report)| {
                pending.screens.get(name) == Some(report)
                    && pending.updates.iter().any(|u| {
                        u.source == Source::Aur
                            && u.name == *name
                            && u.new == report.version
                            && matches!(group(ctx, pending, u), Group::Clean | Group::Trusted)
                    })
            })
        {
            return Flow::Stay;
        }
        Flow::Push(start(Job::screened(reports.clone()), ctx))
    })
    .icon(icon::UPDATE)
    .note(count.to_string(), tone)
}

struct Reports {
    list: List<String>,
}

impl Page for Reports {
    fn title(&self) -> String {
        t("AUR reports").into()
    }

    fn draw(&mut self, area: Rect, buf: &mut Buffer, ctx: &mut Ctx) {
        let Some(pending) = crate::ui::detail::loaded(&ctx.shared.updates, area, buf, ctx) else {
            return;
        };
        let mut rows = Vec::new();
        for g in Group::ALL {
            let mut packages = pending
                .updates
                .iter()
                .filter(|u| u.source == Source::Aur && group(ctx, pending, u) == g)
                .peekable();
            if packages.peek().is_some() {
                rows.push(Row::heading(g.label()));
            }
            for u in packages {
                let score = pending
                    .screens
                    .get(&u.name)
                    .map(|r| r.summary.as_str())
                    .unwrap_or_default();
                rows.push(
                    Row::new(u.name.clone(), u.name.clone())
                        .detail(u.new.clone(), g.tone())
                        .note(score),
                );
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

enum Decision {
    Trust(Report),
    Hold(String),
    Reset,
}

impl Decision {
    fn apply(&self, state: &mut State, name: &str) {
        state.aur_trust.remove(name);
        state.aur_holds.remove(name);
        match self {
            Self::Trust(r) => {
                state.aur_trust.insert(name.to_owned(), r.clone());
            }
            Self::Hold(v) => {
                state.aur_holds.insert(name.to_owned(), v.clone());
            }
            Self::Reset => {}
        }
    }
}

fn decision(label: &str, update: &Update, choice: Decision) -> Act {
    let name = update.name.clone();
    let version = update.new.clone();
    Act::new(label, move |ctx| {
        if !ctx.settings.aur_screening
            || !ctx.shared.updates.ready().is_some_and(|pending| {
                pending
                    .updates
                    .iter()
                    .any(|u| u.source == Source::Aur && u.name == name && u.new == version)
                    && match &choice {
                        Decision::Trust(report) => pending.screens.get(&name) == Some(report),
                        _ => true,
                    }
            })
        {
            return Flow::Stay;
        }
        match State::try_update(|state| choice.apply(state, &name)) {
            Ok(state) => {
                ctx.state.aur_trust = state.aur_trust;
                ctx.state.aur_holds = state.aur_holds;
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
        let g = group(ctx, pending, u);
        let mut body = vec![
            Block::Field(t("Candidate version").into(), u.new.clone(), Tone::Normal),
            Block::Field(t("Group").into(), g.label().into(), g.tone()),
        ];
        if let Some(error) = &self.save_error {
            body.push(Block::Field(
                t("Could not save decision").into(),
                error.clone(),
                Tone::Error,
            ));
        }
        let report = pending.screens.get(&self.name);
        if let Some(r) = report {
            body.push(Block::Blank);
            if !r.version.is_empty() && r.version != u.new {
                body.push(Block::Field(
                    t("Report version").into(),
                    r.version.clone(),
                    Tone::Warn,
                ));
            }
            body.push(Block::Text(r.summary.clone(), Tone::Normal));
            body.extend(
                r.findings
                    .iter()
                    .map(|s| Block::Note(Lead::Bullet, s.clone(), Tone::Normal)),
            );
            if !r.url.is_empty() {
                body.push(Block::Blank);
                body.push(Block::Text(r.url.clone(), Tone::Accent));
            }
        }
        let mut acts = Vec::new();
        if g == Group::Held {
            acts.push(decision(t("Release from quarantine"), u, Decision::Reset));
        } else if g == Group::Trusted {
            acts.push(decision(t("Revoke trust"), u, Decision::Reset));
        } else if let Some(r) = report.filter(|_| g == Group::Flagged) {
            acts.push(decision(
                t("Trust this version and its current findings"),
                u,
                Decision::Trust(r.clone()),
            ));
        } else if let Some(r) = report.filter(|r| {
            g == Group::Unknown
                && r.status == Status::Unknown
                && !u.new.is_empty()
                && r.version == u.new
        }) {
            acts.push(decision(
                t("Trust this version without a current report"),
                u,
                Decision::Trust(r.clone()),
            ));
        }
        if g != Group::Clean && g != Group::Held {
            acts.push(decision(
                t("Quarantine until findings clear"),
                u,
                Decision::Hold(u.new.clone()),
            ));
        }
        if let Some(report) = report.filter(|_| matches!(g, Group::Clean | Group::Trusted)) {
            acts.push(install(
                t("Install this AUR update"),
                BTreeMap::from([(u.name.clone(), report.clone())]),
                g.tone(),
            ));
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
    use crate::data::updates::parse;
    use crate::ui::Loaded;
    use crate::ui::app::tests::{app, open, press, screen};
    use crate::ui::pages::upgrade::UpgradePage;

    fn flagged() -> Report {
        Report {
            version: "2-1".into(),
            status: Status::Flagged,
            summary: "WTAKO: Yellow (1)".into(),
            findings: vec!["Yellow: the build downloads an extra file".into()],
            url: "https://wtako.net/services/aur-audit".into(),
        }
    }

    #[test]
    fn only_current_clear_or_explicitly_trusted_updates_can_start() {
        let (mut app, _) = app();
        app.ctx.settings.aur_screening = true;
        let mut pending = parse(
            "aur\tclean\t1-1\t2-1\naur\tflagged\t1-1\t2-1\naur\tmissing\t1-1\t2-1\naur\tstale\t2-1\t3-1\n",
        );
        let clean = Report {
            status: Status::Clean,
            summary: "WTAKO: no findings".into(),
            findings: Vec::new(),
            ..flagged()
        };
        pending.screens.insert("clean".into(), clean.clone());
        pending.screens.insert("stale".into(), clean);
        pending.screens.insert("flagged".into(), flagged());
        Decision::Trust(flagged()).apply(&mut app.ctx.state, "flagged");
        assert_eq!(
            selection(&app.ctx, &pending, Group::Clean),
            [("clean".into(), "2-1".into())]
        );
        assert_eq!(
            selection(&app.ctx, &pending, Group::Trusted),
            [("flagged".into(), "2-1".into())]
        );
        assert_eq!(
            selection(&app.ctx, &pending, Group::Unknown),
            [
                ("missing".into(), "2-1".into()),
                ("stale".into(), "3-1".into())
            ]
        );
        app.ctx.shared.updates = Loaded::Ready(pending.clone());
        let mut authorized = actions(&app.ctx)
            .into_iter()
            .find(|a| a.label == "Install locally trusted AUR updates")
            .unwrap();
        pending
            .screens
            .get_mut("flagged")
            .unwrap()
            .findings
            .push("New finding".into());
        app.ctx.shared.updates = Loaded::Ready(pending);
        assert!(matches!((authorized.go)(&mut app.ctx), Flow::Stay));
    }

    #[test]
    fn an_unknown_report_needs_an_explicit_exception_that_expires_on_new_evidence() {
        let (mut app, mut term) = app();
        app.ctx.settings.aur_screening = true;
        let name = "screening-unknown-test";
        let mut pending = parse("aur\tscreening-unknown-test\t1-1\t2-1\n");
        let unknown = Report {
            status: Status::Unknown,
            summary: "The scanner is unreachable.".into(),
            findings: Vec::new(),
            ..flagged()
        };
        pending.screens.insert(name.into(), unknown.clone());
        app.ctx.shared.updates = Loaded::Ready(pending.clone());
        open(&mut app, Box::new(PackageReport::new(name.into())));
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("Trust this version without a current report"),
            "{shown}"
        );
        assert!(selection(&app.ctx, &pending, Group::Trusted).is_empty());
        press(&mut app, &[Key::Enter]);
        assert_eq!(State::load().aur_trust.get(name), Some(&unknown));
        assert_eq!(
            selection(&app.ctx, &pending, Group::Trusted),
            [(name.into(), "2-1".into())]
        );
        pending.screens.insert(name.into(), flagged());
        assert!(selection(&app.ctx, &pending, Group::Trusted).is_empty());
        State::try_update(|state| Decision::Reset.apply(state, name)).unwrap();
    }

    #[test]
    fn the_report_shows_findings_and_persists_trust_and_quarantine() {
        let (mut app, mut term) = app();
        app.ctx.settings.aur_screening = true;
        let name = "screening-ui-test";
        let mut pending = parse("aur\tscreening-ui-test\t1-1\t2-1\n");
        pending.screens.insert(name.into(), flagged());
        app.ctx.shared.updates = Loaded::Ready(pending);
        open(&mut app, Box::new(UpgradePage::new()));
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("AUR with findings (1)") && !shown.contains("Install now"),
            "{shown}"
        );
        press(&mut app, &[Key::Enter]);
        assert!(screen(&mut app, &mut term).contains("WTAKO: Yellow (1)"));
        press(&mut app, &[Key::Enter]);
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("the build downloads an extra file") && shown.contains(&flagged().url),
            "{shown}"
        );
        press(&mut app, &[Key::Enter]);
        assert_eq!(State::load().aur_trust.get(name), Some(&flagged()));
        assert!(screen(&mut app, &mut term).contains("Locally trusted AUR updates"));
        press(&mut app, &[Key::Enter]);
        assert!(screen(&mut app, &mut term).contains("Revoke trust"));
        press(&mut app, &[Key::Down, Key::Enter]);
        let persisted = State::load();
        assert_eq!(
            persisted.aur_holds.get(name).map(String::as_str),
            Some("2-1")
        );
        assert!(!persisted.aur_trust.contains_key(name));
        assert!(screen(&mut app, &mut term).contains("Quarantined AUR updates"));
        press(&mut app, &[Key::Enter]);
        assert!(screen(&mut app, &mut term).contains("Release from quarantine"));
        press(&mut app, &[Key::Enter]);
        assert!(!State::load().aur_holds.contains_key(name));
        assert!(screen(&mut app, &mut term).contains("AUR with findings"));
    }
}
