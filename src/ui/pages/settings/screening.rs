//! Sources and update policies for AUR screening.

use ratatui::{buffer::Buffer, layout::Rect};

use super::on_off;
use crate::data::screening::{Category, Policy, Scanner};
use crate::i18n::{t, tf};
use crate::ui::list::{List, Picked, Row};
use crate::ui::target::Target;
use crate::ui::{Ctx, Does, Flow, Key, Nav, Page, Tone};
use crate::{script, state::State};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Setting {
    Enabled,
    Source(Scanner),
    Behavior(Category),
}

pub(crate) fn open() -> Box<dyn Page> {
    Box::new(ScreeningPage {
        list: List::default(),
        sources_changed: false,
    })
}

struct ScreeningPage {
    list: List<Setting>,
    /// Refresh once on leaving, after the user finishes selecting the services to contact.
    sources_changed: bool,
}

impl Page for ScreeningPage {
    fn title(&self) -> String {
        Target::AurScreening.label().into()
    }

    fn draw(&mut self, area: Rect, buf: &mut Buffer, ctx: &mut Ctx) {
        let (value, tone) = on_off(ctx.settings.aur_screening);
        let mut switch =
            Row::new(Setting::Enabled, t("Screen pending AUR updates")).detail(value, tone);
        if ctx.settings.aur_screening
            && !Scanner::ALL
                .into_iter()
                .any(|s| ctx.settings.scanner_enabled(s))
        {
            switch = switch.note(t("All sources are off. Pending updates have no scan."));
        }
        let mut rows = vec![switch, Row::heading(t("Scan sources"))];
        for source in Scanner::ALL {
            let (value, tone) = on_off(ctx.settings.scanner_enabled(source));
            rows.push(Row::new(Setting::Source(source), source.label()).detail(value, tone));
        }
        rows.push(Row::heading(t("Update policies")));
        for category in [
            Category::Clean,
            Category::Minor,
            Category::Suspicious,
            Category::Missing,
            Category::Malicious,
        ] {
            let row = Row::new(Setting::Behavior(category), category.label());
            rows.push(match category {
                Category::Clean => row.detail(t("Eligible"), Tone::Ok).dim(true),
                Category::Malicious => row.detail(t("Always blocked"), Tone::Error).dim(true),
                _ => row.detail(
                    ctx.settings.screening_policy(category).label(),
                    Tone::Normal,
                ),
            });
        }
        if let Some(error) = &ctx.settings_unsaved {
            rows.push(Row::heading(tf(
                "settings.yaml not saved: {error}",
                &[("error", error)],
            )));
        }
        self.list.set(rows);
        self.list.draw(area, buf, ctx);
    }

    fn key(&mut self, key: Key, ctx: &mut Ctx) -> Flow {
        match self.list.key(key) {
            Picked::Open(Setting::Enabled) => {
                ctx.settings.aur_screening = !ctx.settings.aur_screening;
                script::configure(&ctx.settings, ctx.features());
                self.sources_changed = true;
            }
            Picked::Open(Setting::Source(source)) => {
                ctx.settings
                    .set_scanner_enabled(source, !ctx.settings.scanner_enabled(source));
                self.sources_changed |= ctx.settings.aur_screening;
            }
            Picked::Open(Setting::Behavior(Category::Malicious | Category::Clean)) => {
                return Flow::Stay;
            }
            Picked::Open(Setting::Behavior(category)) => {
                return Flow::Push(policy_page(category, ctx));
            }
            Picked::Used => return Flow::Stay,
            Picked::Ignored => {
                if self.sources_changed && key.nav(false) == Some(Nav::Back) {
                    ctx.recheck();
                }
                return Flow::Ignored;
            }
        }
        ctx.save_settings();
        Flow::Stay
    }

    fn hints(&self, _: &Ctx) -> Vec<(&'static str, Does)> {
        let mut hints = vec![("↑↓", Does::Choose)];
        match self.list.selected().and_then(|r| r.id) {
            Some(Setting::Enabled | Setting::Source(_)) => hints.push(("⏎", Does::Use)),
            Some(Setting::Behavior(Category::Minor | Category::Suspicious | Category::Missing)) => {
                hints.push(("⏎", Does::Open))
            }
            _ => {}
        }
        hints.push(("esc", Does::Back));
        hints
    }
}

struct PolicyPage {
    category: Category,
    error: Option<String>,
    list: List<Policy>,
}

fn policy_page(category: Category, ctx: &Ctx) -> Box<dyn Page> {
    let current = ctx.settings.screening_policy(category);
    let rows = [
        (
            Policy::Inspect,
            t("You can approve the update after inspecting its reports."),
        ),
        (Policy::Defer, t("The update waits for a clean scan.")),
        (
            Policy::Block,
            t("Installation stays blocked while this category applies."),
        ),
    ]
    .into_iter()
    .map(|(policy, description)| Row::new(policy, policy.label()).note(description))
    .collect();
    let mut list = List::new(rows);
    list.markable = true;
    list.marked.insert(current);
    list.focus(&current);
    Box::new(PolicyPage {
        category,
        list,
        error: None,
    })
}

impl Page for PolicyPage {
    fn title(&self) -> String {
        self.category.label().into()
    }

    fn draw(&mut self, area: Rect, buf: &mut Buffer, ctx: &mut Ctx) {
        let mut area = area;
        if let Some(error) = &self.error {
            let label = tf("state.yaml not saved: {error}", &[("error", error)]);
            crate::ui::draw::put(
                buf,
                area.x,
                area.y,
                &label,
                area.width,
                ctx.style.tone(Tone::Error),
            );
            area.y += u16::from(area.height != 0);
            area.height = area.height.saturating_sub(1);
        }
        self.list.draw(area, buf, ctx);
    }

    fn key(&mut self, key: Key, ctx: &mut Ctx) -> Flow {
        match self.list.key(key) {
            Picked::Open(policy) => {
                let previous = ctx.settings.screening_policy(self.category);
                if policy != previous {
                    ctx.settings.set_screening_policy(self.category, policy);
                    if ctx.settings.aur_screening
                        && let Some(pending) = ctx.shared.updates.ready()
                    {
                        match State::try_update(|s| {
                            s.apply_policies(&pending.screens, &ctx.settings)
                        }) {
                            Ok(state) => {
                                ctx.state.aur_deferrals = state.aur_deferrals;
                                ctx.state.aur_trust = state.aur_trust;
                            }
                            Err(e) => {
                                ctx.settings.set_screening_policy(self.category, previous);
                                self.error = Some(e.to_string());
                                return Flow::Stay;
                            }
                        }
                    }
                    ctx.save_settings();
                }
                Flow::Pop
            }
            Picked::Used => Flow::Stay,
            Picked::Ignored => Flow::Ignored,
        }
    }

    fn hints(&self, _: &Ctx) -> Vec<(&'static str, Does)> {
        vec![("↑↓", Does::Choose), ("⏎", Does::Use), ("esc", Does::Back)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::app::tests::{app, open as push, press, screen};

    #[test]
    fn choose_sources_and_set_policies_on_the_screening_page() {
        let (mut app, mut term) = app();
        let pages = Target::AurScreening.open(&mut app.ctx);
        assert_eq!(pages.len(), 2);
        for page in pages {
            push(&mut app, page);
        }
        let shown = screen(&mut app, &mut term);
        for source in Scanner::ALL {
            assert!(shown.contains(source.label()), "{shown}");
        }
        assert!(shown.contains("Always blocked"), "{shown}");
        press(&mut app, &[Key::Enter]);
        assert!(app.ctx.settings.aur_screening);
        press(&mut app, &[Key::Down, Key::Enter]);
        assert!(!app.ctx.settings.scanner_enabled(Scanner::ALL[0]));
        for _ in 0..Scanner::ALL.len() + 1 {
            press(&mut app, &[Key::Down]);
        }
        press(&mut app, &[Key::Enter]);
        let shown = screen(&mut app, &mut term);
        assert!(
            shown.contains("The update waits for a clean scan."),
            "{shown}"
        );
        press(&mut app, &[Key::Down, Key::Enter]);
        assert_eq!(
            app.ctx.settings.screening_policy(Category::Minor),
            Policy::Defer
        );
        press(&mut app, &[Key::End, Key::Enter]);
        assert_eq!(
            app.ctx.settings.screening_policy(Category::Malicious),
            Policy::Block
        );
        assert!(screen(&mut app, &mut term).contains("Scan sources"));
        press(&mut app, &[Key::Home, Key::Enter]);
        assert!(!app.ctx.settings.aur_screening);
    }
}
