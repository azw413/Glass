//! Section-map view: coloured strip + legend + virtualised table.
//!
//! Hover state (which section the cursor is on, the cursor x, the
//! interpolated address) lives on `Shell` because the mouse handlers
//! that mutate it are wired via `cx.listener`. The view's renderer
//! and tooltip builder live here as free functions taking `&mut Shell` /
//! `&Shell`.

use std::sync::Arc;

use gpui::{
    div, list, prelude::*, px, rgb, App, Context, SharedString,
};

use crate::scrollbar::list_scrollbar;
use crate::{LoadedBundle, NativeSectionKind, SectionInfo, Shell};

/// Brighten a packed `0xRRGGBB` colour by lifting each channel a
/// quarter of the way toward 0xff. Used for the hover highlight on
/// the section bar so the cursor's cell pops without losing its kind
/// colour.
pub fn brighten(rgb_hex: u32) -> u32 {
    let r = (rgb_hex >> 16) & 0xff;
    let g = (rgb_hex >> 8) & 0xff;
    let b = rgb_hex & 0xff;
    let lift = |c: u32| (c + (0xff - c) / 4).min(0xff);
    (lift(r) << 16) | (lift(g) << 8) | lift(b)
}

/// Linearly blend two packed `0xRRGGBB` colours: `t = 0` → `a`,
/// `t = 1` → `b`.
fn blend(a: u32, b: u32, t: f32) -> u32 {
    let mix = |ca: u32, cb: u32| {
        let v = ca as f32 + (cb as f32 - ca as f32) * t;
        (v.round() as i32).clamp(0, 0xff) as u32
    };
    let r = mix((a >> 16) & 0xff, (b >> 16) & 0xff);
    let g = mix((a >> 8) & 0xff, (b >> 8) & 0xff);
    let bl = mix(a & 0xff, b & 0xff);
    (r << 16) | (g << 8) | bl
}

/// Shade a section's kind-colour toward a warning red, used for
/// likely-encrypted (high-entropy) sections in the overview strip. The
/// cell keeps a trace of its kind colour so the section type stays
/// legible under the red flag.
pub fn entropy_tint(rgb_hex: u32) -> u32 {
    const WARNING_RED: u32 = 0xD0302E;
    blend(rgb_hex, WARNING_RED, 0.55)
}

pub fn render_section_map(
    shell: &mut Shell,
    bundle: &LoadedBundle,
    artifact: &glass_db::ArtifactId,
    panel: gpui::Rgba,
    border: gpui::Rgba,
    fg: gpui::Rgba,
    dim: gpui::Rgba,
    cx: &mut Context<Shell>,
) -> impl IntoElement {
    let empty = Vec::new();
    let sections_ref: &Vec<SectionInfo> =
        bundle.native_sections.get(artifact).unwrap_or(&empty);
    let sections: Arc<Vec<SectionInfo>> = Arc::new(sections_ref.clone());
    shell.ensure_section_table_state(sections.len());
    let hovered = shell.hovered_section;

    // ---- coloured strip --------------------------------------------
    let mut bar_inner = div()
        .size_full()
        .flex()
        .flex_row()
        .rounded_sm()
        .overflow_hidden();
    for (i, sec) in sections.iter().enumerate() {
        let f = sec.fraction.max(0.002);
        let is_hot = hovered == Some(i);
        // Likely-encrypted sections are shaded toward red so they stand
        // out in the overview at a glance.
        let base_colour = if sec.likely_encrypted() {
            entropy_tint(sec.kind.colour())
        } else {
            sec.kind.colour()
        };
        let cell_bg = if is_hot {
            rgb(brighten(base_colour))
        } else {
            rgb(base_colour)
        };
        bar_inner = bar_inner.child(
            div()
                .h_full()
                .w(gpui::relative(f))
                .bg(cell_bg)
                .border_r_1()
                .border_color(border),
        );
    }

    let weak = cx.entity().downgrade();
    let measure = gpui::canvas(
        {
            let weak = weak.clone();
            move |bounds, _window, cx| {
                if let Some(entity) = weak.upgrade() {
                    cx.update_entity(&entity, |shell, cx| {
                        shell.set_section_bar_bounds(bounds, cx);
                    });
                }
            }
        },
        |_, _, _, _| {},
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full();

    let cursor = if let Some(i) = hovered {
        let bar_origin = shell.section_bar_bounds.origin.x;
        let bar_width = shell.section_bar_bounds.size.width;
        let cursor_left_frac = match shell.bar_cursor_x {
            Some(x) if bar_width > px(0.) => {
                ((x - bar_origin) / bar_width).clamp(0., 1.)
            }
            _ => {
                let mut acc_before = 0.0_f32;
                let mut width = 0.0_f32;
                for (j, sec) in sections.iter().enumerate() {
                    let f = sec.fraction.max(0.002);
                    if j < i {
                        acc_before += f;
                    } else if j == i {
                        width = f;
                        break;
                    }
                }
                acc_before + width / 2.0
            }
        };
        Some(
            div()
                .absolute()
                .top_0()
                .h_full()
                .w(px(2.))
                .bg(crate::theme::current().hex.selection_text.rgba())
                .left(gpui::relative(cursor_left_frac)),
        )
    } else {
        None
    };

    let sections_for_move = sections.clone();
    let tooltip = build_section_tooltip(shell, &sections, bundle, artifact, border, fg, dim);

    let bar = div()
        .id("section-map-bar")
        .h(px(28.))
        .w_full()
        .flex_shrink_0()
        .relative()
        .border_1()
        .border_color(border)
        .rounded_sm()
        .child(bar_inner)
        .child(measure)
        .on_mouse_move(cx.listener({
            let sections = sections_for_move.clone();
            move |this, ev: &gpui::MouseMoveEvent, _window, cx| {
                this.on_section_bar_move(ev.position, sections.as_ref(), cx);
            }
        }))
        .on_mouse_down(
            gpui::MouseButton::Left,
            cx.listener({
                let sections = sections_for_move.clone();
                let artifact = artifact.clone();
                move |this, ev: &gpui::MouseDownEvent, _window, cx| {
                    let Some(idx) = this.hovered_section else { return };
                    let Some(sec) = sections.get(idx) else { return };
                    let cursor_addr = this.bar_cursor_addr;
                    let new_tab = ev.modifiers.shift;
                    match sec.kind {
                        NativeSectionKind::Text => {
                            // Snap to the covering function start —
                            // see the long comment in commit a2d0e41.
                            let snap_addr = cursor_addr
                                .and_then(|c| {
                                    this.bundle()
                                        .and_then(|b| b.symbol_maps.get(&artifact))
                                        .and_then(|sm| sm.covering(c))
                                        .map(|s| s.address)
                                })
                                .unwrap_or(sec.address);
                            if new_tab {
                                this.open_listing_force_new_tab(
                                    artifact.clone(),
                                    sec.name.to_string(),
                                    snap_addr,
                                    cx,
                                );
                            } else {
                                this.open_listing_at(
                                    artifact.clone(),
                                    sec.name.to_string(),
                                    snap_addr,
                                    cx,
                                );
                            }
                        }
                        NativeSectionKind::Bss => {}
                        _ => {
                            let addr = cursor_addr.unwrap_or(sec.address);
                            if new_tab {
                                this.open_hex_force_new_tab(
                                    artifact.clone(),
                                    sec.name.to_string(),
                                    addr,
                                    cx,
                                );
                            } else {
                                this.open_hex_in_new_tab(
                                    artifact.clone(),
                                    sec.name.to_string(),
                                    addr,
                                    cx,
                                );
                            }
                        }
                    }
                }
            }),
        )
        // Right-click on a section in the overview bar — Follow /
        // Follow in new tab, matching the listing-link menu.
        .on_mouse_down(
            gpui::MouseButton::Right,
            cx.listener({
                let sections = sections_for_move.clone();
                let artifact = artifact.clone();
                move |this, ev: &gpui::MouseDownEvent, _window, cx| {
                    let Some(idx) = this.hovered_section else { return };
                    let Some(sec) = sections.get(idx) else { return };
                    let pos = ev.position;
                    let display = sec.name.to_string();
                    let cursor_addr = this.bar_cursor_addr;
                    match sec.kind {
                        NativeSectionKind::Text => {
                            let snap_addr = cursor_addr
                                .and_then(|c| {
                                    this.bundle()
                                        .and_then(|b| b.symbol_maps.get(&artifact))
                                        .and_then(|sm| sm.covering(c))
                                        .map(|s| s.address)
                                })
                                .unwrap_or(sec.address);
                            this.open_link_context_menu(
                                artifact.clone(),
                                sec.name.to_string(),
                                snap_addr,
                                false,
                                display,
                                pos,
                                cx,
                            );
                        }
                        NativeSectionKind::Bss => {}
                        _ => {
                            let addr = cursor_addr.unwrap_or(sec.address);
                            this.open_link_context_menu(
                                artifact.clone(),
                                sec.name.to_string(),
                                addr,
                                true,
                                display,
                                pos,
                                cx,
                            );
                        }
                    }
                }
            }),
        )
        .on_hover(cx.listener(|this, &hovered: &bool, _window, cx| {
            if !hovered {
                this.on_section_bar_leave(cx);
            }
        }));
    let bar = match cursor {
        Some(c) => bar.child(c),
        None => bar,
    };

    // ---- legend ----------------------------------------------------
    let mut legend = div()
        .flex()
        .flex_row()
        .gap_4()
        .h(px(20.))
        .flex_shrink_0()
        .text_xs()
        .text_color(dim);
    for k in [
        NativeSectionKind::Text,
        NativeSectionKind::Rodata,
        NativeSectionKind::Data,
        NativeSectionKind::Bss,
        NativeSectionKind::Debug,
        NativeSectionKind::Other,
    ] {
        legend = legend.child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_1()
                .child(div().w(px(10.)).h(px(10.)).bg(rgb(k.colour())))
                .child(SharedString::from(k.label())),
        );
    }

    // ---- table -----------------------------------------------------
    let header = div()
        .h(px(28.))
        .w_full()
        .flex_shrink_0()
        .flex()
        .flex_row()
        .items_center()
        .border_b_1()
        .border_color(border)
        .text_sm()
        .text_color(dim)
        .child(div().w(px(220.)).pl_3().child("name"))
        .child(div().w(px(160.)).child("address"))
        .child(div().w(px(140.)).child("size"))
        .child(div().flex_1().child("kind"));

    let scroll_state = shell.section_table_scroll.clone();
    let row_handle = cx.entity().downgrade();
    let row_artifact = artifact.clone();
    let table_list = list(scroll_state.clone(), {
        let sections = sections.clone();
        let row_handle = row_handle.clone();
        move |index, _window, _cx| {
            let sec = sections[index].clone();
            let is_hot = hovered == Some(index);
            let bg = if is_hot { crate::theme::current().hovers.standard.rgba() } else { gpui::rgba(0x00000000) };
            let hover_handle = row_handle.clone();
            let click_handle = row_handle.clone();
            let click_artifact = row_artifact.clone();
            let click_section_name = sec.name.to_string();
            let click_section_addr = sec.address;
            let is_text = matches!(sec.kind, NativeSectionKind::Text);
            let is_hex_eligible =
                !is_text && !matches!(sec.kind, NativeSectionKind::Bss);
            let is_clickable = is_text || is_hex_eligible;
            div()
                .h(px(26.))
                .w_full()
                .flex()
                .flex_row()
                .items_center()
                .bg(bg)
                .border_b_1()
                .border_color(crate::theme::current().shell.border_alt.rgba())
                .on_mouse_move(move |_ev, _window, cx: &mut App| {
                    if let Some(entity) = hover_handle.upgrade() {
                        cx.update_entity(&entity, |shell, cx| {
                            shell.set_hovered_section_from_table(index, cx);
                        });
                    }
                })
                .when(is_clickable, move |this| {
                    this.cursor_pointer().on_mouse_down(
                        gpui::MouseButton::Left,
                        move |_ev, _window, cx: &mut App| {
                            if let Some(entity) = click_handle.upgrade() {
                                cx.update_entity(&entity, |shell, cx| {
                                    if is_text {
                                        shell.open_listing_in_new_tab(
                                            click_artifact.clone(),
                                            click_section_name.clone(),
                                            click_section_addr,
                                            cx,
                                        );
                                    } else {
                                        shell.open_hex_in_new_tab(
                                            click_artifact.clone(),
                                            click_section_name.clone(),
                                            click_section_addr,
                                            cx,
                                        );
                                    }
                                });
                            }
                        },
                    )
                })
                .child(
                    div()
                        .w(px(220.))
                        .pl_3()
                        .whitespace_nowrap()
                        .overflow_hidden()
                        .child(sec.name.clone()),
                )
                .child(
                    div()
                        .w(px(160.))
                        .text_color(crate::theme::current().shell.text.rgba())
                        .child(format!("0x{:x}", sec.address)),
                )
                .child(
                    div()
                        .w(px(140.))
                        .text_color(crate::theme::current().shell.text.rgba())
                        .child(format!("0x{:x}", sec.size)),
                )
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .flex_row()
                        .items_center()
                        .gap_2()
                        .child(div().w(px(10.)).h(px(10.)).bg(rgb(sec.kind.colour())))
                        .child(SharedString::from(sec.kind.label())),
                )
                .into_any()
        }
    })
    .flex_1();

    let scrollbar = list_scrollbar(&scroll_state, border, dim);
    let table = div()
        .flex_1()
        .min_h_0()
        .flex()
        .flex_col()
        .text_sm()
        .text_color(fg)
        .font_family("Courier New")
        .child(header)
        .child(
            div()
                .flex_1()
                .relative()
                .overflow_hidden()
                .child(div().size_full().flex().flex_col().child(table_list))
                .child(scrollbar),
        );

    let bottom = match tooltip {
        Some(t) => div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_row()
            .gap_3()
            .child(table)
            .child(t),
        None => div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_row()
            .child(table),
    };

    div()
        .flex_1()
        .min_h_0()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .bg(panel)
        .child(bar)
        .child(legend)
        .child(bottom)
}

fn build_section_tooltip(
    shell: &Shell,
    sections: &[SectionInfo],
    bundle: &LoadedBundle,
    artifact: &glass_db::ArtifactId,
    border: gpui::Rgba,
    fg: gpui::Rgba,
    dim: gpui::Rgba,
) -> Option<gpui::AnyElement> {
    let idx = shell.hovered_section?;
    let sec = sections.get(idx)?;
    let end = sec.address + sec.size;
    let empty = glass_arch_arm::SymbolMap::default();
    let symbol_map = bundle.symbol_maps.get(artifact).unwrap_or(&empty);
    let in_section: Vec<&glass_arch_arm::Symbol> =
        symbol_map.in_range(sec.address, end).collect();
    let covering = shell
        .bar_cursor_addr
        .and_then(|addr| symbol_map.covering(addr));

    let mut body = div()
        .w(px(280.))
        .flex_shrink_0()
        .p_3()
        .bg({
            let p = crate::theme::current().shell.bg.rgba();
            gpui::Rgba { r: p.r * 0.8, g: p.g * 0.8, b: p.b * 0.8, a: 1.0 }
        })
        .border_1()
        .border_color(border)
        .rounded_md()
        .flex()
        .flex_col()
        .gap_1()
        .text_xs()
        .text_color(fg);

    body = body.child(
        div()
            .flex()
            .flex_row()
            .items_center()
            .gap_2()
            .child(div().w(px(8.)).h(px(8.)).bg(rgb(sec.kind.colour())))
            .child(
                div()
                    .text_sm()
                    .text_color(crate::theme::current().shell.text_bright.rgba())
                    .child(sec.name.clone()),
            )
            .child(
                div()
                    .text_color(dim)
                    .child(SharedString::from(sec.kind.label())),
            ),
    );
    body = body.child(
        div().text_color(dim).child(format!(
            "0x{:x} – 0x{:x}   ({} bytes)",
            sec.address, end, sec.size,
        )),
    );

    if let Some(addr) = shell.bar_cursor_addr {
        let line = match covering {
            Some(s) => {
                let off = addr - s.address;
                if off == 0 {
                    format!("@ 0x{:x}   {}", addr, s.display_name)
                } else {
                    format!("@ 0x{:x}   {} + 0x{:x}", addr, s.display_name, off)
                }
            }
            None => format!("@ 0x{:x}", addr),
        };
        body = body.child(div().text_color(crate::theme::current().shell.text_bright.rgba()).child(line));
    }

    body = body.child(
        div()
            .text_color(dim)
            .child(format!("{} symbols in section", in_section.len())),
    );
    for sym in in_section.iter().take(5) {
        body = body.child(
            div()
                .flex()
                .flex_row()
                .gap_2()
                .child(
                    div()
                        .w(px(70.))
                        .text_color(dim)
                        .font_family("Courier New")
                        .child(format!("{:08x}", sym.address)),
                )
                .child(
                    div()
                        .flex_1()
                        .whitespace_nowrap()
                        .overflow_hidden()
                        .child(sym.display_name.clone()),
                ),
        );
    }
    if in_section.len() > 5 {
        body = body.child(
            div()
                .text_color(dim)
                .child(format!("… ({} more)", in_section.len() - 5)),
        );
    }

    Some(body.into_any_element())
}

#[cfg(test)]
mod tests {
    use super::{blend, entropy_tint};

    #[test]
    fn blend_endpoints_and_midpoint() {
        assert_eq!(blend(0x000000, 0xFFFFFF, 0.0), 0x000000);
        assert_eq!(blend(0x000000, 0xFFFFFF, 1.0), 0xFFFFFF);
        // Halfway between black and white is mid-grey (0x80 each).
        assert_eq!(blend(0x000000, 0xFFFFFF, 0.5), 0x808080);
    }

    #[test]
    fn entropy_tint_pushes_toward_red() {
        // A neutral grey, once flagged, should read clearly red:
        // red channel well above green/blue.
        let tinted = entropy_tint(0x808080);
        let r = (tinted >> 16) & 0xff;
        let g = (tinted >> 8) & 0xff;
        let b = tinted & 0xff;
        assert!(r > g + 0x20 && r > b + 0x20, "not red enough: {tinted:06x}");
    }
}
