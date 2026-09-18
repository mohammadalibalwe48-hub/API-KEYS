/**
 * Shared group colour palette.
 * ---------------------------------------------------------------------
 * The database stores a group colour as one of a fixed set of names
 * (key_groups.color). This module is the single source of truth that turns
 * a name into an OKLCH hue the stylesheet consumes through the
 * `--group-hue` custom property — so a group's identity carries into dots,
 * chips, filter pills and cards without any per-component duplication.
 *
 * It is a separate module so the mapping can be imported without pulling in
 * the whole application.
 *
 * `light-dark()` is used deliberately: the same hue renders at a darker,
 * more saturated lightness in light mode and a lighter one in dark mode, so
 * contrast holds in both themes from one declaration.
 */

/**
 * hue + chroma per colour name. Lightness is fixed by the light-dark pair.
 *
 * Tuned against the cream-and-green palette: `slate` and `teal` are kept
 * near-neutral or cool so they never compete with the mint accent, and
 * warm hues sit at amber and rose with the green gap between them left
 * deliberately empty — that space belongs to the brand.
 */
const GROUP_TONES = {
    slate: { h: 150, c: 0.022 },
    indigo: { h: 278, c: 0.158 },
    rose: { h: 16, c: 0.162 },
    amber: { h: 74, c: 0.148 },
    emerald: { h: 162, c: 0.134 },
    sky: { h: 240, c: 0.138 },
    violet: { h: 302, c: 0.152 },
    teal: { h: 196, c: 0.104 },
};

/** Human labels for the picker and screen-reader text. */
export const GROUP_COLOR_LABELS = {
    slate: 'Slate',
    indigo: 'Indigo',
    rose: 'Rose',
    amber: 'Amber',
    emerald: 'Emerald',
    sky: 'Sky',
    violet: 'Violet',
    teal: 'Teal',
};

/**
 * Build the inline custom-property declaration for a group colour.
 * Returns a string suitable for an element's `style` attribute.
 */
export function groupHueStyle(color) {
    const tone = GROUP_TONES[color] ?? GROUP_TONES.slate;
    return `--group-hue: light-dark(oklch(0.60 ${tone.c} ${tone.h}), oklch(0.75 ${tone.c} ${tone.h}))`;
}