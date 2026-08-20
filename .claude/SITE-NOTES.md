# Site source notes

Why the stylesheets and templates in `site/` look the way they do. These were comments
**inside** those files until 2026-08-20, and they were wrong there for the reason the
global rule gives: anything served to a browser as-is is read by anyone who hits View
Source, and 40% of that source was this prose. It is not deleted, because most of it is
load-bearing — a rule whose reason is gone gets "simplified" by the next person and the
bug it was written for comes back.

Not linked from anywhere and not published: `gen_site.py` fails the build on an unlinked
`docs/*.md`, so this lives under `.claude/` with `TECH-DEBT.md`.

## `site/shell.html`

**L32** — `:root{`

========================================================================= SecAudit site shell — head, palette, chrome, nav, footer and the one inline script, shared by every page. A page supplies its own main element from site/page-NAME.html, and any rules only it needs from site/css-NAME.css, appended at the end of this block so an equal-specificity page rule wins. (Both are substituted by name, so do not spell either token in a comment — the substitution is a plain string replace and it does not know what a comment is. This one used to, and the whole landing page rendered inside the stylesheet.) One shell rather than one file per page, for the same reason there is one template for two languages: a second copy of 470 lines of CSS does not stay a copy, and the drift is invisible until the two pages look like two products. Dark-first and cinematic, and every effect here is CSS or a 50-line inline script: no framework, no animation library, no webfont, no CDN, no video. That is not austerity — it is the same claim the product makes. A security tool whose marketing page pulls a third-party bundle in order to look trustworthy has undercut itself before the visitor reads a word. Palette lives on bare :root (dark IS the design); light is the override, handled in all three states so an explicit choice always wins. =========================================================================

**L65** — `--edge:inset 0 1px 0 rgba(255,255,255,.17),inset 0 -1px 0 rgba(255,255,255,.09),`

The bevel on a glass panel, as three inset layers rather than a gradient ring: lit from above, faintly lit from below, flat on the sides. A token because the hover states of the cards and the surface tiles replace `box-shadow` wholesale, and an outline that vanishes under the pointer is the bug that construction invites.

**L103** — `.skip{position:fixed;top:.6rem;left:.6rem;z-index:60;padding:.7rem 1.1rem;border-radius:10px;`

WCAG 2.4.1. Visually absent until focused, and then it is a real control in the top-left rather than something that shifts the layout: a keyboard user should not have to tab the brand, the language segment and eight nav entries before reaching the page, on every page.

**L121** — `main[tabindex="-1"]:focus,main[tabindex="-1"]:focus-visible{outline:none}`

The main element is focusable so the skip link can hand focus to it, and that is the only reason — a ring around the whole page when someone uses it would be the wrong answer to the right problem. `:focus-visible` already excludes programmatic focus in current browsers; this states it rather than relying on it.

**L130** — `.scroll,.code,pre,.tall{scrollbar-width:thin;`

Themed scrollbars, on every element this site actually scrolls. Left to the platform, a horizontal overflow on a dark page renders as the operating system's own bar — an opaque white trough with arrow buttons, drawn across the bottom of a table it has nothing to do with, and the single loudest element on the page. `scrollbar-width`/`scrollbar-color` covers Firefox and the WebKit block covers the rest; both degrade to the platform bar rather than to no bar, which is the right failure: a scroll region whose scrollbar is invisible is a scroll region nobody finds. `stable` gutter so a table does not shift by ten pixels when its bar appears.

**L152** — `.field{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}`

---------- ambient field ------------------------------------------------

**L168** — `/* One clip, not two. The outline used to be a pseudo-element ring: a gradient painted into a`

---------- glass -------------------------------------------------------- The gradient hairline is the whole trick: a 1.4px inset ring painted with a vertical light-to-dark gradient and punched out with mask-composite, so the edge catches light top and bottom the way a real bevel does. THE GRADIENT NEVER REACHES ZERO, and that is the fix rather than a detail. It used to pass through fully transparent across the middle 14%, which put the ring's only lit bands at the very top and the very bottom of the box — exactly where the four corner arcs are. The straight sides went invisible and the corners did not, so a panel read as four bright brackets floating at its corners instead of as one outlined object. A floor of 7.5% keeps the ring continuous all the way round; the bevel still brightens top and bottom, it just no longer has to carry the outline on its own.

**L181** — `.glass{position:relative;background:var(--glass);backdrop-filter:blur(16px) saturate(1.25);`

One clip, not two. The outline used to be a pseudo-element ring: a gradient painted into a 1.4px pad and then hollowed out with `mask-composite: exclude` between a content-box mask and a border-box mask. That construction is exact only where the two clips are axis-aligned — along the four straight edges. At the corners it subtracts one antialiased curve from another, and the difference of two coverage ramps is not the coverage of a ring, which is why the artefact appeared at the four corners and nowhere else. No amount of tuning the gradient reaches it; the geometry is the problem. Inset shadows are painted against the element's own rounded clip, so there is no second curve to subtract and no corner to get wrong. The bevel survives as `--edge`, three layers instead of a gradient. It also drops `mask-composite` from on top of `backdrop-filter` — the most expensive pairing on the page — and twenty lines with it.

**L197** — `.js .rv{opacity:0;transform:translateY(18px);`

---------- motion -------------------------------------------------------- One system, not a set of effects. Everything below shares a single easing curve and a 400–750ms band; what changes between sections is the DIRECTION and the property, chosen to match what the section is showing, never the timing. That is what keeps a page with a dozen different entrances reading as one page — vary the gesture, hold the rhythm. Everything animates transform, opacity or clip-path only, so none of it touches layout, and all of it is switched off under reduced motion in one place at the bottom.

**L212** — `.js h2.rv{opacity:1;transform:none;padding-bottom:.24em;margin-bottom:-.24em;`

Headings are uncovered rather than moved: a mask lifts off the type. A section title that slides in is a title that arrives from somewhere; one that is uncovered was always there. A mask, and not the `clip-path` this used to be — that is a bug fix, not a refactor. A clip changes the element's box, and the box is the thing IntersectionObserver measures: a heading hidden behind `inset(0 0 108% 0)` reports an empty intersection rectangle no matter how much of it is on screen, so its own reveal could never be triggered. Arrive at a section from the menu and that section's title stayed masked for good — a blank band where the heading should be, which is exactly how it looked. Masking hides the same pixels and leaves the geometry alone, so the observer measures the box it is actually being asked about. The mask grows to 128% because the last 28% is the descender room the old `-28%` bottom inset was giving it. The padding/negative-margin pair is what makes that 28% reachable, and it is not optional. `mask-clip` defaults to `border-box`, so the moment an element has a mask its paint is cut to its own box no matter how large the mask image is — and with `line-height: 1.04` the last line's descenders sit *below* that box. Every ğ, y and p on a Turkish heading came out sheared flat. The padding grows the box to contain them and the negative margin gives the space straight back, so nothing below moves: the same trick `h1 .hl` uses two rules up. `mask-clip: no-clip` would also do it and is deliberately not used — Chrome takes it unprefixed but not as `-webkit-mask-clip`, which is the property Safari reads, so it would fix this on one engine and leave it broken on the other.

**L241** — `.js .heroinner h1.lines.rv{opacity:1;transform:none;transition:none}`

A hero headline says the same thing a line at a time. The element itself is pinned still — it would otherwise be doing two gestures at once, the block fading up while its lines rise out of the mask, which is the one thing this system exists to prevent. The `lines` class is carried in the markup rather than inferred, because the neutraliser has to outrank `.js .split>*:first-child .rv` — the landing hero is a split, and the split's rule would otherwise drag the whole heading in from the left as well.

**L248** — `.js h1.lines .hl>span{transform:translateY(calc(100% + .45em));`

110% cleared the old, shorter window. It does not clear this one: the line has to start below a mask that is now `.22em` deeper, and the glyph tops sit above the span's own box by roughly another .15em, so a 110% start left the accents of `Açığı` visible above the mask before the line had moved. Expressed as the window plus a margin rather than as a round percentage, because the percentage is of the span and the distance that matters is the window's.

**L258** — `.kicker::after{content:'';flex:1 1 auto;height:1px;max-width:0;margin-left:.2rem;`

The kicker draws its own rule outward from the label — the smallest possible signal that a new section has begun, and it starts at the accent dot that is already there.

**L265** — `.js .split>*:first-child .rv{transform:translate(-18px,10px)}`

A two-column section moves the way it is built: the argument in from the left, the evidence in from the right, meeting in the middle.

**L272** — `@media (max-width:63.99rem){`

The hero is the one split that stops being a split: below 64rem its two halves stack, and a centred stack that arrives from the sides is moving along an axis the layout no longer has. It rises instead, which is what every other stacked thing on the page does.

**L288** — `.js .chip{opacity:1;transform:none;transition:none}`

These two carry their own delays rather than `--i`, so the universal duration reset below does not reach them — without this the finding's chips still arrived a second and a half late, instantly but late, which is the wait without the animation that justified it.

**L299** — `/* At the top of the page the bar is nothing at all — the brand and the language sit directly on`

---------- top bar ------------------------------------------------------- Two elements, not one: the bar is the banner (brand and language), and the navigation is the capsule below, which has to live outside the bar for the reason spelled out on `.navpillwrap`. Separating them also gets the semantics right — a `<header>` that holds a `<nav>` inside it was one element doing two jobs.

**L305** — `.topbar{position:sticky;top:0;z-index:40;background:transparent;`

At the top of the page the bar is nothing at all — the brand and the language sit directly on the hero, and the capsule brings its own glass. It only becomes a surface once there is content passing underneath it that needs separating. A bar that is opaque before anything has scrolled is a band of chrome across the first thing anyone sees. The separator is a gradient hairline that fades out at both ends rather than a rule drawn edge to edge — the same treatment the footer already uses, so the page opens and closes the same way.

**L325** — `.brand svg{height:22px;width:auto;flex:none}`

Height, not width: the mark is portrait (a 24x32 box), so a square 22px would have shrunk the glyph to 16px wide beside a 22px wordmark. Letting the width follow keeps it cap-height.

**L329** — `/* The capsule is a sibling of the bar, not a child of it, and this is load-bearing rather than`

---------- the capsule -------------------------------------------------- The links live in a glass capsule rather than loose in the bar, because the page is already built out of glass panels and the navigation was the one part that was not. The capsule earns its shape by doing something a row of links cannot: a single indicator slides to whichever section you are actually in, so the bar answers "where am I" and not only "where can I go". It is the same object at every width. Below the breakpoint it detaches and pins to the bottom of the viewport, in reach of a thumb, and scrolls sideways. That replaces a hamburger — and it replaces nothing, because before this the links simply vanished below 62rem and no menu took their place. A panel that has to trap focus, close on Escape and be labelled is a lot of machinery to get back to where a visible bar already is.

**L342** — `.navpillwrap{position:fixed;top:0;left:0;right:0;height:64px;z-index:45;display:flex;`

The capsule is a sibling of the bar, not a child of it, and this is load-bearing rather than tidy: the bar carries a `backdrop-filter`, and a filtered ancestor becomes the containing block for anything `position:fixed` inside it. Nested, the capsule pinned itself to the bottom of the 64px bar instead of to the bottom of the viewport — on a phone it landed on top of the brand and hid it. Outside, `fixed` means what it says. The wrapper is inert to the pointer so the bar underneath stays clickable, and centring the capsule is the flexbox's job rather than a number that has to be kept equal to the bar's height.

**L361** — `.pillglow{position:absolute;z-index:1;top:.3rem;bottom:.3rem;left:0;width:0;`

The indicator is one element moved by transform, not a background per link: a moved element animates between positions, and six backgrounds cross-fade.

**L369** — `@media (max-width:61.99rem){.navpillwrap{display:none}}`

Not on a phone. The capsule was pinned to the bottom of the viewport there, and at that width it stopped being navigation and became a floating bar that covered the content underneath it on every scroll position — it had to be scrolled sideways to read, it needed 4.6rem of body padding so it would not sit on the footer, and it pushed the way-back-up button up with it. Three accommodations for one control that duplicates what scrolling already does. The page's sections are reachable by scrolling and the site's pages are in the footer, so nothing is lost by removing it; what goes with it is the padding and the button's displacement.

**L378** — `.totop{position:fixed;right:1.1rem;bottom:1.1rem;z-index:46;width:46px;height:46px;`

---------- back to top --------------------------------------------------- Absent until there is something to go back from — it appears once the first screen has been left behind, which is also the point at which the page stops fitting on one. On a phone it sits above the pinned capsule rather than beside it: two floating controls competing for the same corner is how a thumb hits the wrong one. The ring around it is the read position, drawn as the stroke of a circle that closes as the document does. It is not decoration bolted onto a button: the control that takes you back to the start is the natural place to show how far from the start you are, so one object answers both. The script writes a single custom property and the dash offset follows in CSS — no per-frame style thrash, nothing that touches layout.

**L405** — `.totop .ring circle{fill:none;stroke:var(--accent);stroke-width:2;stroke-linecap:round;`

r=22 in a 46 box, so the stroke sits on the button's own edge and reads as the border filling in rather than as a second circle outside it. 2*pi*22 = 138.23.

**L410** — `@media (max-width:61.99rem){.totop{bottom:1.1rem;right:.9rem}}`

5.4rem while the nav capsule was pinned above it on a phone; the capsule is gone at this width now, so the button sits where every other floating control does.

**L414** — `.langseg{display:inline-flex;align-items:center;gap:.1rem;padding:.22rem;`

---------- language ------------------------------------------------------ Both languages, with the open one marked. The previous control was a single link showing the OTHER language — "TR" on the English page — which never said which one you were reading, and read equally well as a label and as a switch. Every page has a counterpart in both languages by construction, so the segment can always offer both.

**L430** — `.btn{display:inline-flex;align-items:center;justify-content:center;text-align:center;gap:.5rem;`

---------- buttons ------------------------------------------------------- No `white-space: nowrap`, which this used to carry. In a `flex-wrap` row a button that does not fit beside its neighbour already moves to its own line, so nowrap only ever decided what happens to a label wider than the whole container — and there it guaranteed the one outcome nobody wants, a page 10px wider than the phone holding it. That is not hypothetical on a bilingual site: "All 6 runs, and what each cost" fits a 390px screen and the Turkish sentence that means the same thing does not. Left to shrink, the label wraps to two lines inside the pill, which is what a button too long for the screen should do.

**L451** — `/* The first screen is one composition and it ends where the screen ends. Before this the hero`

---------- hero ----------------------------------------------------------

**L452** — `/* `.hero .heroinner` rather than `.heroinner`: the element also carries `.split`, which is what`

The first screen is one composition and it ends where the screen ends. Before this the hero was a stack of five things followed by a panel, and on an ordinary laptop the fold landed somewhere inside the panel's code — so the first thing anyone saw was a page cut in half rather than a finished statement. The fix was first to give the statement the whole viewport and start the panel underneath it; the claim and its evidence now sit side by side instead, which is better than either: the promise and the proof are read together rather than one scroll apart, and the fold stops being something to design around. Below 64rem the two stack, which is the old arrangement and the only one a phone has room for. `svh` rather than `vh` so a phone's collapsing address bar does not push it around.

**L461** — `.hero{--pad-b:4.5rem;--chrome:64px;padding:0 0 var(--pad-b);text-align:center}`

`.hero .heroinner` rather than `.heroinner`: the element also carries `.split`, which is what earns it the two-column entrance further down, and `.split`'s own rules are declared later in this file. Equal specificity would hand the columns to whichever came last.

**L465** — `/* A hero that is not a split stays a centred flex column — the benchmark page's is, and its`

The first screen is the hero and nothing else. The arithmetic says so rather than approximating it: the section starts below the fixed bar and ends at its own bottom padding, so subtracting exactly those two from the viewport makes the next section start at the fold instead of 40px above it. Below 62rem the pinned nav capsule floats over the bottom of the viewport too, so it comes out of the same budget — otherwise the hero's last rows sit behind it.

**L470** — `.hero .heroinner{min-height:calc(100vh - var(--chrome) - var(--pad-b));`

A hero that is not a split stays a centred flex column — the benchmark page's is, and its children are the pill, the heading and the buttons directly. Made a grid with centred items they size to max-content, which for the copy column is wider than `.wrap` allows, and the text walks out through the page's own side padding on a phone. Only the split needs a grid.

**L477** — `padding-top:2.5rem;padding-bottom:1.5rem}`

Longhand, deliberately: the shorthand here used to be `2.5rem 0 1.5rem`, which quietly reset the side padding `.wrap` provides, so the hero — alone among the sections — had none. At 390px the lede ran to the very edge of the screen. Only the vertical padding is the hero's business; the horizontal belongs to the wrapper and now stays there.

**L482** — `.hero:has(.heroinner + *) .heroinner{min-height:calc(100vh - var(--chrome));`

…unless something follows the copy column INSIDE the hero. The reservation above exists so the NEXT SECTION lands exactly at the fold, and on two of the four heroes the next thing is not a section: the benchmark page keeps its result matrix in the hero and the install page keeps the four counts and the six surface cards there. The reserved strip then handed itself to that sibling and it peeked in under the note. `:has()` asks the question the arithmetic was assuming an answer to, so neither page needs an override of its own.

**L490** — `.hero .heroinner.split{display:grid;align-content:center;gap:2.6rem}`

The gap belongs to the split too: the benchmark hero's spacing already comes from its elements' own margins, and a row gap on top of those would push it apart twice.

**L493** — `.hero .heroinner.split>*{min-width:0}`

Grid items default to `min-width:auto`, which means a track cannot get narrower than its widest item's min-content — and stacked on a phone both halves share one track, so the demo panel's longest chip was setting the width of the copy above it and pushing the whole column 21px past the page's side padding. The panel already knows how to handle being narrow; it just has to be allowed to be.

**L499** — `.herocopy{display:flex;flex-direction:column;align-items:center}`

The 4.6rem this used to add was the pinned nav capsule's own height plus the body padding that kept it off the footer. Both are gone at this width, so the hero's first screen is the bar and nothing else — leaving the reservation in would crop 4.6rem off every mobile hero to make room for an element that is no longer drawn.

**L504** — `@media (min-width:66rem){`

66rem, not the 64rem the other splits use. Between the two the hero has room for two columns and not enough for what goes in them: the finding's three chips break to a second row and the claim beside them is down to about 390px. Stacked at that width both halves get the full measure, which is the arrangement a narrow laptop was always going to be better served by.

**L510** — `.hero .heroinner.split{grid-template-columns:1fr 1.22fr;gap:3.4rem;align-items:center}`

1.22, up from 1.08: the finding panel is the denser half — a code block, a taint rail and three chips that are one statement — and the claim beside it is capped at 15ch anyway, so the width was going to the column with less to do with it.

**L515** — `.herocopy h1{max-width:15ch;font-size:clamp(2.5rem,4.3vw,3.5rem)}`

Half the width takes the display size down with it — 5.3rem set for a full-width centred line would run three words to the row here. Capped rather than re-clamped against the viewport, because `.wrap` stops growing at 80rem and the column stops with it.

**L523** — `/* `max-width` and no `nowrap`, for the reason spelled out on `.btn`: three segments that refuse`

The eyebrow is three claims, not one sentence, so it is built as three segments divided by hairlines instead of a middot floating in a capsule. The first is a state — open source, right now, with the pulse to say so — and it is tinted to read as one; the two after it are static facts and are left plain. A middot cannot make that distinction and a divider can.

**L527** — `.pill{display:inline-flex;align-items:stretch;max-width:100%;font-size:.75rem;color:var(--muted)`

`max-width` and no `nowrap`, for the reason spelled out on `.btn`: three segments that refuse to wrap add up to a fixed width, and the capsule is centred rather than stretched, so below about 300px it simply hung past both edges of the page. A segment now wraps its own text when there is no room for it, which keeps the one capsule and its dividers instead of breaking the row apart.

**L537** — `.pill .seg:first-child{padding-left:1.05rem}`

The rounded ends eat into the first and last segment's padding, so those two get more of it — otherwise a capsule with one segment sets its text against the curve.

**L541** — `.pill:not(:has(.seg)){padding:.45rem 1.05rem;line-height:1.35}`

And a floor for a capsule whose text was interpolated directly rather than through `segments`. The comparison page did exactly that and drew its border against the glyphs; this stops the next one being a bug that has to be seen to be found.

**L554** — `h1 .hl{display:block;overflow:hidden;padding-bottom:.3em;margin-bottom:-.3em}`

Each line is its own masked window, so the headline is uncovered from below one line at a time rather than sliding in as a block — the same gesture the section titles already use, which is why the page reads as one page. The padding/negative-margin pair gives the descender somewhere to be while it is still below the mask, without moving anything. `.1em` was that room until it was measured, and it was sized against the English headline — whose deepest glyph is the `p` of "proof". Turkish reaches further: `Açığı` carries a `ç` cedilla and a `ğ` descender in the same line, and the mask cut **4.8px of them at 56px**, so the first thing a Turkish reader saw was a headline with its bottom sliced off. Measured with canvas `actualBoundingBoxDescent` rather than by eye, because `getBoundingClientRect` on a text range returns the font's ascent/descent box and reports the same overflow for both languages — including the one that renders correctly. `.3em` covers the measured 0.186em with room for a face whose cedilla hangs lower — which is not hypothetical, because `system-ui` is a different typeface on every platform and this was measured on one of them. It is layout-neutral: the negative margin cancels it, so nothing below the hero moves. The reveal's start position moves with it — a taller window would otherwise show the top of the glyphs before the line has risen, which is the same bug pointing the other way.

**L575** — `.shine{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,`

The second line is set in the face the rest of the site writes code in, and that is the whole effect: the promise is in prose and the thing being handed over is in code. It replaced a gradient sweeping across the type, which had two problems. The visible one was legibility — the ramp ran through `#4a3a2a`, near enough to the page for "you can" to read as a smudge, so the brightest treatment on the page was also its least readable text. The quieter one was that it was decoration: a shine says nothing about what this tool does, and it looped forever underneath a hero whose own entrance is a line rising out of a mask, which is two gestures at once — the single thing the motion system exists to prevent. No animation here at all. `.86em` because a monospace face at the display face's size reads a size larger, and the tighter tracking puts the mono line's colour back near the first line's. Solid `--accent`, so it is theme-aware and there is no gradient stop that can wash out.

**L596** — `#e404:not(.tr) .l-tr,`

The 404 carries both languages because GitHub Pages serves one file for the whole site, but it shows one. It used to show both at once — two headlines stacked, then the same paragraph twice — which reads as a page that could not decide rather than as a page that speaks your language. The address that failed is the cue: under `/tr/` the shell's script adds `.tr` here. English is what a reader gets with no script and no cue, because English is the site's `x-default`. The other language is never more than the button below it, so the guess being wrong costs one click rather than a dead end. The headline's two lines have no classes of their own — `head_lines` marks the second with `lang`, and that is enough to pick either one out. Written as `:not(.tr)` / `.tr` rather than as a blanket hide plus an override, because the elements being switched do not share a display value — the eyebrow is a pill, the paragraphs are blocks — and putting one back would mean naming it here, where it would then be wrong the next time the pill's own display changed. Neither branch touches the visible element.

**L616** — `#e404.tr h1 .shine{font-family:inherit;font-weight:inherit;font-size:inherit;`

The Turkish line is the headline's SECOND line, and the second line is set in the code face and the accent colour — a deliberate contrast when both are on screen, and a different design when it is the only line there. Shown alone it takes the first line's treatment, so the two languages get the same page rather than two.

**L622** — `#e404.tr .b-tr{order:1}`

The reader's own language leads, because the thing they want is that tree's home page. The other button stays beside it: the cue is the address that failed, and it can be wrong.

**L627** — `.panel{margin-top:3.4rem;text-align:left;width:100%}`

---------- panels --------------------------------------------------------

**L640** — `.codewrap{position:relative;padding-left:1.9rem;font-size:.9rem;--lh:2.15em}`

---------- signature 1: the taint rail ----------------------------------- The wire is drawn in the GUTTER, not over the text. An earlier version put an absolutely-positioned SVG path at hard-coded pixel coordinates on top of the code, which cannot be right by construction: the x it needed depends on the width of the text, and that changes with the font, the language and the viewport. It rendered as an orange curve hanging in empty space. Everything here is sized in `em` off the code block's own line-height, so the rail lands on the right two rows in any font and any translation.

**L654** — `.rail{position:absolute;left:.2rem;top:calc(var(--lh)*.5);width:1rem;height:var(--lh);`

Drawn, not hidden-then-drawn: the rail is at full height by default and only starts at zero in a document that has the script to grow it. It used to be `height:0` unconditionally, so with JavaScript off the signature simply never appeared.

**L677** — `.chips{display:flex;flex-wrap:wrap;gap:.4rem;margin:1.3rem 0 0;padding:0;list-style:none}`

The three chips are one statement in three parts — CWE, path, verdict — so they belong on one row wherever the column is wide enough to hold them. They still wrap below that rather than scrolling or truncating: a taint path with an ellipsis in it is not a taint path.

**L681** — `.chip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.72rem;letter-spacing:.015em;`

The displaced state is scoped to `.js` for the reason the script's own comment gives — the page is finished without it. These three chips are the finding: the CWE, the taint path and whether it is refutable. Hidden unconditionally, as they were, a reader without JavaScript got the code and the caption and none of the evidence between them.

**L693** — `section{padding:5rem 0;position:relative;scroll-margin-top:64px}`

---------- sections ------------------------------------------------------

**L706** — `.split>*{min-width:0}`

A grid item's automatic minimum size is its min-content, and a `pre` holding a 70-character URL has a min-content of about 600px — so on a phone the column grew to fit the command instead of the command scrolling inside the column, and the whole page went 715px wide in a 371px viewport. `overflow-x:auto` on the `pre` does not help: the exception applies to the scroll container itself, and the thing being measured is the plain div wrapping it.

**L712** — `@media (min-width:64rem){.split:not(.heroinner){grid-template-columns:1fr 1.2fr;gap:4rem}}`

`:not(.heroinner)` because the hero sets its own columns at its own breakpoint, two rem later than this one. Without the exclusion this rule reached it anyway and the hero spent 64–66rem in a two-column layout its own media query had deliberately declined to give it.

**L716** — `.tail.tail{margin-top:2.6rem}`

Doubled deliberately, and it is a bug fix rather than a flourish. Nearly every list and grid on this site resets its own margin with the `margin` shorthand — `.surfaces`, `.langgrid`, `.stats`, `.miss`, `.reg`, `.famgrid` — and all of them are declared after this rule with the same specificity, so `class="surfaces tail"` silently lost its top margin and the cards sat against the paragraph above them. Three of the six `.tail` elements on the landing page were in that state. `.minor.tail` had to restate the value for exactly this reason; doubling the class here fixes the whole family instead, and `.minor.tail` still wins its own case on source order.

**L726** — `/* `min(21rem, 100%)` rather than `21rem`, and the same everywhere this pattern appears below.`

---------- stats ---------------------------------------------------------

**L727** — `.blocks{display:grid;gap:1.2rem;grid-template-columns:repeat(auto-fit,minmax(min(21rem,100%),1fr`

`min(21rem, 100%)` rather than `21rem`, and the same everywhere this pattern appears below. `minmax(21rem, 1fr)` reads as "at least 21rem, share the rest" but the floor is unconditional: the track stays 336px in a container narrower than 336px, so the panel simply hangs out of the page. At 320px that was 48px of the landing page's widest block sitting past the right edge — and it is invisible in testing right up until someone opens it on a small phone, because every width wide enough to fit the minimum looks perfect. Wrapping the floor in `min()` says what was meant: 21rem when there is room for it, the container when there is not.

**L744** — `.stat{container-type:inline-size}`

The figure sizes to its own cell, not to the viewport. A stat is a monospace number in an auto-fit column, so its width is set by how many characters the measurement happens to have — and that changed under this layout without anything moving: putting both corpora on one scale turned `31.5` into `31.5%`, which is a sixth of a character wider than the lead cell is at the four-across breakpoint, and the number ran into its neighbour at 360px and nowhere else. Clamping to the container rather than patching that one band is what stops the next digit doing it again — `100.0%` is already the widest thing here and an F-score is one carry away from being wider. The plain `font-size` above each clamp is the fallback: a browser that does not know `cqi` drops the whole declaration and keeps it.

**L763** — `.stat{display:flex;flex-direction:column;justify-content:flex-end}`

Two rows that line up across every card, and both halves of that are load-bearing. `.stat b` is 2rem in three cells and 2.8rem in the lead one, so the four numbers sat on four different baselines and their labels started at four different heights — the eye reads that as a broken grid before it reads any of the figures. Reserving the tall row and bottom-aligning inside it puts the numbers on one line; the two-line floor on the label (above) does the same for the captions, including the ones that wrap — `tuzaklarda yanlış pozitif` is two lines in Turkish and one in English, which is how the misalignment differed per language. Done with `justify-content:flex-end` on a stretched grid cell and nothing else. The obvious alternative — a `min-height` on the tall figure with `display:flex` to bottom-align inside it — breaks the lead figure outright: `.stat.big b` paints a gradient through `background-clip:text`, and a flex container clips to its own box rather than to the glyphs of an anonymous item, so 61.1% would have rendered as `color:transparent` over nothing.

**L776** — `.block:has(.stats){display:flex;flex-direction:column}`

And the cards themselves: a stat block pinned to the bottom of its card survives a card whose paragraph is a line longer than its neighbour's, which is the other half of what was crooked here.

**L782** — `.langgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(15rem,100%),1fr));`

---------- language coverage ---------------------------------------------

**L789** — `.track{height:5px;border-radius:99px;background:color-mix(in srgb,var(--ink) 8%,transparent);`

The recall bar is a component, not a language-row detail: the benchmark page draws one per CWE family from the same helper. Scoped to `.langrow` it was styled in one place and inert in the other — a bar that stays at zero width reads as "this scores nothing", which is the worst possible way for a layout bug to fail on a page about measurements.

**L802** — `.reg{list-style:none;margin:0;padding:0}`

---------- register ------------------------------------------------------ A two- or three-column list inside a panel: a label, a value, and on the install page a state chip. It began as the landing page's OpenVEX register and outlived it — the benchmark page's provenance block and the install page's manifest read-outs are the same object.

**L815** — `.term{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.84rem;line-height:2}`

---------- authorization terminal -----------------------------------------

**L832** — `.pr{list-style:none;margin:0;padding:0}`

---------- checklist ------------------------------------------------------ A list of steps with a marker each, used by the install page's release table. The marker is a shape and the state beside it is a word: a green dot and a grey dot are the same dot to a reader who cannot tell them apart.

**L845** — `.fan{position:relative;height:19rem;display:grid;place-items:center}`

---------- evidence pack (fanning documents) --------------------------------

**L853** — `.doc h3{margin:0 0 .3rem;font-size:.86rem;font-weight:650}`

h3 sized like the h4 it replaced: the level is the outline's business, the size is this card's. Both blocks in the section above are h3 too, and they are set larger — the fan is a stack of four small cards and a section-block heading's type would not fit one.

**L861** — `/* Six surfaces, so the grid is 3×2 and 2×3 rather than auto-fit. `auto-fit` fitted five across`

---------- where it runs ----------------------------------------------------

**L862** — `.surfaces{display:grid;grid-template-columns:1fr;gap:1rem;list-style:none;margin:0;padding:0}`

Six surfaces, so the grid is 3×2 and 2×3 rather than auto-fit. `auto-fit` fitted five across at 1440px and left the sixth alone on a row of its own, which reads as an afterthought — and the sixth is the pre-commit hook, the one that runs earliest of all of them.

**L870** — `.surface:hover{transform:translateY(-3px);`

`--edge` first, because this replaces the whole `box-shadow` and the outline is part of it — without it the card loses its edge for exactly as long as the pointer is on it.

**L878** — `.next{display:flex;align-items:center;gap:1.2rem;max-width:34rem;padding:1.15rem 1.3rem;`

---------- the way to the next page ------------------------------------------- The two links on the landing page that leave it. They were pill buttons, which made them identical to the ones that scroll you down the page — the label was the only thing telling you the click cost a page load, and a control like that gets pressed by accident and skipped on purpose. A panel instead, in the same glass as everything around it: where it goes, what is there, and an arrow that leans into the destination under the pointer. The third line is three figures the destination is actually made of, and each of them is derived and gated — so what the card promises cannot drift from the page it promises.

**L890** — `.next:hover{transform:translateY(-3px);`

`--edge` first, for the reason `.surface:hover` gives: this replaces the whole `box-shadow` and the outline is part of it.

**L908** — `@media (hover:none){`

Below the hover breakpoint the arrow never gets a pointer to lean into, so it carries the accent from the start rather than being a grey circle that does nothing.

**L914** — `.miss{list-style:none;margin:0;padding:0}`

---------- what we miss ------------------------------------------------------

**L925** — `.marquee{overflow:hidden;border-top:1px solid var(--line);border-bottom:1px solid var(--line);`

---------- marquee ------------------------------------------------------------

**L934** — `table{width:100%;border-collapse:collapse;font-size:.94rem}`

---------- table ---------------------------------------------------------------

**L943** — `table.grid{font-size:.87rem}`

The denser variant, for a table that carries data rather than eight comparison rows: tabular figures, a tighter cell, and a hover that earns its keep as a reading aid. Shared rather than page-local because the moment a second page wanted a data table, the alternative was a second copy — and a copy of a stylesheet is a copy right up until someone fixes one of them.

**L954** — `table.grid tr.now td{color:var(--ink);font-weight:600;`

The row the page is about. A tint and a rule on the leading edge — never a reordering.

**L959** — `.minor{font-size:1rem;font-weight:650;margin:0 0 1rem;letter-spacing:-.01em}`

A heading below h2 that is not a section of its own. The `.tail` spacing has to be restated here: `.minor`'s shorthand `margin` sets all four sides and it is declared after `.tail`, so `class="minor tail"` silently lost its top margin and the heading sat against the block above it. Two classes beat one, so this composes rather than fighting the order.

**L966** — `pre.sh{background:color-mix(in srgb,var(--bg-3) 90%,transparent);border:1px solid var(--line);`

---------- code / notes -----------------------------------------------------------

**L971** — `.lede code,.sub code,.pfoot code,.note code,.miss .d code{font-size:.88em;color:var(--ink-2);`

Inline code in prose. The copy is written in the same markdown habit as the documents it quotes, and a flag or a path set in the body face reads as a typo. Scoped to the prose containers so the code chips inside components keep their own treatment.

**L976** — `.note{position:relative;padding:1.15rem 1.4rem 1.15rem 1.4rem;color:var(--muted);`

The caveat card. It was a paragraph with a coloured stripe down its left edge and two square corners, which is the shape of a quote and not of a card — and on a page whose whole argument is "read the limits", the limits looked like an aside. Now it is a card in the same family as every other surface here: a hairline ring, a soft ground, one corner radius. The stripe stays but as a short mark at the top-left rather than a full-height rule, so it flags the block without fencing it off.

**L991** — `.finale{padding:4rem 1.5rem;text-align:center;position:relative}`

---------- finale + footer --------------------------------------------------------

**L999** — `footer{position:relative;padding:2.8rem 0;`

---------- footer ------------------------------------------------------------------ One row: the mark, and who made it. It began as two labelled columns, a tagline repeating the hero, a four-line ethics statement and a bottom bar — five blocks of grey text at the point where the reader has already decided — then became three rows, and is now the two ends of one object. Everything the link row pointed at is one click into the repository, and the button that goes there is on every page twice. What went with it is worth knowing rather than rediscovering: the small print carried the only "not affiliated with Anthropic or OWASP" on the site, and the only "defensive use only" outside the landing page's own eyebrow. Neither is stated anywhere else now. If either has to come back, it belongs in this footer as one line under the row above and not as a third block.

**L1017** — `@media (max-width:47.99rem){`

Once the three blocks stop fitting on one line, `space-between` has nothing to distribute and every block falls to the left edge — three stacked items, each a different width, none of them lined up with anything. Centred they read as one signature block, which is what they are: a mark, a list of pages, and a byline.

**L1025** — `.fnav{display:flex;flex-wrap:wrap;gap:.35rem 1.4rem;font-size:.82rem}`

The site's list of pages. In the footer rather than the header because the header capsule is this page's sections — two different questions, and putting them in one control makes both harder to read.

**L1032** — `.credit{display:inline-flex;align-items:center;gap:.36rem;margin:0;color:var(--muted);`

The author's signature. Carried over from FollowLens rather than reinvented: same wording, same heart, same two-beats-then-rest pulse, so the two products sign themselves identically. Scale only — the glyph sits inline in a sentence, and anything that moved it would shift the baseline of the text around it. No capsule around it, which is where this parts company with FollowLens. Beside the brand mark it was a bordered pill next to an unbordered wordmark on the same row — two things given the same job and only one of them boxed, so the smaller of the two was the one asking to be clicked. A signature is a line of text. It reads as one now.

**L1054** — `@media print{`

---------- print --------------------------------------------------------- Not a nicety. Printing this page produced a mostly blank sheet: the reveal system leaves every section it has not seen at `opacity:0`, print renders the document in whatever state it is in, and a reader who printed from the top got the hero and a dozen empty pages. On top of that, browsers drop background colours by default, so the near-white body text was being laid onto white paper — the little that did print was invisible too. So this block does two jobs: put every displaced state back, and invert the palette by redefining the tokens rather than by overriding the rules that use them. External link targets are printed after the link text, because a URL the reader cannot click is a URL they have to be able to type.

**L1075** — `.js .rv,.js h1.lines .hl>span,.js .chip{opacity:1;transform:none;transition:none}`

Every displaced state, undone. The `.js`-scoped rules are the reveal system and the headline's line-by-line entrance; the last two are the code rail and the finding chips, which start at zero height and zero opacity.

**L1085** — `.btn,.btn-1,.btn-2{background:none;color:#000;border:1px solid #888;box-shadow:none}`

The primary button is a filled pill, and filled means a black rectangle across the page with the link's own printed URL sitting inside it in grey. On paper a button is just a link that was styled to look pressable.

**L1089** — `.hero .heroinner{min-height:0;padding:0;display:block}`

The hero fills a viewport on screen and centres in it. Paper has no viewport, and the centring turned into a third of a blank first page.

**L1111** — `<filter id="sa-field">`

`sa-grain` lived here to texture the headline gradient and went out with it. `sa-field` is the ambient background and stays.

**L1144** — `<nav class="fnav" aria-label="{{footer_nav_label}}">{{footer_links}}</nav>`

Every page the build produces, linked from every page. A page nothing links to is a page that does not exist, and the build's link check only ever asked the opposite question — that a link resolves, not that a page is reachable.

**L1154** — `(function () {`

Everything animated here is CSS. This adds the two things CSS cannot do alone: tell a section it has been reached, and count a number up. No library, no external request, and the page is finished without it — `js` is added first, so the displaced states only ever exist in a document that can un-displace them.

**L1190**

0.15 rather than 0, so a section announces itself when a slice of it is genuinely in view

**L1191**

and not when its first pixel crosses the edge. Nothing observed here may hide behind a

**L1192**

clip: a clipped target reports an empty intersection rectangle however much of it is on

**L1193**

screen, and a ratio threshold can then never be met. That was a real defect — section

**L1194** — `}, { rootMargin: '0px 0px -6% 0px', threshold: 0.15 });`

headings used a `clip-path` reveal and never fired when a menu link landed straight on

**L1195** — `}, { rootMargin: '0px 0px -6% 0px', threshold: 0.15 });`

one — and the fix was in the stylesheet, where `h2.rv` now masks instead. Read the note

**L1196** — `}, { rootMargin: '0px 0px -6% 0px', threshold: 0.15 });`

there before giving anything on this list a clip.

**L1203**

The counter writes intermediate values into the element, so for about a second after a stat

**L1204**

block is reached the page states a number that is not the measurement. On screen that is an

**L1205** — `if (window.matchMedia) {`

animation; on paper it is a wrong figure printed under a heading that says the figures are

**L1206** — `if (window.matchMedia) {`

checkable. Snapped back before the print dialog reads the document. The stylesheet handles

**L1207** — `if (window.matchMedia) {`

the rest of printing; this is the one part of it that is not a style.

**L1216** — `if (print.addEventListener) {`

Safari fires no `beforeprint`; the media-query listener is what covers it.

**L1223** — `(function () {`

GitHub Pages serves one `404.html` for the whole site and cannot choose one by path, so the page carries both languages and shows one. The only cue it has is the address that failed: a path under `/tr/` was almost certainly a Turkish reader. This adds the class the stylesheet switches on and makes that reader's own button the primary one. With no script the page stays English, which is the site's `x-default`, and the other language is one button away either way — the cue can be wrong, and being wrong should cost a click rather than a dead end.

**L1240** — `(function () {`

Page chrome that depends on where you are: the bar becomes a surface once something is passing under it, and the way back up appears once there is a way back. Both are pure state toggles — no measurement, no layout read — so they are cheap enough to run on every frame the scroll produces. Kept separate from the capsule below because they belong on every page and the capsule's second job does not.

**L1254** — `if (top) {`

One screen down: far enough that returning is a real journey, near enough that the button

**L1255** — `if (top) {`

is there when the first section has been read.

**L1257** — `var travel = document.documentElement.scrollHeight - window.innerHeight;`

Progress against what is actually scrollable, not against document height — on a page

**L1258** — `var travel = document.documentElement.scrollHeight - window.innerHeight;`

barely taller than the window those differ by a whole viewport and the ring would never

**L1259** — `var travel = document.documentElement.scrollHeight - window.innerHeight;`

close. Guarded so a page that does not scroll reports 0 rather than dividing by zero.

**L1261**

Two conditions, and the second one is why the ring is measured before the toggle rather

**L1262**

than after it. One screen down: far enough that returning is a real journey, near enough

**L1263**

that the button is there when the first section has been read. And gone again in the

**L1264** — `var atEnd = travel > 0 && travel - y < 120;`

last stretch, where the footer carries the same links the button competes with — on a

**L1265** — `var atEnd = travel > 0 && travel - y < 120;`

phone it was a filled circle sitting on top of the byline, which is the one place on the

**L1266** — `var atEnd = travel > 0 && travel - y < 120;`

page where nothing should be covering anything.

**L1280** — `(function () {`

The capsule's indicator. Two jobs, and the second one only exists on a page whose navigation points into itself: put the marker under whichever link is current, and on the landing page move it as you scroll. Everything degrades to a plain row of links without it — the marker is the only thing that needs scripting, and a link that is merely unmarked still works.

**L1301**

Every nav entry is a section of this page — the generator builds the menu per page — so

**L1302** — `var spies = links.filter(function (a) { return a.getAttribute('data-spy'); });`

there is always something to spy on. There used to be a branch here for a page whose nav

**L1303** — `var spies = links.filter(function (a) { return a.getAttribute('data-spy'); });`

held no anchors at all, which is what a sub-page's menu was when it listed the landing

**L1304** — `var spies = links.filter(function (a) { return a.getAttribute('data-spy'); });`

page's sections; that page cannot exist now and the branch went with it.

**L1311** — `var y = window.pageYOffset + 96, found = null;`

The nav is sticky and 64px tall, so "which section am I in" is asked from just below it

**L1312** — `var y = window.pageYOffset + 96, found = null;`

rather than from the top of the viewport — otherwise the marker changes one section late.

**L1317** — `mark(found);`

Above the first section — in the hero — nothing is current, and saying otherwise would

**L1318** — `mark(found);`

mark a section the reader has not reached.

## `site/css-benchmark.css`

**L1** — `/* The four counts the aggregates are computed from. Set apart from the ratios by a`

---------- benchmark page only --------------------------------------------- Appended after the shared block, so an equal-specificity rule here wins. Only what the landing page has no use for: a confusion-matrix strip, the blind-vs-now gap, a family grid that carries a count as well as a bar, and a 62-row table that has to scroll inside its panel instead of stretching the page.

**L7** — `.matrix{margin-top:1.6rem;padding-top:1.4rem;border-top:1px solid var(--line)}`

The four counts the aggregates are computed from. Set apart from the ratios by a rule rather than by a heading — they are the same measurement, read closer.

**L15** — `.gap{display:grid;gap:1.2rem;align-items:center;justify-items:center;`

Blind → now. The whole disclosure in one object: two figures and the distance between them, which is the thing the paragraph is actually about.

**L34** — `.scroll.tall{max-height:34rem;overflow-y:auto}`

Data tables. `table.grid` moved into the shell when the install page wanted one too — a second copy of a stylesheet is a copy right up until someone fixes one of them. What stays here is what only a sixty-two-row table needs: a scroll ceiling and a header that survives it.

**L42** — `/* One column, deliberately, where the landing page's language rows are two: here the ordering`

Families. The landing page's language rows plus a count, because "27.6%" and "229 / 831" are not the same statement and the second one is the honest one.

**L44** — `.famgrid{display:grid;grid-template-columns:1fr;gap:.2rem;max-width:56rem;`

One column, deliberately, where the landing page's language rows are two: here the ordering IS the argument — largest labelled pool first, and the four the tier is worst at are the four at the top. Two columns turn a ranking into a grid you read in the wrong order.

**L59** — `.reg.two li{grid-template-columns:9rem minmax(0,1fr)}`

Provenance rows: a heading and a 71-character digest, shown whole. A digest truncated to fit is a digest nobody can check, which is all it is for.

**L64** — `.reg.two li{grid-template-columns:1fr;gap:.3rem}`

A 9rem label column leaves a hex digest about thirteen characters of width. Stack.

**L73** — `html[lang="tr"] .hero h1{max-width:26ch}`

The Turkish headline needs three more characters than the shared 17ch allows. `Başkasının veri kümesi,` is 23 characters where `Someone else's corpus,` is 22 and the words are longer, so each half of the headline wrapped and a two-line title became four. Scoped by `lang` rather than raised for everyone: the English headline sits correctly at 17ch and widening it there would change a page nobody asked about.

## `site/css-compare.css`

**L1** — `/* The capability table. A tick and a dash are the two loudest characters on the`

---------- comparison page only --------------------------------------------- Appended after the shared block, so an equal-specificity rule here wins. Three things this page needs that no other page does: a table whose cells are ticks and dashes rather than numbers, a quotation that is followed by the reason it is quoted, and a list where each item's name and its explanation belong to each other. The first draft reused `.reg`, which is a label-and-value grid — the note ended up in a narrow right column, seven words wide and twelve lines tall, which is what a layout borrowed from a different question looks like.

**L10** — `.yes{color:var(--ok);font-size:1.05rem}`

The capability table. A tick and a dash are the two loudest characters on the page, so they carry the colour and the rest of the row stays quiet.

**L14** — `.fig{color:var(--accent);font-variant-numeric:tabular-nums;font-size:.86rem;`

The cells that state a figure instead of a tick. Tabular so the two numbers in one cell line up with each other, and accented because they are the only cells a reader can go and verify.

**L21** — `#quotes .reg{display:block}`

Quotation, then why it is here. Stacked, because the note is an argument about the quote and not a value belonging to it.

**L24** — `#quotes .reg li{display:block;padding:1.5rem 1.1rem;border-bottom:1px solid var(--line)}`

Horizontal padding to match the panel's own chrome. Without it the quotations started hard against the panel border while `code.claude.com/docs` sat 1.1rem in, so the two halves of the same card were on two different left edges — the header looked inset and the content looked like it had escaped. `1.1rem` is `.chrome`'s padding, so the first character of a quotation now lines up with the first traffic light above it.

**L35** — `#quotes .gloss{display:block;margin-top:.55rem;padding-left:.9rem;`

The reading, under the words themselves. It is set apart from both lines it sits between — quieter and smaller than the quotation, ruled off from the note below it — because it is neither: the quotation is what Anthropic wrote and the note is what this project argues, and a translation is a third thing that must not be mistaken for either. On the English tree the key is empty and the element is not rendered at all.

**L44** — `.famrow.wide{display:block;padding:1.35rem 0;border-bottom:1px solid var(--line)}`

The four things this is not. Same rhythm as the family rows elsewhere on the site, but carrying a sentence rather than a bar — so the name gets its own line at every width instead of competing with the sentence for one.

**L60** — `.finale{padding:5.5rem 1.5rem}`

The closing card, taller and wider than the shared default, and the two changes belong together. Lowering the heading with a top margin was the wrong instrument: it pushed the whole block down inside a card whose padding had not moved, so the gap above the heading grew to twice the gap under the buttons and the card read as bottom-clipped. Padding does the same job symmetrically — the content block stays centred and the whole card simply has more room. The width is the other half. `.finale h2` is capped at 18ch in the shell, which is right for the English `Install the official plugins. Then install this one.` and wrong for a Turkish sentence of the same meaning: at 18ch it broke into three lines, mid-clause, twice. 26ch lets it fall on its own two sentences.

## `site/css-install.css`

**L1** — `/* The four counts, below the fold rather than in it. Inside `.heroinner` they were a flex item`

---------- install page only ------------------------------------------------- Appended after the shared block, so an equal-specificity rule here wins. Only what the other two pages have no use for: cards that are links rather than statements, a two-column register, a caption above a code block, and the stack of per-client snippets. Everything else on this page — panels, tables, the `.miss` list, `pre.sh` — is the shared vocabulary, which is the point: an install page that looked like a different product would undo the argument the rest of the site is making.

**L9** — `.stats.fourup{max-width:52rem;margin-inline:auto;text-align:center;`

The four counts, below the fold rather than in it. Inside `.heroinner` they were a flex item in a centred column, which sizes to fit-content — the grid then resolved to one track and four stacked numbers ate the whole first screen. Out here they are a row, and the fold stays the claim and the two buttons.

**L16** — `a.surface{display:flex;flex-direction:column;gap:.5rem;color:inherit}`

The six surfaces, as the page's own table of contents. On the landing page these cards state something; here they go somewhere, so the whole card is the target and it says so on hover and on focus rather than only under the pointer. The children already carry `z-index:2`, so the link is the card instead of a layer under it.

**L26** — `.reg.pair li{grid-template-columns:10rem minmax(0,1fr);gap:1rem}`

Two columns, not the register's three: these rows are a label and a value, and the third `auto` track of the shared rule would leave the value hard against it.

**L32** — `.cap{margin:0 0 .6rem;color:var(--faint);font-size:.78rem;line-height:1.6;`

A caption belongs to the block it names, so it sits tight above it — and `.after` is the same caption placed below, for a line that comments on the block rather than labelling it.

**L41** — `.snips{display:grid;gap:1.4rem;grid-template-columns:1fr}`

One snippet per client. A grid rather than a stack because five of them stacked is a page of scrolling for five lines of JSON that differ in one key.

**L45** — `.snips>*{min-width:0}`

Same automatic-minimum-size trap the `.split` columns hit: a one-line JSON config is ~90 characters of unbreakable text, so without this the cell grew to fit it and took the page with it instead of letting the `pre` scroll.

**L51** — `.hint{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;`

The command list reuses `.miss`, which pairs a marker with a title and a line of prose — the same shape a command has. What it does not have is the argument hint, which is neither the name nor the description and reads as a typo in the body face.

**L58** — `.pr .state{margin-left:auto;font-family:ui-monospace,Menlo,Consolas,monospace;`

Release state. `.pr` rows already carry a marker, a label and a right-aligned meta column; all this adds is a state word that is legible without its colour, because a green dot and a grey dot are the same dot to a reader who cannot tell them apart.

## `site/page-404.html`

**L1** — `<main id="top" tabindex="-1">`

`tabindex="-1"` so the skip link actually skips. A fragment link moves the viewport in every browser but only moves keyboard focus if the target can hold it, and a plain `main` cannot: in Firefox and Safari the next Tab used to continue from the header, landing the reader back in the navigation they had just asked to jump over.

**L7** — `<section class="hero" id="e404">`

One page for both languages, because GitHub Pages serves a single `404.html` for the whole site and cannot choose one by path: `/tr/typo/` and `/typo/` both land here. Every link is root-absolute for the same reason — the file is served at whatever address failed, so a relative href would resolve against a path that does not exist. The one language cue available is that address, and it is read in the shell's script rather than here: a path under `/tr/` was almost certainly a Turkish reader. Both halves are in the markup and the stylesheet shows one — a page that prints the same paragraph twice reads as one that could not decide which language it is in. English is what shows with no script, because it is the site's `x-default`, and the other language is one button away either way.

## `site/page-benchmark.html`

**L1** — `<main id="top" tabindex="-1">`

`tabindex="-1"` so the skip link actually skips. A fragment link moves the viewport in every browser but only moves keyboard focus if the target can hold it, and a plain `main` cannot: in Firefox and Safari the next Tab used to continue from the header, landing the reader back in the navigation they had just asked to jump over.

**L135** — `<section class="sep" id="javascript">`

The second external number. It gets a section on this page rather than a page of its own because a reader who has just read a Python figure is exactly the reader who has to be told it is a Python figure — and because the two are not comparable, so putting them side by side as peers would be the overstatement this page exists to prevent.

## `site/page-compare.html`

**L1** — `<main id="top" tabindex="-1">`

`tabindex="-1"` so the skip link actually skips — same reasoning as every other page here.

## `site/page-index.html`

**L1** — `<main id="top" tabindex="-1">`

`tabindex="-1"` so the skip link actually skips. A fragment link moves the viewport in every browser but only moves keyboard focus if the target can hold it, and a plain `main` cannot: in Firefox and Safari the next Tab used to continue from the header, landing the reader back in the navigation they had just asked to jump over.

**L44** — `<section class="sep" id="what">`

First, because everything below it argues about a property of the tool — the score, the gate, the evidence pack, the limits — and every one of those arguments assumes the reader already knows what the tool does. This section is the only one on the page that takes no position: what you type, what runs, what comes back.

**L66** — `<ul class="stats">`

Percentages, not the raw forms the two scorers happen to emit. The benchmark page keeps those, because it is a mirror of the benchmark's tables; this panel sits beside the fixture panel below and the comparison between them is the section.

**L173** — `{{install_next}}`

Built without `rv`: the column around it already reveals, and inside a `.split` the entrance carries a horizontal offset, so a full-width child pinned to the right-hand column starts 18px outside it and puts a scrollbar on the page until the reveal lands. `next_page(..., reveal=False)` in the generator is that decision.

## `site/page-install.html`

**L1** — `<main id="top" tabindex="-1">`

`tabindex="-1"` so the skip link actually skips. A fragment link moves the viewport in every browser but only moves keyboard focus if the target can hold it, and a plain `main` cannot: in Firefox and Safari the next Tab used to continue from the header, landing the reader back in the navigation they had just asked to jump over.


---

## Later notes

Added after the comments were moved out of `site/`. Same rule: the reasoning lives here, the
stylesheet stays bare.

### `site/shell.html` — `.stat`, the figure rows

`justify-content:flex-end` was wrong and had to go. It bottom-aligned each cell, so a stat whose
label wrapped to two lines pushed its **number** upward — the four figures in a row sat at four
different heights, which is what a reader notices first. `min-height:2.4em` on the label was meant
to prevent that by reserving two lines, and it under-reserved: the label inherits `line-height:1.6`
from the body, so two lines need `3.2em`.

Now: `justify-content:flex-start` aligns every number to the top of its cell, and the label carries
its own `line-height:1.35` with a matching `min-height:2.7em`, so one-line and two-line labels
occupy identical space and the cards below them stay level.

`.stats:has(.big) .stat b{min-height:min(2.8rem,32cqi)}` is the third piece. A row containing the
emphasised figure — `.stat.big`, set at `2.8rem` against the others' `2rem` — had its labels 7px
out of line, because the taller number pushed its own label down. Reserving the big number's height
for every number box in that row puts the labels back on one line. The reserve uses the same
`min(2.8rem,32cqi)` expression as the font size, so it tracks the figure when the container
narrows instead of stranding dead space under it.

Verified by measurement rather than by eye: `numSpread` and `labSpread` are 0 for all three rows on
the landing page, and an alignment audit over every page in both languages — comparing the first
text element of each same-class sibling on a shared visual row — reports nothing above 2px.
