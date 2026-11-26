# Design decisions

## Design system

The reference is the design mock, "Network diagnosis · Incident workspace" (dark). Follow it; don't
introduce another house style. Tokens in `src/app/globals.css` are sampled from the mock's pixels; the light
theme is derived with the same roles.

| Role | Dark | Notes |
| --- | --- | --- |
| Page / sidebar / chrome / agent panel | `#17191d` / `#1c1f25` / `#202329` / `#1d2026` | Plain, no gradients |
| Card / raised card / sunken field | `#1b1e24` / `#22262e` / `#16181d` | Edges are a hairline ring in the shadow stack |
| Ink steps | `#f0f2f7`, `#c6cdd9`, `#b9bcc7`, `#a0aabd`, `#858b98` | |
| Accent | `#9ab9fe` text and indicators, `#335bc8` the primary button | One primary action per view |
| Meaning | amber `#f4be7f`, green `#8ac5aa`, red `#f2a3a3` | Colour by meaning only |
| Chart marks | `#6f8fe8` dark, `#2f56c4` light | Validated against each surface with the dataviz palette check |

Type is Inter for the interface and Geist Mono for readings and identifiers, as in the mock. Icons are
Lucide outlines, as in the mock, and each one depicts its label.

## Behaviour

Controls come from ui-sdk (`@ui-sdk/react`, pinned beta): Dialog, Menu, Popover, Select, Tabs, Tooltip,
Switch, SegmentedControl, Toggle, Command, Toast, Field, Input, Textarea, Button. The library's documentation
is in `node_modules/@ui-sdk/react/docs/`; for a new primitive, see `core.md` and `rendering.md` there.

## Rules applied

- Changing numbers roll their digits (`components/ui/flow.tsx`).
- Motion uses critically damped springs baked into `linear()` (`--ease-spring`, `--ease-snappy`).
- Stats sharing a comparison sit in one flush bar split by seams, not one card per number.
- The next step is outcome-first copy with one primary button.
- Empty states are the first step itself: the Diagnose page opens on the report form with "start from"
  chips.
- No figure the API doesn't supply: confidence is a level, not a percentage, and there are no sparklines
  without a time series.
