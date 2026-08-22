# Semantic Router Measurements

The generated semantic router is a navigation aid, not runtime authority. These
measurements compare the last manually maintained semantic index at commit
`a237a9bc462d3a3fef73ff82d295a1d4750f563d` with the manifest-generated router
introduced for issue #114 and extended with the issue #110 operating-mode
route after its specification archival. Issue #98 adds the released common
platform-runtime route, and issue #99 releases the native Windows filesystem
and locking route. Issue #100 releases the native Windows atomic-state route
while keeping the other five Windows routes planned.

## Results

| Measure | Manual index baseline | Generated router | Result |
| --- | ---: | ---: | --- |
| Checked-in router bytes | 29,903 | 18,555 | 37.9% smaller |
| Approximate context tokens (`bytes / 4`) | 7,476 | 4,639 | 37.9% smaller |
| Production-module coverage | 80/97 direct links | 118/118 exact owners | Complete and machine-checked |
| Test-module coverage | 68/80 direct links | 88/88 exact owners | Complete and machine-checked |
| Current-requirement coverage | 0/16 direct links | 24/24 exact owners | Complete and machine-checked |
| Stable machine route IDs | 0 | 23 | Every declared route is addressable |
| Automated routing fixtures | 0/24 | 24/24 | 100% deterministic fixture accuracy |
| Median lookup time | 652.75 microseconds | 126.05 microseconds | 5.18 times faster |
| Example selected-route payload | Not available | 1,014 bytes | One route and its local agent contract |

The baseline coverage rows count direct links in the prose index; the generated
rows count exact manifest owners after the issue #83 merge added repository
assets, issue #110 added progressive operating modes, and issue #98 added the
common platform-runtime implementation. Issue #99 adds the native Windows
filesystem slice; issue #100 adds atomic-state implementation, verification,
and current-requirement ownership. Intervening archived work is also reflected
in the live exact-owner totals. The baseline `0/24`
records that the prose index did not expose a
deterministic machine route-ID operation. It does not claim that a human reader
would choose the wrong document. Timing is a local development measurement and
is not a release threshold; exact ownership, lifecycle, topology, and routing-
fixture validation are the release gates.

## Method

The baseline measured the previous `docs/semantic-index.md` byte count, used a
bounded in-memory linear scan of its route headings and aliases, and attempted
the same 24 manifest routing fixtures without a stable route-ID interface. The
generated result comes from:

```bash
python3 scripts/semantic_router.py metrics
python3 scripts/semantic_router.py route "semantic router topology"
python3 scripts/semantic_router.py changes HEAD
```

The metrics command parses the bounded TOML manifest, verifies all 24 routing
fixtures, and reports the median of 11 repeated in-process route-selection
batches. This is bounded route-selection latency, not end-to-end task duration.
The route command emits only the selected route and its selected agent's local
contract; it does not emit sibling profiles or the complete manifest. The
changes command maps one bounded Git path inventory to exact route contracts
without reading file contents.

## Coverage

The manifest exactly owns 118 production Python modules, 88 test modules, 24
current requirements, 31 configurations, 35 CLI commands, 82
capabilities, 26 connector modules, 11 platform capabilities, and all three
checked-in agent profiles. Adding, deleting, or renaming an owned asset without
updating the manifest fails semantic-router validation.
