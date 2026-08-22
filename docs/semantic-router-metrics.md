# Semantic Router Measurements

The generated semantic router is a navigation aid, not runtime authority. These
measurements compare the last manually maintained semantic index at commit
`a237a9bc462d3a3fef73ff82d295a1d4750f563d` with the manifest-generated router
introduced for issue #114 and extended with the issue #110 operating-mode
route after its specification archival. Issue #98 adds the released common
platform-runtime route, and issue #99 releases the native Windows filesystem
and locking route while keeping the other six Windows routes planned.

## Results

| Measure | Manual index baseline | Generated router | Result |
| --- | ---: | ---: | --- |
| Checked-in router bytes | 29,903 | 17,797 | 40.5% smaller |
| Approximate context tokens (`bytes / 4`) | 7,476 | 4,450 | 40.5% smaller |
| Production-module coverage | 80/97 direct links | 116/116 exact owners | Complete and machine-checked |
| Test-module coverage | 68/80 direct links | 86/86 exact owners | Complete and machine-checked |
| Current-requirement coverage | 0/16 direct links | 22/22 exact owners | Complete and machine-checked |
| Stable machine route IDs | 0 | 23 | Every declared route is addressable |
| Automated routing fixtures | 0/24 | 24/24 | 100% deterministic fixture accuracy |
| Median lookup time | 652.75 microseconds | 127.67 microseconds | 5.11 times faster |
| Example selected-route payload | Not available | 1,014 bytes | One route and its local agent contract |

The baseline coverage rows count direct links in the prose index; the generated
rows count exact manifest owners after the issue #83 merge added repository
assets, issue #110 added progressive operating modes, and issue #98 added the
common platform-runtime implementation. Issue #99 adds four native Windows
modules, their focused test owner, and the Windows filesystem requirement. The
baseline `0/24`
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

The manifest exactly owns 116 production Python modules, 86 test modules, 22
current requirements, 31 configurations, 34 CLI commands, 82
capabilities, 26 connector modules, 11 platform capabilities, and all three
checked-in agent profiles. Adding, deleting, or renaming an owned asset without
updating the manifest fails semantic-router validation.
