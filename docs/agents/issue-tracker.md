# Issue tracker: Local Markdown

Issues and specs for this repo live as Markdown files in `.scratch/`.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`
- The spec is `.scratch/<feature-slug>/spec.md`
- Implementation issues are one file per ticket at `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`
- Triage state is a `Status:` line near the top of each issue file; use the strings in `docs/agents/triage-labels.md`
- Append conversation history under `## Comments` at the bottom of the issue file

## Publish and fetch

When a skill says “publish to the issue tracker,” create a file under `.scratch/<feature-slug>/`. When it says “fetch the relevant ticket,” read the referenced issue file.

## Wayfinding operations

For `wayfinder`, use `.scratch/<effort>/map.md` as the map and `.scratch/<effort>/issues/NN-<slug>.md` for each child ticket.

- Record ticket type as `Type: research`, `prototype`, `grilling`, or `task`.
- Record ticket state as `Status: claimed` or `Status: resolved`.
- Record dependencies as `Blocked by: NN, NN`. A ticket is unblocked when all listed tickets are resolved.
- Find the frontier by scanning open, unblocked, unclaimed tickets in number order.
- Claim a ticket by saving `Status: claimed` before work begins.
- Resolve a ticket by adding an `## Answer`, setting `Status: resolved`, and adding a brief decision and link to the map.
