<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright © 2026 Lei Zhou
https://creativecommons.org/licenses/by/4.0/
-->

# A Log Is a Story the Agent Told About Itself

Talk by Lei Zhou at AI Security Engineers Toronto, 19 November 2026.

Slides: [A_Log_Is_a_Story_Lei_Zhou_2026-11-19.pdf](A_Log_Is_a_Story_Lei_Zhou_2026-11-19.pdf) (21 slides)

## What has changed since the talk

The slides are published as given on the night. The project has moved since;
read them with these changes in mind.

- **The software observer no longer signs its records.** Slides 13, 14, 18, 19
  and 20 describe a signed, chained observer stream and a software key. The
  software source's records are now unsigned and their transport is the
  operator's word, so the reader uses that source to agree or say nothing: it
  never contradicts.
- **The TPM-anchored kernel observer is built.** Slides 14, 15 and 20 show it as
  designed, not running. It is now the reference observer, measured on the same
  laptop; see [What the runs showed](../../../README.md#what-the-runs-showed).
- **File access and network egress (slides 17 and 18) are still design
  direction.** The observers built today see process executions only.
- **The live demos (slides 10 to 12) ran on the software observer,** as it was
  that night.

## Licence

[CC BY 4.0](../../../LICENSE-docs)
