---
title: Create a threat model
description: Review source code and design documents together to identify trust boundaries, threats, and missing controls.
---

# Create a threat model

Use a threat model to examine entry points, trust boundaries, sensitive data, and security controls. Threatlint can review the implementation alongside supporting design documents.

## Before you begin

- Open a repository in the [Workbench](workbench.md).
- Select and configure a [model provider](model-providers.md).
- Decide which system, change, or security question the review should cover.
- Check that you are permitted to share the selected code and documents with that provider.

## Run the review

1. Choose **Model a system** in the Workbench.
2. Select the source revision. Describe the system's users, important data, and the security question you want reviewed.
3. Use **Add supporting docs** for relevant design inputs, such as an architecture description, data-flow diagram, API specification, or deployment notes. Explain assumptions that the source alone cannot establish.
4. Wait for extraction to finish, inspect the inputs, and confirm the selected model before starting the review.
5. Open the completed report and inspect its evidence, assumptions, and coverage.

Check the supported file formats and displayed limits before adding documents. See [Add supporting documents](workbench.md#design-inputs) for input details.

## Review the result

For each threat, check the affected component, prerequisite, impact, and cited source or design evidence. Distinguish a control implemented in code from one described only in a document. Investigate disagreements between the design and implementation.

Treat missing context and unverified assumptions as follow-up work. A generated threat model does not demonstrate that a control has been tested or that all attack paths were covered.

Save or export the report for review with the system owner. Turn confirmed issues into specific remediation tasks, then review the changed code or design again. See [Reports and exports](reports.md) and [Review findings](finding-intelligence.md).
