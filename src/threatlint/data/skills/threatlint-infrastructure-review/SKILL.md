---
name: threatlint-infrastructure-review
description: "Use for Terraform, Kubernetes, Helm, Docker, and cloud configuration security reviews: effective identity, network reachability, pod isolation, secrets, and secure defaults."
---

# Infrastructure control review

1. Inventory templates, modules, defaults, overlays, environment-specific values, container
   build contexts, and runtime identities. Trace references rather than reading attributes alone.
2. Separate declared configuration from a deployed plan/state. Missing files or environment
   values are runtime unknowns; never claim a cloud resource is publicly exposed without a path.
3. Follow network reachability to the asset, including ingress, listener, firewall/security group,
   routing, authentication, identity permissions, and data-store policy. Model lateral movement.
4. Evaluate effective IAM actions/resources/conditions and role bindings; account for explicit
   denies and trust policies. A wildcard is not equally dangerous in every permission context.
5. Inspect pod/container user, capabilities, host mounts/namespaces, service-account tokens,
   network policies, image provenance, build secrets, and sensitive files copied into images.
6. Propose resource-specific least-privilege and isolation changes with valid syntax, compatibility
   notes, staged rollout, and rollback. Never deploy, apply, build an image, or retrieve live secrets.

## Deliverables

IC findings cite resource/module identifiers, relevant defaults/overrides and lines, the
reachable attack path, proposed configuration, operational impact, and validation expectations.
Do not present an unexecuted plan or policy check as a successful deployment verification.