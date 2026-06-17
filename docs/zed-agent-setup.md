# Zed Agent Setup

Use the generic editor and agent setup guide:
[agent-environment-setup.md](agent-environment-setup.md).

The Zed-specific notes there cover Zed's launch environment, terminal settings,
and agent terminal tools. The core requirement is not Zed-specific: every
process that calls `via` needs `via` and the provider CLI, such as `op`, on
`PATH`, and 1Password desktop app CLI integration should handle cross-process
auth.
