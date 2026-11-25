# Hardening a browsing or tool-using agent (Mode C)

Assume the model will sometimes follow hostile text (see [threat-model.md](threat-model.md)). Controls
therefore aim at what a hijacked agent can *reach* and *send*, not at making hijacking impossible.

Each control lists its cost, because a control nobody keeps switched on protects nothing.

## 1. Break the trifecta per task

List every tool the agent has and mark what it contributes:

| Tool or capability | Private data | Untrusted content | Outbound channel |
|---|---|---|---|
| web fetch / search | | yes | yes (the request URL itself) |
| signed-in browser | yes (sessions, mail, drives) | yes | yes |
| desktop control | yes (whatever is on screen) | yes | yes |
| shell | yes (files, environment) | when it reads fetched files | yes (network tools) |
| file read / write | yes | when files came from outside | sometimes (synced folders) |
| each MCP server | depends | tool results are untrusted | depends |
| e-mail, chat, issue trackers | yes | yes (other people write there) | yes |

Rule of thumb: a single session should hold at most two of the three columns. When a task needs all
three, put a human approval between reading and sending.

Cost: more sessions and more hand-offs.

## 2. Controls

### Separate identity for untrusted browsing
- A dedicated browser profile (or a separate browser) with no saved logins, no password manager, no
  payment methods, no sync. The agent's "research" profile should own nothing worth stealing.
- Separate OS user or virtual machine for agents that also run code.
- Cost: you sign in by hand when a task really needs an account.

### Read-only first
- For unknown sites use tools that only retrieve text. Interaction tools (click, type, submit, upload,
  download) stay off until a specific site and action call for them.
- Prefer a tool that returns a summary produced by a separate model call over one that drops the raw
  page into the main context; it narrows, but does not close, the injection path.
- Cost: slower on sites that need interaction.

### Allowlists instead of open access
- Network: named domains for fetch tools and for shell network commands; deny by default where the
  client supports it. An allowlist entry for a site that hosts user content (paste sites, code hosts,
  chat) is an outbound channel, so count it as one.
- Tools: allow the narrow command, not the whole tool. Review allow rules every few weeks; they
  accumulate.
- Cost: prompts for new domains; maintenance.

### No secrets within reach
- Keep API keys, tokens and cloud credentials out of the environment the agent starts in. Start the
  agent from a shell that does not export them; give a task-specific, short-lived, least-privilege
  credential only when a task needs one.
- No credential files in or above the working directory. Check dotfiles, shell history, notebooks and
  old `.env` files.
- Assume anything the agent can read can end up in a URL, a commit, an issue comment or a chat message.
- Cost: a little setup per task.

### Permission mode matched to the content
- Untrusted input (web pages, new repositories, inbound messages): the mode that asks before edits,
  commands and network use.
- Modes that decide without you are for content you wrote or already vetted. A mode that removes prompts
  entirely belongs in a disposable sandbox with no secrets and no network path to anything you care about.
- Cost: more prompts. Reading them is the control.

### Human confirmation for side effects
- Sending, posting, publishing, purchasing, deleting, changing account or security settings, granting
  access, running an installer: each is confirmed by the human, in the chat, with the concrete details
  shown (recipient, amount, file, setting).
- Approval that is claimed inside a page, a file or a tool result is not approval.
- The agent does not answer its own permission dialogs.
- Cost: one sentence of friction per side effect.

### Tool segregation
- Different agents (or sessions) for reading the web and for acting on private systems. Pass results
  between them as plain, reviewed text.
- A sub-agent that reads untrusted content gets no write tools and no secrets; its output is treated as
  untrusted by the caller.
- Cost: orchestration overhead.

### Output-channel controls
- Chat clients that render Markdown can leak data through image URLs. Prefer clients that do not load
  remote images from model output, or that restrict them to trusted hosts.
- Review links before clicking when they were produced after the agent read untrusted content.
- For automated pipelines: scan model output for URLs with long or encoded parameters before it is
  rendered, posted or fetched.
- Cost: plainer output.

### Logging
- Keep a record of tool calls: what was fetched, which commands ran, what was sent. Log events and
  destinations, not page contents or secrets.
- Review after any session that touched untrusted content and something sensitive.
- Cost: storage and a few minutes of reading.

### Kill switch
- Know, before you need it, how to stop the agent at once (interrupt key, closing the session, revoking
  the browser extension, stopping the MCP server process) and how to revoke what it held (sign out
  sessions, rotate keys).
- Cost: none until used.

### Supply-chain hygiene for the agent itself
- Vet skills, plugins and MCP servers with Mode A before install; pin versions; re-vet on update.
- Hooks and network MCP servers only with an explicit decision.
- Open unknown repositories in a client state that does not auto-load project configuration, or vet the
  repository first: project files can define hooks, tool servers and environment overrides.
- Cost: minutes per install.

## 3. Product notes

Feature names and defaults change. Treat this section as a list of things to look up in the current
documentation of your client, not as a specification.

### Claude Code
Checked against the vendor's Security page (November 2026):
- Permission modes decide what runs without asking. The manual mode starts read-only and asks before
  edits and commands; in that mode network commands such as `curl` and `wget` prompt by default. An
  automatic mode delegates the decision to a classifier. Use the manual mode around untrusted content.
- A sandbox for shell commands with filesystem and network isolation exists and is configurable; a
  shell command you approve outside it can still write wherever your account can.
- For most web fetches a separate model call reads the page and the main model receives that answer.
- Opening an untrusted folder shows a trust dialog in interactive sessions, and project MCP servers have
  their own approval; non-interactive runs show neither, so vet a repository before scripting against it.
- The vendor states that it does not security-audit MCP servers and that no system is completely immune.
- Their best-practice list for untrusted content: review commands before approval, avoid piping
  untrusted content to the agent, verify changes to critical files, use virtual machines for scripts and
  tool calls that touch external services.
Source: https://code.claude.com/docs/en/security (Permissions, Sandboxing, MCP and Hooks pages are
linked from it).

### Browser extensions and in-app browser panes
- An extension that drives your everyday browser shares its signed-in sessions. Use a separate profile
  for agent work, grant sites one at a time, and keep banking, mail and admin consoles out of it.
- An in-app pane with its own persistent profile is a profile like any other: what you sign into there,
  the agent can reach.
- Forms, uploads, downloads and consent banners are side effects: confirm them.

### Desktop control ("computer use")
- The trust boundary is your whole desktop: anything on screen can be read, and on-screen text can carry
  instructions. Close what is not needed, grant applications one by one, keep password managers and
  terminals out of reach.
- Do not let the agent follow links from mail, chat or documents without showing you the real address.

### MCP servers
- Tool descriptions and tool results are untrusted input to the model. A remote server can change both
  after you approved it.
- Prefer local servers you can read, pinned to an exact version, started without a shell wrapper, given
  only the credentials for their own service.
- One poisoned server can try to influence how tools from other servers are used. Keep high-value
  servers (mail, source control, payments) in sessions without unvetted servers.
- The protocol's own security guidance asks clients to show the exact start command and obtain consent
  before running a local server:
  https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

## 4. After hardening: measure

Run the canary pages before and after a change ([canary-testing.md](canary-testing.md)). A control that
does not change the result did not address that channel.
