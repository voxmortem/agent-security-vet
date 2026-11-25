# Manual vetting checklist (Mode A)

The scanner finds shapes. This list is for what only a reader can judge. Go through it after the scan,
with the files open. Answer each item with "checked: <what you saw>" or "not checked: <why>".

## 1. Provenance

- [ ] Where did it come from (URL, registry, person)? Is that the publisher's real home, or a fork, a
      mirror, a re-upload under a similar name?
- [ ] Compare the name letter by letter with the one you expected (extra hyphen, swapped letters, a
      different owner with the same repository name, a look-alike character).
- [ ] Is the exact version pinned (commit hash, tag plus hash, exact package version)? "latest" and a
      branch name are moving targets.
- [ ] Age and history: first commit, number of contributors, sudden ownership change, a burst of
      unrelated changes just before a release.
- [ ] License present and compatible with the intended use.
- [ ] Does the description match the size? A "formatting helper" with network code and 40 files is a
      mismatch worth explaining.

## 2. Everything that runs without being asked

For each item: what runs, when, with which rights, and can it reach the network?

- [ ] Hooks: in settings files, in `hooks/hooks.json`, in plugin manifests, in skill or agent
      frontmatter. Read the command and the script it points to.
- [ ] Load-time shell commands inside skill or command Markdown (an exclamation mark followed by a
      back-quoted command, or a fenced block marked with an exclamation mark). They run before the model
      reads the text.
- [ ] MCP servers: the start command and its arguments, the package it pulls, the URL it connects to,
      which environment variables and headers it receives.
- [ ] Plugin extras: executables placed on the shell path, background monitors, language servers.
- [ ] Install and build steps: package lifecycle scripts, `setup.py`, custom build back ends, `.pth`
      files, container build files, dev-container commands (one of them runs on the host).
- [ ] Editor and tool auto-run files: tasks that run when a folder opens, direnv files, git hooks and
      hook managers, wrapper properties that download a build tool.
- [ ] A copied `.git` directory: its `config` and `hooks` can execute commands. Prefer a fresh clone.

Hooks and network MCP servers always go to the user for an explicit decision.

## 3. What the instructions ask the agent to do

Read every instruction file end to end, including comments and collapsed sections.

- [ ] Does any step send data out (upload, webhook, issue comment, e-mail, image URL with parameters)?
      Is the destination the service the skill is about?
- [ ] Does it ask the agent to read credentials, browser data, shell history, other projects, or the
      agent's own configuration and memory files?
- [ ] Does it ask the agent to change its own configuration, memory or instruction files, or to register
      tools, so that the effect outlives the task?
- [ ] Does it lower the guard: skip confirmations, approve prompts automatically, widen allow rules,
      turn off the sandbox, hide output from the user?
- [ ] Does it pull instructions or code from a URL at run time? Then what you reviewed is not what will
      run next week.
- [ ] Is the trigger description honest? A description that claims every request, or priority over other
      skills, is asking for more context share than the task needs.
- [ ] Tools granted in frontmatter: is each one needed? Unrestricted shell access is a decision for the user.
- [ ] Do the examples contain real-looking secrets, internal host names or personal data?

## 4. Code

- [ ] Read each script the instructions mention, top to bottom. Follow imports into local modules.
- [ ] Any network call: where to, what is sent, is the host fixed or built at run time?
- [ ] Any process start: is the command a fixed list or a string assembled from input?
- [ ] Any decode, decompress or dynamic evaluation: what does the decoded content turn out to be?
- [ ] File access outside the working folder; deletion; permission changes.
- [ ] Minified, packed or compiled files: where is the readable source, and does a checksum tie the two
      together? If not, treat the file as unreviewed.
- [ ] Dependencies: exact versions, registry only, no install-time scripts you have not read.
- [ ] Remove `__pycache__` and other compiled leftovers before install; bytecode can run in place of the
      source you read.

## 5. Scanner findings

- [ ] Every HIGH: open the file, find the line, write one sentence on what it really is.
- [ ] Every MED: read the surrounding paragraph or function.
- [ ] `scan-incomplete`, `scan-truncated`, `decode-budget`, `decode-limit`, `match-limit`, `archive-*`,
      `bin-*`: these mark content the scanner did not or could not inspect. Inspect it another way or
      count it as unknown; until then the verdict is HOLD.
- [ ] "Scan incomplete", "Not scanned" and "repeats not listed" sections of the report are read too.
- [ ] External hosts list: is each host expected for this tool?

## 6. Decision hygiene

- [ ] The verdict follows from what was read, not from the count of findings.
- [ ] Unknowns are listed as unknowns. "Looks fine" is not a finding.
- [ ] The report says which commit was reviewed, so the install can be tied to it.
- [ ] If the user says yes: install the reviewed copy, not a fresh download, and record it in the ledger.
