# Security policy

This project is a security tool. Two kinds of reports matter most:

1. **A vulnerability in the tool itself**, for example: the scanner executing, extracting, following a
   link to, or fetching something from a scanned target; `fetch_page.py` reaching a private or metadata
   address; output that lets scanned content inject terminal control sequences, unmasked secrets or live
   links; a crash or hang on crafted input (denial of service of the scan).
2. **A detection bypass**: content that hides an instruction or a dangerous behaviour from the scanner
   in a way a reader would also miss, especially when it falls inside a family the README says is
   covered.

## How to report

- Use the repository's private vulnerability reporting ("Report a vulnerability" under the Security
  tab) for anything in category 1, and for bypasses that you consider sensitive.
- Ordinary bypasses and false positives are welcome as public issues or pull requests with a test.
- Please include: the smallest input that shows the problem, the command you ran, what you expected,
  and what happened. Build invisible characters with code (`chr(...)`) rather than pasting them.
- Do not include real secrets, personal data or working malware. A harmless marker is enough.

## What to expect

- Reports are acknowledged on a best-effort basis; this is a volunteer project without a response-time
  guarantee.
- A fix for a confirmed issue comes with a regression test. Bypasses that cannot be fixed with a
  reasonable rule are documented as known limitations in the README.
- Credit is given in the changelog unless you ask otherwise.

## Scope notes

- "The scanner did not flag X" is a bypass only if X is hidden, encoded or behaviourally dangerous. The
  scanner is not a classifier of arbitrary bad advice, and the README states that it is not proof of
  safety.
- The canary pages are deliberately harmless. A request to make them carry real payloads is out of scope.
- Supported versions: the latest release on the default branch.
