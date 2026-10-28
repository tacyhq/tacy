# Security policy

If you find a weakness in Tacy, please tell us privately. If you follow this policy, we'll treat your research as authorized and won't take legal action against you. The full policy is at https://tacy.io/security.

## How to report

- Use GitHub's private vulnerability reporting ("Report a vulnerability" under this repository's Security tab), or email security@tacy.io.
- Say what you found, how to reproduce it, and what someone could do with it. A short proof of concept helps.
- Please don't open a public issue or pull request for a vulnerability.

We aim to reply within five working days and to keep you updated until it's fixed.

## Scope

- The code in this repository: the agent VM, the verifier the browser runs, and how releases are built and signed.
- tacy.io and chat.tacy.io, including the app's API.

We most want to hear about anything that lets anyone, us included, read someone's content, get past the browser's hardware check, run an unsigned release, take a key, or get data out without the person's say.

Out of scope: weaknesses in our providers' own services (report those to them, and tell us too if it affects Tacy), denial of service, load testing, spam, social engineering, and automated scanner reports with no shown impact.

## Please

- Test only with accounts you own. Don't access, change or delete other people's data; if you reach it by accident, stop, don't keep it, and tell us.
- Don't degrade the service for others.
- Give us a reasonable time to fix the issue before you publish, normally 90 days. We'll agree a date with you.

## Safe harbor

If you make a good-faith effort to follow this policy, we consider your research authorized. We won't take legal action against you or report you to law enforcement for it. If someone else does, we'll make it known that you acted under this policy.

We don't pay bounties yet. With your permission, we'll thank you by name when the fix ships.
