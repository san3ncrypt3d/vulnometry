# Security

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability) rather than opening a public issue.

## What Vulnometry does with your data

Worth stating plainly, because this tool reads security findings:

- **Your inventory never leaves your machine.** `vulnometry.yaml` is read locally and
  used only for scoring. It is not sent anywhere.
- **Only CVE identifiers go over the network.** Vulnometry queries the public feeds
  with CVE ids, package names and versions. Hostnames, asset names, owners and
  business units from your scanner exports stay local.
- **The cache holds public feed responses only**, in a SQLite file under your
  state directory. Delete it with `vulnometry cache --clear`.
- **`vulnometry ask` is the exception.** That command sends your question, and the
  action results it retrieves, to whichever model provider you selected. If your
  question or inventory is sensitive, use a local model (`--model ollama:...`)
  or skip the AI surface entirely; every other command works without it.
- **The HTTP surface binds to 127.0.0.1 by default.** It has no authentication.
  Do not expose it to a network without putting something in front of it.

## Supply chain

Runtime dependencies are deliberately few: `httpx`, `rich`, `openpyxl`, `PyYAML`.
Bedrock and the HTTP service are optional extras so that most installs pull
neither `boto3` nor `fastapi`.
