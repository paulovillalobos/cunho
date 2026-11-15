"""The cunho demo: a public page where a wallet scans a QR code and gets a PID or a course certificate.

It is an operator's front end, written the way any operator would write one: it talks to cunho only through its
admin API, with the operator token, and holds no keys and no credential. It issues made-up data about fictional
people only; nothing a visitor types ends up in a credential."""
