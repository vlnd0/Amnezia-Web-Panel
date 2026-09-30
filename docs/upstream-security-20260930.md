# Security maintenance from upstream v1.7.0

Ports upstream 553f419 authentication, CAPTCHA, share authorization, backup
validation, SSH staging and Telemt shell quoting. SMTP delivery, public
endpoints and locale rewrites are separate features and are not included.
The successful sudo-upload chmod command is quoted too.

Existing Bearer tokens and bot admin-session cookies retain their formats.
Disabled or record-only panel accounts lose session access immediately.
Share URLs remain stable; password-protected shares require reauthentication
after password changes. CAPTCHA challenges expire after five minutes and
are single-use. Its bounded in-memory store requires one application process;
multiple workers need a shared store with atomic consumption.

Preserve the existing DATA_FILE, volume and SECRET_KEY at deployment. No node
reinstall, peer rewrite or key migration is needed. Updated dependencies are
tested in the production Python Docker image. Paramiko remains at 3.5.1;
this maintenance does not claim a complete dependency security audit.
