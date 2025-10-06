# GMS-AI

## Prowler CLI requirement

Compliance checks depend on the [Prowler CLI](https://github.com/prowler-cloud/prowler).
Ensure the `prowler` command is installed and available in your `PATH` before
running any compliance scripts or scheduled jobs. The application expects
`prowler` version 3.0.0 or newer. Prowler v4 uses the `--regions` flag while
earlier versions rely on `--region`; the scan runner automatically detects and
uses the correct flag for the installed version.

Install via pip:

```bash
pip install prowler
```

For other installation methods, refer to the
[official Prowler installation guide](https://docs.prowler.cloud/en/latest/installation/).
Without the CLI, attempting to run compliance checks will result in a
`FileNotFoundError`.

## Password reset email configuration

The password reset workflow first attempts to send messages through the
Microsoft Graph API. Supplying Azure AD application credentials avoids the
basic SMTP authentication failures that Office365 now blocks by default.

Set one of the following to make the Graph integration available:

* `CLIENT_SECRET` – provide the secret directly via the environment.
* `AZURE_CLIENT_SECRET_PARAMETER` – name of an AWS Systems Manager parameter
  (with decryption enabled) that stores the client secret.
* `AZURE_CLIENT_SECRET_SECRET_ID` – identifier of an AWS Secrets Manager secret
  containing the client secret.

When none of the options above are present the application falls back to SMTP.
If basic authentication is disabled for the tenant, update `MAIL_USERNAME` and
`MAIL_PASSWORD` with a modern app password or configure one of the Graph secret
options instead.
