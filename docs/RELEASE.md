# Pro release checklist

- Canonical identity: `gracewell-security-suite-pro/gracewell-security-suite-pro.php`.
- Bootstrap version and readme stable tag: 1.0.0.
- Update URI points to the GitHub repository, preventing accidental WordPress.org name-based updates; this is not an automatic GitHub updater.
- Released Free code provides the metadata convention and dedicated site-salt crypto scheme. Pro additionally accepts previous Pro auth-salt ciphertext and both recovery verifier formats.
- Deactivate the previous edition before activation. Pro preserves the `gwqsh_` database and metadata namespace, and stops early if another known edition is active.
- Backup codes continue to be consumed atomically. New Pro recovery verifiers explicitly identify the site-salt scheme.
- Pro uninstall leaves shared data and maintenance alone when another edition is active. Free's uninstaller is unchanged; keep data removal disabled before deleting it.
- Activation honors plugin master status for upload protection, matching Free. Deactivation clears Pro maintenance hooks and removes its managed Guardian while preserving data.
- ZIP contains a single canonical root; build tools and fixtures are omitted.
- Free-plugin sources are reference only and must remain unchanged.

References: [WordPress plugin headers](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/), [activation and deactivation](https://developer.wordpress.org/plugins/plugin-basics/activation-deactivation-hooks/).
