# Documentation

For installation and everyday use, start with the [project README](../README.md).

| Topic | Guide | What it covers |
|---|---|---|
| Usage | [Usage and detection limits](usage.md) | App controls, review decisions, supported formats and scan limits. |
| Development | [Repository instructions](../AGENTS.md) | Working rules, safety limits and which checks a change needs. |
| Development | [Standards](development/standards.md) | The detail, reasons and sources behind each rule in AGENTS.md. |
| Testing | [Local checks](testing/local-verification.md) | Every check that runs on the development Mac, and the list before a push. |
| Testing | [The macOS guest](testing/guest.md) | Virtual machine setup, Accessibility grants, and the shipped-bundle and native-helper checks. |
| Testing | [Native helper integration](testing/native-helper-tests.md) | Guest prerequisites, positive and negative controls, and cleanup. |
| Testing | [Power checks](testing/power-tests.md) | Synthetic sleep/wake and Low Power Mode checks, with their limits. |
| Report contract | [JSON report schema](../schema/report-1.schema.json) | The permitted fields of an exported report. |
