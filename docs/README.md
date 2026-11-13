# Documentation

Loose Keys scans a Mac for passwords, keys and tokens stored in plain files,
and says how to deal with each one. To install it, see the
[project README](../README.md). Then pick the guide that answers your question:

- What does a control do, and what do the lists mean?
  [Using the app](usage.md)
- Why didn't Loose Keys find something? Does it check for that kind of
  credential at all?
  [Detection and limits](detection.md)
- How do I run it on the Macs I manage?
  [Deploying to managed Macs](managed.md)

## For contributors

| Topic | Guide | What it covers |
|---|---|---|
| Development | [Repository instructions](../AGENTS.md) | Working rules, safety limits and which checks a change needs. |
| Development | [Standards](development/standards.md) | The detail, reasons and sources behind each rule in AGENTS.md. |
| Testing | [Local checks](testing/local-verification.md) | Every check that runs on the development Mac, and which ones to run before a push. |
| Testing | [The macOS guest](testing/guest.md) | Virtual machine setup and the shipped-bundle check. |
| Testing | [Native helper integration](testing/native-helper-tests.md) | Guest prerequisites, positive and negative controls, and cleanup. |
| Report contract | [JSON report schema](../schema/report-1.schema.json) | The fields an exported report can have. |
