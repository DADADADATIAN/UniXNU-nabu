# Agent notes

Read `README.md`, `board.toml` and `porting.toml` first. The record is the
single truth for porting state; update the owning area's findings/evidence
whenever a covered path changes (the `Porting record` CI enforces this).

- Keep evidence honest: `source`/`host`/`device` kinds and the completion
  levels in the records guide. Device evidence needs the real run command and
  the 40-hex commit that produced it — placeholders are not publishable.
- Never commit Apple firmware, vendor firmware, IPSW contents, ESP/GPT images,
  credentials or device serials. `proprietary-files.txt` documents inputs
  fetched at build time.
- Hardware writes, partitioning, flashing and reboots require explicit
  per-session authorization; repository work never implies device access.
- Builds needing macOS/Xcode run on the project's CI; keep host-only checks
  (record check, static gates) runnable locally.
