## Description
Briefly describe the changes, bug fixes, or new rescue engines introduced in this PR.

## Checklist
- [ ] **One-File Rule**: All C code is strictly contained in `shell.c`.
- [ ] **Zero Warnings**: Compiles cleanly with `gcc -Wall -Wextra -std=c99 -pedantic -Os -static`.
- [ ] **Zero Disk Footprint**: Does not write to dotfiles, history, or `/tmp`.
- [ ] **Tests**: Ran `./minish test_suite.sh` and all test suites pass (100%).
- [ ] **Documentation**: Updated both `README.md` and `MANUAL.md`.
