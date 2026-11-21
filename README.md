# TensorFlow Lite C ARM64 cloud build

Isolated, manual-only GitHub Actions project for building TensorFlow Lite C 2.17.1 for Linux AArch64 and performing offline ABI and inference smoke checks against Capsule-14/15 OTA 44.90 userspaces. This directory is intentionally separate from `standalone-prototype`.

## Scope and safety

- The workflow runs only through `workflow_dispatch`; it does not run on push or pull request.
- It uses the standard `ubuntu-24.04` x86_64 GitHub-hosted runner and exits at preflight if it sees fewer than 4 CPUs, 8 GiB `MemAvailable`, or 10 GiB free disk. These are conservative project guardrails, not measured TensorFlow minima.
- All downloads, Bazel output, extracted OTA files, and the Alice model live in the disposable runner workspace. No hardware is contacted.
- OTA and model files are SHA-256 checked. They are not in the artifact upload allowlist. The smoke test fills Float32, Int8, and Int32 inputs with zeros; for UInt8 it uses the quantization `zero_point` when `scale` is nonzero and zero otherwise. It only checks model load, tensor allocation, invoke, and readable output; it does not evaluate wake-word accuracy or the semantic correctness of test inputs for quantized types.
- QEMU success is reported separately and is not proof of execution on the physical RK3308 Capsule.

## Pinned build inputs

| Input | Pin |
|---|---|
| TensorFlow | tag `v2.17.1`, commit `3c92ac03cab816044f7b18a86eb86aa01a294d95` |
| Bazel | TensorFlow `.bazelversion`, exactly `6.5.0` |
| Target | `--config=elinux_aarch64` |
| Alice model | pinned raw URL from `alice-for-marusia/config/wake-model-download.json`, SHA-256 `481cf6c180d3b5cbebfa6af47b4f9544c631d05b73cecf51fb8363ab7d143f38` |
| Capsule-15 OTA | `https://vcfw.vkcdn.ru/Capsule-15/44.90`, SHA-256 `AA219C810CFE5C0AC9D761832962FF33236E484A377B5076EE3CB1E56347FDE4` |
| Capsule-14 OTA | `https://vcfw.vkcdn.ru/Capsule-14/44.90`, SHA-256 `B13AF88714CFC114F2C6909C6E56A2ECBEFC77D4FB857DF0E78BACFF0A44AD26` |
| `actions/checkout` | full commit `08c6903cd8c0fde910a37f88322edcfb5dd907a8` (`v5.0.0`) |
| `actions/upload-artifact` | full commit `b7c566a772e6b6bfb58ed0dc250532a479d7789f` (`v6.0.0`) |

Bazelisk `v1.29.0` is downloaded as the official amd64 Debian package and checked against its release SHA-256 (`186d78a20e1a64f59ba08987791a989892d142c9d3a9f9cc0c5c35e201f53924`) before extraction into the job workspace. Bazelisk then selects the exact TensorFlow-pinned Bazel version. TensorFlow tag and source `.bazelversion` are checked before the build.

## Build and validation sequence

1. Preflight records runner architecture, CPU, available RAM, and free disk, rejects a low-resource runner before the build downloads begin, and runs ABI-auditor regression tests.
2. Download both official OTA packages, check the existing pinned hashes, extract their SquashFS root filesystems using the pinned `afptool-rs` revision, and validate the RKAF metadata `full_path`. This preparation now occurs before compilation so the exact Capsule root filesystems are available for diagnostics. The extraction logic is shared with the later ABI checks; OTA downloads are not uploaded.
3. Build TensorFlow target `//tensorflow/lite/c:libtensorflowlite_c.so` using the pinned source and unchanged `elinux_aarch64` configuration. Public build logs omit Bazel `--subcommands` and `--verbose_failures`. A later diagnostics step captures CppCompile/CppLink actions and actual compiler/linker evidence privately under the runner workspace, then publishes only a field-allowlisted, redacted toolchain summary. The summary records resolved fields and explicit `NOT RESOLVED` reasons; `-print-prog-name=ld` is reported only as a candidate unless the captured action dry-run proves the invoked linker. Raw action commands, environment values, and raw toolchain reports are not uploaded or printed to workflow logs. Diagnostic collection can remain nonzero when critical facts cannot be proven; this is informational and does not replace the strict ABI gates.
4. Download and hash-check the Alice model, build the tiny C API smoke executable for the same target, then run the strict library and smoke ABI audits against both extracted Capsule userspaces. Separate informational reports capture the exact rootfs `libc.so.6` and `libstdc++.so.6` providers, symbol definitions, and dependency chains for all required GLIBC/GLIBCXX versions. Diagnostic reports do not replace or weaken the strict ABI gates.
5. Run QEMU only after both ELF targets pass both OTA ABI audits. The QEMU step records separate Capsule-15 and Capsule-14 results and still attempts Capsule-14 if the Capsule-15 smoke execution fails.
6. Generate `SHA256SUMS` over the files under `artifacts/` that are included by the workflow upload allowlist (excluding the manifest itself), then upload that allowlist for seven days. Raw aquery and raw toolchain reports are stored outside `artifacts/` in the runner's private workspace and are not included in the manifest or upload.

The checks are separate gates. A build can succeed while ABI or QEMU validation fails; the workflow will still provide the diagnostics and finish with a failed job conclusion when a required gate fails.

TensorFlow 2.17.1 labels the `elinux` configurations experimental in its `.bazelrc`; this project pins and requests the specified target, but this local preparation has not run the cloud build. Treat the first workflow run as validation of the proposed build recipe, not as a pre-certified result.

The ELF script checks `ELF64/AArch64`, resolves transitive `DT_NEEDED`, compares requested GLIBC/GLIBCXX/CXXABI version names against providers, and examines `DT_RPATH`/`DT_RUNPATH` plus the explicitly supplied runtime library path. Absolute RPATH/RUNPATH entries are interpreted inside the extracted Capsule rootfs; `$ORIGIN` follows the resolved loaded object, and an external result is usable only when it remains under an explicitly supplied library directory. Rootfs absolute symlinks are resolved inside the extracted rootfs. Distinct physical providers are ambiguous even when their bytes match; multiple symlink names safely resolving to one physical file count as one provider. Dependencies falling through to unparsed loader cache/config/preload state fail closed. Non-empty glibc-hwcaps/TLS hwcap directories and unsupported `DT_AUDIT`, `DT_FILTER`, `DT_AUXILIARY`, and `DF_1_NODEFLIB` cases also fail closed when default-path resolution is needed. QEMU clears `LD_PRELOAD` and `LD_AUDIT`. This remains a static audit, not a complete glibc loader emulation: it does not model all loader-cache/config semantics or runtime `dlopen()`. A PASS is evidence for this modeled dependency graph, not an ABI guarantee for every runtime environment.

## Artifacts

The workflow uploads only:

- `libtensorflowlite_c.so`;
- ARM64 `tflite_smoke` executable;
- ELF ABI reports for both OTA root filesystems;
- scoped ABI and dependency-chain diagnostics for both OTA root filesystems;
- sanitized compiler/linker toolchain summaries (`toolchain-library-sanitized.txt` and `toolchain-smoke-sanitized.txt`) with selected compiler path/version, target triple, sysroot assessment, search directories, linker candidate/selection evidence, and toolchain repository identities; raw commands and action environment values are omitted;
- library ELF header and file-identification reports;
- SHA-256 manifest containing only files from the workflow upload allowlist (the manifest itself is excluded);
- preflight, OTA preparation, build, ABI, smoke-build, smoke-ABI, diagnostics, and QEMU logs;
- short result summary.

It does **not** upload raw Bazel aquery files, raw toolchain reports, OTA packages, extracted root filesystems, the Alice model, or Bazel cache. The SHA-256 manifest covers only the published files, so every manifest entry can be checked against the downloaded artifact. Artifacts and workflow logs are visible to repository users (and to everyone if the repository is public) until retention expires. Download before expiry if needed.

GitHub artifact extraction does not preserve Unix executable permissions. After downloading on Linux, run `chmod +x tflite_smoke` before attempting to execute it.

## Create and publish later

This project is prepared locally only. No GitHub repository is created, no push is performed, and no workflow is started by this preparation.

When you approve publication:

1. Create a separate GitHub repository named, for example, `tflite-arm64-cloud-build`. Choose public only if you accept that its source, workflow runs, logs, and artifacts can be viewed by anyone. Do not include the parent workspace or the main project.
2. From this directory, initialize Git, add only these project files, review `git status` and the staged diff, then commit and push to the new repository's default branch. Keep `.gitignore` in place.
3. Open **Actions → Build TensorFlow Lite ARM64 → Run workflow**, choose the default branch, and start it manually. The `workflow_dispatch` workflow file must already be present on that repository's default branch, and the account needs write access to run it.
4. Review the job outcome and download the seven-day artifact from the run page. The QEMU result is not a substitute for later physical-device validation, which is outside this workflow.

No PAT or API secret is needed by the workflow. GitHub's UI or `gh` may be used by the owner for repository setup; do not put credentials in this repository.

## Runner and cost caveats

GitHub documents standard GitHub-hosted runner use for public repositories as free; artifact storage remains subject to the account's plan and shared storage allowance. Private-repository usage can draw from included account quotas and may be billed when those are exceeded. Public repositories expose workflow runs, logs, and uploaded outputs. Runner disk space is finite and TensorFlow/Bazel builds are storage-intensive; preflight is only a minimum guard and cannot guarantee that Bazel will fit. The job has a six-hour timeout and may fail from disk exhaustion, network throttling, dependency availability, or upstream changes despite pinned source versions. Review [GitHub Actions billing](https://docs.github.com/en/actions/concepts/billing-and-usage) before publishing or dispatching.
