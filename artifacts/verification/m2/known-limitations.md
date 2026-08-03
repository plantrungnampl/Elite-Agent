# Known M2 limitations

- The local verification account cannot create symbolic links directly, so the direct LPAC probe uses a second inert NTFS junction for that reparse-point case. The filesystem adapter matrix separately covers retained-handle reparse replacement, and GitHub-hosted Windows CI runs the same tests.
- Non-denied network profiles remain disabled because endpoint-specific Windows enforcement is not implemented. Requests for those profiles fail closed before process creation.
- M3 provider execution and M5 candidate-tree/final-commit behavior remain out of scope and are not enabled.
