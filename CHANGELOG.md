# Changelog

## 0.1.0

- First release: APK viewer for `.apk` files with the decoded `AndroidManifest.xml`, permissions (dangerous ones flagged), components with their exported flag and reason, DEX counts against the 65,536 method limit, method counts by package as a tree, classes, size by folder and file type, native ABIs, signing blocks and the signer certificate, and a hex view of any entry.
- `.aab`, `.apks` and `.xapk` files open too (files, sizes, DEX counts; the base APK of a set is analysed).
- Readers run in a worker thread with memory and time limits; counts are checked against the file; unpacking is capped.
- Zovo Pro tools with 3 free tries each: compare two APKs, export the report (JSON, Markdown, CSV), find in DEX.
- Support links at the bottom of the viewer (Rate, More free viewers, Zovo Pro, PayPal, Hide), a README section with related Zovo extensions, and a last walkthrough step that links extensions for files that often come with APKs.
