# Focused-field live output (experimental)

Focused-field live output writes native streaming transcription into the text control that was focused when dictation started. It is an experimental, opt-in alternative to the live transcription overlay. **Overlay remains the default.**

This mode is deliberately fail-closed. Handy enables it only when it can capture and monitor a supported editable control before recording; it does not turn on partway through a dictation.

## Enable it and understand fallback

In **Settings → Advanced → Experimental**, enable experimental features and choose **Focused text field** as the progressive output destination.

Focused sessions do not send transcript text to the webview overlay. Windows and macOS show only a nonactivating minimal recording indicator; Linux shows no recording overlay.

Handy checks all of the following at the start of every dictation:

- experimental features and **Focused text field** are enabled;
- the selected model supports native streaming;
- post-processing is off;
- the paste method is neither **None** nor **External script**, so normal delivery remains available if eligibility fails before focused output is armed;
- the native backend and required permissions are available;
- one non-Handy, non-secure, editable control is focused with a collapsed selection;
- the control has a supported insertion route and mixed-input monitor; and
- if auto-submit is enabled, that target can safely emit the configured submit chord.

A failed check **before arming** uses Handy's normal overlay and final-delivery behavior. Handy captures the original control, chooses one route, and starts its monitors before showing a recording surface or opening microphone capture.

Once focused output is armed, ownership changes: the session can never fall back to a late final paste. A stream failure, target change, unsafe edit, partial or ambiguous insertion, cancellation, or final transcript conflict preserves what was already delivered and stops further output. It never retries into another control, deletes text, or pastes the final transcript over the result.

## Native routes

Route availability is decided again for each target. A platform being globally available does not mean every application or text control is supported.

| OS      | Native route                                                               | Safety and receipt                   | Mixed-input evidence               | Important constraints                                                                                                                                                                 |
| ------- | -------------------------------------------------------------------------- | ------------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows | UI Automation capture + Unicode `SendInput` (`windows_unicode_send_input`) | `guarded_focused_control` / `posted` | `guarded_keyboard_insertions_only` | The UI Automation control identity, editable metadata, collapsed selection, subscriptions, focus, and input hooks must remain valid. Text is focus-routed in small revalidated units. |
| macOS   | Accessibility `AXSelectedText` (`mac_ax_selected_text`)                    | `verified_control` / `verified`      | `guarded_keyboard_insertions_only` | Handy uses this target-bound route only when the selected range is settable and affected-range readback is available.                                                                 |
| macOS   | Core Graphics Unicode events (`mac_cg_event_unicode`)                      | `guarded_focused_control` / `posted` | `guarded_keyboard_insertions_only` | Selected once when the AX write route is unavailable; Handy does not switch routes after arming. Text is focus-routed in small revalidated units.                                     |
| Linux   | AT-SPI `EditableText.insert_text` (`at_spi_editable_text`)                 | `verified_control` / `verified`      | `observed_insertions_only`         | The focused object's application/control identity, D-Bus owner, editable states, selection, affected-range readback, and event monitoring must all be provable.                       |
| Linux   | Focused keyboard tool (`linux_focused_keyboard`)                           | `guarded_focused_control` / `posted` | `observed_insertions_only`         | Requires a pinned AT-SPI target and a positively checked, canonical stdin tool from the allowlist below. Text is sent in units of at most 16 Unicode scalars.                         |

`verified` means the target-bound route read back the affected range. `posted` means the OS accepted a focus-routed event; it does not prove which control ultimately consumed it. Guarded routes revalidate immediately before each small unit and dispatch nothing further after Handy observes invalidation. There is still an irreducible interval between the final check and OS consumption in which focus can change, so an already-posted unit or submit chord can reach the wrong control. Handy does not describe these routes as target-bound.

Only exact target-bound affected-range readback can classify a verified UTF-8 prefix as a partial insertion. If output may have been posted but cannot be verified, Handy classifies the result as ambiguous and does not guess, retry, or switch transport.

Windows has an additional residual limitation: low-level hooks provide no reliable query for silent hook removal. macOS and Windows accessibility providers can also report only coarse value/caret evidence for ordinary typing; hidden autocorrect or provider-side transformations may not be detectable. Direct AX and AT-SPI routes trust the platform accessibility provider and their exact affected-range readback.

### Linux tool allowlist

Focused-field live output accepts only these reviewed stdin transports:

- canonical `wtype` invoked as `wtype -`; or
- canonical `ydotool` invoked as `ydotool type --file=-`, and only after that exact transport is positively probed.

`dotool` command mode, `kwtype`, `xdotool`, argv-only tool versions, Enigo, portals, and external scripts are not eligible. The executable is pinned for the session, transcript text is written through stdin rather than argv, output is discarded, and the bounded child is killed and reaped on cancellation or timeout. These restrictions apply only to focused-field live output; they do not change legacy paste behavior.

## Speaking and typing in the same control

Handy keeps a speech-only ledger. Each newer streaming revision may append only the byte-exact speech suffix compatible with speech already delivered. Handy does not normalize text, rewrite an earlier word, or treat text you type as part of the transcript. If a volatile recognizer revision conflicts, Handy emits nothing for that revision and can resume if a later revision is compatible.

Ordinary insertions at the expected caret in the captured control may interleave with speech when the chosen monitor can classify them. For example, you can speak, type an insertion, and continue speaking; later compatible speech is appended without removing your text. Handy observes the insertion for ordering but does not retain its contents in the speech ledger. The configured Handy stop shortcut is treated as a control action rather than a user edit.

The first destructive, positional, or ambiguous action permanently stops further live output. This includes:

- delete/backspace, replacement, cut, paste, undo, or redo;
- selecting text, moving the caret, navigation, focus traversal, or pointer activity;
- command shortcuts, Enter/newline outside Handy's guarded final auto-submit, or IME composition;
- an unmatched, reordered, duplicated, or timed-out target effect; and
- focus/target change, target closure, accessibility-provider or monitor loss, or backend disconnection.

Handy does not attempt to undo the action. Start a new dictation after restoring focus if you want to continue.

## Stop, recovery, clipboard, space, and submit

On stop, Handy finalizes the exact active session and consumes the streaming barrier before considering final text. A compatible final speech tail is inserted once. If the final transcript conflicts with speech already delivered, or delivery has become unsafe, Handy preserves the partial field contents and does not paste.

The processed final speech transcript is still saved to History through Handy's normal history path. A recovery action is offered only when the recording and History entry were actually saved; if persistence failed, Handy reports that recovery is unavailable rather than claiming an entry exists. User-typed coediting is not part of the speech transcript in History.

Final options keep their existing meaning, with focused safeguards:

- **Append trailing space** inserts one space only after speech completes and the target is still valid.
- **Copy to clipboard** performs a clipboard write without simulating paste or keyboard input. A successful delivery copies the speech result including a delivered trailing space. A preserved/invalidated session copies the processed final speech without a trailing space, so it can be recovered manually.
- **Auto-submit** runs only after compatible final speech and any trailing space complete, and only while the target is still valid. The configured chord must be supported for that target before arming. The submit operation itself is a separately revalidated guarded/posted unit; a rejected or ambiguous submit does not undo speech and does not trigger a paste.

Clipboard contents can be visible to the operating system and clipboard managers. History and recording retention continue to follow Handy's existing settings.

## Permissions and headless use

- **macOS:** both Accessibility and Input Monitoring permission are required. Capability checks and recording never prompt. Use the explicit permission buttons in the experimental setting, then review the result in macOS System Settings. A permission request is rejected while a dictation plan is active. Secure Input disables focused output.
- **Windows:** there is no focused-output permission prompt, but secure/password controls, unprovable metadata, unsupported controls, and targets Handy cannot inject into are rejected.
- **Linux:** there is no permission prompt. A working AT-SPI accessibility bus, verifiable object/process ownership, required object/device events, and either direct `EditableText` support or an eligible tool route are required.

Handy's headless CLI constructs no focused-output backend, does not inspect the focused target, does not start accessibility/input monitoring, and never requests these permissions. The setting affects the desktop GUI only.

## Troubleshooting and limitations

- **The overlay/final output is still used:** inspect the displayed reason. Common causes are an incompatible model, post-processing, **None** or **External script** paste mode, missing permissions, unsupported auto-submit, an active selection, a secure or non-editable control, or no safe route/monitor.
- **macOS reports a missing permission:** grant the named permission only through the explicit settings action. Both Accessibility and Input Monitoring must pass preflight; passive status checks intentionally do not prompt.
- **Linux reports AT-SPI or typing-tool unavailable:** confirm the desktop accessibility bus is running and the target exposes a focused editable AT-SPI `Text`/`EditableText` object. For a guarded route, select `Auto`, `wtype`, or `ydotool`; only the stdin forms listed above qualify.
- **Output stops after typing or clicking:** only classified insertions at the expected caret are coediting-safe. Navigation, selection, pointer input, IME, commands, target changes, and uncertain provider events invalidate the session by design. Recover the speech transcript from History when available and start a new dictation.
- **Auto-submit does not run:** unsupported submit routes fall back before arming. A target change or dispatch failure after arming preserves delivered speech without retrying the chord or pasting.
- **Application compatibility:** support is control-specific and established at runtime, not by an application allowlist. Password fields, Handy-owned controls, terminals/custom controls without sufficient accessibility semantics, active selections, and IME composition are unsupported. Native interactive application matrices are unverified unless published separately for a release; the route table documents implementation contracts, not blanket application results.

## Privacy and trusted components

Audio and recognition remain local. Focused output necessarily gives Handy local access to the captured accessibility control and input events while the session is armed. It pins target identity and locally reads accessibility metadata and the target values or affected ranges required to validate changes; these reads are not used to merge user text into the speech transcript. Input events are inspected transiently to distinguish Handy output from user edits, and user-inserted text is not retained in the speech ledger.

Status and metrics contain session IDs, counts, timings, route/safety values, application product name when safely available, and stable reason codes. They exclude transcript chunks, user text, field/control names, window or document titles, URLs, raw event strings, and tool stderr. Transcript text still reaches the selected application, History when enabled, the clipboard when requested, and an allowlisted Linux tool's stdin when that route is used.

The trusted computing base is the operating system's UI Automation/Accessibility/Core Graphics/AT-SPI provider and, on Linux guarded routes, the canonical allowlisted executable. Grant accessibility/input permissions and install typing tools only when you trust those components.

### Native dependency notes

The shared manager uses `crossbeam-channel` 0.5.15 (MIT OR Apache-2.0) for bounded, nonblocking event delivery. Windows uses additional UI Automation, COM, and keyboard/input bindings from the existing `windows` crate. macOS uses the 0.3.2 `objc2-application-services`, `objc2-core-foundation`, and `objc2-core-graphics` bindings (Zlib OR Apache-2.0 OR MIT). Linux uses the pure-Rust `atspi` 0.30/zbus stack (Apache-2.0 OR MIT) and adds no native package; a guarded keyboard route still requires one separately installed allowlisted tool.

## Verification status

The implementation source and native-test workflow were verified at commit `0cc7bd8`; the branch's next commit, `804fa28`, only records the already-resolved direct `windows-core` dependency in `Cargo.lock`.

### Automated checks

| Check                       | Result                                      | Evidence and scope                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rust tests                  | Passed                                      | The local full suite passed 355 tests. The fork's final [Rust test run](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33355883210) also passed.                                                                                                                                                                                                                                                                            |
| Focused Linux tests         | Passed                                      | All 15 focused Linux policy, helper, cancellation, modifier, race, and child-process tests passed locally.                                                                                                                                                                                                                                                                                                                               |
| Rust quality                | Passed                                      | `cargo clippy --all-targets -- -D warnings`, `cargo fmt`, and repository formatting checks passed locally.                                                                                                                                                                                                                                                                                                                               |
| Frontend quality            | Passed                                      | Translation consistency, ESLint, and Prettier passed in the fork's [Code Quality run](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33354958609). The production frontend build also passed locally.                                                                                                                                                                                                                       |
| Settings browser regression | Passed                                      | Both existing Playwright tests passed locally and in the fork's [Playwright run](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33354960033). This exercises the browser test surface, not the native Tauri webview.                                                                                                                                                                                                        |
| Native compile/test matrix  | Passed                                      | In the final [Build Test run](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33356984130), native Rust library tests passed on Windows x64, Windows ARM64, macOS Intel, macOS ARM64, Linux x64 on Ubuntu 22.04 and 24.04, and Linux ARM64. The overall workflow is red only after those tests: the fork lacks the macOS certificate, Windows trusted-signing configuration, and updater signing key required for packaging. |
| Nix                         | Passed locally; fork run externally blocked | Local `nix flake check` passed for x86_64 Linux. The fork's [Nix run](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33354961443) and [retry](https://github.com/ZebulonRouseFrantzich/Handy/actions/runs/33355045619) reached the Handy build but crates.io returned HTTP 403 while Nix fetched `atspi` crates.                                                                                                            |
| Headless isolation          | Passed                                      | The real headless CLI listed models and transcribed an audio file with Moonshine without constructing a focused-output backend, inspecting a focused target, or requesting focused-output permissions.                                                                                                                                                                                                                                   |
| Privacy sentinel audit      | Passed                                      | Persisted logs contained neither acceptance sentinel, and the repository source and documentation contained neither sentinel. Runtime status/log paths were also independently reviewed for transcript, user-text, title, URL, raw-event, and tool-stderr exposure.                                                                                                                                                                      |
| Independent review          | Passed                                      | Fresh code and security reviews found no remaining blocker or high-severity issue after the race, cancellation, target-validation, and privacy fixes were applied.                                                                                                                                                                                                                                                                       |

### Interactive and packaging gaps

These rows remain unverified and must not be read as application support claims:

| Surface                                | Status                                                    | Reason                                                                                                                                                                                                                                                     |
| -------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native Tauri settings webview          | Unverified on the local workstation                       | The application process launched, but WebKitGTK failed EGL display creation with `EGL_BAD_PARAMETER` and rendered a blank webview even with the DMA-BUF renderer disabled. The actual native settings surface could not be observed.                       |
| Linux live route matrix                | Safe fallback observed; live insertion unverified locally | The available GtkSourceView target omitted the required AT-SPI `Enabled` state, and GNOME Wayland rejected authenticated `DeviceEventController` keystroke-listener registration. Strict pre-arm validation therefore selected fallback instead of arming. |
| Windows and macOS application matrices | Unverified                                                | Native compilation and unit tests passed on x64 and ARM64 runners, but interactive Notepad/Word/Office/browser/editor and TextEdit/Notes/Pages/Office/browser/editor matrices still require physical hosts with the relevant permissions.                  |
| Latency and event-processing targets   | Unverified                                                | The local environment could not arm a live route, so the 500 ms eligibility target and 80 ms p95 event-processing target were not measured.                                                                                                                |
| Signed packages and size delta         | Unverified in the fork                                    | Native tests precede packaging and passed, but packaging then failed closed because fork signing credentials are intentionally absent. No comparable signed artifacts were produced for bundle-size measurement.                                           |

## Credit

The concept and early prototype discussion came from [GitHub Discussion #1919](https://github.com/cjpais/Handy/discussions/1919), started by [`andrewD-github`](https://github.com/andrewD-github). This implementation was developed independently; no prototype code or diagnostic output was copied. AI tools assisted with implementation and documentation.
