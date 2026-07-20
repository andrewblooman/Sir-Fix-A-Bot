Your previous change to `{{SERVICE_NAME}}` did not pass verification. The details are below.

You have one attempt to correct it. If you cannot fix the problem without breaching one of the hard
constraints from the original task, report the fix as blocked instead — a clear blocked report is a
better outcome than a change that fails again or quietly violates a rule.

{{FAILURE_SECTION}}

## What to do

Address the specific failures listed above and nothing else. Do not start over, do not broaden the
change, and do not revisit decisions that were not flagged. The constraints from the original task
still apply in full — in particular, the runtime major/minor version must not change, and you must
not add a `USER` instruction or create a user or group.

If a gate violation and a build failure point in opposite directions — for example, the build fails
in a way that would be easiest to fix by adding a `USER` line — that tension is what a blocked report
is for. Say which constraint the fix would breach and stop.

Re-read your diff before reporting, then finish with the same JSON block as before.
