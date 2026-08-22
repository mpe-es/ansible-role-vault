# Count preflight gate ASSERT tasks by their stable name prefix.
# Emits executed / skipped / failed so a did-not-fire oracle reads the same
# instrument as a fires oracle. Issue #36.
/^TASK \[/                    { pending = 0 }
/^TASK \[.*Preflight \| /     { pending = 1; next }
pending && /^(ok|changed):/   { exec++; pending = 0 }
pending && /^(failed|fatal):/ { exec++; fail++; pending = 0 }
pending && /^skipping:/       { skip++; pending = 0 }
END { printf "executed=%d skipped=%d failed=%d\n", exec+0, skip+0, fail+0 }
