# apolaki-autocontinue heartbeat

Append-only. One `FIRED` line when the scheduled task starts, one `DONE` line when it ends. Never
pruned, never rewritten.

It exists because on 2026-08-19 the task reported `lastRunAt` 21 hours earlier on an hourly cron and
there was no way to tell whether it had been suppressed while a session was already active or had
missed 21 fires. `_autocontinue_stamp.md` cannot answer that -- it exists only during a retirement
streak and is deleted whenever a criterion fails, so its absence means "never ran" and "ran and reset
the streak" equally. The absence of evidence was being produced by the design.

A gap in this file is a fact. A gap in the old arrangement was a guess.

Format:

    FIRED <ISO-8601 UTC>  head=<short sha>  open=<count of ready/proposed in QUEUE.md>
    DONE  <ISO-8601 UTC>  <one clause: which ticket, or which retirement criterion failed>

---

