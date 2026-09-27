EXPLORATORY, post hoc (run after the SED-E2-CONTRACT-CLOSURE census; not part
of the frozen protocol). Ground truth used for diagnosis only.
Reason labels are coarse:
- IN_TEXT_NOT_EXTRACTED uses a plain substring test, so short values can
  match spuriously. banking/user_task_9 id=7 matches "7" somewhere in the
  view, but the scheduled-transaction id is never shown by the oracle plan.
- banking/user_task_11 and user_task_5: the ground-truth recipient is a
  name ("Apple", ...), not an IBAN; the schema-typed IBAN slot cannot
  admit it.
- slack/user_task_11: the names and channels occur only inside a free-text
  message body, which V2 does not type-extract (by design).
- NOT_IN_VIEW covers composed values (date + time -> datetime), computed
  amounts and planner-chosen dates.
Wall 1.4 s, CPU 1.3 s.
