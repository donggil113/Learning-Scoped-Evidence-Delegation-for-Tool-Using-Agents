STATUS: INVALID (implementation bug), kept for the record.

The census script tested a success witness with `if witness`, so an empty
assignment {} -- the only action of a zero-slot task -- was treated as "no
witness". Zero-slot variants therefore got best_lower = best_upper = 0 while
the rule scored 1, producing negative gaps (aggregate upper < lower).
The run was stopped during the secondary analysis; only the primary file
exists. The protocol (configs/agentdojo_headroom.json) is unchanged; the fix
(variant_bounds(witness is not None, ...)) and an invariant check
(best >= rule) were added and the census was re-run.
