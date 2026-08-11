# Cross-lane hand-off notes

One file per lane, because two agents writing the shared queue concurrently is how 189 lines of it
got corrupted and how one lane had to "restore the other lane`s block that I set aside".

An agent that needs a change in a file it does not own writes the exact patch into
`docs/handoff/<lane>.md`. The Coordinator folds accepted notes into `docs/QUEUE.md` afterwards.

ASCII only. Write these with the Write/Edit tools, never shell redirection.
