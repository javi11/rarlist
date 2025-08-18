# RAR Volume Header Sizer

Utility to parse multi‑part RAR (v3 and v5) archives and compute, for every volume, the cumulative header size (so you know the data payload offset) for non‑encrypted & non‑compressed stored files. This is useful to allow random or streaming access directly to file data across volumes.

Status: WIP
