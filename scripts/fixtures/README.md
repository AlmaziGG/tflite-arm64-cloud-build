# JSONPROTO fixtures

`actiongraph-sample.json` is a small, deidentified test fixture shaped from the
ActionGraphContainer structure observed with the repository's pinned Bazel
6.5.0 Phase 0 queries. Field names, types, and nesting are representative of
the observed records. Labels use the public project target names; all action
keys, argv values, environment values, paths, and object names are synthetic.
The fixture is for parser and selection regression tests only. It is not a raw
or reduced copy of a private Phase 0 action dump.
