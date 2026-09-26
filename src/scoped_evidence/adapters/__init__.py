"""Adapters that turn a benchmark (or stored traces) into headroom TaskRecords."""


class SourceNotAvailable(RuntimeError):
    """Raised when an approved local copy of the benchmark source is missing."""
