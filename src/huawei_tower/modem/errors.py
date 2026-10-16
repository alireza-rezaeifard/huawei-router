class ModemError(RuntimeError):
    """Base error for modem communication."""


class UnsafeOperationError(ModemError):
    """Raised when an endpoint or operation is outside the approved read-only scope."""


class ModemHTTPError(ModemError):
    """Raised for unexpected HTTP responses."""


class ModemParseError(ModemError):
    """Raised when a modem response cannot be parsed safely."""
