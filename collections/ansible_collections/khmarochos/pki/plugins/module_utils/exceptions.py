class PKICascadeError(Exception):
    pass


class CANotFound(PKICascadeError):
    pass


class UnknownProperty(PKICascadeError):
    pass


class MandatoryPropertyUnset(PKICascadeError):
    pass


class ReadOnlyProperty(PKICascadeError):
    pass


class StructureError(PKICascadeError):
    pass


class InterpolationLoop(PKICascadeError):
    pass


class UnbalancedBraces(PKICascadeError):
    pass


class ReservedCharacter(PKICascadeError):
    pass
