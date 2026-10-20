"""Fixed Bundle-ID entry on the original SavedCommand engine."""
from ._desktop_saved_command_control import SavedCommandDomain
from ._desktop_saved_command_engine import _SavedCommandEngine, run_engine


class _Engine(_SavedCommandEngine):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.AppleProvisioning)
        self.input._bind_engine(self)

    def provisioning_event(self, kind, payload):
        self._require(self.service is self.input.require_operation() and self.service.request is self.request)
        self.write(self._response(kind, payload))


    def terminal(self):
        self._require(self.request is not None and self.service is not None)
        profile = getattr(self.service, "_profile_output", None)
        if profile is None:
            return super().terminal()
        from ._desktop_apple_profile_private import ProfileOutput
        self._require(type(profile) is ProfileOutput)
        profile.terminal(self, self.service.terminal())

    def close_output(self):
        super().close_output()
        original = self.service if self.service is not None else self.input.operation
        profile = getattr(original, "_profile_output", None)
        if profile is not None:
            from ._desktop_apple_profile_private import ProfileOutput
            self._require(type(profile) is ProfileOutput)
            profile.retire(self)
        key = getattr(original, "_key_output", None)
        if key is not None:
            from ._desktop_apple_key_private import KeyOutput
            self._require(type(key) is KeyOutput)
            key.retire(self)

    def _service_resources_closed(self):
        if not super()._service_resources_closed():
            return False
        original = self.service if self.service is not None else self.input.operation
        profile = getattr(original, "_profile_output", None)
        key = getattr(original, "_key_output", None)
        return (profile is None or profile.closed()) and (key is None or key.closed())


def main(*, started):
    return run_engine(_Engine(started))
