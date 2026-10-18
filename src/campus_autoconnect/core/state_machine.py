"""One bounded manual operation, with explicit state transitions."""

from campus_autoconnect.core.models import AuthState

_S = AuthState
TRANSITIONS = {
    _S.DISCONNECTED: {_S.NETWORK_CONNECTED, _S.UNKNOWN},
    _S.NETWORK_CONNECTED: {_S.CHECKING, _S.DISCONNECTED, _S.UNKNOWN},
    _S.CHECKING: {_S.AUTHENTICATED, _S.AUTH_REQUIRED, _S.UNKNOWN, _S.DISCONNECTED},
    _S.AUTH_REQUIRED: {_S.AUTHENTICATING, _S.AUTH_FAILED, _S.UNKNOWN, _S.DISCONNECTED},
    _S.AUTHENTICATING: {_S.AUTHENTICATED, _S.AUTH_FAILED, _S.UNKNOWN, _S.DISCONNECTED},
    _S.AUTHENTICATED: set(),
    _S.AUTH_FAILED: set(),
    _S.UNKNOWN: set(),
}


class StateMachine:
    def __init__(self) -> None:
        self.state = AuthState.DISCONNECTED
        self.history = [self.state]

    def transition(self, state: AuthState) -> None:
        if state == self.state:
            return
        if state not in TRANSITIONS[self.state]:
            raise ValueError(f"Invalid transition: {self.state} -> {state}")
        self.state = state
        self.history.append(state)
