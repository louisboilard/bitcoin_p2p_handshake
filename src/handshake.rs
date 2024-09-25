/// States the handshake goes through (post connection).
#[derive(Debug)]
enum State {
    Init,
    SendVersion,
    RecvVersion,
    ValidateVersion,
    SendAck,
    RecvAck,
    ValidateAck,
    Complete,
}

impl State {
    fn new() -> Self {
        Self::Init
    }

    /// States transitions.
    fn next(s: Self) -> Self {
        match s {
            Self::Init => Self::SendVersion,
            Self::SendVersion => Self::RecvVersion,
            Self::RecvVersion => Self::ValidateVersion,
            Self::ValidateVersion => Self::SendAck,
            Self::SendAck => Self::RecvAck,
            Self::RecvAck => Self::ValidateAck,
            Self::ValidateAck => Self::Complete,
            Self::Complete => Self::Complete,
        }
    }
}
