use std::fmt;

/// States the handshake goes through (post connection).
#[derive(Debug)]
pub enum State {
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

    fn completed(&self) -> bool {
        match self {
            Self::Complete => return true,
            _ => return false,
        }
    }

    fn next(&mut self) {
        match self {
            Self::Init => *self = Self::SendVersion,
            Self::SendVersion => *self = Self::RecvVersion,
            Self::RecvVersion => *self = Self::ValidateVersion,
            Self::ValidateVersion => *self = Self::SendAck,
            Self::SendAck => *self = Self::RecvAck,
            Self::RecvAck => *self = Self::ValidateAck,
            Self::ValidateAck => *self = Self::Complete,
            Self::Complete => *self = Self::Complete,
        };
    }
}

impl fmt::Display for State {
    // relies on the fact that State implements Debug
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    First,
}

#[derive(Debug)]
pub struct Handshake {
    state: State,
}

impl Handshake {
    pub fn new() -> Self {
        let state = State::new();
        Self { state }
    }

    pub fn handshake(&mut self) -> Result<(), HandshakeError> {
        while let Some(state_result) = self.next() {
            match state_result {
                Ok(state) => {
                    tracing::info!("Reached state: {}", state);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

// This iterator returns None when the handshake is complete and the current
// State or error when stepping.
impl Iterator for Handshake {
    type Item = Result<State, HandshakeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.completed() {
            return None;
        }

        // Step
        // todo: handle the errors here, whenever there's an error here we need to bubble it up.
        self.state.next();
        None
    }
}
