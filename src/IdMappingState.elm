module IdMappingState exposing (..)

-- ( Allowed
-- , IdMappingState(..)
--    -- Convenience re-exports from StateMachine
--
-- , State
-- -- Constructors
-- ,  noMappedId
--    -- Map
--
-- ,  mapAuthenticated
--    -- State transitions
--
-- , toAttempting
-- , toChallenged
-- , toFailed
-- , toLoggedIn
-- , toRefreshing
-- , toResponding
-- , toRestoring
-- ,  untag
--
-- )

import AWS.CognitoIdentity as CI
import StateMachine exposing (Allowed, State(..), map)
import Time exposing (Posix)


untag : State tag value -> value
untag =
    StateMachine.untag


type alias State p m =
    StateMachine.State p m


type alias Allowed =
    StateMachine.Allowed


type alias MappedId =
    {}


type IdMappingState
    = NoMappedState (State { requestingId : Allowed } {})
    | RequestingId (State { requestingCredentials : Allowed } {})
    | RequestingCredentials (State { idMapped : Allowed } {})
    | IdMapped (State {} { mappedId : MappedId })



-- State constructors.


loggedOut : AuthState
loggedOut =
    State {} |> LoggedOut



-- Map functions


mapAuth : (a -> a) -> ({ m | auth : a } -> { m | auth : a })
mapAuth func =
    \model -> { model | auth = func model.auth }


mapAuthenticated :
    (Authenticated -> Authenticated)
    -> State p { m | auth : Authenticated }
    -> State p { m | auth : Authenticated }
mapAuthenticated func state =
    map (mapAuth func) state



-- State transition functions that can be applied only to states that are permitted
-- to make a transition.


toChallenged : ChallengeSpec -> State { a | challenged : Allowed } m -> AuthState
toChallenged spec _ =
    challenged spec
