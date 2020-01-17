module AuthState exposing
    ( Allowed
    , AuthState(..)
    , Authenticated
    ,  ChallengeSpec
       -- Convenience re-exports from StateMachine

    , State
    ,  loggedOut
       -- Map

    ,  mapAuthenticated
       -- State transitions

    , toAttempting
    , toChallenged
    , toFailed
    , toLoggedIn
    , toRefreshing
    , toResponding
    , toRestoring
    ,  untag
       -- Constructors

    )

import AWS.CognitoIdentityProvider as CIP
import StateMachine exposing (Allowed, State(..), map)
import Time exposing (Posix)
import Tokens exposing (AccessToken, IdToken)


untag : State tag value -> value
untag =
    StateMachine.untag


type alias State p m =
    StateMachine.State p m


type alias Allowed =
    StateMachine.Allowed


type alias Authenticated =
    { subject : String
    , scopes : List String
    , accessToken : CIP.TokenModelType
    , idToken : CIP.TokenModelType
    , refreshToken : CIP.TokenModelType
    , decodedAccessToken : AccessToken
    , decodedIdToken : IdToken
    , expiresAt : Posix
    , refreshFrom : Posix
    }


type alias ChallengeSpec =
    { session : CIP.SessionType
    , challenge : CIP.ChallengeNameType
    , parameters : CIP.ChallengeParametersType
    , username : String
    }


{-| Note that the LoggedOut state is effectively a reset on the state machine,
and is allowed from any state, so it is not marked explcitly here.
-}
type AuthState
    = LoggedOut (State { restoring : Allowed, attempting : Allowed } {})
    | Restoring (State { loggedIn : Allowed } {})
    | Attempting (State { loggedIn : Allowed, failed : Allowed, requestingId : Allowed, challenged : Allowed } {})
    | RequestingId (State { requestingCredentials : Allowed } {})
    | RequestingCredentials (State { loggedIn : Allowed } {})
    | Failed (State {} {})
    | LoggedIn (State { refreshing : Allowed, loggedOut : Allowed } { auth : Authenticated })
    | Refreshing (State { loggedIn : Allowed } { auth : Authenticated })
    | Challenged (State { responding : Allowed } { challenge : ChallengeSpec })
    | Responding (State { loggedIn : Allowed, failed : Allowed, challenged : Allowed } { challenge : ChallengeSpec })



-- State constructors.


loggedOut : AuthState
loggedOut =
    State {} |> LoggedOut


restoring : AuthState
restoring =
    State {} |> Restoring


attempting : AuthState
attempting =
    State {} |> Attempting


failed : AuthState
failed =
    State {} |> Failed


loggedIn : Authenticated -> AuthState
loggedIn model =
    State { auth = model } |> LoggedIn


refreshing : Authenticated -> AuthState
refreshing model =
    State { auth = model } |> Refreshing


challenged : ChallengeSpec -> AuthState
challenged model =
    State { challenge = model } |> Challenged


responding : ChallengeSpec -> AuthState
responding model =
    State { challenge = model } |> Responding



-- Map functions


mapAuth : (a -> a) -> ({ m | auth : a } -> { m | auth : a })
mapAuth func =
    \model -> { model | auth = func model.auth }


mapChallenge : (a -> a) -> ({ m | challenge : a } -> { m | challenge : a })
mapChallenge func =
    \model -> { model | challenge = func model.challenge }


mapAuthenticated :
    (Authenticated -> Authenticated)
    -> State p { m | auth : Authenticated }
    -> State p { m | auth : Authenticated }
mapAuthenticated func state =
    map (mapAuth func) state


mapChallengeSpec :
    (ChallengeSpec -> ChallengeSpec)
    -> State p { m | challenge : ChallengeSpec }
    -> State p { m | challenge : ChallengeSpec }
mapChallengeSpec func state =
    map (mapChallenge func) state



-- State transition functions that can be applied only to states that are permitted
-- to make a transition.


toRestoring : State { a | restoring : Allowed } m -> AuthState
toRestoring _ =
    restoring


toAttempting : State { a | attempting : Allowed } m -> AuthState
toAttempting _ =
    attempting


toFailed : State { a | failed : Allowed } m -> AuthState
toFailed _ =
    failed


toLoggedIn : Authenticated -> State { a | loggedIn : Allowed } m -> AuthState
toLoggedIn authModel _ =
    loggedIn authModel


toRefreshing : State { a | refreshing : Allowed } { m | auth : Authenticated } -> AuthState
toRefreshing (State model) =
    refreshing model.auth


toChallenged : ChallengeSpec -> State { a | challenged : Allowed } m -> AuthState
toChallenged spec _ =
    challenged spec


toResponding : ChallengeSpec -> State { a | responding : Allowed } m -> AuthState
toResponding spec _ =
    responding spec
