module AuthState exposing
    ( Allowed
    , AuthState(..)
    , Authenticated
    , ChallengeSpec
    , State
    , loggedIn
    , loggedOut
    , mapAuthenticated
    , toAttempting
    , toChallenged
    , toFailed
    , toLoggedIn
    , toRefreshing
    , toRequestingCredentials
    , toRequestingId
    , toResponding
    , toRestoring
    , untag
    )

import AWS.CognitoIdentity as CI
import AWS.CognitoIdentityProvider as CIP
import AWS.Credentials exposing (Credentials)
import AWS.Http exposing (AWSAppError, Error)
import AWS.Tokens exposing (AccessToken, IdToken)
import StateMachine exposing (Allowed, State(..), map)
import Time exposing (Posix)


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
    | Attempting (State { loggedIn : Allowed, requestingId : Allowed, failed : Allowed, challenged : Allowed } {})
    | RequestingId (State { requestingCredentials : Allowed } { auth : Authenticated })
    | RequestingCredentials (State { loggedIn : Allowed } { auth : Authenticated, id : CI.IdentityId })
    | Failed (State {} { error : Maybe (Error AWSAppError) })
    | LoggedIn (State { refreshing : Allowed, loggedOut : Allowed } { auth : Authenticated, credentials : Maybe Credentials })
    | Refreshing (State { loggedIn : Allowed } { auth : Authenticated, credentials : Maybe Credentials })
    | Challenged (State { responding : Allowed } { challenge : ChallengeSpec })
    | Responding (State { loggedIn : Allowed, requestingId : Allowed, failed : Allowed, challenged : Allowed } { challenge : ChallengeSpec })



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


requestingId : Authenticated -> AuthState
requestingId auth =
    State { auth = auth } |> RequestingId


requestingCredentials : Authenticated -> CI.IdentityId -> AuthState
requestingCredentials auth identityId =
    State { auth = auth, id = identityId } |> RequestingCredentials


failed : Maybe (Error AWSAppError) -> AuthState
failed maybeAppError =
    State { error = maybeAppError } |> Failed


loggedIn : Authenticated -> Maybe Credentials -> AuthState
loggedIn model credentials =
    State { auth = model, credentials = credentials } |> LoggedIn


refreshing : Authenticated -> Maybe Credentials -> AuthState
refreshing model credentials =
    State { auth = model, credentials = credentials } |> Refreshing


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


toRequestingId : Authenticated -> State { a | requestingId : Allowed } m -> AuthState
toRequestingId auth _ =
    requestingId auth


toRequestingCredentials : Authenticated -> CI.IdentityId -> State { a | requestingCredentials : Allowed } m -> AuthState
toRequestingCredentials auth identityId _ =
    requestingCredentials auth identityId


toFailed : Maybe (Error AWSAppError) -> State { a | failed : Allowed } m -> AuthState
toFailed error _ =
    failed error


toLoggedIn : Authenticated -> Maybe Credentials -> State { a | loggedIn : Allowed } m -> AuthState
toLoggedIn authModel credentials _ =
    loggedIn authModel credentials


toRefreshing : Maybe Credentials -> State { a | refreshing : Allowed } { m | auth : Authenticated } -> AuthState
toRefreshing credentials (State model) =
    refreshing model.auth credentials


toChallenged : ChallengeSpec -> State { a | challenged : Allowed } m -> AuthState
toChallenged spec _ =
    challenged spec


toResponding : ChallengeSpec -> State { a | responding : Allowed } m -> AuthState
toResponding spec _ =
    responding spec
