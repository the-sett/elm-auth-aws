module AWS.Auth exposing
    ( Config, Model, Msg
    , api, Challenge(..), CognitoAPI
    )

{-| Manages the state of the authentication process, and provides an API
to request authentication operations.

@docs Config, Model, Msg
@docs api, Challenge, CognitoAPI

-}

import AWS.CognitoIdentityProvider as CIP
import AWS.Core.Credentials
import AWS.Core.Http
import AWS.Core.Service exposing (Region, Service)
import AuthAPI exposing (AuthAPI, Credentials, Status(..))
import AuthState exposing (Allowed, AuthState, Authenticated, ChallengeSpec)
import Dict exposing (Dict)
import Http
import Json.Decode as Decode exposing (Decoder)
import Json.Decode.Extra exposing (andMap, withDefault)
import Jwt
import Process
import Refined
import Task
import Task.Extra
import Time exposing (Posix)
import Tokens exposing (AccessToken, IdToken)



-- The Auth API implementation.


api : AuthAPI Config Model Msg Challenge CognitoAPI
api =
    { init = init
    , login = login
    , logout = logout
    , unauthed = unauthed
    , refresh = refresh
    , update = update
    , requiredNewPassword = requiredNewPassword
    , addAuthHeaders = addAuthHeaders
    }


{-| AWS Cognito specific API for responding to challenges.
-}
type alias CognitoAPI =
    { requiredNewPassword : String -> Cmd Msg }


{-| The types of challenges that Cognito can issue.

Challenge types not yet covered:

  - SmsMfa
  - SoftwareTokenMfa
  - SelectMfaType
  - MfaSetup
  - PasswordVerifier
  - CustomChallenge
  - DeviceSrpAuth
  - DevicePasswordVerifier
  - AdminNoSrpAuth

-}
type Challenge
    = NewPasswordRequired


{-| The configuration needed to interact with Cognito.
-}
type alias Config =
    { clientId : String
    , userPoolId : String
    , region : Region
    }


{-| The authentication model consisting of the evaluated config and the private state.
-}
type alias Model =
    { clientId : CIP.ClientIdType
    , userPoolId : String
    , region : Region
    , innerModel : Private
    }


{-| The private authentication state.
-}
type Private
    = Private AuthState.AuthState


{-| The internal authentication events.
-}
type Msg
    = LogIn Credentials
    | Refresh
    | LogOut
    | NotAuthed
    | RespondToChallenge (Dict String String)
    | InitiateAuthResponse (Result.Result Http.Error CIP.InitiateAuthResponse)
    | RespondToChallengeResponse (Result.Result Http.Error CIP.RespondToAuthChallengeResponse)


{-| Attempts to create an initialalized auth state from the configuration.

This may result in errors if the configuration is not correct.

-}
init : Config -> Result String Model
init config =
    let
        clientIdResult =
            Refined.build CIP.clientIdType config.clientId
    in
    case clientIdResult of
        Ok clientId ->
            Ok
                { clientId = clientId
                , userPoolId = config.userPoolId
                , region = config.region
                , innerModel = Private AuthState.loggedOut
                }

        Err strErr ->
            "clientId " ++ Refined.stringErrorToString strErr |> Err



-- Standard auth commands.


unauthed : Cmd Msg
unauthed =
    Cmd.none


logout : Cmd Msg
logout =
    Cmd.none


login : Credentials -> Cmd Msg
login credentials =
    LogIn credentials |> Task.Extra.message


refresh : Cmd Msg
refresh =
    Refresh |> Task.Extra.message



-- Extended auth commands for Cognito for responding to challenges.


requiredNewPassword : String -> Cmd Msg
requiredNewPassword new =
    let
        challengeParams =
            Dict.empty
                |> Dict.insert "NEW_PASSWORD" new
    in
    RespondToChallenge challengeParams |> Task.Extra.message



-- Processing of auth related requests and internal auth state.


{-| Lifts the inner model out of the model.
-}
getAuthState : Model -> AuthState
getAuthState model =
    let
        (Private inner) =
            model.innerModel
    in
    inner


{-| Lowers the inner model into the model.
-}
setAuthState : AuthState -> Model -> Model
setAuthState inner model =
    { model | innerModel = Private inner }


{-| Extracts a summary view of the authentication status from the model.
-}
getStatus : AuthState -> Status Challenge
getStatus authState =
    let
        extractAuth : AuthState.State p { auth : Authenticated } -> { scopes : List String, subject : String }
        extractAuth state =
            let
                authModel =
                    AuthState.untag state
            in
            { scopes = authModel.auth.scopes, subject = authModel.auth.subject }

        extractChallenge : AuthState.State p { challenge : ChallengeSpec } -> Challenge
        extractChallenge state =
            let
                authModel =
                    AuthState.untag state
            in
            case authModel.challenge.challenge of
                _ ->
                    NewPasswordRequired
    in
    case authState of
        AuthState.LoggedOut _ ->
            LoggedOut

        AuthState.Restoring _ ->
            LoggedOut

        AuthState.Attempting _ ->
            LoggedOut

        AuthState.Failed _ ->
            Failed

        AuthState.LoggedIn state ->
            LoggedIn <| extractAuth state

        AuthState.Refreshing state ->
            LoggedIn <| extractAuth state

        AuthState.Challenged state ->
            Challenged <| extractChallenge state

        AuthState.Responding state ->
            Challenged <| extractChallenge state


{-| Compares two AuthStates and outputs the status of the newer one, if it differs
from the older one, otherwise Nothing.
-}
statusChange : AuthState -> AuthState -> Maybe (Status Challenge)
statusChange oldAuthState newAuthState =
    let
        oldStatus =
            getStatus oldAuthState

        newStatus =
            getStatus newAuthState
    in
    case ( oldStatus, newStatus ) of
        ( LoggedIn _, LoggedIn _ ) ->
            Nothing

        ( Failed, Failed ) ->
            Nothing

        ( LoggedOut, LoggedOut ) ->
            Nothing

        ( Challenged oldSpec, Challenged newSpec ) ->
            if oldSpec == newSpec then
                Nothing

            else
                Just newStatus

        ( _, _ ) ->
            Just newStatus


{-| Updates the model from Auth commands.
-}
update : Msg -> Model -> ( Model, Cmd Msg, Maybe (Status Challenge) )
update msg model =
    let
        authState =
            getAuthState model

        ( newAuthState, cmds ) =
            innerUpdate model.region model.clientId msg authState
    in
    ( setAuthState newAuthState model, cmds, statusChange authState newAuthState )


innerUpdate : Region -> CIP.ClientIdType -> Msg -> AuthState -> ( AuthState, Cmd Msg )
innerUpdate region clientId msg authState =
    -- | RespondToChallengeResponse (Result.Result Http.Error CIP.RespondToAuthChallengeResponse)
    case ( msg, authState ) of
        ( LogIn credentials, AuthState.LoggedOut state ) ->
            updateLogin region clientId credentials state

        ( LogOut, _ ) ->
            reset

        ( NotAuthed, _ ) ->
            reset

        ( Refresh, AuthState.LoggedIn state ) ->
            updateRefresh region clientId state

        ( InitiateAuthResponse loginResult, AuthState.Attempting state ) ->
            updateInitiateAuthResponse loginResult state

        ( InitiateAuthResponse refreshResult, AuthState.Refreshing state ) ->
            updateInitiateAuthResponseToRefresh refreshResult state

        ( RespondToChallenge responseParams, AuthState.Challenged state ) ->
            updateChallengeResponse region clientId responseParams state

        _ ->
            noop authState


noop authState =
    ( authState, Cmd.none )


reset =
    ( AuthState.loggedOut, Cmd.none )


failed state =
    ( AuthState.toFailed state, Cmd.none )


updateLogin :
    Region
    -> CIP.ClientIdType
    -> Credentials
    -> AuthState.State { a | attempting : Allowed } m
    -> ( AuthState, Cmd Msg )
updateLogin region clientId credentials state =
    let
        authParams =
            Dict.empty
                |> Dict.insert "USERNAME" credentials.username
                |> Dict.insert "PASSWORD" credentials.password

        authRequest =
            CIP.initiateAuth
                { userContextData = Nothing
                , clientMetadata = Nothing
                , clientId = clientId
                , authParameters = Just authParams
                , authFlow = CIP.AuthFlowTypeUserPasswordAuth
                , analyticsMetadata = Nothing
                }

        authCmd =
            authRequest
                |> AWS.Core.Http.sendUnsigned (CIP.service region)
                |> Task.attempt InitiateAuthResponse
    in
    ( AuthState.toAttempting state, authCmd )


updateRefresh :
    Region
    -> CIP.ClientIdType
    -> AuthState.State { a | refreshing : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
updateRefresh region clientId state =
    let
        auth =
            AuthState.untag state
                |> .auth

        authParams =
            Dict.empty
                |> Dict.insert "REFRESH_TOKEN" auth.refreshToken

        authRequest =
            CIP.initiateAuth
                { userContextData = Nothing
                , clientMetadata = Nothing
                , clientId = clientId
                , authParameters = Just authParams
                , authFlow = CIP.AuthFlowTypeRefreshTokenAuth
                , analyticsMetadata = Nothing
                }

        authCmd =
            authRequest
                |> AWS.Core.Http.sendUnsigned (CIP.service region)
                |> Task.attempt InitiateAuthResponse
    in
    ( AuthState.toRefreshing state, authCmd )


updateInitiateAuthResponse :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> AuthState.State { a | loggedIn : Allowed, failed : Allowed, challenged : Allowed } m
    -> ( AuthState, Cmd Msg )
updateInitiateAuthResponse loginResult state =
    case Debug.log "loginResult" loginResult of
        Err httpErr ->
            failed state

        Ok authResponse ->
            case authResponse.authenticationResult of
                Nothing ->
                    case
                        ( authResponse.session
                        , authResponse.challengeParameters
                        , authResponse.challengeName
                        )
                    of
                        ( Just session, Just parameters, Just challengeType ) ->
                            handleChallenge session parameters challengeType state

                        ( _, _, _ ) ->
                            failed state

                Just authResult ->
                    handleAuthResult authResult state


updateInitiateAuthResponseToRefresh :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> AuthState.State { a | loggedIn : Allowed, failed : Allowed } m
    -> ( AuthState, Cmd Msg )
updateInitiateAuthResponseToRefresh loginResult state =
    case Debug.log "loginResult" loginResult of
        Err httpErr ->
            failed state

        Ok authResponse ->
            case authResponse.authenticationResult of
                Nothing ->
                    failed state

                Just authResult ->
                    handleAuthResult authResult state


handleAuthResult :
    CIP.AuthenticationResultType
    -> AuthState.State { a | loggedIn : Allowed, failed : Allowed } m
    -> ( AuthState, Cmd Msg )
handleAuthResult authResult state =
    case ( authResult.refreshToken, authResult.idToken, authResult.accessToken ) of
        ( Just refreshToken, Just idToken, Just accessToken ) ->
            let
                rawRefreshToken =
                    Refined.unbox CIP.tokenModelType refreshToken

                rawAccessToken =
                    Refined.unbox CIP.tokenModelType accessToken

                rawIdToken =
                    Refined.unbox CIP.tokenModelType idToken

                decodedAccessTokenResult =
                    rawAccessToken
                        |> Jwt.decode Tokens.accessTokenDecoder
                        |> Debug.log "accessToken"

                decodedIdTokenResult =
                    rawIdToken
                        |> Jwt.decode Tokens.idTokenDecoder
                        |> Debug.log "idToken"
            in
            case ( decodedAccessTokenResult, decodedIdTokenResult ) of
                ( Ok decodedAccessToken, Ok decodedIdToken ) ->
                    ( AuthState.toLoggedIn
                        { subject = decodedAccessToken.sub
                        , scopes = [ decodedAccessToken.scope ]
                        , accessToken = rawAccessToken
                        , idToken = rawIdToken
                        , refreshToken = rawRefreshToken
                        , decodedAccessToken = decodedAccessToken
                        , decodedIdToken = decodedIdToken
                        , expiresAt = decodedAccessToken.exp
                        , refreshFrom = decodedAccessToken.exp
                        }
                        state
                    , Cmd.none
                    )

                _ ->
                    failed state

        _ ->
            failed state


handleChallenge :
    CIP.SessionType
    -> Dict String String
    -> CIP.ChallengeNameType
    -> AuthState.State { a | challenged : Allowed, failed : Allowed } m
    -> ( AuthState, Cmd Msg )
handleChallenge session parameters challengeType state =
    let
        maybeUsername =
            Dict.get "USER_ID_FOR_SRP" parameters
    in
    case ( challengeType, maybeUsername ) of
        ( CIP.ChallengeNameTypeNewPasswordRequired, Just username ) ->
            ( AuthState.toChallenged
                { session = session
                , challenge = challengeType
                , parameters = parameters
                , username = username
                }
                state
            , Cmd.none
            )

        _ ->
            failed state


updateChallengeResponse :
    Region
    -> CIP.ClientIdType
    -> Dict String String
    -> AuthState.State { a | responding : Allowed, failed : Allowed } { m | challenge : ChallengeSpec }
    -> ( AuthState, Cmd Msg )
updateChallengeResponse region clientId responseParams state =
    let
        challengeSpec =
            AuthState.untag state
                |> .challenge

        preparedParams =
            Dict.insert "USERNAME" challengeSpec.username responseParams

        challengeRequest =
            CIP.respondToAuthChallenge
                { userContextData = Nothing
                , session = Just challengeSpec.session
                , clientId = clientId
                , challengeResponses = Just preparedParams
                , challengeName = CIP.ChallengeNameTypeNewPasswordRequired
                , analyticsMetadata = Nothing
                }

        challengeCmd =
            challengeRequest
                |> AWS.Core.Http.sendUnsigned (CIP.service region)
                |> Task.attempt RespondToChallengeResponse
    in
    ( AuthState.toResponding challengeSpec state, challengeCmd )



-- Functions for building and executing the refresh cycle task.


second : Int
second =
    1000


delayedRefreshCmd : Authenticated -> Cmd Msg
delayedRefreshCmd model =
    tokenExpiryTask model.refreshFrom
        |> Task.attempt (\_ -> Refresh)


{-| A delay task that should end 30 seconds before the token is due to expire.
If the token expiry is less than 1 minute away, the delay is set to half of the remaining
time, which should be under 30 seconds.
The delay will expire immediately if the token expiry is already in the past.
-}
tokenExpiryTask : Posix -> Task.Task Never ()
tokenExpiryTask timeout =
    let
        safeInterval =
            30 * second

        delay posixBy posixNow =
            let
                by =
                    Time.posixToMillis posixBy

                now =
                    Time.posixToMillis posixNow
            in
            max ((by - now) // 2) (by - now - safeInterval)
                |> max 0
    in
    Time.now
        |> Task.andThen (\now -> Process.sleep <| toFloat (delay timeout now))



-- Authorising HTTP requests.


addAuthHeaders : model -> List Http.Header -> List Http.Header
addAuthHeaders model headers =
    headers
