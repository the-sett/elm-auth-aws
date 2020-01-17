module AWS.Auth exposing
    ( Config, Model, Msg
    , api, AuthExtensions, Challenge(..), CognitoAPI
    )

{-| Manages the state of the authentication process, and provides an API
to request authentication operations.

@docs Config, Model, Msg
@docs api, AuthExtensions, Challenge, CognitoAPI

-}

import AWS.CognitoIdentity as CI
import AWS.CognitoIdentityProvider as CIP
import AWS.Core.Credentials
import AWS.Core.Http
import AWS.Core.Service exposing (Region, Service)
import AuthAPI exposing (AuthAPI, Credentials, Status(..))
import AuthState exposing (Allowed, AuthState, Authenticated, ChallengeSpec)
import Dict exposing (Dict)
import Dict.Refined
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


{-| An extended API for working with Cognito.

This provides the functions needed to response to Cognito challenges.

-}
api : AuthAPI Config Model Msg AuthExtensions Challenge CognitoAPI
api =
    { init = init
    , login = login
    , logout = logout
    , unauthed = unauthed
    , refresh = refresh
    , update = update
    , addAuthHeaders = addAuthHeaders
    , requiredNewPassword = requiredNewPassword
    , getAWSCredentials = getAWSCredentials
    }


{-| AWS Cognito specific API for:

  - Responding to challenges.
  - Obtaining temporary AWS access credentials (for signing requests).

-}
type alias CognitoAPI =
    { requiredNewPassword : String -> Cmd Msg
    , getAWSCredentials : Model -> Maybe AWS.Core.Credentials.Credentials
    }


{-| Defines the extensions to the `AuthAPI.Authenticated` fields that this
authenticator supports.
-}
type alias AuthExtensions =
    {}


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

The `userIdentityMapping` field is optional. Fill it in and a request to obtain
AWS credentials will be automatically made once logged in. That is to say that
the user will be mapped to an AWS IAM identity, which can be used to access
AWS services directly through request signing.

-}
type alias Config =
    { clientId : String
    , region : Region
    , userIdentityMapping : Maybe UserIdentityMapping
    }


{-| Optional configuration needed to request temporary AWS credentials.
-}
type alias UserIdentityMapping =
    { userPoolId : String
    , identityPoolId : String
    , accountId : String
    }


{-| The authentication model consisting of the evaluated config and the private state.
-}
type alias Model =
    { clientId : CIP.ClientIdType
    , region : Region
    , userIdentityMapping : Maybe UserIdentityMapping
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
    | SignOutResponse (Result.Result Http.Error CIP.GlobalSignOutResponse)
    | RespondToChallengeResponse (Result.Result Http.Error CIP.RespondToAuthChallengeResponse)
    | RequestAWSCredentialsResponse (Result.Result Http.Error CI.GetCredentialsForIdentityResponse)


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
                , region = config.region
                , userIdentityMapping = config.userIdentityMapping
                , innerModel = Private AuthState.loggedOut
                }

        Err strErr ->
            "clientId " ++ Refined.stringErrorToString strErr |> Err



-- Standard auth commands.


unauthed : Cmd Msg
unauthed =
    NotAuthed |> Task.Extra.message


logout : Cmd Msg
logout =
    LogOut |> Task.Extra.message


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


getAWSCredentials : Model -> Maybe AWS.Core.Credentials.Credentials
getAWSCredentials _ =
    Nothing



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
getStatus : AuthState -> Status AuthExtensions Challenge
getStatus authState =
    let
        extractAuth : AuthState.State p { m | auth : Authenticated } -> { scopes : List String, subject : String }
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

        AuthState.RequestingId _ ->
            LoggedOut

        AuthState.RequestingCredentials _ ->
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
statusChange : AuthState -> AuthState -> Maybe (Status AuthExtensions Challenge)
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
update : Msg -> Model -> ( Model, Cmd Msg, Maybe (Status AuthExtensions Challenge) )
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
    case ( msg, authState ) of
        ( LogIn credentials, AuthState.LoggedOut state ) ->
            updateLogin region clientId credentials state

        ( LogOut, AuthState.LoggedIn state ) ->
            updateLogout region state

        ( NotAuthed, _ ) ->
            reset

        ( Refresh, AuthState.LoggedIn state ) ->
            updateRefresh region clientId state

        ( InitiateAuthResponse loginResult, AuthState.Attempting state ) ->
            updateInitiateAuthResponse loginResult state

        ( InitiateAuthResponse refreshResult, AuthState.Refreshing state ) ->
            updateInitiateAuthResponseForRefresh refreshResult state

        ( RespondToChallenge responseParams, AuthState.Challenged state ) ->
            updateRespondToChallenge region clientId responseParams state

        ( RespondToChallengeResponse challengeResult, AuthState.Responding state ) ->
            updateRespondToChallengeResponse challengeResult state

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


updateLogout :
    Region
    -> AuthState.State { a | loggedOut : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
updateLogout region state =
    let
        auth =
            AuthState.untag state |> .auth

        logoutCmd =
            CIP.globalSignOut { accessToken = auth.accessToken }
                |> AWS.Core.Http.sendUnsigned (CIP.service region)
                |> Task.attempt SignOutResponse
    in
    ( AuthState.loggedOut, logoutCmd )


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

        refreshToken =
            Refined.unbox CIP.tokenModelType auth.refreshToken

        authParams =
            Dict.empty
                |> Dict.insert "REFRESH_TOKEN" refreshToken

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
    case loginResult of
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

                _ =
                    Jwt.extractTokenBody rawAccessToken
                        |> Debug.log "accessToken"

                rawIdToken =
                    Refined.unbox CIP.tokenModelType idToken

                _ =
                    Jwt.extractTokenBody rawIdToken
                        |> Debug.log "idToken"

                decodedAccessTokenResult =
                    rawAccessToken
                        |> Jwt.decode Tokens.accessTokenDecoder

                decodedIdTokenResult =
                    rawIdToken
                        |> Jwt.decode Tokens.idTokenDecoder
            in
            case ( decodedAccessTokenResult, decodedIdTokenResult ) of
                ( Ok decodedAccessToken, Ok decodedIdToken ) ->
                    let
                        auth =
                            { subject = decodedAccessToken.sub
                            , scopes = [ decodedAccessToken.scope ]
                            , accessToken = accessToken
                            , idToken = idToken
                            , refreshToken = refreshToken
                            , decodedAccessToken = decodedAccessToken
                            , decodedIdToken = decodedIdToken
                            , expiresAt = decodedAccessToken.exp
                            , refreshFrom = decodedAccessToken.exp
                            }
                    in
                    ( AuthState.toLoggedIn auth Nothing state
                    , delayedRefreshCmd auth
                    )

                _ ->
                    failed state

        _ ->
            failed state


updateInitiateAuthResponseForRefresh :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> AuthState.State { a | loggedIn : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
updateInitiateAuthResponseForRefresh loginResult state =
    case loginResult of
        Err httpErr ->
            reset

        Ok authResponse ->
            case authResponse.authenticationResult of
                Nothing ->
                    reset

                Just authResult ->
                    handleAuthResultForRefresh authResult state


handleAuthResultForRefresh :
    CIP.AuthenticationResultType
    -> AuthState.State { a | loggedIn : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
handleAuthResultForRefresh authResult state =
    case ( authResult.idToken, authResult.accessToken ) of
        ( Just idToken, Just accessToken ) ->
            let
                auth =
                    AuthState.untag state
                        |> .auth

                rawAccessToken =
                    Refined.unbox CIP.tokenModelType accessToken

                rawIdToken =
                    Refined.unbox CIP.tokenModelType idToken

                decodedAccessTokenResult =
                    rawAccessToken
                        |> Jwt.decode Tokens.accessTokenDecoder

                decodedIdTokenResult =
                    rawIdToken
                        |> Jwt.decode Tokens.idTokenDecoder
            in
            case ( decodedAccessTokenResult, decodedIdTokenResult ) of
                ( Ok decodedAccessToken, Ok decodedIdToken ) ->
                    ( AuthState.toLoggedIn
                        { auth
                            | subject = decodedAccessToken.sub
                            , scopes = [ decodedAccessToken.scope ]
                            , accessToken = accessToken
                            , idToken = idToken
                            , decodedAccessToken = decodedAccessToken
                            , decodedIdToken = decodedIdToken
                            , expiresAt = decodedAccessToken.exp
                            , refreshFrom = decodedAccessToken.exp
                        }
                        Nothing
                        state
                    , delayedRefreshCmd auth
                    )

                _ ->
                    reset

        _ ->
            reset


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


updateRespondToChallenge :
    Region
    -> CIP.ClientIdType
    -> Dict String String
    -> AuthState.State { a | responding : Allowed } { m | challenge : ChallengeSpec }
    -> ( AuthState, Cmd Msg )
updateRespondToChallenge region clientId responseParams state =
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


updateRespondToChallengeResponse :
    Result.Result Http.Error CIP.RespondToAuthChallengeResponse
    -> AuthState.State { a | loggedIn : Allowed, challenged : Allowed, failed : Allowed } { m | challenge : ChallengeSpec }
    -> ( AuthState, Cmd Msg )
updateRespondToChallengeResponse challengeResult state =
    case challengeResult of
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


updateRequestAWSCredentials :
    Region
    -> UserIdentityMapping
    -> AuthState.State a { m | auth : Authenticated }
    -> Cmd Msg
updateRequestAWSCredentials region userIdentityMapping state =
    let
        auth =
            AuthState.untag state
                |> .auth

        idToken =
            Refined.unbox CIP.tokenModelType auth.idToken

        idProviderString =
            "cognito-idp." ++ region ++ ".amazonaws.com/" ++ userIdentityMapping.userPoolId

        idProviderNameResult =
            Refined.build CI.identityProviderName idProviderString

        idProviderTokenResult =
            Refined.build CI.identityProviderToken idToken

        identityIdResult =
            --Refined.build CI.identityId userIdentityMapping.identityPoolId
            Err "Need to get an identity id first."
    in
    case ( identityIdResult, idProviderNameResult, idProviderTokenResult ) of
        ( Ok identityId, Ok idProviderName, Ok idProviderToken ) ->
            let
                loginsMap =
                    Refined.emptyDict CI.identityProviderName
                        |> Dict.Refined.insert idProviderName idProviderToken

                getCredentialsRequest =
                    CI.getCredentialsForIdentity
                        { logins = Just loginsMap
                        , identityId = identityId
                        , customRoleArn = Nothing
                        }

                credentialsCmd =
                    getCredentialsRequest
                        |> AWS.Core.Http.sendUnsigned (CI.service region)
                        |> Task.attempt RequestAWSCredentialsResponse
            in
            credentialsCmd

        _ ->
            Cmd.none



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
            max ((by - now) // 2) (by - now - safeInterval) |> max 0
    in
    Time.now |> Task.andThen (\now -> toFloat (delay timeout now) |> Process.sleep)



-- Authorising HTTP requests.


addAuthHeaders : model -> List Http.Header -> List Http.Header
addAuthHeaders model headers =
    headers
