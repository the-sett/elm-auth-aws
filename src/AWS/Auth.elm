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
import AWS.Tokens exposing (AccessToken, IdToken)
import AuthAPI exposing (AuthAPI, AuthInfo, Credentials, Status(..))
import AuthState exposing (Allowed, AuthState, Authenticated, ChallengeSpec)
import Codec exposing (Codec)
import Dict exposing (Dict)
import Dict.Refined
import Http
import Json.Decode as Decode exposing (Decoder)
import Json.Decode.Extra exposing (andMap, withDefault)
import Json.Encode as Encode exposing (Value)
import Jwt
import Process
import Refined
import Task
import Task.Extra
import Time exposing (Posix)



-- The Auth API implementation.


{-| An extended API for working with Cognito.

This provides the functions needed to response to Cognito challenges.

Note that this API, extends the base API defined in the `the-sett/elm-auth` package.

The `addAuthHeaders` function, adds an `Authorization : Bearer XXXX` header into
any set of HTTP headers given to it. Alternatively the extended `CognitoAPI` can
be used to obtain the raw access directly, if it needs to be used in a different
way.

-}
api : AuthAPI Config Model Msg AuthExtensions Challenge CognitoAPI FailReason
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
    , restore = restore
    }


{-| AWS Cognito specific API for:

  - Responding to challenges.
  - Obtaining temporary AWS access credentials (for signing requests).
  - Obtaining the raw or decoded id and access tokens.

-}
type alias CognitoAPI =
    { requiredNewPassword : String -> Cmd Msg
    , getAWSCredentials : Model -> Maybe AWS.Core.Credentials.Credentials
    , restore : Value -> Result String Model
    }


{-| Defines the extensions to the `AuthAPI.AuthInfo` fields that this
authenticator supports.

`saveState` provides a JSON serialized snapshot of the authenticated state. This
can be used with the `CognitoAPI.restore` function to attempt to re-create the
authenticated state without logging in again. Be aware that the save state will
contain sensitive information such as access tokens - so think carefully about
the security implications of where you put it. For example, local storage can be
compromised by XSS attacks, are you really sure your site is invulnerable to this?

-}
type alias AuthExtensions =
    { accessToken : String
    , decodedAccessToken : AccessToken
    , idToken : String
    , decodedIdToken : IdToken
    , saveState : Value
    }


{-| Gives a reason why the `Failed` state has been reached.
-}
type FailReason
    = FailReason


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

The `authHeaderName` field provides the name of the field into which the
`AuthAPI.addAuthHeaders` function will set the authentication token. Almost
always the `Authorization` header field is used.

The 'authHeaderPrefix' may provide a string with which the access token value is
prefixed in the header field. Patterns like 'Bearer XXX' or 'Token XXX' are common.
Note that the space will be automatically inserted between then prefix and the
token, if a prefix is provided - so `authHeaderPrefix = "Bearer"` will yield
`Bearer XXX`. If no prefix is provided just the token on its own will be set in
the header field.

-}
type alias Config =
    { clientId : String
    , region : Region
    , userIdentityMapping : Maybe UserIdentityMappingConfig
    , authHeaderName : String
    , authHeaderPrefix : Maybe String
    }


{-| Optional configuration needed to request temporary AWS credentials.
-}
type alias UserIdentityMappingConfig =
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
    , authHeaderName : String
    , authHeaderPrefix : Maybe String
    , innerModel : Private
    }


type alias UserIdentityMapping =
    { -- userPoolId : CI.UserPoolIdType
      identityPoolId : CI.IdentityPoolId
    , identityProviderName : CI.IdentityProviderName
    , accountId : CI.AccountId
    }


{-| The save state when LoggedIn. This can potentially be used to restore the
LoggedIn state.
-}
type alias SaveState =
    { clientId : CIP.ClientIdType
    , region : Region
    , accessToken : String
    , idToken : String
    , refreshToken : String
    , userIdentity : Maybe SavedUserIdentity
    }


type alias SavedUserIdentity =
    { mapping : UserIdentityMapping
    , credentials : AWS.Core.Credentials.Credentials
    }


saveStateCodec : Codec SaveState
saveStateCodec =
    Codec.object SaveState
        |> Codec.field "clientId" .clientId Codec.string
        |> Codec.field "region" .region Codec.string
        |> Codec.field "accessToken" .accessToken Codec.string
        |> Codec.field "idToken" .idToken Codec.string
        |> Codec.field "refreshToken" .refreshToken Codec.string
        |> Codec.optionalField "userIdentity" .userIdentity userIdentityMappingCodec
        |> Codec.buildObject


savedUserIdentityCodec : Codec SavedUserIdentity
savedUserIdentityCodec =
    Codec.object UserIdentityMapping
        |> Codec.field "mapping" .mapping userIdentityMappingCodec
        |> Codec.field "credentials" .credentials credentialsCodec
        |> Codec.buildObject


userIdentityMappingCodec : Codec UserIdentityMapping
userIdentityMappingCodec =
    Codec.object UserIdentityMapping
        |> Codec.field "identityPoolId" .identityPoolId Codec.string
        |> Codec.field "idProviderName" .identityProviderName Codec.string
        |> Codec.field "accountId" .accountId Codec.string
        |> Codec.buildObject


credentialsCodec : Codec Credentials
credentialsCodec =
    Codec.object
        (\accessKeyId secretAccessKey ->
            AWS.Core.Credentials.fromAccessKeys accessKeyId secretAccessKey
        )
        |> Codec.field "accessKeyId" AWS.Core.Credentials.accessKeyId
        |> Codec.field "secretAccessKey" AWS.Core.Credentials.secretAccessKey
        |> Codec.buildObject



--
--
-- userIdentityMappingEncoder : Maybe UserIdentityMapping -> Value
-- userIdentityMappingEncoder uid =
--     case uid of
--         Nothing ->
--             Encode.null
--
--         Just { mapping, credentials } ->
--             Encoder.object
--                 [ ( "mapping", userIdentityMappingEncoder mapping )
--                 , ( "credentials", credentialsEncoder credentials )
--                 ]


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
    | RequestAWSIdentityResponse (Result.Result Http.Error CI.GetIdResponse)
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
            case config.userIdentityMapping of
                Nothing ->
                    Ok
                        { clientId = clientId
                        , region = config.region
                        , userIdentityMapping = Nothing
                        , innerModel = Private AuthState.loggedOut
                        , authHeaderName = config.authHeaderName
                        , authHeaderPrefix = config.authHeaderPrefix
                        }

                Just userIdentityMapping ->
                    let
                        idMapping =
                            initIdentityMapping config.region userIdentityMapping
                    in
                    case idMapping of
                        Ok mapping ->
                            Ok
                                { clientId = clientId
                                , region = config.region
                                , userIdentityMapping = Just mapping
                                , innerModel = Private AuthState.loggedOut
                                , authHeaderName = config.authHeaderName
                                , authHeaderPrefix = config.authHeaderPrefix
                                }

                        Err strErr ->
                            Err strErr

        Err strErr ->
            "clientId " ++ Refined.stringErrorToString strErr |> Err


initIdentityMapping : Region -> UserIdentityMappingConfig -> Result String UserIdentityMapping
initIdentityMapping region userIdentityMapping =
    let
        idProviderString =
            "cognito-idp." ++ region ++ ".amazonaws.com/" ++ userIdentityMapping.userPoolId

        idProviderNameResult =
            Refined.build CI.identityProviderName idProviderString

        identityPoolIdResult =
            Refined.build CI.identityPoolId userIdentityMapping.identityPoolId

        accountIdResult =
            Refined.build CI.accountId userIdentityMapping.accountId
    in
    case idProviderNameResult of
        Ok idProviderName ->
            let
                _ =
                    Refined.encoder CI.identityProviderName idProviderName |> Encode.encode 0
            in
            case identityPoolIdResult of
                Ok identityPoolId ->
                    case accountIdResult of
                        Ok accountId ->
                            Ok
                                { identityPoolId = identityPoolId
                                , identityProviderName = idProviderName
                                , accountId = accountId
                                }

                        Err strErr ->
                            "accountId " ++ Refined.stringErrorToString strErr |> Err

                Err strErr ->
                    "identityPoolId " ++ Refined.stringErrorToString strErr |> Err

        Err strErr ->
            "userPoolId " ++ Refined.stringErrorToString strErr |> Err



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


{-| When in the `LoggedIn` state and if 'user id mapping' was requested by
providing a value for `Config.userIdentityMapping`, this will return the
AWS access credentials that were fetched from a Cognito Identity pool duing
the log in process.
-}
getAWSCredentials : Model -> Maybe AWS.Core.Credentials.Credentials
getAWSCredentials model =
    let
        tryGetCredentials state =
            AuthState.untag state |> .credentials
    in
    case model.innerModel of
        Private authState ->
            case authState of
                AuthState.LoggedIn state ->
                    tryGetCredentials state

                AuthState.Refreshing state ->
                    tryGetCredentials state

                _ ->
                    Nothing


restore : Value -> Result String Model
restore _ =
    Err "todo"



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
getStatus : AuthState -> Status AuthExtensions Challenge FailReason
getStatus authState =
    let
        extractAuth : AuthState.State p { m | auth : Authenticated } -> AuthInfo AuthExtensions
        extractAuth state =
            let
                authModel =
                    AuthState.untag state
            in
            { scopes = authModel.auth.scopes
            , subject = authModel.auth.subject
            , accessToken = Refined.unbox CIP.tokenModelType authModel.auth.accessToken
            , decodedAccessToken = authModel.auth.decodedAccessToken
            , idToken = Refined.unbox CIP.tokenModelType authModel.auth.idToken
            , decodedIdToken = authModel.auth.decodedIdToken
            , saveState = Encode.string "todo"
            }

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
            Failed FailReason

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
statusChange : AuthState -> AuthState -> Maybe (Status AuthExtensions Challenge FailReason)
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

        ( _, Failed _ ) ->
            Just newStatus

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
update : Msg -> Model -> ( Model, Cmd Msg, Maybe (Status AuthExtensions Challenge FailReason) )
update msg model =
    let
        authState =
            getAuthState model

        ( newAuthState, cmds ) =
            innerUpdate model.region model.clientId model.userIdentityMapping msg authState
    in
    ( setAuthState newAuthState model, cmds, statusChange authState newAuthState )


innerUpdate :
    Region
    -> CIP.ClientIdType
    -> Maybe UserIdentityMapping
    -> Msg
    -> AuthState
    -> ( AuthState, Cmd Msg )
innerUpdate region clientId userIdentityMapping msg authState =
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
            updateInitiateAuthResponse loginResult region userIdentityMapping state

        ( InitiateAuthResponse refreshResult, AuthState.Refreshing state ) ->
            updateInitiateAuthResponseForRefresh refreshResult state

        ( RespondToChallenge responseParams, AuthState.Challenged state ) ->
            updateRespondToChallenge region clientId responseParams state

        ( RespondToChallengeResponse challengeResult, AuthState.Responding state ) ->
            updateRespondToChallengeResponse challengeResult region userIdentityMapping state

        ( RequestAWSIdentityResponse idResponse, AuthState.RequestingId state ) ->
            updateRequestAWSIdentityResponse region userIdentityMapping idResponse state

        ( RequestAWSCredentialsResponse credentialsResponse, AuthState.RequestingCredentials state ) ->
            updateRequestAWSCredentialsResponse credentialsResponse state

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
    -> AuthState.State { a | refreshing : Allowed } { m | auth : Authenticated, credentials : Maybe AWS.Core.Credentials.Credentials }
    -> ( AuthState, Cmd Msg )
updateRefresh region clientId state =
    let
        auth =
            AuthState.untag state
                |> .auth

        credentials =
            AuthState.untag state
                |> .credentials

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
    ( AuthState.toRefreshing credentials state, authCmd )


updateInitiateAuthResponse :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> Region
    -> Maybe UserIdentityMapping
    -> AuthState.State { a | loggedIn : Allowed, requestingId : Allowed, failed : Allowed, challenged : Allowed } m
    -> ( AuthState, Cmd Msg )
updateInitiateAuthResponse loginResult region userIdentityMapping state =
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
                    handleAuthResult authResult region userIdentityMapping state


handleAuthResult :
    CIP.AuthenticationResultType
    -> Region
    -> Maybe UserIdentityMapping
    -> AuthState.State { a | loggedIn : Allowed, requestingId : Allowed, failed : Allowed } m
    -> ( AuthState, Cmd Msg )
handleAuthResult authResult region userIdentityMapping state =
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
                        |> Jwt.decode accessTokenDecoder

                decodedIdTokenResult =
                    rawIdToken
                        |> Jwt.decode idTokenDecoder
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
                    case userIdentityMapping of
                        Nothing ->
                            ( AuthState.toLoggedIn auth Nothing state
                            , delayedRefreshCmd auth
                            )

                        Just idMappingConfig ->
                            let
                                requestingIdState =
                                    AuthState.toRequestingId auth state
                            in
                            ( requestingIdState
                            , Cmd.batch
                                [ requestAWSIdentity region idMappingConfig auth
                                , delayedRefreshCmd auth
                                ]
                            )

                _ ->
                    failed state

        _ ->
            failed state


updateInitiateAuthResponseForRefresh :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> AuthState.State { a | loggedIn : Allowed } { m | auth : Authenticated, credentials : Maybe AWS.Core.Credentials.Credentials }
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
    -> AuthState.State { a | loggedIn : Allowed } { m | auth : Authenticated, credentials : Maybe AWS.Core.Credentials.Credentials }
    -> ( AuthState, Cmd Msg )
handleAuthResultForRefresh authResult state =
    case ( authResult.idToken, authResult.accessToken ) of
        ( Just idToken, Just accessToken ) ->
            let
                auth =
                    AuthState.untag state
                        |> .auth

                credentials =
                    AuthState.untag state
                        |> .credentials

                rawAccessToken =
                    Refined.unbox CIP.tokenModelType accessToken

                rawIdToken =
                    Refined.unbox CIP.tokenModelType idToken

                decodedAccessTokenResult =
                    rawAccessToken
                        |> Jwt.decode accessTokenDecoder

                decodedIdTokenResult =
                    rawIdToken
                        |> Jwt.decode idTokenDecoder
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
                        credentials
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
    -> Region
    -> Maybe UserIdentityMapping
    -> AuthState.State { a | loggedIn : Allowed, requestingId : Allowed, challenged : Allowed, failed : Allowed } { m | challenge : ChallengeSpec }
    -> ( AuthState, Cmd Msg )
updateRespondToChallengeResponse challengeResult region userIdentityMapping state =
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
                    handleAuthResult authResult region userIdentityMapping state


requestAWSIdentity :
    Region
    -> UserIdentityMapping
    -> Authenticated
    -> Cmd Msg
requestAWSIdentity region userIdentityMapping auth =
    let
        idToken =
            Refined.unbox CIP.tokenModelType auth.idToken

        idProviderTokenResult =
            Refined.build CI.identityProviderToken idToken
    in
    case idProviderTokenResult of
        Ok idProviderToken ->
            let
                loginsMap =
                    Refined.emptyDict CI.identityProviderName
                        |> Dict.Refined.insert userIdentityMapping.identityProviderName idProviderToken

                getIdRequest =
                    CI.getId
                        { logins = Just loginsMap
                        , identityPoolId = userIdentityMapping.identityPoolId
                        , accountId = Just userIdentityMapping.accountId
                        }

                getIdCmd =
                    getIdRequest
                        |> AWS.Core.Http.sendUnsigned (CI.service region)
                        |> Task.attempt RequestAWSIdentityResponse
            in
            getIdCmd

        _ ->
            Cmd.none


updateRequestAWSIdentityResponse :
    Region
    -> Maybe UserIdentityMapping
    -> Result Http.Error CI.GetIdResponse
    -> AuthState.State { a | requestingCredentials : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
updateRequestAWSIdentityResponse region maybeUserIdentityMapping idResponseResult state =
    case ( maybeUserIdentityMapping, idResponseResult ) of
        ( Just userIdentityMapping, Ok idResponse ) ->
            case idResponse.identityId of
                Just identityId ->
                    let
                        auth =
                            AuthState.untag state
                                |> .auth
                    in
                    ( AuthState.toRequestingCredentials auth identityId state
                    , requestAWSCredentials region userIdentityMapping identityId auth
                    )

                _ ->
                    reset

        _ ->
            reset


requestAWSCredentials :
    Region
    -> UserIdentityMapping
    -> CI.IdentityId
    -> Authenticated
    -> Cmd Msg
requestAWSCredentials region userIdentityMapping identityId auth =
    let
        idToken =
            Refined.unbox CIP.tokenModelType auth.idToken

        idProviderTokenResult =
            Refined.build CI.identityProviderToken idToken
    in
    case idProviderTokenResult of
        Ok idProviderToken ->
            let
                loginsMap =
                    Refined.emptyDict CI.identityProviderName
                        |> Dict.Refined.insert userIdentityMapping.identityProviderName idProviderToken

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


updateRequestAWSCredentialsResponse :
    Result Http.Error CI.GetCredentialsForIdentityResponse
    -> AuthState.State { a | loggedIn : Allowed } { m | auth : Authenticated }
    -> ( AuthState, Cmd Msg )
updateRequestAWSCredentialsResponse credentialsResponseResult state =
    case credentialsResponseResult of
        Ok credentialsResponse ->
            case credentialsResponse.credentials of
                Just credentials ->
                    let
                        auth =
                            AuthState.untag state
                                |> .auth
                    in
                    case ( credentials.accessKeyId, credentials.secretKey, credentials.sessionToken ) of
                        ( Just accessKeyId, Just secretKey, Just sessionToken ) ->
                            let
                                coreCredentials =
                                    AWS.Core.Credentials.fromAccessKeys accessKeyId secretKey
                                        |> AWS.Core.Credentials.setSessionToken sessionToken
                            in
                            ( AuthState.toLoggedIn auth (Just coreCredentials) state, Cmd.none )

                        _ ->
                            reset

                _ ->
                    reset

        _ ->
            reset



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


addAuthHeaders : Model -> List Http.Header -> List Http.Header
addAuthHeaders model headers =
    case getAccessToken model of
        Nothing ->
            headers

        Just val ->
            case model.authHeaderPrefix of
                Nothing ->
                    Http.header model.authHeaderName val
                        :: headers

                Just prefix ->
                    Http.header model.authHeaderName (prefix ++ " " ++ val)
                        :: headers


getAccessToken : Model -> Maybe String
getAccessToken model =
    getAuthenticated model
        |> Maybe.map .accessToken
        |> Maybe.map (Refined.unbox CIP.tokenModelType)


getAuthenticated : Model -> Maybe Authenticated
getAuthenticated model =
    let
        tryGetAuthenticated state =
            AuthState.untag state |> .auth
    in
    case model.innerModel of
        Private authState ->
            case authState of
                AuthState.LoggedIn state ->
                    tryGetAuthenticated state |> Just

                AuthState.Refreshing state ->
                    tryGetAuthenticated state |> Just

                AuthState.RequestingId state ->
                    tryGetAuthenticated state |> Just

                AuthState.RequestingCredentials state ->
                    tryGetAuthenticated state |> Just

                _ ->
                    Nothing



-- Decoders


accessTokenDecoder : Decoder AccessToken
accessTokenDecoder =
    Decode.succeed AccessToken
        |> andMap (Decode.field "sub" Decode.string)
        |> andMap (Decode.field "event_id" Decode.string)
        |> andMap (Decode.field "token_use" Decode.string)
        |> andMap (Decode.field "scope" Decode.string)
        |> andMap (Decode.field "auth_time" decodePosix)
        |> andMap (Decode.field "iss" Decode.string)
        |> andMap (Decode.field "exp" decodePosix)
        |> andMap (Decode.field "iat" decodePosix)
        |> andMap (Decode.field "jti" Decode.string)
        |> andMap (Decode.field "client_id" Decode.string)
        |> andMap (Decode.field "username" Decode.string)


idTokenDecoder : Decoder IdToken
idTokenDecoder =
    Decode.succeed IdToken
        |> andMap (Decode.field "sub" Decode.string)
        |> andMap (Decode.field "aud" Decode.string)
        |> andMap (Decode.field "event_id" Decode.string)
        |> andMap (Decode.field "token_use" Decode.string)
        |> andMap (Decode.field "auth_time" decodePosix)
        |> andMap (Decode.field "iss" Decode.string)
        |> andMap (Decode.field "cognito:username" Decode.string)
        |> andMap (Decode.field "exp" decodePosix)
        |> andMap (Decode.field "iat" decodePosix)
        |> andMap (Decode.field "email" Decode.string)


{-| Decodes an integer as a posix timestamp.
-}
decodePosix : Decoder Posix
decodePosix =
    Decode.map
        (Time.millisToPosix << (*) 1000)
        Decode.int



-- rawTokensToAuth : String -> String -> String -> Result String Authenticated
-- rawTokensToAuth rawAccessToken rawIdToken rawRefreshToken =
--     Result.map5
--         (\accessToken idToken refreshToken decodedAccessToken decodedIdToken ->
--             { subject = decodedAccessToken.sub
--             , scopes = [ decodedAccessToken.scope ]
--             , accessToken = accessToken
--             , idToken = idToken
--             , refreshToken = refreshToken
--             , decodedAccessToken = decodedAccessToken
--             , decodedIdToken = decodedIdToken
--             , expiresAt = decodedAccessToken.exp
--             , refreshFrom = decodedAccessToken.exp
--             }
--         )
--         (rawAccessToken |> Jwt.decode accessTokenDecoder)
--         (rawIdToken |> Jwt.decode idTokenDecoder)
