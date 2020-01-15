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
import Dict exposing (Dict)
import Http
import Json.Decode as Decode exposing (Decoder)
import Json.Decode.Extra exposing (andMap, withDefault)
import Jwt
import Refined
import Task
import Task.Extra
import Time exposing (Posix)



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
    = Uninitialized
    | RespondingToChallenges
        { session : CIP.SessionType
        , challenge : CIP.ChallengeNameType
        , parameters : CIP.ChallengeParametersType
        , username : String
        }
    | Authenticated
        { refreshToken : CIP.TokenModelType
        , idToken : CIP.TokenModelType
        , accessToken : CIP.TokenModelType
        }


{-| Cognito access token.
-}
type alias AccessToken =
    { sub : String
    , event_id : String
    , token_use : String
    , scope : String
    , auth_time : Posix
    , iss : String
    , exp : Posix
    , iat : Posix
    , jti : String
    , client_id : String
    , username : String
    }


{-| Cognito id token.
-}
type alias IdToken =
    { sub : String
    , aud : String
    , event_id : String
    , token_use : String
    , auth_time : Posix
    , iss : String
    , cognito_username : String
    , exp : Posix
    , iat : Posix
    , email : String
    }


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



-- | RefreshResponse (Result.Result Http.Error Model.AuthResponse)
-- | LogOutResponse (Result.Result Http.Error ())


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
                , innerModel = Uninitialized
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


failed model =
    ( model, Cmd.none, Just Failed )


noop model =
    ( model, Cmd.none, Nothing )


update : Msg -> Model -> ( Model, Cmd Msg, Maybe (Status Challenge) )
update msg model =
    case msg of
        LogIn credentials ->
            updateLogin credentials model

        RespondToChallenge responseParams ->
            case model.innerModel of
                RespondingToChallenges challengeState ->
                    updateChallengeResponse challengeState responseParams model

                _ ->
                    failed model

        InitiateAuthResponse loginResult ->
            updateInitiateAuthResponse loginResult model

        Refresh ->
            ( model, Cmd.none, Just LoggedOut )

        _ ->
            noop model


updateLogin : Credentials -> Model -> ( Model, Cmd Msg, Maybe (Status Challenge) )
updateLogin credentials model =
    let
        authParams =
            Dict.empty
                |> Dict.insert "USERNAME" credentials.username
                |> Dict.insert "PASSWORD" credentials.password

        authRequest =
            CIP.initiateAuth
                { userContextData = Nothing
                , clientMetadata = Nothing
                , clientId = model.clientId
                , authParameters = Just authParams
                , authFlow = CIP.AuthFlowTypeUserPasswordAuth
                , analyticsMetadata = Nothing
                }

        authCmd =
            authRequest
                |> AWS.Core.Http.sendUnsigned (CIP.service model.region)
                |> Task.attempt InitiateAuthResponse
    in
    ( model, authCmd, Nothing )


updateChallengeResponse :
    { s | session : CIP.SessionType, challenge : CIP.ChallengeNameType, username : String }
    -> Dict String String
    -> Model
    -> ( Model, Cmd Msg, Maybe (Status Challenge) )
updateChallengeResponse { session, challenge, username } responseParams model =
    let
        preparedParams =
            Dict.insert "USERNAME" username responseParams

        challengeRequest =
            CIP.respondToAuthChallenge
                { userContextData = Nothing
                , session = Just session
                , clientId = model.clientId
                , challengeResponses = Just preparedParams
                , challengeName = CIP.ChallengeNameTypeNewPasswordRequired
                , analyticsMetadata = Nothing
                }

        challengeCmd =
            challengeRequest
                |> AWS.Core.Http.sendUnsigned (CIP.service model.region)
                |> Task.attempt RespondToChallengeResponse
    in
    ( model, challengeCmd, Nothing )


updateInitiateAuthResponse :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> Model
    -> ( Model, Cmd Msg, Maybe (Status Challenge) )
updateInitiateAuthResponse loginResult model =
    case Debug.log "loginResult" loginResult of
        Err httpErr ->
            failed model

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
                            handleChallenge session parameters challengeType model

                        ( _, _, _ ) ->
                            failed model

                Just authResult ->
                    handleAuthResult authResult model


handleAuthResult : CIP.AuthenticationResultType -> Model -> ( Model, Cmd Msg, Maybe (Status Challenge) )
handleAuthResult authResult model =
    case ( authResult.refreshToken, authResult.idToken, authResult.accessToken ) of
        ( Just refreshToken, Just idToken, Just accessToken ) ->
            let
                _ =
                    Refined.unbox CIP.tokenModelType accessToken
                        |> Jwt.decode accessTokenDecoder
                        |> Debug.log "accessToken"

                _ =
                    Refined.unbox CIP.tokenModelType idToken
                        |> Jwt.decode idTokenDecoder
                        |> Debug.log "idToken"
            in
            ( { model
                | innerModel =
                    Authenticated
                        { refreshToken = refreshToken
                        , idToken = idToken
                        , accessToken = accessToken
                        }
              }
            , Cmd.none
            , LoggedIn { scopes = [], subject = "" }
                |> Just
            )

        _ ->
            failed model


handleChallenge :
    CIP.SessionType
    -> Dict String String
    -> CIP.ChallengeNameType
    -> Model
    -> ( Model, Cmd Msg, Maybe (Status Challenge) )
handleChallenge session parameters challengeType model =
    let
        maybeUsername =
            Dict.get "USER_ID_FOR_SRP" parameters
    in
    case ( challengeType, maybeUsername ) of
        ( CIP.ChallengeNameTypeNewPasswordRequired, Just username ) ->
            ( { model
                | innerModel =
                    RespondingToChallenges
                        { session = session
                        , challenge = challengeType
                        , parameters = parameters
                        , username = username
                        }
              }
            , Cmd.none
            , Challenged NewPasswordRequired |> Just
            )

        _ ->
            failed model



-- Authorising HTTP requests.


addAuthHeaders : model -> List Http.Header -> List Http.Header
addAuthHeaders model headers =
    headers



-- Codecs for JWT Tokens


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
