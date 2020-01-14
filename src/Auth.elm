module Auth exposing
    ( Config, Credentials, Status(..)
    , login, refresh, logout, unauthed
    , Model, Msg, init, update
    , Challenge(..), requiredNewPassword
    )

{-| Manages the state of the authentication process, and provides an API
to request authentication operations.

@docs Config, Credentials, Status
@docs login, refresh, logout, unauthed
@docs Model, Msg, init, update

@docs Challenge, requiredNewPassword

-}

import AWS.CognitoIdentityProvider as CIP
import AWS.Core.Credentials
import AWS.Core.Http
import AWS.Core.Service exposing (Region, Service)
import Dict exposing (Dict)
import Http
import Jwt exposing (Token)
import Refined
import Task
import Task.Extra


{-| The configuration specifying the API root to authenticate against.
-}
type alias Config =
    { clientId : String
    , userPoolId : String
    , region : Region
    }


{-| Username and password based login credentials.
-}
type alias Credentials =
    { username : String
    , password : String
    }


type alias Model =
    { clientId : CIP.ClientIdType
    , userPoolId : String
    , region : Region
    , innerModel : Private
    }


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


type Status
    = LoggedOut
    | Failed
    | LoggedIn { scopes : List String, subject : String }
    | Challenged Challenge


type Challenge
    = NewPasswordRequired



-- | SmsMfa
-- | SoftwareTokenMfa
-- | SelectMfaType
-- | MfaSetup
-- | PasswordVerifier
-- | CustomChallenge
-- | DeviceSrpAuth
-- | DevicePasswordVerifier
-- | AdminNoSrpAuth


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


update : Msg -> Model -> ( Model, Cmd Msg, Maybe Status )
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


updateLogin : Credentials -> Model -> ( Model, Cmd Msg, Maybe Status )
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
                |> AWS.Core.Http.sendUnsigned (cipService model.region)
                |> Task.attempt InitiateAuthResponse
    in
    ( model, authCmd, Nothing )


updateChallengeResponse :
    { s | session : CIP.SessionType, challenge : CIP.ChallengeNameType, username : String }
    -> Dict String String
    -> Model
    -> ( Model, Cmd Msg, Maybe Status )
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
                |> AWS.Core.Http.sendUnsigned (cipService model.region)
                |> Task.attempt RespondToChallengeResponse
    in
    ( model, challengeCmd, Nothing )


updateInitiateAuthResponse :
    Result.Result Http.Error CIP.InitiateAuthResponse
    -> Model
    -> ( Model, Cmd Msg, Maybe Status )
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


handleAuthResult : CIP.AuthenticationResultType -> Model -> ( Model, Cmd Msg, Maybe Status )
handleAuthResult authResult model =
    case ( authResult.refreshToken, authResult.idToken, authResult.accessToken ) of
        ( Just refreshToken, Just idToken, Just accessToken ) ->
            let
                _ =
                    Refined.unbox CIP.tokenModelType accessToken
                        |> Jwt.decodeWithErrors
                        |> Debug.log "accessToken"

                _ =
                    Refined.unbox CIP.tokenModelType idToken
                        |> Jwt.decodeWithErrors
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
    -> ( Model, Cmd Msg, Maybe Status )
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


{-| Provides the service handle for a specified region.
-}
cipService : String -> Service
cipService awsRegion =
    CIP.service awsRegion
