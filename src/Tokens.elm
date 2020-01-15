module Tokens exposing (AccessToken, IdToken, accessTokenDecoder, idTokenDecoder)

import Json.Decode as Decode exposing (Decoder)
import Json.Decode.Extra exposing (andMap, withDefault)
import Time exposing (Posix)


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
