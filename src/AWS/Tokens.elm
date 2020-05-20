module AWS.Tokens exposing (AccessToken, IdToken)

{-| Defines the decoded form that the AWS access and id tokens take.

@docs AccessToken, IdToken

-}

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
