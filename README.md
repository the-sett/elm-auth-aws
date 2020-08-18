**Contacts for Support**
- @rupertlssmith on https://elmlang.slack.com
- @rupert on https://discourse.elm-lang.org

# elm-auth-aws

To learn how to use this the best place is to look at the demo code. The demo authenticates against Amazon Cognito.

[the-sett/elm-auth-demo](https://github.com/the-sett/elm-auth-demo) - Demo authenticating against AWS Cognito.

# A simplified API for authentication.

The API specification is defined in the `the-sett/elm-auth` package.

[the-sett/elm-auth](https://github.com/the-sett/elm-auth) - An extensible API for authentication.

Cognito can authenticate a user and will provide a set of JWT tokens once this has successfully happened. 2 JWT tokens are issues, one for identity and the other for access. The identity token contains claims about the identity of the user, their email address, cognito user name and so on. The access token contains a list of scopes that define which protected resources may be accessed. This access token is usually the one used to determine if a caller is authorised to access some protected resource.

The `AuthAPI.addAuthHeaders` function adds set the access token in the HTTP Authorization header.

A simple authentication may be all that is required in order to access server side resources. This scenario is covered by a so-called resource server which adds scopes to the tokens and your back-end logic must check the token in order to verify these scopes in order to allow access to protected resource.

## Automatic access token refresh.

When the `LoggedIn` state is achieved, the `update` function will return a `Cmd` which is a timer task. When this timer
task expires, it automatically performes a refresh of the access token from the refresh token. The expiry interval is chosen to come 30 seconds before the access token expires, or half-way to the access token expiry, whichever is further
in the future.

# An extended API for Cognito.

## Amazon IAM Identities.

An authenticated user does not automatically obtain an Amazon IAM identity or access keys for such an identity. An additional step is needed to map a user identity to an IAM identity through a Cognito Identity pool.

The `CognitoAPI.getAWSCredentials` function requests that temporary AWS access credentials are created for a logged in user. The identity token is exchanged for a set of `AWS.Core.Credentials.Credentials` which can be used to sign requests to AWS services.

For a list of the various scenarios that Cognito can be used for, consult the AWS documentation available here:

https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-scenarios.html#scenario-aws-and-user-pool

## Challenges.

Cognito can respond to an authentication attempt with a set of challenges that need to be completed in order to succesfully authenticate. For example, a new account may be forced to set up a new password on the first logon.

The `CongitoAPI` provides functions for responding to such challenges, and the `Challenge` type lists all of the supported challenges.

## Failure reasons.

The API documents a set of `FailReason`s which closely follows the error types that AWS Cognito or Cognito Identity Provider APIs can generate. This allows the user of this authentication API to differentiate the ways in which authentication failures happen. Is
the password wrong, is the user not known, is the user not verified, does the users password 
need reset and so on. The `FailReason` also accounts for server errors on AWS.

## Save state and restoring auth.

This package provides these extra values and functions in its API over the standard auth API:

```elm
type alias AuthExtensions =
    { ...
    , saveState : Value
    }

type alias CognitoAPI =
    { ...
    , restore : Value -> Cmd Msg
    }
```

When the `LoggedIn` state is achieved, a JSON Value will be supplied that encodes the auth state in JSON. This
includes the refresh, identity and access tokens. A side effecting function is supplied in the API, to attempt to
restore the auth state to `LoggedIn` from this JSON data. This can be useful if refreshing the page when running
a single page app - as the auth state can be recovered for example from local storage and the user would not be forced
to log in again.

You need to consider the security implications of putting auth tokens in browser local storage. Note that this package
only supplies the JSON value, you would need to explicitly decide where to put the save state. An alternative to local
storage might be a web worker.

# Issues

It does not seem possible to authenticate and get back custom scopes in the access token. The only scope given back when using the implicit flow through the Cognito API seems to be `aws.cognito.signin.user.admin`, whether you ask for it or not. An OAuth flow through either the hosted UI or a third party provider seems to be necessary to get custom scopes.

It would be nice to do Oauth flows through third parties anyway. This seems sufficiently different that it would exist as a separate auth module in this package.

To have a custom UI and make use of custom scopes, it seems necessary to implement your own auth server that support the OAuth flows through OpenIDConnect.
