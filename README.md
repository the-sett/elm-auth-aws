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

# An extended API for Cognito.

## Amazon IAM Identities.

An authenticated user does not automatically obtain an Amazon IAM identity or access keys for such an identity. An additional step is needed to map a user identity to an IAM identity through a Cognito Identity pool.

The `CognitoAPI.getAWSCredentials` function requests that temporary AWS access credentials are created for a logged in user. The identity token is exchanged for a set of `AWS.Core.Credentials.Credentials` which can be used to sign requests to AWS services.

For a list of the various scenarios that Cognito can be used for, consult the AWS documentation available here:

https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-scenarios.html#scenario-aws-and-user-pool

## Challenges.

Cognito can respond to an authentication attempt with a set of challenges that need to be completed in order to succesfully authenticate. For example, a new account may be forced to set up a new password on the first logon.

The `CongitoAPI` provides functions for responding to such challenges, and the `Challenge` type lists all of the supported challenges.
