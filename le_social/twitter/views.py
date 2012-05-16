from __future__ import absolute_import

from ..oauth.views import OAuth1Authenticate, OAuth1Callback


class TwitterAuthenticate(OAuth1Authenticate):
    """An implementation of Twitter's OAuth1 "Sign In With Twitter"

    Get a request token and redirect to the service's authentication endpoint.

    For details, see https://dev.twitter.com/docs/auth/implementing-sign-twitter
    """
    def get_request_token_endpoint(self):
        return 'https://api.twitter.com/oauth/request_token'

    def get_authenticate_endpoint(self):
        return 'https://api.twitter.com/oauth/authenticate'


class TwitterCallback(OAuth1Callback):
    """An implementation of Twitter's OAuth1 "Sign In With Twitter"

    A base class for the return callback. Subclasses must define:

        - success(token, secret): logic for handling a successful authentication.
          Must return an HttpResponse.
        - error(error_msg, exception=None): logic for handling a failed
          authentication. Must return an HttpResponse.

    For details, see https://dev.twitter.com/docs/auth/implementing-sign-twitter
    """
    def get_access_token_endpoint(self):
        return 'https://api.twitter.com/oauth/access_token'
