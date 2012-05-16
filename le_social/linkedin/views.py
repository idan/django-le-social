from __future__ import absolute_import

from ..oauth.views import OAuth1Authenticate, OAuth1Callback


class LinkedInAuthenticate(OAuth1Authenticate):
    """An implementation of LinkedIn OAuth1 "Login with LinkedIn" flow.

    Get a request token and redirect to the service's authentication endpoint.

    For details, see https://developer.linkedin.com/documents/linkedins-oauth-details
    """
    def get_request_token_endpoint(self):
        return 'https://api.linkedin.com/uas/oauth/requestToken'

    def get_authenticate_endpoint(self):
        return 'https://api.linkedin.com/uas/oauth/authenticate'


class LinkedInCallback(OAuth1Callback):
    """An implementation of LinkedIn OAuth1 "Login with LinkedIn" flow.

    A base class for the return callback. Subclasses must define:

        - success(token, secret): logic for handling a successful authentication.
          Must return an HttpResponse.
        - error(error_msg, exception=None): logic for handling a failed
          authentication. Must return an HttpResponse.

    For details, see https://developer.linkedin.com/documents/linkedins-oauth-details
    """
    def get_access_token_endpoint(self):
        return 'https://api.linkedin.com/uas/oauth/accessToken'
