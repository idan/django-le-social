from __future__ import absolute_import

from ..oauth.views import OAuth1Authenticate


class TwitterAuthenticate(OAuth1Authenticate):
    """An implementation of Twitter's OAuth1 "Sign In With Twitter
    """
    def get_request_token_endpoint(self):
        return 'https://api.twitter.com/oauth/request_token'
