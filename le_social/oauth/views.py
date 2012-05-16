from __future__ import absolute_import

import urlparse
import urllib

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect
from django.http import HttpResponseNotAllowed, HttpResponseServerError

from ..utils import generic

import requests
from requests.auth import OAuth1


# Valid OAuth1 Signature Types (from oauthlib)
OAUTH1_SIGNATURE_TYPES = (
    'auth_header',
    'query',
    'body'
)


class OAuth1Mixin(object):
    client_key = None
    client_secret = None
    resource_owner_key = None
    resource_owner_secret = None
    verifier = None

    # Must be one of OAUTH1_SIGNATURE_TYPES
    signature_type = None

    def get_client_key(self):
        if self.client_key is not None:
            return self.client_key
        if hasattr(settings, 'CLIENT_KEY'):
            return settings.CLIENT_KEY
        else:
            raise ImproperlyConfigured("Set settings.CLIENT_KEY or the "
                                       "client_key attribute or "
                                       "implement get_client_key")

    def get_client_secret(self):
        if self.client_secret is not None:
            return self.client_secret
        if hasattr(settings, 'CLIENT_SECRET'):
            return settings.CLIENT_SECRET
        else:
            raise ImproperlyConfigured("Set settings.CLIENT_SECRET or the "
                                       "client_secret attribute or "
                                       "implement get_client_secret")

    def get_signature_type(self):
        if self.signature_type is not None:
            return self.signature_type
        if hasattr(settings, 'OAUTH1_SIGNATURE_TYPE'):
            if settings.OAUTH1_SIGNATURE_TYPE in OAUTH1_SIGNATURE_TYPES:
                return settings.OAUTH1_SIGNATURE_TYPE
            else:
                raise ImproperlyConfigured("The signature type specified in "
                                           "settings.OAUTH1_SIGNATURE_TYPE is "
                                           "invalid.")
        else:
            raise ImproperlyConfigured("Set settings.OAUTH1_SIGNATURE_TYPE or the "
                                       "signature_type attribute or "
                                       "implement signature_type")

    def get_callback_uri(self):
        """Generate a callback URI

        If you really don't want a callback URI, override with a method which
        returns None.
        """
        raise NotImplementedError("You must provide an implementation of "
                                  "get_callback_uri()")

    def get_auth(self):
        return OAuth1(
            self.get_client_key(),
            client_secret=self.get_client_secret(),
            resource_owner_key=self.resource_owner_key,
            resource_owner_secret=self.resource_owner_secret,
            callback_uri=self.get_callback_uri(),
            signature_type=self.signature_type,
            verifier=self.verifier)


class OAuth1Authenticate(generic.View, OAuth1Mixin):
    """A base class for the authenthicate view.

    Get a request token and redirect to the service's.
    """
    def get(self, request, force_login=False, *args, **kwargs):
        oauth = self.get_auth()
        try:
            r = requests.post(self.get_request_token_endpoint(), auth=oauth)
        except requests.exceptions.RequestsException:
            # TODO: more meaningful handling of errors here.
            return self.error('An error occured while getting request tokens from the service.')

        if r.status_code != 200:
            # TODO: what should we do here?
            # can't proceed if we don't get request tokens from the service.
            return HttpResponseServerError()

        params = dict(urlparse.parse_qsl(r.content, strict_parsing=True))
        callback_confirmed = params.get('oauth_callback_confirmed', None)
        if not callback_confirmed:
            # TODO: more meaningful handling of missing/false
            raise Exception('Callback URL was not confirmed by the service.')

        request.session['request_tokens'] = (params['oauth_token'],
                                            params['oauth_token_secret'])
        redirect_params = {
            'oauth_token': params['oauth_token'],
            'force_login': str(force_login).lower()
        }

        scheme, netloc, path, query, fragment = urlparse.urlsplit(
            self.get_request_token_endpoint())

        if query != '':
            queryparams = dict(urlparse.parse_qsl(query, strict_parsing=True))
            redirect_params.update(queryparams)

        query = urllib.urlencode(redirect_params)

        url = urlparse.urlunsplit((scheme, netloc, path, query, fragment))
        return redirect(url)

    def get_request_token_endpoint(self):
        """Get the API endpoint for acquiring a request token."""
        raise NotImplementedError("You must provide an implementation of "
                                  "get_request_token_endopoint")

    def get_authenticate_endpoint(self):
        raise NotImplementedError("You must provide an implementation of "
                                  "get_authenticate_endpoint")

    def build_callback(self):
        """ Override this if you'd like to specify a callback URL"""
        return None


class OAuth1Callback(generic.View, OAuth1Mixin):
    """
    A base class for the return callback. Subclasses must define:

        - error(error_msg, exception=None): what to do when
          something goes wrong? Must return an HttpResponse

        - success(auth): what to do on successful auth? Do
          some stuff with the twitter.OAuth object and return
          an HttpResponse
    """
    def get(self, request, *args, **kwargs):
        if request.method != 'GET':
            # Invalid.
            return HttpResponseNotAllowed()

        oauth_token = request.GET.get('oauth_token', None)
        oauth_verifier = request.GET.get('oauth_verifier', None)

        if not oauth_verifier or oauth_token:
            return self.error('Callback OAuth parameters did not include a token and verifier.')

        request_token, request_token_secret = request.session.pop('request_tokens')
        request.session.modified = True

        if oauth_token != request_token:
            return self.error('Request token and returned OAuth token do not match.')

        self.verifier = oauth_verifier
        oauth = self.get_auth()
        try:
            r = requests.post(self.get_access_token_endpoint(), auth=oauth)
        except requests.exceptions.RequestsException as e:
            # TODO: more meaningful handling of errors here.
            return self.error('An error occured while exchanging request token '
                              'for access token.', e)

        if r.status_code != 200:
            # TODO: what should we do here?
            # can't proceed if we don't get access tokens from the service.
            return self.error('Access tokens were not successfully acquired.')

        params = dict(urlparse.parse_qsl(r.content, strict_parsing=True))
        resource_owner_key = params.get('oauth_token', None)
        resource_owner_secret = params.get('oauth_token_secret', None)
        if not resource_owner_key or resource_owner_secret:
            return self.error('Access token exchange did not return a token and secret.')

        return self.success(resource_owner_key, resource_owner_secret)

    def get_access_token_endpoint(self):
        """Get the API endpoint for acquiring a request token."""
        raise NotImplementedError("You must provide an implementation of "
                                  "get_access_token_endopoint")

    def success(self, key, secret):
        """
        Twitter authentication successful, do some stuff with his key.
        """
        raise NotImplementedError("You must provide an implementation of "
                                  "success(auth)")

    def error(self, message, exception=None):
        """
        Meh. Something broke.
        """
        raise NotImplementedError("You must provide an implementation of "
                                  "error(message, exception=None)")
