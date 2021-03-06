"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator
from uuid import uuid4

NAVER_HOST = 'https://nid.naver.com/oauth2.0'


def generate_state():
    state=str(uuid4())
    return state

class NaverMixin(OAuth2Mixin):
#how python use these urls?, Especially authorizing with parameters. Anyother apps also need parameters, but parameters are not explicitly written
    _OAUTH_AUTHORIZE_URL = "%s/authorize" % NAVER_HOST
    _OAUTH_ACCESS_TOKEN_URL = "%s/token" % NAVER_HOST


class NaverLoginHandler(OAuthLoginHandler, NaverMixin):
    pass


class NaverOAuthenticator(OAuthenticator):
    
    login_service = "Naver"
    
    # deprecated names
    naver_client_id = Unicode(config=True, help="DEPRECATED")
    def _naver_client_id_changed(self, name, old, new):
        self.log.warn("naver_client_id is deprecated, use client_id")
        self.client_id = new
    naver_client_secret = Unicode(config=True, help="DEPRECATED")
    def _naver_client_secret_changed(self, name, old, new):
        self.log.warn("naver_client_secret is deprecated, use client_secret")
        self.client_secret = new
    
    client_id_env = 'NAVER_CLIENT_ID'
    client_secret_env = 'NAVER_CLIENT_SECRET'
    login_handler = NaverLoginHandler
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/
        
        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code
        )
       #append ?a=b&c=d 
        url = url_concat("%s/token" % NAVER_HOST,
                         params)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "token {}".format(access_token)
        }
        req = HTTPRequest("https://openapi.naver.com/v1/nid/me",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["login"]
