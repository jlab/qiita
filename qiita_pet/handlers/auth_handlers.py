# -----------------------------------------------------------------------------
# Copyright (c) 2014--, The Qiita Development Team.
#
# Distributed under the terms of the BSD 3-clause License.
#
# The full license is in the file LICENSE, distributed with this software.
# -----------------------------------------------------------------------------

from tornado.escape import url_escape, json_encode
from tornado.auth import OAuth2Mixin

import sys
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
import os

import urllib.parse
import json

from tornado.web import RequestHandler
from tornado.web import authenticated
from typing import Any, Dict
import urllib.parse
from tornado import escape, web

import json


from qiita_pet.handlers.base_handlers import BaseHandler
from qiita_core.qiita_settings import qiita_config, r_client
from qiita_core.util import execute_as_transaction
from qiita_core.exceptions import (IncorrectPasswordError, IncorrectEmailError,
                                   UnverifiedEmailError)
from qiita_db.util import send_email
from qiita_db.user import User
from qiita_db.exceptions import (QiitaDBUnknownIDError, QiitaDBDuplicateError,
                                 QiitaDBError)
# login code modified from https://gist.github.com/guillaumevincent/4771570


class AuthCreateHandler(BaseHandler):
    """User Creation"""
    def get(self):
        try:
            error_message = self.get_argument("error")
        # Tornado can raise an Exception directly, not a defined type
        except Exception:
            error_message = ""
        self.render("create_user.html", error=error_message)

    @execute_as_transaction
    def post(self):
        username = self.get_argument("email", "").strip().lower()
        password = self.get_argument("newpass", "")
        info = {}
        for info_column in ("name", "affiliation", "address", "phone"):
            hold = self.get_argument(info_column, None)
            if hold:
                info[info_column] = hold

        created = False
        try:
            created = User.create(username, password, info)
        except QiitaDBDuplicateError:
            msg = "Email already registered as a user"

        if created:
            info = created.info
            try:
                # qiita_config.base_url doesn't have a / at the end, but the
                # qiita_config.portal_dir has it at the beginning but not at
                # the end. This constructs the correct URL
                url = qiita_config.base_url + qiita_config.portal_dir
                send_email(username, "QIITA: Verify Email Address", "Please "
                           "click the following link to verify email address: "
                           "%s/auth/verify/%s?email=%s\n\nBy clicking you are "
                           "accepting our term and conditions: "
                           "%s/iframe/?iframe=qiita-terms"
                           % (url, info['user_verify_code'],
                              url_escape(username), url))
            except Exception:
                msg = ("Unable to send verification email. Please contact the "
                       "qiita developers at <a href='mailto:qiita.help"
                       "@gmail.com'>qiita.help@gmail.com</a>")
                self.redirect(u"%s/?level=danger&message=%s"
                              % (qiita_config.portal_dir, url_escape(msg)))
                return

            msg = ("<h3>User Successfully Created</h3><p>Your Qiita account "
                   "has been successfully created. An email has been sent to "
                   "the email address you provided. This email contains "
                   "instructions on how to activate your account.</p>"
                   "<p>If you don't receive your activation email within a "
                   "couple of minutes, check your spam folder. If you still "
                   "don't see it, send us an email at <a "
                   "href=\"mailto:qiita.help@gmail.com\">qiita.help@gmail.com"
                   "</a>.</p>")
            self.redirect(u"%s/?level=success&message=%s" %
                          (qiita_config.portal_dir, url_escape(msg)))
        else:
            error_msg = u"?error=" + url_escape(msg)
            self.redirect(u"%s/auth/create/%s"
                          % (qiita_config.portal_dir, error_msg))


class AuthVerifyHandler(BaseHandler):
    def get(self, code):
        email = self.get_argument("email").strip().lower()

        code_is_valid = False
        msg = "This code is not valid."

        # an exception is raised if the 'code type' is not available, otherwise
        # the method determines the validity of the code
        try:
            code_is_valid = User.verify_code(email, code, "create")
        except QiitaDBError:
            msg = "This user has already created an account."

        if code_is_valid:
            msg = "Successfully verified user. You are now free to log in."
            color = "black"
            r_client.zadd('qiita-usernames', {email: 0})
        else:
            color = "red"

        self.render("user_verified.html", msg=msg, color=color,
                    email=self.get_argument("email").strip())


class AuthLoginHandler(BaseHandler):
    """user login, no page necessary"""
    def get(self):
        self.redirect("%s/" % qiita_config.portal_dir)

    @execute_as_transaction
    def post(self):
        username = self.get_argument("username", "").strip().lower()
        passwd = self.get_argument("password", "")
        nextpage = self.get_argument("next", None)
        if nextpage is None:
            if "auth/" not in self.request.headers['Referer']:
                nextpage = self.request.headers['Referer']
            else:
                nextpage = "%s/" % qiita_config.portal_dir

        msg = ""
        # check the user level
        try:
            if User(username).level == "unverified":
                # email not verified so dont log in
                msg = ("Email not verified. Please check your email and click "
                       "the verify link. You may need to check your spam "
                       "folder to find the email.<br/>If a verification email"
                       " has not arrived in 15 minutes, please email <a href='"
                       "mailto:qiita.help@gmail.com'>qiita.help@gmail.com</a>")
        except QiitaDBUnknownIDError:
            msg = "Unknown user"
        except RuntimeError:
            # means DB not available, so set maintenance mode and failover
            r_client.set("maintenance", "Database connection unavailable, "
                         "please try again later.")
            self.redirect("%s/" % qiita_config.portal_dir)
            return

        # Check the login information
        login = None
        try:
            login = User.login(username, passwd)
        except IncorrectEmailError:
            msg = "Unknown user"
        except IncorrectPasswordError:
            msg = "Incorrect password"
        except UnverifiedEmailError:
            msg = "You have not verified your email address"

        if login:
            # everything good so log in
            self.set_current_user(username)
            self.redirect(nextpage)
        else:
            self.render("index.html", message=msg, level='danger')

    def set_current_user(self, user):
        if user:
            self.set_secure_cookie("user", json_encode(user), SameSite=None)
        else:
            self.clear_cookie("user")



class KeycloakMixin(OAuth2Mixin):
    _OIDC_CLIENT_ID = '%s' % qiita_config.oidc_clients['KEYCLOAK_1']['OIDC_CLIENT_ID']
    _OIDC_CLIENT_SECRET = '%s' % qiita_config.oidc_clients['KEYCLOAK_1']['OIDC_CLIENT_SECRET']
    _OAUTH_ACCESS_TOKEN_URL = '%s' % qiita_config.oidc_clients['KEYCLOAK_1']['OAUTH_ACCESS_TOKEN_URL']
    _OAUTH_AUTHORIZE_URL = '%s' % qiita_config.oidc_clients['KEYCLOAK_1']['OAUTH_AUTHORIZE_URL']
    _OAUTH_USERINFO_URL = '%s' % qiita_config.oidc_clients['KEYCLOAK_1']['OAUTH_USERINFO_URL']

    def change_settings(self, identity_provider):
        self.__class__._OIDC_CLIENT_ID = '%s' % qiita_config.oidc_clients[f'{identity_provider}']['OIDC_CLIENT_ID']
        self.__class__._OIDC_CLIENT_SECRET = '%s' % qiita_config.oidc_clients[f'{identity_provider}']['OIDC_CLIENT_SECRET']
        self.__class__._OAUTH_ACCESS_TOKEN_URL = '%s' % qiita_config.oidc_clients[f'{identity_provider}']['OAUTH_ACCESS_TOKEN_URL']
        self.__class__._OAUTH_AUTHORIZE_URL = '%s' % qiita_config.oidc_clients[f'{identity_provider}']['OAUTH_AUTHORIZE_URL']
        self.__class__._OAUTH_USERINFO_URL = '%s' % qiita_config.oidc_clients[f'{identity_provider}']['OAUTH_USERINFO_URL']

    async def get_authenticated_user(
        self, redirect_uri: str, code: str
    ) -> Dict[str, Any]:
        
        http = self.get_auth_http_client()
        body = urllib.parse.urlencode(
            {
                "redirect_uri": redirect_uri,
                "code": code,
                "client_id": self._OIDC_CLIENT_ID,
                "client_secret": self._OIDC_CLIENT_SECRET,
                "grant_type": "authorization_code"
            }
        )
        response = await http.fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return escape.json_decode(response.body)

class AuthLoginOIDCHandler(BaseHandler, KeycloakMixin):
    SUPPORTED_METHODS = ("CONNECT", "GET", "HEAD", "POST", "DELETE", "PATCH", "PUT", "OPTIONS")

    async def get(self, login):
        code = self.get_argument('code', False)
        if code:
            # get OIDC IP from URI
            provider = self.path_args[0]
            # change Keycloak settings to match for authenticated user
            self.change_settings(provider)
            access = await self.get_authenticated_user(
                redirect_uri='%s/auth/login_OIDC/%s' % (qiita_config.base_url, provider),
                code=self.get_argument('code')
            )
            access_token = access['access_token']
            if not access_token:
                raise web.HTTPError(400, "failed to get access token")
            user_info_req = HTTPRequest(
                self._OAUTH_USERINFO_URL,
                method="GET",
                headers={
                    "Accept": "application/json",
                    "Authorization": "Bearer {}".format(access_token)
                },
            )

            http_client = AsyncHTTPClient()
            user_info_res = await http_client.fetch(user_info_req, raise_error=False)
            user_info_res_json = json.loads(user_info_res.body.decode('utf8', 'replace'))
            print("  user info: %s" % user_info_res, file=sys.stderr)
            username = user_info_res_json['email']

            if not User.exists(username):
                self.create_new_user(username)
            else:
                self.not_verified(username)

                self.set_secure_cookie("user", username)
                self.set_secure_cookie("token", access_token)

            self.redirect('%s/' % qiita_config.base_url)


        else:
            #fetch requested client name from button call
            for client in qiita_config.oidc_clients.keys():
                if self.get_argument(f'{client}', None) is not None:
                    provider = client
                else:
                    pass

            self.authorize_redirect(
                 redirect_uri='%s/auth/login_OIDC/%s' % (qiita_config.base_url, provider),
                 client_id='%s' % qiita_config.oidc_clients[f'{provider}']['OIDC_CLIENT_ID'],
                 client_secret='%s' % qiita_config.oidc_clients[f'{provider}']['OIDC_CLIENT_SECRET'],
                 response_type='code',
                 scope=['openid']
            )
    post = get
   
    @execute_as_transaction
    def create_new_user(self, username):
        try:
            created = User.create_oidc(username)
        except QiitaDBDuplicateError:
            msg = "Email already registered as a user"
        if created:
            try:
                # qiita_config.base_url doesn't have a / at the end, but the
                # qiita_config.portal_dir has it at the beginning but not at
                # the end. This constructs the correct URL
                msg = (f"<h3>User Successfully Registered!</h3><p>Your Qiita account "
                            "has been successfully registered using the email address provided by your "
                            "chosen identity provider. Your account is now awaiting authorization "
                            "by a Qiita admin.</p>"
                            "<p>If you have any questions regarding the authorization process, please email us at <a "
                            "href=\"mailto:qiita.help@gmail.com\">qiita.help@gmail.com"
                            "</a>.</p>")

                self.redirect(u"%s/?level=success&message=%s" %
                            (qiita_config.portal_dir, url_escape(msg)))
            except Exception:
                msg = ("Unable to create account. Please contact the "
                                "qiita developers at <a href='mailto:qiita.help"
                                "@gmail.com'>qiita.help@gmail.com</a>")
                self.redirect(u"%s/?level=danger&message=%s"
                             % (qiita_config.portal_dir, url_escape(msg)))
                return
        else:
            error_msg = u"?error=" + url_escape(msg)
            self.redirect(u"%s/%s"
                            % (qiita_config.portal_dir, error_msg))
    
    def not_verified(self, username):
        user = User(username)
        if user.level == "unverified":
            msg = ("You are not yet verified by an admin. Please wait or contact the "
                                "qiita developers at <a href='mailto:qiita.help"
                                "@gmail.com'>qiita.help@gmail.com</a>")
            self.redirect(u"%s/?level=danger&message=%s"
                             % (qiita_config.portal_dir, url_escape(msg)))
        else:
            return      

class AuthLogoutHandler(BaseHandler):
    """Logout handler, no page necessary"""
    def get(self):
        self.clear_cookie("user")
        self.redirect("%s/" % qiita_config.portal_dir)
