#!/usr/bin/env python

# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START imports]
import os
import urllib

from google.appengine.api import users
from google.appengine.ext import ndb

import jinja2
import webapp2

import json
import cgi

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)
    
from Crypto.PublicKey import RSA
import base64
# [END imports]

DEFAULT_GUESTBOOK_NAME = 'default_guestbook'


# We set a parent key on the 'Greetings' to ensure that they are all
# in the same entity group. Queries across the single entity group
# will be consistent. However, the write rate should be limited to
# ~1/second.

def guestbook_key(guestbook_name=DEFAULT_GUESTBOOK_NAME):
    """Constructs a Datastore key for a Guestbook entity.

    We use guestbook_name as the key.
    """
    return ndb.Key('Guestbook', guestbook_name)


# [START greeting]
class Author(ndb.Model):
    """Sub model for representing an author."""
    identity = ndb.StringProperty(indexed=False)
    email = ndb.StringProperty(indexed=False)


class Greeting(ndb.Model):
    """A main model for representing an individual Guestbook entry."""
    author = ndb.StructuredProperty(Author)
    content = ndb.StringProperty(indexed=False)
    date = ndb.DateTimeProperty(auto_now_add=True)
# [END greeting]


# [START constants]
PSEUDONYM_STORE_KEY = 'anonionmail_users'
MAIL_STORE_KEY = 'anonionmail_mails'
# [END constants]


# [START models]
class Anonionmail(ndb.Model):
    """Model for representing an email."""
    recipient = ndb.StringProperty(indexed=True)
    author = ndb.StringProperty(indexed=False)
    date = ndb.DateTimeProperty(auto_now_add=True)
    key = ndb.StringProperty(indexed=False)
    message = ndb.TextProperty(indexed=False)
    
    
class Pseudonym(ndb.Model):
    """Model for representing a user."""
    alias = ndb.StringProperty(indexed=True)
    pubkeymod = ndb.StringProperty(indexed=False)
    pubkeyexp = ndb.StringProperty(indexed=False)
    password = ndb.StringProperty(indexed=False)
# [END models]

# [START main_page]
class MainPage(webapp2.RequestHandler):

    def get(self):
        guestbook_name = self.request.get('guestbook_name',
                                          DEFAULT_GUESTBOOK_NAME)
        greetings_query = Greeting.query(
            ancestor=guestbook_key(guestbook_name)).order(-Greeting.date)
        greetings = greetings_query.fetch(10)

        user = users.get_current_user()
        if user:
            url = users.create_logout_url(self.request.uri)
            url_linktext = 'Logout'
        else:
            url = users.create_login_url(self.request.uri)
            url_linktext = 'Login'

        template_values = {
            'user': user,
            'greetings': greetings,
            'guestbook_name': urllib.quote_plus(guestbook_name),
            'url': url,
            'url_linktext': url_linktext,
        }
        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render(template_values))

    def post(self):
        

        self.response.headers['Content-Type'] = 'application/json'  
        
        def decrypt(base64cypher):
            key = open("key/anonionmail", "r").read()
            rsakey = RSA.importKey(key)
            raw_cipher_data = base64.b64decode(base64cypher)
            decrypted = rsakey.decrypt(raw_cipher_data)
            #remove padding
            pos = decrypted.rfind('\x00')
            if pos > 0:
                decrypted = decrypted[pos+1:]
            print decrypted
            return decrypted
        
        def error(msg):
            obj = {
                'type': 'error', 
                'message': msg,
            } 
            return json.dumps(obj)
            
        def alias(jdata):
            pname = decrypt(jdata['id'])
            pwhash = decrypt(jdata['pw'])
            mod = '1' #decrypt(jdata['pub']['modulus'])
            exp = '1' #decrypt(jdata['pub']['pubExp'])
            query = Pseudonym.query(Pseudonym.alias==pname)
            exists = query.get() is not None
            if not exists:
                p = Pseudonym(alias=pname, pubkeymod=mod,pubkeyexp=exp, password=pwhash) 
                p.put()
            
            obj = {
                'type': 'alias-response', 
                'result': not exists,
            } 
            self.response.out.write(json.dumps(obj))
            decrypt("DEADBEEF")
            return
            
        def keyreq(jdata):
            self.response.out.write(error("key request not implemented yet"))
            return
            
        def sendmail(jdata):
            self.response.out.write(error("send not implemented yet"))
            return
            
        def fetchmail(jdata):
            self.response.out.write(error("fetch not implemented yet"))
            return
            
        def login(jdata):
            query = Pseudonym.query(ancestor=PSEUDONYM_STORE_KEY).order(-Greeting.date)
            greetings = greetings_query.fetch(10)
            self.response.out.write(error("longin not implemented yet"))
            return
            
        def serverkey(jdata):
            key = open("key/anonionmail.pub", "r").read()
            rsakey = RSA.importKey(key)
            import struct
            print rsakey.n
            print rsakey.e
            print struct.pack("I", rsakey.e)
            obj = {
                'type': 'serverKey-response', 
                'pubKey': 
                {
                    "modulus":base64.b64encode(str(rsakey.n)),
                    "pubExp":base64.b64encode(str(rsakey.e))
                }
            } 
            
            self.response.out.write(json.dumps(obj))
            return
            
        types = {
            'alias-request' : alias,
            'public-key-request' : keyreq,
            'send-request' : sendmail,
            'fetch-request' : fetchmail,
            'login-request' : login,
            'serverKey-request' : serverkey,
        }
            
        try:
            incomming = cgi.escape(self.request.body)
            print incomming
            jdata = json.loads(incomming)
            reqtype = jdata['type']
            types[reqtype](jdata)
            print reqtype
        except Exception as err:
            print("error occured: {0}".format(err))
            self.response.out.write(error("due to security reasons no specific error message is provided"))
            return
            
        
        #self.response.out.write(json.dumps(obj))
        #self.response.write(cgi.escape(self.request.body))


# [END main_page]


# [START guestbook]
class Guestbook(webapp2.RequestHandler):

    def post(self):
        # We set the same parent key on the 'Greeting' to ensure each
        # Greeting is in the same entity group. Queries across the
        # single entity group will be consistent. However, the write
        # rate to a single entity group should be limited to
        # ~1/second.
        guestbook_name = self.request.get('guestbook_name',
                                          DEFAULT_GUESTBOOK_NAME)
        greeting = Greeting(parent=guestbook_key(guestbook_name))

        if users.get_current_user():
            greeting.author = Author(
                    identity=users.get_current_user().user_id(),
                    email=users.get_current_user().email())

        greeting.content = self.request.get('content')
        greeting.put()

        query_params = {'guestbook_name': guestbook_name}
        self.redirect('/?' + urllib.urlencode(query_params))
# [END guestbook]


# [START app]
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/sign', Guestbook),
], debug=True)
# [END app]
