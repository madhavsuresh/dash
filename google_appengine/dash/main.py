#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#



import httplib2
import os
import re
import pickle
from apiclient.discovery import build
from oauth2client.appengine import CredentialsProperty
from oauth2client.appengine import StorageByKeyName
from google.appengine.ext.webapp import template
from oauth2client.client import OAuth2WebServerFlow
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import db
import webapp2
import simplejson
from google.appengine.ext.webapp.util import login_required
from apiclient import errors

keys = ['timestamp','fname','lname','email', 'school','major','gyear','ptitle', 'discp', 
'biosub', 'chemsub', 'groupmem', 'advis_affil', 'advis_email', 'advis_attn_bool',
'abstract', 'pref_session', 'other_req','oral_why','oral_or_poster','yes_oral']


FLOW = OAuth2WebServerFlow(
    # Visit https://code.google.com/apis/console to
    # generate your client_id, client_secret and to
    # register your redirect_uri.
    client_id='498598150569-l4j2hb8hk7un623umt9vi4q6bdqii52b.apps.googleusercontent.com',
    client_secret='IVCRnv4UJ6UinsNHOA8Du9jG',
    scope='https://www.googleapis.com/auth/drive',
    user_agent='calendarnews/alpha')

class Credentials(db.Model):
  credentials = CredentialsProperty()

class Presenter(db.Model):
    timestamp = db.TimeProperty()
    fname = db.StringProperty()
    lname = db.StringProperty()
    email = db.EmailProperty()
    school = db.StringProperty()
    major = db.StringProperty()
    gyear = db.IntegerProperty()
    ptitle = db.StringProperty()
    discp = db.StringProperty()
    biosub = db.StringProperty()
    chemsub = db.StringProperty()
    groupmem = db.StringProperty()
    advis_affil = db.StringProperty()
    advis_email = db.EmailProperty()
    advis_attn_bool = db.BooleanProperty()
    abstract = db.TextProperty()
    pref_session = db.StringProperty()
    other_req = db.StringProperty()
    oral_why = db.TextProperty()



def retrieve_file_by_name(service, name):
  """Retrieve a list of File resources.

  Args:
    service: Drive API service instance.
  Returns:
    List of File resources.
  """
  result = []
  page_token = None
  while True:
    try:
      param = {}
#      param['q'] = "title='" + name + "'"
      param['q'] = "title='CAURS 2013 Student Registration'"
      print param['q']
      if page_token:
        param['pageToken'] = page_token
      files = service.files().list(**param).execute()

      result.extend(files['items'])
      page_token = files.get('nextPageToken')
      if not page_token:
        break
    except errors.HttpError, error:
      print 'An error occurred: %s' % error
      break
  return result



def get_file(service,file_id):
    try:
        f = service.files().get(fileId=file_id).execute()
        return f
    except errors.HttpError, error:
        print 'An error occured: %s' % error 


def download_file(service,drive_file):
    download_url = drive_file.get('exportLinks')
    if download_url:
        tsv = download_url['application/pdf'][:-3] + 'tsv'
        print tsv
        resp,cont = service._http.request(tsv)
        if resp.status == 200:
            print 'Status: %s' % resp 
            return cont
        else:
            print 'An error occured %s' % resp 
            return None
    else:
        print 'wat'
        print drive_file
        return None

def read_into_db(string):

    lines = string.split('\n')
    print keys
    print len(keys)
    lines = lines[1:]
    for line in lines:
        x = line.split('\t')
        add_presenter_fsv_zip(dict(zip(keys,x)))
        #reg_list.append(dict(zip(keys,x)))


def add_presenter_fsv_zip(fsv_zip):
    p = Presenter()
    p.fname = fsv_zip['fname']
    p.lname = fsv_zip['lname']
    p.email = fsv_zip['email']
    p.school = fsv_zip['school']
    p.major = fsv_zip['major']

    pat = re.compile('\d{}$')
    match = pat.findall(fsv_zip['gyear'])
    if match:
        p.gyear = match[0]

    p.ptitle = fsv_zip['ptitle']
    p.discp = fsv_zip['discp']
    p.biosub = fsv_zip['biosub']
    p.chemsub = fsv_zip['chemsub']
    p.groupmem = fsv_zip['groupmem']
    try:
        p.advis_affil = unicode(fsv_zip['advis_affil'],'utf-8')
    except UnicodeDecodeError:
        p.advis_affil = unicode(fsv_zip['advis_affil'],errors='ignore')

    p.advis_email = fsv_zip['advis_email']
    p.advis_attn_bool = True if fsv_zip['advis_attn_bool'] == 'Yes' else False

    try:
        p.abstract = unicode(fsv_zip['abstract'],'utf-8')
    except UnicodeDecodeError:
        p.abstract = unicode(fsv_zip['abstract'],errors='ignore')

    p.pref_session = fsv_zip['pref_session']
    p.other_req = fsv_zip['other_req']

    try:
        p.oral_why = unicode(fsv_zip['oral_why'],'utf-8')
    except UnicodeDecodeError:
        p.abstract = unicode(fsv_zip['oral_why'],errors='ignore')
    p.put()


class MainHandler(webapp2.RequestHandler):

  @login_required
  def get(self):
    service = None
    user = users.get_current_user()
    user_id = user.user_id()
    credentials = StorageByKeyName(
        Credentials,user_id, 'credentials').get()

    if credentials is None or credentials.invalid == True:
      callback = self.request.relative_url('/oauth2callback')
      authorize_url = FLOW.step1_get_authorize_url(callback)
      memcache.set(user_id + 'goog', pickle.dumps(FLOW))
      return self.redirect(authorize_url)
    else:
      http = httplib2.Http()
      http = credentials.authorize(http)
      service = build("drive", "v2", http=http)

        
    file_entry = retrieve_file_by_name(service,'SleepTime by.txt')[0]
    print type(file_entry)
    #print file_entry['exportLinks']['application/pdf']
    #f = get_file(service,file_entry['id'])
    tsv_data = download_file(service,file_entry)
    read_into_db(tsv_data)

    self.response.write('Hello world!')




class OAuthHandler(webapp2.RequestHandler):

  @login_required
  def get(self):
    user = users.get_current_user()
    flow = pickle.loads(memcache.get(user.user_id() + 'goog'))
    if flow:
      credentials = flow.step2_exchange(self.request.params)
      StorageByKeyName(
          Credentials, user.user_id(), 'credentials').put(credentials)
      self.redirect("/calendarnews")
    else:
      pass


app = webapp2.WSGIApplication([
    ('/calendarnews', MainHandler),
    ('/oauth2callback', OAuthHandler),
    ],
    debug=True)
