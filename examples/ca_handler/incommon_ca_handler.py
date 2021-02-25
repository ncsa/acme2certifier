#!/usr/bin/python
# -*- coding: utf-8 -*-
""" customized CA handler for InCommon"""
from __future__ import print_function
import requests
import json
# pylint: disable=E0401
from acme.helper import b64_decode, b64_encode, load_config, cert_pem2der
import time
import pem

class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.parameter = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.parameter:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cert_fetch(self,sslId):
        headers = {
        'login'         : self.api_user,
        'password'      : self.api_passwd,
        'customerUri'   : self.customer_uri,
        'Content-Type'  : 'application/json'
        }
        
        #Add a wait timer so sectigo can process a cert; this usually takes around 15-20 seconds
        time.sleep(30)
        response = requests.get('https://cert-manager.com/api/ssl/v1/collect/'+sslId+'/'+'x509', headers=headers)
        
        return response.text
        
    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        self.api_user = config_dic['CAhandler']['api_user']
        self.api_passwd = config_dic['CAhandler']['api_passwd']
        self.org_id = config_dic['CAhandler']['org_id']
        self.customer_uri = config_dic['CAhandler']['customer_uri']
        self.cert_type = config_dic['CAhandler']['certType'] 
        self.number_servers = config_dic['CAhandler']['numberServers']
        self.server_type = config_dic['CAhandler']['serverType']
        self.term = config_dic['CAhandler']['term']
        
        self.logger.debug('CAhandler._config_load() ended')


    def _stub_func(self, parameter):
        """" load config from file """
        self.logger.debug('CAhandler._stub_func({0})'.format(parameter))
        self.logger.debug('CAhandler._stub_func() ended')


    def enroll(self, csr):
        """ enroll certificate  """
        self.logger.debug('Incommon CAhandler.enroll()')
        self._config_load()
        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None
        self._stub_func(csr)
        self.csr = csr
        
        self.logger.debug(csr)
        
        headers = {
        'login'         : self.api_user,
        'password'      : self.api_passwd,
        'customerUri'   : self.customer_uri,
        'Content-Type'  : 'application/json'
        }
        
        info = {
        "orgId"         : self.org_id,
        "csr"           : self.csr,
        "certType"      : self.cert_type,
        "numberServers" : self.number_servers,
        "serverType"    : self.server_type,
        "term"          : 398,
        "comments"      : "issued by ncsa-cert-mgr"
        }
        
        data = json.dumps(info)
        try :
            self.logger.debug("Connecting to InCommon cert-manager ...")
            response=requests.post('https://cert-manager.com/api/ssl/v1/enroll/', headers=headers, data=data)

        except BaseException as e:
            self.logger.debug("Error occured while connecting with incommon cert-manager")
            error = 'Error occured during certificate Enrollment with InCommon cert-manager'
            self.logger.debug(e)
        
        json_response = json.loads(response.text)
        rawdata = self._cert_fetch(str(json_response['sslId']))
        self.logger.debug('Fetching certificate from InCommon (rawdata) : {0}'.format(rawdata))

        # Generating a certificate bundle in PEM file format is not needed here
        # InCommon responds with a certificate that is already base64 string encoded
        # InCommon responds with an All-In-One SSLCertificateFile. 
        # Root cert - Intermediate cert - Leaf cert (from top to bottom of response)
        # Apache & NGINX web-servers expect it in REVERSE order meaning, Leaf is first, then intermediate then root cert. 
        # We use the python pem package below to flip the order of certificate in the bundle before sending down the final response back to client
        # The client (which is using certbot) receives a fullchain.pem file which contains the cert bundle
        # End user will point their webserver config to this fullchain.pem file

        cert_bundle = rawdata
        poll_identifier = str(json_response['sslId'])

        self.logger.debug('Certificate.enroll() ended')
        
        return(error, cert_bundle, rawdata, poll_identifier)


    def poll(self, cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False
        self._stub_func(cert_name)

        self.logger.debug('CAhandler.poll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('Certificate.revoke() ended')
        return(code, message, detail)

    def trigger(self, payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None
        self._stub_func(payload)

        if payload:
            # decode payload
            cert = b64_decode(self.logger, payload)
            try:
                # cert is a base64 encoded pem object
                cert_raw = b64_encode(self.logger, cert_pem2der(cert))
            except BaseException:
                # cert is a binary der encoded object
                cert_raw = b64_encode(self.logger, cert)

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
