#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
from acme.helper import decode_message, load_config, print_debug
from acme.error import Error
from acme.nonce import Nonce
from acme.signature import Signature

class Message(object):
    """ Message  handler """

    def __init__(self, debug=None, srv_name=None):
        self.debug = debug
        self.server_name = srv_name
        self.nonce = Nonce(self.debug)
        self.account_path = '/acme/acct/'
        self.nonce_check_disable = False
        self.load_config()

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def check(self, content):
        """ validate message """
        print_debug(self.debug, 'Message.check()')

        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(self.debug, content)
        if result:
            # decoding successful - check nonce for anti replay protection
            (code, message, detail) = self.nonce.check(protected)
            if self.nonce_check_disable:
                print('**** NONCE CHECK DISABLED!!! Security issue ****')
                code = 200

            if code == 200:
                # nonce check successful - check signature
                account_name = self.name_get(protected)
                signature = Signature(self.debug)
                (sig_check, error, error_detail) = signature.check(content, account_name)
                if sig_check:
                    code = 200
                    message = None
                    detail = None
                else:
                    code = 403
                    message = error
                    detail = error_detail
        else:
            # message could not get decoded
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        return(code, message, detail, protected, payload)

    def load_config(self):
        """" load config from file """
        print_debug(self.debug, 'load_config()')
        config_dic = load_config()
        if 'Nonce' in config_dic:
            self.nonce_check_disable = config_dic.getboolean('Nonce', 'nonce_check_disable')

    def name_get(self, content):
        """ get id for account """
        print_debug(self.debug, 'Message.name_get()')
        if 'kid' in content:
            print_debug(self.debug, 'kid: {0}'.format(content['kid']))
            kid = content['kid'].replace('{0}{1}'.format(self.server_name, self.account_path), '')
            if '/' in kid:
                kid = None
        else:
            kid = None
        print_debug(self.debug, 'Message.name_get() returns: {0}'.format(kid))
        return kid

    def prepare_response(self, response_dic, status_dic):
        """ prepare response_dic """
        print_debug(self.debug, 'Message.prepare_response()')
        if 'code' not in status_dic:
            status_dic['code'] = 400
            status_dic['message'] = 'urn:ietf:params:acme:error:serverInternal'
            status_dic['detail'] = 'http status code missing'

        if 'message' not in status_dic:
            status_dic['message'] = 'urn:ietf:params:acme:error:serverInternal'

        if 'detail' not in status_dic:
            status_dic['detail'] = None

        # create response
        response_dic['code'] = status_dic['code']

        # create header if not existing
        if 'header' not in response_dic:
            response_dic['header'] = {}

        if status_dic['code'] >= 400:
            if status_dic['detail']:
                # some error occured get details
                error_message = Error(self.debug)
                status_dic['detail'] = error_message.enrich_error(status_dic['message'], status_dic['detail'])
                response_dic['data'] = {'status': status_dic['code'], 'message': status_dic['message'], 'detail': status_dic['detail']}
            else:
                response_dic['data'] = {'status': status_dic['code'], 'message': status_dic['message'], 'detail': None}
        else:
            # add nonce to header
            response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        return response_dic
