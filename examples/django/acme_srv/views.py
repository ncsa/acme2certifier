# -*- coding: utf-8 -*-
""" acme app main view """
from __future__ import unicode_literals, print_function

from django.http import HttpResponse, HttpResponseNotFound
from django.http import JsonResponse
from acme_srv.authorization import Authorization
from acme_srv.account import Account
from acme_srv.certificate import Certificate
from acme_srv.challenge import Challenge
from acme_srv.directory import Directory
from acme_srv.helper import get_url, load_config, logger_setup, logger_info
from acme_srv.housekeeping import Housekeeping
from acme_srv.nonce import Nonce
from acme_srv.order import Order
from acme_srv.trigger import Trigger
from acme_srv.version import __dbversion__, __version__
from acme_srv.acmechallenge import Acmechallenge

# load config to set debug mode
CONFIG = load_config()
DEBUG = CONFIG.getboolean('DEFAULT', 'debug', fallback=False)

# initialize logger
LOGGER = logger_setup(DEBUG)
LOGGER.info('starting acme2certifier version {0}'.format(__version__))

with Housekeeping(DEBUG, LOGGER) as housekeeping:
    housekeeping.dbversion_check(__dbversion__)

def handle_exception(exc_type, exc_value, exc_traceback):
    """ exception handler """
    print('My Error Information')
    print('Type:', exc_type)
    print('Value:', exc_value)
    print('Traceback:', exc_traceback)

# examption handling via logger
# sys.excepthook = handle_exception

def pretty_request(request):
    """ print request details for debugging """
    headers = ''
    for header, value in request.META.items():
        if not header.startswith('HTTP'):
            continue
        header = '-'.join([h.capitalize() for h in header[5:].lower().split('_')])
        headers += '{}: {}\n'.format(header, value)

    return (
        '{method} HTTP/1.1\n'
        'Content-Length: {content_length}\n'
        'Content-Type: {content_type}\n'
        '{headers}\n\n'
        '{body}'
    ).format(
        method=request.method,
        content_length=request.META['CONTENT_LENGTH'],
        content_type=request.META['CONTENT_TYPE'],
        headers=headers,
        body=request.body, )

def directory(request):
    """ get directory """
    with Directory(DEBUG, get_url(request.META), LOGGER) as cfg_dir:
        return JsonResponse(cfg_dir.directory_get())

def newaccount(request):
    """ new account """
    if request.method == 'POST':
        with Account(DEBUG, get_url(request.META), LOGGER) as account:
            response_dic = account.new(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def newnonce(request):
    """ new nonce """
    if request.method in ['HEAD', 'GET']:
        with Nonce(DEBUG, LOGGER) as nonce:
            if request.method == 'HEAD':
                response = HttpResponse('')
            else:
                response = HttpResponse(status=204)
            # generate nonce
            response['Replay-Nonce'] = nonce.generate_and_add()

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], {'header': {'Replay-Nonce' : response['Replay-Nonce']}})
            # send response
            return response
    else:
        return JsonResponse(status=400, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected HEAD or GET.'})

def servername_get(request):
    """ get server name """
    with Directory(DEBUG, get_url(request.META), LOGGER) as cfg_dir:
        return JsonResponse({'server_name' : cfg_dir.servername_get()})

def acct(request):
    """ xxxx command """
    with Account(DEBUG, get_url(request.META), LOGGER) as account:
        response_dic = account.parse(request.body)
        # create the response
        response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

        # generate additional header elements
        for element in response_dic['header']:
            response[element] = response_dic['header'][element]

        # logging
        logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
        # send response
        return response

def neworders(request):
    """ new account """
    if request.method == 'POST':
        with Order(DEBUG, get_url(request.META), LOGGER) as norder:
            response_dic = norder.new(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            if 'Replay-Nonce' not in response:
                response['Replay-Nonce'] = ''

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], {'header': {'Replay-Nonce' : response['Replay-Nonce']}})
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def authz(request):
    """ new-authz command """
    if request.method == 'POST' or request.method == 'GET':
        with Authorization(DEBUG, get_url(request.META), LOGGER) as authorization:
            if request.method == 'POST':
                response_dic = authorization.new_post(request.body)
            else:
                response_dic = authorization.new_get(request.build_absolute_uri())
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def chall(request):
    """ challenge command """
    with Challenge(DEBUG, get_url(request.META), LOGGER) as challenge:
        # pylint: disable=R1705
        if request.method == 'POST':
            response_dic = challenge.parse(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
        elif request.method == 'GET':
            response_dic = challenge.get(request.build_absolute_uri())
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # logging
            # logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
        else:
            return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def order(request):
    """ order request """
    if request.method == 'POST':
        with Order(DEBUG, get_url(request.META), LOGGER) as eorder:
            response_dic = eorder.parse(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def cert(request):
    """ cert request """
    if request.method == 'POST' or request.method == 'GET':
        with Certificate(DEBUG, get_url(request.META), LOGGER) as certificate:
            if request.method == 'POST':
                response_dic = certificate.new_post(request.body)
            else:
                response_dic = certificate.new_get(request.build_absolute_uri())

            # create the response
            if response_dic['code'] == 200:
                response = HttpResponse(response_dic['data'])
                # generate additional header elements
                for element in response_dic['header']:
                    response[element] = response_dic['header'][element]
            else:
                response = HttpResponse(status=response_dic['code'])

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response

    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def revokecert(request):
    """ cert revocation """
    if request.method == 'POST':
        with Certificate(DEBUG, get_url(request.META), LOGGER) as certificate:
            response_dic = certificate.revoke(request.body)
            # create the response
            if 'data' in response_dic:
                response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            else:
                response = HttpResponse(status=response_dic['code'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def trigger(request):
    """ ca trigger"""
    if request.method == 'POST':
        with Trigger(DEBUG, get_url(request.META), LOGGER) as trigger_:
            response_dic = trigger_.parse(request.body)
            # create the response
            if 'data' in response_dic:
                response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            else:
                response = HttpResponse(status=response_dic['code'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # logging
            logger_info(LOGGER, request.META['REMOTE_ADDR'], request.META['PATH_INFO'], response_dic)
            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def acmechallenge_serve(request):
    """ serving acme challenges """
    with Acmechallenge(DEBUG, get_url(request.META), LOGGER) as acmechallenge:
        key_authorization = acmechallenge.lookup(request.META['PATH_INFO'])
        if key_authorization:
            return HttpResponse(key_authorization)
        else:
            return HttpResponseNotFound('NOT FOUND')

#def blubb(request):
#    """ xxxx command """
#    with acme_srv(request.META['HTTP_HOST']) as acm:
#        return HttpResponse('ok')
# return JsonResponse(status=403, data={'status':403, 'message':'not that far', 'detail': 'we are ot that far.'})
