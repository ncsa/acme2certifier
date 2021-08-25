#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Housekeeping class """
from __future__ import print_function
import csv
import json
from acme_srv.db_handler import DBstore
from acme_srv.authorization import Authorization
from acme_srv.certificate import Certificate
from acme_srv.order import Order
from acme_srv.helper import load_config, uts_to_date_utc, cert_dates_get, cert_serial_get, uts_now
from acme_srv.version import __version__

class Housekeeping(object):
    """ Housekeeping class """
    def __init__(self, debug=None, logger=None):
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.debug = debug

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _accountlist_get(self):
        """ get list of certs from database """
        self.logger.debug('Housekeeping._certlist_get()')
        try:
            result = self.dbstore.accountlist_get()
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Housekeeping._accountlist_get(): {0}'.format(err_))
            result = None
        return result

    def _certificatelist_get(self):
        """ get list of certs from database """
        self.logger.debug('Housekeeping._certlist_get()')
        try:
            result = self.dbstore.certificatelist_get()
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Housekeeping.certificatelist_get(): {0}'.format(err_))
            result = None
        return result

    def _config_load(self):
        """ load config from file """
        self.logger.debug('Housekeeping._config_load()')
        config_dic = load_config()
        if 'Housekeeping' in config_dic:
            pass

    def _convert_data(self, cert_list):
        """ convert data from uts to real date """
        self.logger.debug('Housekeeping._convert_dates()')
        for cert in cert_list:
            expire_list = ('order.expires', 'authorization.expires', 'challenge.expires')
            for ele in expire_list:
                if ele in cert and cert[ele]:
                    cert[ele] = uts_to_date_utc(cert[ele], '%Y-%m-%d %H:%M:%S')

            # set uts to 0 if we do not have them in dictionary
            if 'certificate.issue_uts' not in cert or 'certificate.expire_uts' not in cert:
                cert['certificate.issue_uts'] = 0
                cert['certificate.expire_uts'] = 0

            # if uts is zero we try to get the dates from certificate
            if cert['certificate.issue_uts'] == 0 or cert['certificate.expire_uts'] == 0:
                # cover cases without certificate in dict
                if 'certificate.cert_raw' in cert:
                    (issue_uts, expire_uts) = cert_dates_get(self.logger, cert['certificate.cert_raw'])
                    cert['certificate.issue_uts'] = issue_uts
                    cert['certificate.expire_uts'] = expire_uts
                else:
                    cert['certificate.issue_uts'] = 0
                    cert['certificate.expire_uts'] = 0

            if cert['certificate.issue_uts'] > 0 and cert['certificate.expire_uts'] > 0:
                cert['certificate.issue_date'] = uts_to_date_utc(cert['certificate.issue_uts'], '%Y-%m-%d %H:%M:%S')
                cert['certificate.expire_date'] = uts_to_date_utc(cert['certificate.expire_uts'], '%Y-%m-%d %H:%M:%S')
            else:
                cert['certificate.issue_date'] = ''
                cert['certificate.expire_date'] = ''

           # add serial number
            if 'certificate.cert_raw' in cert:
                try:
                    cert['certificate.serial'] = cert_serial_get(self.logger, cert['certificate.cert_raw'])
                except BaseException:
                    cert['certificate.serial'] = ''

        return cert_list

    def _csv_dump(self, filename, content):
        """ dump content csv file """
        self.logger.debug('Housekeeping._csv_dump()')
        with open(filename, 'w', newline='') as file_:
            writer = csv.writer(file_, delimiter=',', quotechar='"', quoting=csv.QUOTE_NONNUMERIC)
            writer.writerows(content)

    def _json_dump(self, filename, data_):
        """ dump content json file """
        self.logger.debug('Housekeeping._json_dump()')
        jdump = json.dumps(data_, ensure_ascii=False, indent=4, default=str)
        with open(filename, 'w', newline='') as file_:
            file_.write(jdump)

    def _fieldlist_normalize(self, field_list, prefix):
        """ normalize field_list """
        self.logger.debug('Housekeeping._fieldlist_normalize()')
        field_dic = {}
        for field in field_list:
            f_list = field.split('__')
            # items from selected list which do not have a table reference get prefix added
            if len(f_list) == 1:
                new_field = '{0}.{1}'.format(prefix, field)
            elif f_list[-2] == 'status' and len(f_list) >= 3:
                # status fields have one reference more
                new_field = '{0}.{1}.{2}'.format(f_list[-3], f_list[-2], f_list[-1])
            else:
                new_field = '{0}.{1}'.format(f_list[-2], f_list[-1])
            field_dic[field] = new_field

        return field_dic

    def _lists_normalize(self, field_list, value_list, prefix):
        """ normalize list """
        self.logger.debug('Housekeeping._list_normalize()')

        field_dic = self._fieldlist_normalize(field_list, prefix)

        new_list = []
        for v_list in value_list:
            # create a temporary dictionary wiht the renamed fields
            tmp_dic = {}
            for field in v_list:
                if field in field_dic:
                    tmp_dic[field_dic[field]] = v_list[field]
            # append dicutionary to list
            new_list.append(tmp_dic)

        # get field_list
        field_list = list(field_dic.values())

        return(field_list, new_list)

    def _to_acc_json(self, account_list):
        """ stack list to json """
        self.logger.debug('Housekeeping._to_acc_json()')

        tmp_json = {}
        error_list = []
        for ele in account_list:

            # we have to ensure that all keys we need to nest are in
            if ele.keys() >= {'account.name', 'order.name', 'authorization.name', 'challenge.name'}:

                # create account entry in case it does not exist
                if ele['account.name'] not in tmp_json:
                    tmp_json[ele['account.name']] = {}
                    tmp_json[ele['account.name']]['orders_dic'] = {}

                if ele['order.name'] not in tmp_json[ele['account.name']]['orders_dic']:
                    tmp_json[ele['account.name']]['orders_dic'][ele['order.name']] = {}
                    tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'] = {}

                if ele['authorization.name'] not in tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic']:
                    tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']] = {}
                    tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']]['challenges_dic'] = {}

                if ele['challenge.name'] not in tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']]['challenges_dic']:
                    tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']]['challenges_dic'][ele['challenge.name']] = {}

                for value in ele:
                    if value.startswith('account.'):
                        tmp_json[ele['account.name']][value] = ele[value]
                    elif value.startswith('order.'):
                        tmp_json[ele['account.name']]['orders_dic'][ele['order.name']][value] = ele[value]
                    elif value.startswith('authorization.'):
                        tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']][value] = ele[value]
                    elif value.startswith('challenge'):
                        tmp_json[ele['account.name']]['orders_dic'][ele['order.name']]['authorizations_dic'][ele['authorization.name']]['challenges_dic'][ele['challenge.name']][value] = ele[value]

            else:
                error_list.append(ele)

        # convert nested dictionaries (challenges, authorizations and orders) into list
        account_list = []
        for account in tmp_json:
            tmp_json[account]['orders'] = []
            for order in tmp_json[account]['orders_dic']:
                tmp_json[account]['orders_dic'][order]['authorizations'] = []
                for authorization in tmp_json[account]['orders_dic'][order]['authorizations_dic']:
                    tmp_json[account]['orders_dic'][order]['authorizations_dic'][authorization]['challenges'] = []
                    # build list from challenges and delete dictionary
                    for _name, challenge in tmp_json[account]['orders_dic'][order]['authorizations_dic'][authorization]['challenges_dic'].items():
                        tmp_json[account]['orders_dic'][order]['authorizations_dic'][authorization]['challenges'].append(challenge)
                    del tmp_json[account]['orders_dic'][order]['authorizations_dic'][authorization]['challenges_dic']
                    # build list from authorizations
                    tmp_json[account]['orders_dic'][order]['authorizations'].append(tmp_json[account]['orders_dic'][order]['authorizations_dic'][authorization])
                # delete authorization dictionary
                del tmp_json[account]['orders_dic'][order]['authorizations_dic']
                # build list of orders
                tmp_json[account]['orders'].append(tmp_json[account]['orders_dic'][order])
            del tmp_json[account]['orders_dic']

            # add entry to output list
            account_list.append(tmp_json[account])

        # add errors
        if error_list:
            account_list.append({'error_list': error_list})

        return account_list

    def _to_list(self, field_list, cert_list):
        """ convert query to csv format """
        self.logger.debug('Housekeeping._to_list()')
        csv_list = []

        # attach fieldlist as first row
        if field_list:
            csv_list.append(field_list)
        for cert in cert_list:
            tmp_list = []
            # enumarte fields and store them in temporary list
            for field in field_list:
                # in case we are missing a field put empty string in
                if field in cert:
                    try:
                        # we need to deal with some errors from past
                        value = cert[field].replace('\r\n', '\n')
                        value = value.replace('\r', '')
                        value = value.replace('\n', '')
                        tmp_list.append(value)
                    except BaseException:
                        tmp_list.append(cert[field])
                else:
                    tmp_list.append('')

            # append list to output
            csv_list.append(tmp_list)
        self.logger.debug('Housekeeping._to_list() ended with {0} entries'.format(len(csv_list)))
        return csv_list

    def accountreport_get(self, report_format='csv', report_name=None, nested=False):
        """ get account report """
        self.logger.debug('Housekeeping.accountreport_get()')
        (field_list, account_list) = self._accountlist_get()

        # normalize lists
        (field_list, account_list) = self._lists_normalize(field_list, account_list, 'account')

        # convert dates into human readable format
        account_list = self._convert_data(account_list)

        if report_name:
            if account_list:
                self.logger.debug('output to dump: {0}.{1}'.format(report_name, report_format))
                if report_format == 'csv':
                    self.logger.debug('Housekeeping.certreport_get() dump in csv-format')
                    csv_list = self._to_list(field_list, account_list)
                    self._csv_dump('{0}.{1}'.format(report_name, report_format), csv_list)
                elif report_format == 'json':
                    if nested:
                        account_list = self._to_acc_json(account_list)
                    self._json_dump('{0}.{1}'.format(report_name, report_format), account_list)

        return account_list

    def certreport_get(self, report_format='csv', report_name=None):
        """ get certificate report """
        self.logger.debug('Housekeeping.certreport_get()')

        (field_list, cert_list) = self._certificatelist_get()

        # normalize lists
        (field_list, cert_list) = self._lists_normalize(field_list, cert_list, 'certificate')

        # convert dates into human readable format
        cert_list = self._convert_data(cert_list)

        # extend list by additional fields to have the fileds in output
        field_list.insert(2, 'certificate.serial')
        field_list.insert(7, 'certificate.issue_date')
        field_list.insert(8, 'certificate.expire_date')

        if report_name:
            if cert_list:
                self.logger.debug('output to dump: {0}.{1}'.format(report_name, report_format))
                if report_format == 'csv':
                    self.logger.debug('Housekeeping.certreport_get(): Dump in csv-format')
                    csv_list = self._to_list(field_list, cert_list)
                    self._csv_dump('{0}.{1}'.format(report_name, report_format), csv_list)
                elif report_format == 'json':
                    self.logger.debug('Housekeeping.certreport_get(): Dump in json-format')
                    self._json_dump('{0}.{1}'.format(report_name, report_format), cert_list)
                else:
                    self.logger.info('Housekeeping.certreport_get(): No dump just return report')

        return cert_list

    def certificate_dates_update(self):
        """ scan certificates and update issue/expiry date """
        self.logger.debug('Housekeeping.certificate_dates_update()')

        with Certificate(self.debug, None, self.logger) as certificate:
            certificate.dates_update()

    def certificates_cleanup(self, uts=None, purge=False, report_format='csv', report_name=None):
        """ database cleanuip certificate-table """
        self.logger.debug('Housekeeping.certificates_cleanup()')
        if not uts:
            uts = uts_now()

        with Certificate(self.debug, None, self.logger) as certificate:
            (field_list, cert_list) = certificate.cleanup(timestamp=uts, purge=purge)

            # normalize lists
            # (field_list, cert_list) = self._lists_normalize(field_list, cert_list, 'certificate')

            if report_name:
                if cert_list:
                    # dump report to file
                    if report_format == 'csv':
                        self.logger.debug('Housekeeping.certificates_cleanup(): Dump in csv-format')
                        csv_list = self._to_list(field_list, cert_list)
                        self._csv_dump('{0}.{1}'.format(report_name, report_format), csv_list)
                    elif report_format == 'json':
                        self.logger.debug('Housekeeping.certificates_cleanup(): Dump in json-format')
                        self._json_dump('{0}.{1}'.format(report_name, report_format), cert_list)
                    else:
                        self.logger.debug('Housekeeping.certificates_cleanup():  No dump just return report')
                else:
                    self.logger.debug('Housekeeping.certificates_cleanup(): No certificates to dump')

        return cert_list

    def authorizations_invalidate(self, uts=uts_now(), report_format='csv', report_name=None):
        """ authorizations cleanup based on expiry date"""
        self.logger.debug('Housekeeping.authorization_invalidate({0})'.format(uts))

        with Authorization(self.debug, None, self.logger) as authorization:
            # get expired orders
            (field_list, authorization_list) = authorization.invalidate(timestamp=uts)
            # normalize lists
            (field_list, authorization_list) = self._lists_normalize(field_list, authorization_list, 'authorization')
            # convert dates into human readable format
            authorization_list = self._convert_data(authorization_list)

            if report_name:
                if authorization_list:
                    # dump report to file
                    if report_format == 'csv':
                        self.logger.debug('Housekeeping.authorizations_invalidate(): Dump in csv-format')
                        csv_list = self._to_list(field_list, authorization_list)
                        self._csv_dump('{0}.{1}'.format(report_name, report_format), csv_list)
                    elif report_format == 'json':
                        self.logger.debug('Housekeeping.authorizations_invalidate(): Dump in json-format')
                        self._json_dump('{0}.{1}'.format(report_name, report_format), authorization_list)
                    else:
                        self.logger.debug('Housekeeping.authorizations_invalidate():  No dump just return report')
                else:
                    self.logger.debug('Housekeeping.authorizations_invalidate(): No authorizations to dump')

    def dbversion_check(self, version=None):
        """ check database version """
        self.logger.debug('Housekeeping.dbversion_check({0})'.format(version))

        if version:
            try:
                (result, script_name) = self.dbstore.dbversion_get()
            except BaseException as err_:
                self.logger.critical('acme2certifier database error in Housekeeping.dbversion_check(): {0}'.format(err_))
                result = None
                script_name = 'handler specific migration'
            if result != version:
                self.logger.critical('acme2certifier database version mismatch in: version is {0} but should be {1}. Please run the "{2}" script'.format(result, version, script_name))
            else:
                self.logger.debug('acme2certifier database version: {0} is upto date'.format(version))
        else:
            self.logger.critical('acme2certifier database version could not be verified in Housekeeping.dbversion_check()')

    def orders_invalidate(self, uts=uts_now(), report_format='csv', report_name=None):
        """ orders cleanup based on expiry date"""
        self.logger.debug('Housekeeping.orders_invalidate({0})'.format(uts))

        with Order(self.debug, None, self.logger) as order:
            # get expired orders
            (field_list, order_list) = order.invalidate(timestamp=uts)
            # normalize lists
            (field_list, order_list) = self._lists_normalize(field_list, order_list, 'order')
            # convert dates into human readable format
            order_list = self._convert_data(order_list)

            if report_name:
                if order_list:
                    # dump report to file
                    if report_format == 'csv':
                        self.logger.debug('Housekeeping.orders_invalidate(): Dump in csv-format')
                        csv_list = self._to_list(field_list, order_list)
                        self._csv_dump('{0}.{1}'.format(report_name, report_format), csv_list)
                    elif report_format == 'json':
                        self.logger.debug('Housekeeping.orders_invalidate(): Dump in json-format')
                        self._json_dump('{0}.{1}'.format(report_name, report_format), order_list)
                    else:
                        self.logger.debug('Housekeeping.orders_invalidate():  No dump just return report')
                else:
                    self.logger.debug('Housekeeping.orders_invalidate(): No orders to dump')

        return order_list
