#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock
# from OpenSSL import crypto
import shutil
import configparser

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.cmp_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """ teardown """
        pass

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load wrong cahandler section """
        mock_load_cfg.return_value = {'CAhandler': 'foo'}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load cmd predefined in cahandler """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_cmd': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'foo', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load popo predefined in cahandler  """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_popo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 1}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load cmd and popo predefined in cahandler  """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_cmd': 'foo', 'cmp_popo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'foo', 'popo': 1}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - cmp_openssl_bin parameter"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_openssl_bin': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)
        self.assertEqual('foo', self.cahandler.openssl_bin)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-dir parameter """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_tmp_dir': 'foo_tmp'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)
        self.assertEqual('foo_tmp', self.cahandler.tmp_dir)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load - cmp_recipient-dir parameter """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient startwith '/' """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': '/foo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains , """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'fo,o'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/fo/o'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'fo, o'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/fo/o'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank and ,"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo, bar,doo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo/bar/doo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load - cmd_tmp-cmp_recipient contains ,blank and ,"""
        mock_load_cfg.return_value = {'CAhandler': {'cmp_recipient': 'foo, bar, doo,bar,doo'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'popo': 0, 'recipient': '/foo/bar/doo/bar/doo'}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter string """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 'bar'}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 'bar', 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter int """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 1, 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load - any parameter float """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_foo': 0.1}}
        self.cahandler._config_load()
        odict = {'cmd': 'ir', 'foo': 0.1, 'popo': 0}
        self.assertEqual(odict, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load - tmp_dir not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler config error: "cmp_tmp_dir" parameter must be specified in config_file', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """  test _config_load - cmp_openssl_bin not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('WARNING:test_a2c:CAhandler config error: "cmp_openssl_bin" parameter not in config_file. Using default (/usr/bin/openssl)', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """  test _config_load - cmp_recipient not configured """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertIn('ERROR:test_a2c:CAhandler config error: "cmp_recipient" is missing in config_file.', lcm.output)

    @patch.dict('os.environ', {'cmp_ref': 'cmp_ref'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg):
        """ test _config_load - load template with ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'cmp_ref'}}
        self.cahandler._config_load()
        self.assertEqual('cmp_ref', self.cahandler.ref)

    @patch.dict('os.environ', {'cmp_ref': 'user_var'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load - load template with not existing ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.ref)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load cmp_ref:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'cmp_ref': 'cmp_ref'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load - load template overwrite ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_ref_variable': 'cmp_ref', 'cmp_ref': 'cmp_ref_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('cmp_ref_local', self.cahandler.ref)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cmp_ref variable', lcm.output)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load - load template with secret variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'cmp_secret'}}
        self.cahandler._config_load()
        self.assertEqual('cmp_secret', self.cahandler.secret)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_025_config_load(self, mock_load_cfg):
        """ test _config_load - load template with not existing secret variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'does_not_exist'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.secret)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load cmp_secret_variable:'does_not_exist'", lcm.output)

    @patch.dict('os.environ', {'cmp_secret': 'cmp_secret'})
    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_026_config_load(self, mock_load_cfg):
        """ test _config_load - load template overwrite ref variable """
        mock_load_cfg.return_value = {'CAhandler': {'cmp_secret_variable': 'cmp_secret', 'cmp_secret': 'cmp_secret_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('cmp_secret_local', self.cahandler.secret)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite cmp_secret variable', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_027__config_load(self, mock_load_cfg):
        """ config load enforce cmp_boolean True """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cmp_bool': 'True'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual({'bool': True, 'cmd': 'ir', 'popo': 0}, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.load_config')
    def test_028__config_load(self, mock_load_cfg):
        """ config load enforce cmp_boolean False """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'cmp_bool': 'False'}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual({'bool': False, 'cmd': 'ir', 'popo': 0}, self.cahandler.config_dic)

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_027_csr_san_get(self, mock_san):
        """  test _config_load - empty san list """
        mock_san.return_value = []
        olist = []
        self.assertFalse(self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_028_csr_san_get(self, mock_san):
        """ test _csr_san_get  - incomplete san returned """
        mock_san.return_value = ['foo']
        olist = []
        self.assertFalse(self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_029_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned """
        mock_san.return_value = ['foo1:bar1']
        olist = []
        self.assertEqual('"bar1"', self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_030_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned mix upper and lower cases """
        mock_san.return_value = ['fOo1:BaR1']
        olist = []
        self.assertEqual('"bar1"', self.cahandler._csr_san_get('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.csr_san_get')
    def test_031_csr_san_get(self, mock_san):
        """ test _csr_san_get  - single san returned mix upper and lower cases """
        mock_san.return_value = ['fOo1:BaR1', 'foo2:bar2']
        olist = []
        self.assertEqual('"bar1, bar2"', self.cahandler._csr_san_get('csr'))

    def test_032_poll(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_033_trigger(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    def test_034_revoke(self):
        """ test revoke """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._config_load')
    def test_035__enter__(self, mock_load):
        """ test enter """
        self.cahandler.__enter__()
        self.assertTrue(mock_load.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._config_load')
    def test_036__enter__(self, mock_load):
        """ test enter """
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.__enter__()
        self.assertFalse(mock_load.called)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_037__pubkey_save(self):
        """ test pubkey save """
        self.assertFalse(self.cahandler._pubkey_save('uts', 'pubkey'))

    @patch('os.remove')
    @patch('os.path.isfile')
    def test_038_tmp_files_delete(self, mock_exists, mock_remove):
        """ test files_delete if file exists """
        mock_exists.return_value = True
        self.cahandler._tmp_files_delete('uts')
        self.assertTrue(mock_remove.called)

    @patch('os.remove')
    @patch('os.path.isfile')
    def test_039_tmp_files_delete(self, mock_exists, mock_remove):
        """ test files_delete if file exists """
        mock_exists.return_value = False
        self.cahandler._tmp_files_delete('uts')
        self.assertFalse(mock_remove.called)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_040_certs_bundle(self, mock_exists):
        """ certs bundle if no file exists """
        mock_exists.return_value = False
        self.assertEqual((None, None), self.cahandler._certs_bundle('foo'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_041_certs_bundle(self, mock_exists):
        """ certs bundle if only capubs exists """
        mock_exists.side_effect = (True, False)
        self.assertEqual((None, None), self.cahandler._certs_bundle('uts'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_042_certs_bundle(self, mock_exists):
        """ certs bundle if only cert exists """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('foo', 'foo'), self.cahandler._certs_bundle('uts'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('os.path.isfile')
    def test_043_certs_bundle(self, mock_exists):
        """ certs bundle if all exists """
        mock_exists.side_effect = (True, True)
        self.assertEqual(('foofoo', 'foo'), self.cahandler._certs_bundle('uts'))

    @patch("builtins.open", mock_open(read_data='-----BEGIN CERTIFICATE-----\nfoo'), create=True)
    @patch('os.path.isfile')
    def test_044_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace begin tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('-----BEGIN CERTIFICATE-----\nfoo', 'foo'), self.cahandler._certs_bundle('uts'))

    @patch("builtins.open", mock_open(read_data='-----BEGIN CERTIFICATE-----\nfoo-----END CERTIFICATE-----\n'), create=True)
    @patch('os.path.isfile')
    def test_045_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace end tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('-----BEGIN CERTIFICATE-----\nfoo-----END CERTIFICATE-----\n', 'foo'), self.cahandler._certs_bundle('uts'))

    @patch("builtins.open", mock_open(read_data='foo\n'), create=True)
    @patch('os.path.isfile')
    def test_046_certs_bundle(self, mock_exists):
        """ certs bundle if cert exists replace end tag """
        mock_exists.side_effect = (False, True)
        self.assertEqual(('foo\n', 'foo'), self.cahandler._certs_bundle('uts'))

    def test_047_opensslcmd_build(self):
        """test _openssl_cmd_build()"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        uts = 1234
        subject = 'subject'
        san_list = 'foo1.bar.local'
        result = ['openssl_bin', 'cmp', '-subject', 'subject', '-newkey', '/tmp/1234_pubkey.pem', '-sans', 'foo1.bar.local', '-extracertsout', '/tmp/1234_capubs.pem', '-certout', '/tmp/1234_cert.pem', '-msgtimeout', '5', '-totaltimeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build(uts, subject, san_list))

    def test_048_opensslcmd_build(self):
        """test _openssl_cmd_build() with option including in config dic"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.config_dic = {'foo1': 'bar1', 'foo2': 'bar2'}
        uts = 1234
        subject = 'subject'
        san_list = 'foo1.bar.local'
        result = ['openssl_bin', 'cmp', '-foo1', 'bar1', '-foo2', 'bar2', '-subject', 'subject', '-newkey', '/tmp/1234_pubkey.pem', '-sans', 'foo1.bar.local', '-extracertsout', '/tmp/1234_capubs.pem', '-certout', '/tmp/1234_cert.pem', '-msgtimeout', '5', '-totaltimeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build(uts, subject, san_list))

    def test_049_opensslcmd_build(self):
        """test _openssl_cmd_build()"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.config_dic = {'-msgtimeout': 10}
        uts = 1234
        subject = 'subject'
        san_list = 'foo1.bar.local'
        result = ['openssl_bin', 'cmp', '--msgtimeout', '10', '-subject', 'subject', '-newkey', '/tmp/1234_pubkey.pem', '-sans', 'foo1.bar.local', '-extracertsout', '/tmp/1234_capubs.pem', '-certout', '/tmp/1234_cert.pem', '-msgtimeout', '5', '-totaltimeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build(uts, subject, san_list))

    def test_050_opensslcmd_build(self):
        """test _openssl_cmd_build()"""
        self.cahandler.openssl_bin = 'openssl_bin'
        self.cahandler.tmp_dir = '/tmp'
        self.cahandler.config_dic = {'-totaltimeout': 10}
        uts = 1234
        subject = 'subject'
        san_list = 'foo1.bar.local'
        result = ['openssl_bin', 'cmp', '--totaltimeout', '10', '-subject', 'subject', '-newkey', '/tmp/1234_pubkey.pem', '-sans', 'foo1.bar.local', '-extracertsout', '/tmp/1234_capubs.pem', '-certout', '/tmp/1234_cert.pem', '-msgtimeout', '5', '-totaltimeout', '10']
        self.assertEqual(result, self.cahandler._opensslcmd_build(uts, subject, san_list))

    def test_051_enroll(self):
        """ test enroll without openssl_bin """
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_052_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get):
        """ test enroll csr_dn_get returns_exception """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.side_effect = Exception('ex_dn_get')
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.return_value = 'san.foo.bar'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('CSR invalid', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): csr_dn_get() failed with error: ex_dn_get', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_files_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._pubkey_save')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_053_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll csr_dn_get returns None and gets corrected """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = None
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.return_value = 'san.foo.bar'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 0
        mock_exists.return_value = True
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        #with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual((None, 'cert_bundle', 'cert_raw', None), self.cahandler.enroll('csr'))
        #self.assertIn('ERROR:test_a2c:CAhandler.enroll(): csr_dn_get() failed with error: ex_dn_get', lcm.output)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertTrue(mock_bundle.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_054_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get):
        """ test enroll csr_pubkey_get returns_exception """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = 'dn'
        mock_pkey_get.side_effect = Exception('ex_pubkey_get')
        mock_san_get.return_value = 'san.foo.bar'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('CSR invalid', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): csr_pubkey_get() failed with error: ex_pubkey_get', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_055_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get):
        """ test enroll _csr_san_get returns_exception """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = 'dn'
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.side_effect = Exception('ex_san_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('CSR invalid', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): _csr_san_get() failed with error: ex_san_get', lcm.output)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_files_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._pubkey_save')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_056_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll csr_dn_get runs through without issues """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = 'dn'
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.return_value = 'san.foo.bar'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 0
        mock_exists.return_value = True
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        #with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual((None, 'cert_bundle', 'cert_raw', None), self.cahandler.enroll('csr'))
        #self.assertIn('ERROR:test_a2c:CAhandler.enroll(): csr_dn_get() failed with error: ex_dn_get', lcm.output)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertTrue(mock_bundle.called)

    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_files_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._pubkey_save')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')
    def test_057_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll subprocess.call returns other than 0 """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = 'dn'
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.return_value = 'san.foo.bar'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 25
        mock_exists.return_value = True
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('rc from enrollment not 0', 'cert_bundle', 'cert_raw', None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll(): failed: 25', lcm.output)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertTrue(mock_bundle.called)
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._certs_bundle')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._tmp_files_delete')
    @patch('os.path.isfile')
    @patch('subprocess.call')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._opensslcmd_build')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._pubkey_save')
    @patch('examples.ca_handler.cmp_ca_handler.CAhandler._csr_san_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_pubkey_get')
    @patch('examples.ca_handler.cmp_ca_handler.csr_dn_get')

    def test_058_enroll(self, mock_dn_get, mock_pkey_get, mock_san_get, mock_save, mock_build, mock_call, mock_exists, mock_del, mock_bundle):
        """ test enroll subprocess.call files do not exist """
        self.cahandler.openssl_bin = 'openssl_bin'
        mock_dn_get.return_value = 'dn'
        mock_pkey_get.return_value = 'pkey'
        mock_san_get.return_value = 'san.foo.bar'
        mock_save.return_value = True
        mock_build.return_value = 'opensslcmd'
        mock_call.return_value = 0
        mock_exists.return_value = False
        mock_bundle.return_value = ('cert_bundle', 'cert_raw')
        mock_del.return_value = True
        self.assertEqual(('Enrollment failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_exists.called)
        self.assertTrue(mock_del.called)
        self.assertFalse(mock_bundle.called)

if __name__ == '__main__':

    unittest.main()
