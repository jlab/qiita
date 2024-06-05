# -----------------------------------------------------------------------------
# Copyright (c) 2014--, The Qiita Development Team.
#
# Distributed under the terms of the BSD 3-clause License.
#
# The full license is in the file LICENSE, distributed with this software.
# -----------------------------------------------------------------------------

from unittest import TestCase, main
from os import environ, close, remove
from tempfile import mkstemp
from functools import partial
import warnings

from qiita_core.exceptions import MissingConfigSection
from qiita_core.configuration_manager import ConfigurationManager

from configparser import ConfigParser


class ConfigurationManagerTests(TestCase):
    def setUp(self):
        self.old_conf_fp = environ.get('QIITA_CONFIG_FP')
        fd, self.conf_fp = mkstemp(suffix='.txt')
        close(fd)
        with open(self.conf_fp, 'w') as f:
            f.write(CONF)
        environ['QIITA_CONFIG_FP'] = self.conf_fp

        self.conf = ConfigParser()
        with open(self.conf_fp, newline=None) as f:
            self.conf.read_file(f)

    def tearDown(self):
        if self.old_conf_fp is not None:
            environ['QIITA_CONFIG_FP'] = self.old_conf_fp
        else:
            del environ['QIITA_CONFIG_FP']
        remove(self.conf_fp)

    def test_init(self):
        obs = ConfigurationManager()
        # Main section
        self.assertEqual(obs.conf_fp, self.conf_fp)
        self.assertTrue(obs.test_environment)
        self.assertEqual(obs.base_data_dir, "/tmp/")
        self.assertEqual(obs.log_dir, "/tmp/")
        self.assertEqual(obs.base_url, "https://localhost")
        self.assertEqual(obs.max_upload_size, 100)
        self.assertTrue(obs.require_approval)
        self.assertEqual(obs.qiita_env, "source activate qiita")
        self.assertEqual(obs.private_launcher, 'qiita-private-launcher')
        self.assertEqual(obs.plugin_launcher, "qiita-plugin-launcher")
        self.assertEqual(obs.plugin_dir, "/tmp/")
        self.assertEqual(
            obs.valid_upload_extension,
            ["fastq", "fastq.gz", "txt", "tsv", "sff", "fna", "qual"])
        self.assertEqual(obs.certificate_file, "/tmp/server.cert")
        self.assertEqual(obs.cookie_secret, "SECRET")
        self.assertEqual(obs.key_file, "/tmp/server.key")

        # job_scheduler section
        self.assertEqual(obs.job_scheduler_owner, "user@somewhere.org")
        self.assertEqual(obs.job_scheduler_poll_val, 15)
        self.assertEqual(obs.job_scheduler_dependency_q_cnt, 2)

        # Postgres section
        self.assertEqual(obs.user, "postgres")
        self.assertEqual(obs.admin_user, "postgres")
        self.assertEqual(obs.password, "andanotherpwd")
        self.assertEqual(obs.admin_password, "thishastobesecure")
        self.assertEqual(obs.database, "qiita_test")
        self.assertEqual(obs.host, "localhost")
        self.assertEqual(obs.port, 5432)

        # Redis section
        self.assertEqual(obs.redis_host, "localhost")
        self.assertEqual(obs.redis_password, "anotherpassword")
        self.assertEqual(obs.redis_db, 13)
        self.assertEqual(obs.redis_port, 6379)

        # SMTP section
        self.assertEqual(obs.smtp_host, "localhost")
        self.assertEqual(obs.smtp_port, 25)
        self.assertEqual(obs.smtp_user, "qiita")
        self.assertEqual(obs.smtp_password, "supersecurepassword")
        self.assertFalse(obs.smtp_ssl)
        self.assertEqual(obs.smtp_email, "example@domain.com")

        # EBI section
        self.assertEqual(obs.ebi_seq_xfer_user, "Webin-41528")
        self.assertEqual(obs.ebi_seq_xfer_pass, "passwordforebi")
        self.assertEqual(obs.ebi_seq_xfer_url, "webin.ebi.ac.uk")
        self.assertEqual(
            obs.ebi_dropbox_url,
            "https://www-test.ebi.ac.uk/ena/submit/drop-box/submit/")
        self.assertEqual(obs.ebi_center_name, "qiita-test")
        self.assertEqual(obs.ebi_organization_prefix, "example_organization")

        # VAMPS section
        self.assertEqual(obs.vamps_user, "user")
        self.assertEqual(obs.vamps_pass, "password")
        self.assertEqual(obs.vamps_url,
                         "https://vamps.mbl.edu/mobe_workshop/getfile.php")

        # Portal section
        self.assertEqual(obs.portal_fp, "/tmp/portal.cfg")
        self.assertEqual(obs.portal, "QIITA")
        self.assertEqual(obs.portal_dir, "/portal")

        # iframe section
        self.assertIsNone(obs.iframe_qiimp)

    def test_init_error(self):
        with open(self.conf_fp, 'w') as f:
            f.write("\n")

        with self.assertRaises(MissingConfigSection):
            ConfigurationManager()

    def test_get_main(self):
        obs = ConfigurationManager()

        conf_setter = partial(self.conf.set, 'main')
        conf_setter('COOKIE_SECRET', '')
        conf_setter('JWT_SECRET', '')
        conf_setter('BASE_DATA_DIR', '')
        conf_setter('PLUGIN_DIR', '')
        conf_setter('CERTIFICATE_FILE', '')
        conf_setter('KEY_FILE', '')
        conf_setter('QIITA_ENV', '')

        # Warning raised if No files will be allowed to be uploaded
        # Warning raised if no cookie_secret
        self.conf.set('main', 'HELP_EMAIL', 'ignore@me')
        self.conf.set('main', 'SYSADMIN_EMAIL', 'ignore@me')
        with warnings.catch_warnings(record=True) as warns:
            obs._get_main(self.conf)

            obs_warns = [str(w.message) for w in warns]
            exp_warns = ['Random cookie secret generated.',
                         'Random JWT secret generated.  Non Public Artifact '
                         'Download Links will expire upon system restart.']
            self.assertCountEqual(obs_warns, exp_warns)

        self.assertNotEqual(obs.cookie_secret, "SECRET")
        # Test default base_data_dir
        self.assertTrue(
            obs.base_data_dir.endswith("/qiita_db/support_files/test_data"))
        # Test default plugin dir
        self.assertTrue(obs.plugin_dir.endswith("/.qiita_plugins"))
        # Default certificate_file
        self.assertTrue(
            obs.certificate_file.endswith(
                "/qiita_core/support_files/ci_server.crt"))
        # Default key_file
        self.assertTrue(
            obs.key_file.endswith("/qiita_core/support_files/ci_server.key"))

        # BASE_DATA_DIR does not exist
        conf_setter('BASE_DATA_DIR', '/surprised/if/this/dir/exists')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

        # WORKING_DIR does not exist
        conf_setter('BASE_DATA_DIR', '/tmp')
        conf_setter('WORKING_DIR', '/surprised/if/this/dir/exists')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

        # PLUGIN_DIR does not exist
        conf_setter('WORKING_DIR', '/tmp')
        conf_setter('PLUGIN_DIR', '/surprised/if/this/dir/exists')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

        # No files can be uploaded
        conf_setter('PLUGIN_DIR', '/tmp')
        conf_setter('VALID_UPLOAD_EXTENSION', '')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

        self.assertEqual(obs.qiita_env, "")

    def test_help_email(self):
        obs = ConfigurationManager()

        with warnings.catch_warnings(record=True) as warns:
            # warning get only issued when in non test environment
            self.conf.set('main', 'TEST_ENVIRONMENT', 'FALSE')

            obs._get_main(self.conf)
            self.assertEqual(obs.help_email, 'foo@bar.com')
            self.assertEqual(obs.sysadmin_email, 'jeff@bar.com')

            obs_warns = [str(w.message) for w in warns]
            exp_warns = [
                'Using the github fake email for HELP_EMAIL, '
                'are you sure this is OK?',
                'Using the github fake email for SYSADMIN_EMAIL, '
                'are you sure this is OK?']
            self.assertCountEqual(obs_warns, exp_warns)

        # test if it falls back to qiita.help@gmail.com
        self.conf.set('main', 'HELP_EMAIL', '')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

        # test if it falls back to qiita.help@gmail.com
        self.conf.set('main', 'SYSADMIN_EMAIL', '')
        with self.assertRaises(ValueError):
            obs._get_main(self.conf)

    def test_get_job_scheduler(self):
        obs = ConfigurationManager()

        conf_setter = partial(self.conf.set, 'job_scheduler')
        conf_setter('JOB_SCHEDULER_JOB_OWNER', '')
        obs._get_job_scheduler(self.conf)
        self.assertEqual('', obs.job_scheduler_owner)

    def test_get_postgres(self):
        obs = ConfigurationManager()

        conf_setter = partial(self.conf.set, 'postgres')
        conf_setter('PASSWORD', '')
        conf_setter('ADMIN_PASSWORD', '')
        obs._get_postgres(self.conf)
        self.assertIsNone(obs.password)
        self.assertIsNone(obs.admin_password)

    def test_get_portal(self):
        obs = ConfigurationManager()
        conf_setter = partial(self.conf.set, 'portal')
        # Default portal_dir
        conf_setter('PORTAL_DIR', '')
        obs._get_portal(self.conf)
        self.assertEqual(obs.portal_dir, "")
        # Portal dir does not start with /
        conf_setter('PORTAL_DIR', 'gold_portal')
        obs._get_portal(self.conf)
        self.assertEqual(obs.portal_dir, "/gold_portal")
        # Portal dir endswith /
        conf_setter('PORTAL_DIR', '/gold_portal/')
        obs._get_portal(self.conf)
        self.assertEqual(obs.portal_dir, "/gold_portal")

    def test_get_portal_latlong(self):
        obs = ConfigurationManager()

        # if parameters are given, but not set, they should default to Boulder
        self.assertEqual(obs.stats_map_center_latitude, 40.01027)
        self.assertEqual(obs.stats_map_center_longitude, -105.24827)

        # a string cannot be parsed as a float
        self.conf.set('portal', 'STATS_MAP_CENTER_LATITUDE', 'kurt')
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)

        # check for illegal float values
        self.conf.set('portal', 'STATS_MAP_CENTER_LATITUDE', "-200")
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)
        self.conf.set('portal', 'STATS_MAP_CENTER_LATITUDE', "200")
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)

        # check if value defaults if option is missing altogether
        self.conf.remove_option('portal', 'STATS_MAP_CENTER_LATITUDE')
        obs._get_portal(self.conf)
        self.assertEqual(obs.stats_map_center_latitude, 40.01027)

        # same as above, but for longitude
        # a string cannot be parsed as a float
        self.conf.set('portal', 'STATS_MAP_CENTER_LONGITUDE', 'kurt')
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)

        # check for illegal float values
        self.conf.set('portal', 'STATS_MAP_CENTER_LONGITUDE', "-200")
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)
        self.conf.set('portal', 'STATS_MAP_CENTER_LONGITUDE', "200")
        with self.assertRaises(ValueError):
            obs._get_portal(self.conf)

        # check if value defaults if option is missing altogether
        self.conf.remove_option('portal', 'STATS_MAP_CENTER_LONGITUDE')
        obs._get_portal(self.conf)
        self.assertEqual(obs.stats_map_center_longitude, -105.24827)

    def test_get_oidc(self):
        SECTION_NAME = 'oidc_academicid'
        obs = ConfigurationManager()
        self.assertTrue(len(obs.oidc), 1)
        self.assertTrue(obs.oidc.keys(), [SECTION_NAME])

        # assert endpoint starts with /
        self.conf.set(SECTION_NAME, 'REDIRECT_ENDPOINT', 'auth/something')
        obs._get_oidc(self.conf)
        self.assertEqual(obs.oidc['academicid']['redirect_endpoint'],
                         '/auth/something')

        # assert endpoint does not end with /
        self.conf.set(SECTION_NAME, 'REDIRECT_ENDPOINT', 'auth/something/')
        obs._get_oidc(self.conf)
        self.assertEqual(obs.oidc['academicid']['redirect_endpoint'],
                         '/auth/something')

        self.conf.set(SECTION_NAME, 'CLIENT_ID', 'foo')
        obs._get_oidc(self.conf)
        self.assertEqual(obs.oidc['academicid']['client_id'], "foo")

        self.assertTrue('gwdg.de' in obs.oidc['academicid']['wellknown_uri'])

        self.assertEqual(obs.oidc['academicid']['label'],
                         'GWDG Academic Cloud')
        # test fallback, if no label is provided
        self.conf.set(SECTION_NAME, 'LABEL', '')
        obs._get_oidc(self.conf)
        self.assertEqual(obs.oidc['academicid']['label'], 'academicid')

<<<<<<< HEAD
=======
        self.assertEqual(obs.oidc['academicid']['scope'], 'openid')
        print(obs.oidc['academicid']['scope'])
        # test fallback, if no scope is provided
        self.conf.set(SECTION_NAME, 'SCOPE', '')
        obs._get_oidc(self.conf)
        self.assertEqual(obs.oidc['academicid']['scope'], 'openid')

        # test if scope will be automatically extended with 'openid'
        self.conf.set(SECTION_NAME, 'SCOPE', 'email affiliation')
        obs._get_oidc(self.conf)
        self.assertTrue('openid' in obs.oidc['academicid']['scope'].split())
>>>>>>> c9d413af (using the well-known json dict instead of manually providing multiple API endpoints through the config file)


CONF = """
# ------------------------------ Main settings --------------------------------
[main]
# Change to FALSE in a production system
TEST_ENVIRONMENT = TRUE

# Absolute path to the directory where log files are saved. If not given, no
# log file will be created
LOG_DIR = /tmp/

# Whether studies require admin approval to be made available
REQUIRE_APPROVAL = True

# Base URL: DO NOT ADD TRAILING SLASH
BASE_URL = https://localhost

# Download path files
UPLOAD_DATA_DIR = /tmp/

# Working directory path
WORKING_DIR = /tmp/

# Maximum upload size (in Gb)
MAX_UPLOAD_SIZE = 100

# Path to the base directory where the data files are going to be stored
BASE_DATA_DIR = /tmp/

# Valid upload extension, comma separated. Empty for no uploads
VALID_UPLOAD_EXTENSION = fastq,fastq.gz,txt,tsv,sff,fna,qual

# The script used to start the qiita environment, if any
# used to spawn private CLI to a cluster
QIITA_ENV = source activate qiita

# Script used for launching private Qiita tasks
PRIVATE_LAUNCHER = qiita-private-launcher

# Script used for launching plugins
PLUGIN_LAUNCHER = qiita-plugin-launcher

# Plugins configuration directory
PLUGIN_DIR = /tmp/

# Webserver certificate file paths
CERTIFICATE_FILE = /tmp/server.cert
KEY_FILE = /tmp/server.key

# The value used to secure cookies used for user sessions. A suitable value can
# be generated with:
#
# python -c "from base64 import b64encode;\
#   from uuid import uuid4;\
#   print b64encode(uuid4().bytes + uuid4().bytes)"
COOKIE_SECRET = SECRET

# The value used to secure JWTs for delegated permission artifact download.
JWT_SECRET = SUPER_SECRET

# Address a user should write to when asking for help
HELP_EMAIL = foo@bar.com

# The email address, Qiita sends internal notifications to a sys admin
SYSADMIN_EMAIL = jeff@bar.com

# ----------------------------- SMTP settings -----------------------------
[smtp]
# The hostname to connect to
# Google: smtp.google.com
HOST = localhost

# The port to connect to the database
# Google: 587
PORT = 25

# SSL needed (True or False)
# Google: True
SSL = False

# The user name to connect with
USER = qiita

# The user password to connect with
PASSWORD = supersecurepassword

# The email to have messages sent from
EMAIL = example@domain.com

# ----------------------------- Redis settings --------------------------------
[redis]
HOST = localhost
PORT = 6379
PASSWORD = anotherpassword
# The redis database you will use, redis has a max of 16.
# Qiita should have its own database
DB = 13

# ----------------------------- Postgres settings -----------------------------
[postgres]
# The user name to connect to the database
USER = postgres

# The administrator user, which can be used to create/drop environments
ADMIN_USER = postgres

# The database to connect to
DATABASE = qiita_test

# The host where the database lives on
HOST = localhost

# The port to connect to the database
PORT = 5432

# The password to use to connect to the database
PASSWORD = andanotherpwd

# The postgres password for the admin_user
ADMIN_PASSWORD = thishastobesecure

# ------------------------- job_scheduler settings -------------------------
[job_scheduler]
# The email address of the submitter of jobs
JOB_SCHEDULER_JOB_OWNER = user@somewhere.org

# The number of seconds to wait between successive calls
JOB_SCHEDULER_POLLING_VALUE = 15

# Hard upper-limit on concurrently running validator jobs
JOB_SCHEDULER_PROCESSING_QUEUE_COUNT = 2

# ----------------------------- EBI settings -----------------------------
[ebi]
# The user to use when submitting to EBI
EBI_SEQ_XFER_USER = Webin-41528

# Password for the above user
EBI_SEQ_XFER_PASS = passwordforebi

# URL of EBI's FASP site
EBI_SEQ_XFER_URL = webin.ebi.ac.uk

# URL of EBI's HTTPS dropbox
EBI_DROPBOX_URL = https://www-test.ebi.ac.uk/ena/submit/drop-box/submit/

# The name of the sequencing center to use when doing EBI submissions
EBI_CENTER_NAME = qiita-test

# This string (with an underscore) will be prefixed to your EBI submission and
# study aliases
EBI_ORGANIZATION_PREFIX = example_organization

# ----------------------------- VAMPS settings -----------------------------
[vamps]
# general info to submit to vamps
USER = user
PASSWORD = password
URL = https://vamps.mbl.edu/mobe_workshop/getfile.php

# ----------------------------- Portal settings -----------------------------
[portal]

# Portal the site is working under
PORTAL = QIITA

# Portal subdirectory
PORTAL_DIR = /portal

# Full path to portal styling config file
PORTAL_FP = /tmp/portal.cfg

# The center latitude of the world map, shown on the Stats map.
# Defaults to 40.01027 (Boulder, CO, USA)
STATS_MAP_CENTER_LATITUDE =

# The center longitude of the world map, shown on the Stats map.
# Defaults to -105.24827 (Boulder, CO, USA)
STATS_MAP_CENTER_LONGITUDE =

# ----------------------------- iframes settings ---------------------------
[iframe]

# ------------------- External Identity Provider settings ------------------
[oidc_academicid]

# client ID for Qiita as registered at your Identity Provider of choice
CLIENT_ID = gi-qiita-prod

# client secret to verify Qiita as the correct client. Not all IdPs require
# a client secret.
CLIENT_SECRET = verySecretString

# redirect URL (end point in your Qiita instance), to which the IdP redirects
# after user types in his/her credentials. If you don't want to change code in
# qiita_pet/webserver.py the URL must follow the pattern:
# base_URL/auth/login_OIDC/foo where foo is the name of this config section
# without the oidc_ prefix!
REDIRECT_ENDPOINT = /auth/login_OIDC/academicid

# The URL of the well-known json document, specifying how API end points
# like 'authorize', 'token' or 'userinfo' are defined. See e.g.
# https://swagger.io/docs/specification/authentication/
#    openid-connect-discovery/
WELLKNOWN_URI = https://keycloak.sso.gwdg.de/.well-known/openid-configuration

# a speaking label for the Identity Provider. Section name is used if empty.
LABEL = GWDG Academic Cloud

# The scope, i.e. fields about a user, which Qiita requests from the
# Identity Provider, e.g. "profile email eduperson_orcid".
# Will be automatically extended by the scope "openid", to enable the
# "authorize_code" OIDC flow.
SCOPE = openid

# Optional. Name of a file in qiita_pet/static/img that shall be
# displayed for login through Service Provider, instead of a plain button
LOGO = oidc_lifescienceAAI.png
"""

if __name__ == '__main__':
    main()
