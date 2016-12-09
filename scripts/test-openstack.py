#!/usr/bin/python
#
#    test-openstack.py quality assurance test script for OpenStack
#    Copyright (C) 2012-2014 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages:
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends: private/qrt/Pkg.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    IMPORTANT: this is not complete

    Based on https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack

    How to run in a clean VM:
    1. Create a server install (12.04 or later) following:
       https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack#VM_host_configuration
    2. Setup networking in the guest VM following:
       https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack#Networking_on_the_OpenStack_VM
    3. Run this script:
       $ sudo ./test-openstack.py setup-all
    4. Start using OpenStack - see:
       https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack#Using_OpenStack

    ...

    TODO:
    - make setup_mysql() not fail if databases exists
    - make setup_rabbitmq() not full if run multiple times
    - implement 'sudo ./test-openstack.py verify'
    - 13.10 support

    Notes:
    - argh python-keystone in 11.10 does not ship the
      keystone/middleware/nova_keystone_context and
      keystone.middleware.ec2_token necessary to integrate nova with keystone
'''

import unittest, sys
import os
import shutil
import subprocess
import tempfile
import testlib
import time

use_private = True
try:
    from private.qrt.mytest import MyPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class MyTest(testlib.TestlibCase):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_thing(self):
        '''Test thing'''
        # useful for testing (ie get shell after setUp())
        #subprocess.call(['bash'])


def _config_append(path,contents):
    '''Sorta like config_replace(), but don't restore'''
    if os.path.exists(path):
        testlib._save_backup(path)
        orig = file(path).read()
        if contents not in orig:
            open(path, 'w').write(orig + contents)
        #else: # debugging
        #    print "Found contents, skipping"

def find_free_ip():
    '''Find free ip address'''
    network = "192.168.122"
    first = 10
    for i in range(first,32):
        ip = '%s.%d' % (network, i)
        rc, report = testlib.cmd(['ping', 'c', '1', ip])
        if rc != 0:
            return ip
    return None

def setup_host_networking(version):
    '''Setup networking on the host'''
    # Make sure we have two interfaces
    testlib.require_sudo()
    print "Verifying interfaces...",
    rc, report = testlib.cmd(['ifconfig', '-a'])
    if rc != 0:
        print >> sys.stderr, "ifconfig -a failed"
        sys.exit(1)
    for i in ['eth0', 'eth1']:
        if i not in report:
            print >> sys.stderr, "Could not find '%s' in:\n%s" % (i, report)
            sys.exit(1)
    print "done"

    if os.path.exists("/etc/network/interfaces.autotest"):
        return None

    print "Bring down eth1...",
    testlib.cmd(['ifdown', 'eth1'])
    testlib.cmd(['ifconfig', 'eth1', 'down'])
    print "done"

    ip = find_free_ip()
    if ip == None:
        print >>sys.stderr, "Could not find free IP address"
        sys.exit(1)

    print "Setup /etc/network/interfaces...",
    contents = '''
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
        address %s
        network 192.168.122.0
        netmask 255.255.255.128
        broadcast 192.168.122.127
        gateway 192.168.122.1

iface eth1 inet6 manual
iface eth1 inet manual
''' % (ip)
    if version >= 13.10:
        contents += '''        up ifconfig $IFACE 0.0.0.0 up
        up ifconfig $IFACE promisc
'''

    testlib.config_replace("/etc/network/interfaces", contents)
    print "done"

    print "Setup /etc/resolvconf/resolv.conf.d/base..."
    contents = '''search defaultdomain
nameserver 192.168.122.1
'''
    testlib.config_replace("/etc/resolvconf/resolv.conf.d/base", contents)
    print "done"

    return ip # triggers a reboot

def install_packages(version):
    '''Install packages to run OpenStack'''
    print "Installing packages..."
    packages = [
                "rabbitmq-server",
                "mysql-server",
                "nova-compute",
                "nova-api",
                "nova-scheduler",
                "nova-objectstore",
                "nova-network",
                "glance",
                "python-mysqldb",
                "euca2ools",
                "python-memcache",
                "memcached",
                "openstack-dashboard",
                "lvm2",
               ]

    if version >= 12.04:
        packages.append("nova-cert")
        packages.append("keystone")

    if version < 12.04:
        packages.append("unzip")

    if version < 13.04: # nova-volume vs cinder
        packages.append("nova-volume")
    else:
        packages.append("cinder-api")
        packages.append("cinder-scheduler")
        packages.append("cinder-volume")
        packages.append("python-cinderclient")

    if version >= 13.04: #  grizzly needs nova-conductor
        packages.append("nova-conductor")

    if version >= 13.10: #  heat only in havana and higher
        packages.append("heat-api")
        packages.append("heat-api-cfn")
        packages.append("heat-engine")

    rc, report = testlib.cmd(['apt-get', 'update'])
    if rc != 0:
        print >> sys.stderr, "Error running apt-get update"
        sys.exit(1)

    # For now, create a tempfile to run
    tmp = tempfile.mktemp(dir='/tmp')
    contents = '''#!/bin/sh
apt-get install -y --force-yes %s
''' % " ".join(packages)
    testlib.create_fill(tmp, contents)
    print "TODO: preseed the mysql password so we can automate this step"
    print "Install packages with the following (use 'pass' for mysql root"
    print "password and type 'exit' when done):"
    print "# sh %s" % tmp
    subprocess.call(['bash'])
    os.unlink(tmp)

    # TODO: fix debconf here
    #rc, report = testlib.cmd(['apt-get', 'install', '-y', '--force-yes'] + packages)
    #if rc != 0:
    #    print >> sys.stderr, "Error installing packages:\n%s" % report
    #    sys.exit(1)
    print "done"

def setup_network():
    '''Setup networking for libvirt and OpenStack'''
    print "Setting up networking...",

    # Taken from test-libvirt.py
    rc, report = testlib.cmd(['id'])

    # libvirt will fail with error if defining things just after it
    # it starts. This capabilities call is a hack to know when libvirtd
    # is ready, since it will wait rather than return error
    rc, report = testlib.cmd(['virsh', 'capabilities'])
    if rc != 0:
        print >>sys.stderr, "virsh capabilities failed:\n%s" % report
        sys.exit(1)

    rc, report = testlib.cmd_pipe(['virsh', 'net-dumpxml', 'default'], ['sed', '-e', 's#192.168.122.#192.168.123.#g', '-e', 's#^Connecting.*##g'])
    print report
    if rc != 0:
        print >>sys.stderr, "virsh net-dumpxml failed:\n%s" % report
        sys.exit(1)
    tmp = tempfile.mktemp(dir='/tmp')
    testlib.create_fill(tmp, report)

    rc, report = testlib.cmd(['virsh', 'net-destroy', 'default'])
    if rc != 0:
        print >>sys.stderr, "WARN: virsh net-destroy failed. Continuing (non-fatal)"

    rc, report = testlib.cmd(['virsh', 'net-undefine', 'default'])
    if rc != 0:
        print >>sys.stderr, "WARN: virsh net-undefine failed. Continuing (non-fatal)"

    rc, report = testlib.cmd(['virsh', 'net-define', tmp])
    if rc != 0:
        print >>sys.stderr, "virsh net-define failed:\n%s" % report
        subprocess.call(['mv', '-f', tmp, '/tmp/net.xml'])
        print >>sys.stderr, "xml saved in /tmp/net.xml"
        sys.exit(1)

    rc, report = testlib.cmd(['virsh', 'net-autostart', 'default'])
    if rc != 0:
        print >>sys.stderr, "virsh net-autostart default failed:\n%s" % report
        subprocess.call(['mv', '-f', tmp, '/tmp/net.xml'])
        print >>sys.stderr, "xml saved in /tmp/net.xml"
        sys.exit(1)

    # clean up
    os.unlink(tmp)

    print "Restarting libvirt"
    testlib.cmd(['sudo', '/etc/init.d/libvirt-bin', 'stop'])
    testlib.cmd(['sudo', 'killall', 'dnsmasq'])
    testlib.cmd(['sudo', '/etc/init.d/libvirt-bin', 'start'])
    print "done"

nova_mysql_passwd     = "novamysqlpasswd"
nova_rabbitmq_passwd  = "rabbitmqpasswd"
glance_mysql_passwd   = "glancemysqlpasswd"
cinder_mysql_passwd   = "cindermysqlpasswd"
keystone_mysql_passwd = "keystonemysqlpasswd"
keystone_admin_token  = "keystoneadmintoken"
heat_mysql_passwd     = "heatmysqlpasswd"
admin_password        = "adminpasswd"

def setup_mysql(version):
    print "Setting up mysql...",
    contents = '''create database glance;
create database keystone;
create database nova;
create database cinder;
create database heat;
grant all privileges on glance.* to 'glance'@'localhost' identified by '%s';
grant all privileges on keystone.* to 'keystone'@'localhost' identified by '%s';
grant all privileges on nova.* to 'nova'@'localhost' identified by '%s';
grant all privileges on cinder.* to 'cinder'@'localhost' identified by '%s';
grant all privileges on heat.* to 'heat'@'localhost' identified by '%s';
grant all privileges on heat.* to 'heat'@'%' identified by '%s';
''' % (glance_mysql_passwd, keystone_mysql_passwd, nova_mysql_passwd,
       cinder_mysql_passwd, heat_mysql_passwd)
    if version >= 13.04:
        contents += '''grant all privileges on nova.* to 'nova'@'localhost' identified by '%s';
''' % (nova_mysql_passwd)
    tmp = tempfile.mktemp(dir='/tmp')
    testlib.create_fill(tmp, contents)
    rc, report = testlib.cmd_pipe(['cat', tmp], ['mysql', '-v', '--user=root', '--password=pass'])
    if rc != 0:
        print >>sys.stderr, "Could not setup mysql:\n%s" % report
        sys.exit(1)
    print "done"

def setup_rabbitmq():
    print "Setting up rabbitmq...",
    rc, report = testlib.cmd(['rabbitmqctl', 'add_vhost', 'nova'])
    if rc != 0:
        print >>sys.stderr, "Could not setup rabbitmq 'add_vhost':\n%s" % report
        sys.exit(1)

    rc, report = testlib.cmd(['rabbitmqctl', 'add_user', 'nova', nova_rabbitmq_passwd])
    if rc != 0:
        print >>sys.stderr, "Could not setup rabbitmq 'add_user':\n%s" % report
        sys.exit(1)

    rc, report = testlib.cmd(['rabbitmqctl', 'set_permissions', '-p', 'nova', 'nova', ".*", ".*", ".*"])
    if rc != 0:
        print >>sys.stderr, "Could not setup rabbitmq 'set_permissions':\n%s" % report
        sys.exit(1)
    print "done"

def setup_nova(version):
    print "Setting up nova...",
    sys.stdout.flush()
    contents = ''
    if version < 12.04: # oneiric
        contents = '''--sql_connection=mysql://nova:%s@localhost/nova
--rabbit_host=localhost
--rabbit_userid=nova
--rabbit_password=%s
--rabbit_virtual_host=nova
--rabbit_vhost=nova
--rpc_backend=nova.rpc.impl_carrot
--network_manager=nova.network.manager.FlatDHCPManager
--auth_driver=nova.auth.dbdriver.DbDriver
--ec2_url=http://localhost:8773/services/Cloud
--image_service=nova.image.glance.GlanceImageService
--glance_api_servers=127.0.0.1:9292
''' % (nova_mysql_passwd, nova_rabbitmq_passwd)
# Add this if ever get to use keystone on 11.10
#--keystone_ec2_url=http://localhost:5000/v2.0/ec2tokens
    elif version < 12.10: # precise
        contents = '''--sql_connection=mysql://nova:%s@localhost/nova
--rabbit_host=localhost
--rabbit_userid=nova
--rabbit_password=%s
--rabbit_virtual_host=nova
--rabbit_vhost=nova
--network_manager=nova.network.manager.FlatDHCPManager
--auth_strategy=keystone
--ec2_url=http://localhost:8773/services/Cloud
--keystone_ec2_url=http://localhost:5000/v2.0/ec2tokens
''' % (nova_mysql_passwd, nova_rabbitmq_passwd)
    else:
        contents = '''sql_connection=mysql://nova:%s@localhost/nova
rabbit_host=localhost
rabbit_userid=nova
rabbit_password=%s
rabbit_virtual_host=nova
rabbit_vhost=nova
network_manager=nova.network.manager.FlatDHCPManager
ec2_url=http://localhost:8773/services/Cloud
auth_strategy=keystone
keystone_ec2_url=http://localhost:5000/v2.0/ec2tokens
''' % (nova_mysql_passwd, nova_rabbitmq_passwd)
    fn = "/etc/nova/nova.conf"
    _config_append(fn, contents)

    if version >= 13.04: #  raring and higher use cinder
        rc, report = testlib.cmd(['sed', '-i', 's#^volumes_path=.*#volume_api_class=nova.volume.cinder.API#', fn])

    rc, report = testlib.cmd(['nova-manage', 'db', 'sync'])
    if rc != 0:
        print >>sys.stderr, "nova-manage db sync failed"
        sys.exit(1)

    services = ['nova-api', 'nova-scheduler', 'nova-network', 'nova-conductor', 'nova-compute', 'nova-objectstore']
    for s in services:
        if s == 'nova-conductor' and version < 13.04: # nova-conductor in grizzly and later
            continue
        testlib.cmd(['service', s, 'restart'])

    time.sleep(10)

    # verify it worked
    rc, report = testlib.cmd(['netstat', '-nl'])
    for port in ['5672']:
        if not ":%s" % port in report:
            print >>sys.stderr, "Could not find '%s' in report:\n%s" % (port, report)
            sys.exit(1)
    print "done"

def setup_glance(version):
    print "Setting up glance..."

    fn = "/etc/glance/glance-registry.conf"
    print "  %s" % fn
    if version >= 12.04:
        contents = '''[paste_deploy]
flavor = keystone
'''
        if version >= 12.10:
            contents = '''flavor = keystone
'''
        _config_append(fn, contents)

    rc, report = testlib.cmd(['sed', '-i', 's#^sql_connection.*#sql_connection = mysql://glance:%s@localhost/glance#' % glance_mysql_passwd, fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup glance-registry.conf 'sql_connection':\n%s" % report
        sys.exit(1)

# keystone 1.0~d4~20110909.1108-0ubuntu3.1 is broken
#    if version < 12.04:
#        rc, report = testlib.cmd(['sed', '-i', 's#auth_port = 5001#auth_port = 35357#', fn])
#        if rc != 0:
#            print >>sys.stderr, "Could not setup autho_port in glance-registry.conf':\n%s" % report
#            sys.exit(1)
#
#        rc, report = testlib.cmd(['sed', '-i', 's#admin_token = .*#admin_token = %s#' % keystone_admin_token, fn])
#        if rc != 0:
#            print >>sys.stderr, "Could not setup admin_token in glance-registry.conf':\n%s" % report
#            sys.exit(1)

    fn = "/etc/glance/glance-api.conf"
    print "  %s" % fn

    if version >= 12.04:
        contents = '''[paste_deploy]
flavor = keystone
'''
        if version >= 12.10:
            contents = '''flavor = keystone
'''
        _config_append(fn, contents)

    if version >= 12.10: # quantal and higher
        rc, report = testlib.cmd(['sed', '-i', 's#^sql_connection.*#sql_connection = mysql://glance:%s@localhost/glance#' % glance_mysql_passwd, fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup glance-api.conf 'sql_connection':\n%s" % report
            sys.exit(1)
# keystone 1.0~d4~20110909.1108-0ubuntu3.1 is broken
#    elif version < 12.04:
#        rc, report = testlib.cmd(['sed', '-i', 's#auth_port = 5001#auth_port = 35357#', fn])
#        if rc != 0:
#            print >>sys.stderr, "Could not setup auth_port in glance-api.conf':\n%s" % report
#            sys.exit(1)
#        rc, report = testlib.cmd(['sed', '-i', 's#admin_token = .*#admin_token = %s#' % keystone_admin_token, fn])
#        if rc != 0:
#            print >>sys.stderr, "Could not setup admin_token in glance-api.conf':\n%s" % report
#            sys.exit(1)

    # need to also adjust /etc/glance/glance-scrubber.conf in Diablo
    if version < 12.04:
        rc, report = testlib.cmd(['sed', '-i', 's#^sql_connection.*#sql_connection = mysql://glance:%s@localhost/glance#' % glance_mysql_passwd, "/etc/glance/glance-scrubber.conf"])
        if rc != 0:
            print >>sys.stderr, "Could not setup glance-scrubber.conf 'sql_connection':\n%s" % report
            sys.exit(1)

    if version >= 13.10 and os.path.exists('/var/lib/glance/glance.sqlite'):
        os.unlink('/var/lib/glance/glance.sqlite')

    testlib.cmd(['stop', 'glance-api'])
    testlib.cmd(['stop', 'glance-registry'])
    testlib.cmd(['glance-manage', 'version_control', '0'])
    testlib.cmd(['glance-manage', 'db_sync'])
    testlib.cmd(['start', 'glance-api'])
    testlib.cmd(['start', 'glance-registry'])

    time.sleep(10)

    # verify it worked
    rc, report = testlib.cmd(['netstat', '-nl'])
    for port in ['9191', '9292']:
        if not ":%s" % port in report:
            print >>sys.stderr, "Could not find '%s' in report:\n%s" % (port, report)
            sys.exit(1)
    print "done"

def setup_cinder(version):
    if version < 13.04:
        print "  SKIPPED: setup cinder manually on 12.10 and earlier"
        return

    fn = "/etc/cinder/api-paste.ini"
    print "  %s" % fn

    rc, report = testlib.cmd(['sed', '-i', 's#^admin_user =.*#admin_user = cinder#', fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup 'admin_user':\n%s" % report
        sys.exit(1)
    rc, report = testlib.cmd(['sed', '-i', 's#^admin_password =.*#admin_password = cinder#', fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup 'admin_password':\n%s" % report
        sys.exit(1)
    rc, report = testlib.cmd(['sed', '-i', 's#^admin_tenant_name =.*#admin_tenant_name = services#', fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup 'admin_tenant_name':\n%s" % report
        sys.exit(1)

    fn = "/etc/cinder/cinder.conf"
    print "  %s" % fn
    contents = '''sql_connection = mysql://cinder:%s@localhost/cinder
rabbit_host = localhost
rabbit_userid = nova
rabbit_password = %s
rabbit_virtual_host = nova
rabbit_vhost = nova
''' % (cinder_mysql_passwd, nova_rabbitmq_passwd)
    _config_append(fn, contents)

    print "  restarting cinder"
    rc, report = testlib.cmd(['cinder-manage', 'db', 'sync'])
    if rc != 0:
        print >>sys.stderr, "cinder-manage db sync failed"
        sys.exit(1)

    services = ['cinder-volume', 'cinder-api', 'cinder-scheduler', 'tgt']
    for s in services:
        testlib.cmd(['service', s, 'restart'])

    time.sleep(10)

    # verify it worked
    rc, report = testlib.cmd(['netstat', '-nl'])
    for port in ['8776']:
        if not ":%s" % port in report:
            print >>sys.stderr, "Could not find '%s' in report:\n%s" % (port, report)
            sys.exit(1)
    print "done"

def setup_heat(version):
    if version < 13.10:
        print "  SKIPPED: heat doesn't exist on 13.04 and earlier"
        return

    print "  TODO: heat setup: http://docs.openstack.org/havana/install-guide/install/apt/content/heat-install.html"
    return

    fn = "/etc/heat/heat.conf"
    print "  %s" % fn
    contents = '''sql_connection = mysql://heat:%s@localhost/heat
verbose = True
rabbit_host = localhost
rabbit_userid = nova
rabbit_password = %s
rabbit_virtual_host = nova
rabbit_vhost = nova
''' % (heat_mysql_passwd, nova_rabbitmq_passwd)
    rc, report = testlib.cmd(['sed', '-i', 's#^sql_connection.*#%s#' % contents, fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup /etc/heat/heat.conf:\n%s" % report
        sys.exit(1)

    contents = '''[ec2authtoken]
auth_uri = http://localhost:5000/v2.0
keystone_ec2_uri = http://localhost:5000/v2.0/ec2tokens
'''
    rc, report = testlib.cmd(['sed', '-i', 's#^\[ec2authtoken\].*# %s#' % contents, fn])
    if rc != 0:
        print >>sys.stderr, "Could not setup /etc/heat/heat.conf [ec2authtoken]:\n%s" % report
        sys.exit(1)

    contents = '''[keystone_authtoken]
auth_host = localhost
auth_port = 35357
auth_protocol = http
auth_uri = http://localhost:5000/v2.0
admin_tenant_name = services
admin_user = heat
admin_password = heat
'''
    _config_append(fn, contents)

    print "  restarting heat"
    rc, report = testlib.cmd(['heat-manage', 'db_sync'])
    if rc != 0:
        print >>sys.stderr, "heat-manage db sync failed"
        sys.exit(1)

    services = ['heat-api', 'heat-api-cfn', 'heat-engine']
    for s in services:
        testlib.cmd(['service', s, 'restart'])

    time.sleep(10)

    # verify it worked
    rc, report = testlib.cmd(['netstat', '-nl'])
    for port in ['8000', '8004']:
        if not ":%s" % port in report:
            print >>sys.stderr, "Could not find '%s' in report:\n%s" % (port, report)
            sys.exit(1)
    print "done"

def setup_keystone(version):
    print "Setting up keystone..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    _config_append("/etc/keystone/keystone.conf", '') # create a backup
    if version < 12.04:
        rc, report = testlib.cmd(['sed', '-i', 's#^sql_connection = sqlite.*#sql_connection = mysql://keystone:%s@localhost/keystone#' % keystone_mysql_passwd, "/etc/keystone/keystone.conf"])
    else:
        rc, report = testlib.cmd(['sed', '-i', 's#^connection = sqlite.*#connection = mysql://keystone:%s@localhost/keystone#' % keystone_mysql_passwd, "/etc/keystone/keystone.conf"])
    if rc != 0:
        print >>sys.stderr, "Could not setup /etc/keystone/keystone.conf 'connection':\n%s" % report
        sys.exit(1)

    if version < 12.04:
        rc, report = testlib.cmd(['sed', '-i', 's/^\(# \)\?admin_port = 5001/#admin_port = 5001\\nadmin_port = 35357/', "/etc/keystone/keystone.conf"])
        if rc != 0:
            print >>sys.stderr, "Could not setup /etc/keystone/keystone.conf 'admin_port':\n%s" % report
            sys.exit(1)
    else:
        rc, report = testlib.cmd(['sed', '-i', 's/^\(# \)\?admin_token = ADMIN/# admin_token = ADMIN\\nadmin_token = %s/' % keystone_admin_token, "/etc/keystone/keystone.conf"])
        if rc != 0:
            print >>sys.stderr, "Could not setup /etc/keystone/keystone.conf 'admin_token':\n%s" % report
            sys.exit(1)

    testlib.cmd(['keystone-manage', 'db_sync'])
    testlib.cmd(['stop', 'keystone'])
    testlib.cmd(['start', 'keystone'])

    time.sleep(10)

    # verify it worked
    rc, report = testlib.cmd(['netstat', '-nl'])
    ports = ['5000', '35357']
    for port in ports:
        if not ":%s" % port in report:
            print >>sys.stderr, "Could not find '%s' in report:\n%s" % (port, report)
            sys.exit(1)

    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'user', 'list'])
        if rc != 0:
            print >>sys.stderr, "keystone-manage user list failed:\n%s" % report
            sys.exit(1)
    else:
        os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
        os.environ["SERVICE_TOKEN"] = keystone_admin_token
        rc, report = testlib.cmd(['keystone', 'user-list'])
        if rc != 0:
            print >>sys.stderr, "keystone user-list failed:\n%s" % report
            sys.exit(1)

        os.environ["SERVICE_ENDPOINT"] = ""
        os.environ["SERVICE_TOKEN"] = ""
    print "done"

def _get_id(version, idtype, name):
    '''Get id for name'''
    id = None
    if version < 12.04:
        rc, report = testlib.cmd_pipe(["keystone-manage", idtype, 'list'], ['egrep', '^%s' % name])
        id = report.split()[0].strip()
    else:
        rc, report = testlib.cmd_pipe(["keystone", "%s-list" % idtype], ['egrep', ' %s ' % name])
        id = report.split()[1].strip()
    if rc != 0:
        return None
    return id

def setup_tenants(version):
    print "Setting up tenants..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
    os.environ["SERVICE_TOKEN"] = keystone_admin_token

    for tenant in ['admin', 'users', 'services']:
        print "  '%s'" % tenant,
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'tenant', 'list'])
        else:
            rc, report = testlib.cmd(['keystone', 'tenant-list'])
        if tenant in report:
            print "already exists"
            continue

        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'tenant', 'add', \
                                      tenant])
        else:
            rc, report = testlib.cmd(['keystone', 'tenant-create', '--name', \
                                      tenant, '--description', \
                                      "%s tenant" % tenant.capitalize()])
        if rc != 0:
            print >>sys.stderr, "Could not setup tenant '%s':\n%s" % (tenant, report)
            sys.exit(1)
        print "created"

    # verify
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'tenant', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'tenant-list'])
    for user in ['admin', 'users', 'services']:
        if not tenant in report:
            print >>sys.stderr, "Could not find '%s': \n%s" % (tenant, report)
            sys.exit(1)

    os.environ["SERVICE_ENDPOINT"] = ""
    os.environ["SERVICE_TOKEN"] = ""
    print "done"

def setup_roles(version):
    print "Setting up roles..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
    os.environ["SERVICE_TOKEN"] = keystone_admin_token

    roles = ['Member', 'admin']
    if version < 12.04:
        roles = ['Member', 'Admin', 'KeystoneAdmin', 'KeystoneServiceAdmin']
    for role in roles:
        print "  '%s'" % role,
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'role', 'list'])
        else:
            rc, report = testlib.cmd(['keystone', 'role-list'])
        if role in report:
            print "already exists"
            continue
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'role', 'add', role])
        else:
            rc, report = testlib.cmd(['keystone', 'role-create', '--name', role])
        if rc != 0:
            print >>sys.stderr, "Could not setup role '%s':\n%s" % (role, report)
            sys.exit(1)
        print "created"

    # verify
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'role', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'role-list'])
    for user in ['Member', 'admin']:
        if not role in report:
            print >>sys.stderr, "Could not find '%s': \n%s" % (role, report)
            sys.exit(1)

    os.environ["SERVICE_ENDPOINT"] = ""
    os.environ["SERVICE_TOKEN"] = ""
    print "done"

def setup_users(version):
    print "Setting up users..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
    os.environ["SERVICE_TOKEN"] = keystone_admin_token

    def add_user(version, tenant_id, role_id, user, password):
        print "    create user"
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'user', 'add', \
                                      user, password])
            if rc != 0:
                print >>sys.stderr, "Could not add user '%s':\n%s" % (user, report)
                sys.exit(1)
        else:
            rc, report = testlib.cmd(['keystone', 'user-create', \
                                      '--tenant_id', tenant_id, \
                                      '--name', user, \
                                      '--pass', password, \
                                      '--enabled', 'true'])
            if rc != 0:
                print >>sys.stderr, "Could not setup user '%s':\n%s" % (user, report)
                sys.exit(1)

        user_id = _get_id(version, "user", user)
        if version < 12.10:
            print "    add user '%s' to role '%s'" % (user_id, role_id)
            rc, report = testlib.cmd(['keystone-manage', 'role', 'grant', \
                                      role_id, user_id])
            if rc != 0:
                print >>sys.stderr, "Could not grant user '%s' the role '%s':\n%s" % (user, report)
                sys.exit(1)
            print "    add user '%s' and tenant '%s' to role '%s'" % (user_id, tenant_id, role_id)
            rc, report = testlib.cmd(['keystone-manage', 'role', 'grant', \
                                      role_id, user_id, tenant_id])
            if rc != 0:
                print >>sys.stderr, "Could not grant user '%s' the role '%s':\n%s" % (user, report)
                sys.exit(1)
        else:
            print "    add user '%s' and tenant '%s' to role '%s'" % (user_id, tenant_id, role_id)
            rc, report = testlib.cmd(['keystone', 'user-role-add', \
                                      '--user_id', user_id, \
                                      '--tenant_id', tenant_id, \
                                      '--role_id', role_id])
            if rc != 0:
                print >>sys.stderr, "Could not setup user role for '%s':\n%s" % (user, report)
                sys.exit(1)

    user = 'admin'
    print "  '%s'" % user
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'user', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'user-list'])
    if user in report:
        print "already exists"
    else:
        tenant_id = _get_id(version, "tenant", user)
        if version < 12.04:
            role_id = _get_id(version, "role", user.capitalize())
        else:
            role_id = _get_id(version, "role", user)
        add_user(version, tenant_id, role_id, user, admin_password)
        if version < 12.04:
            # Roles are setup a bit differently in Diablo
            for r in ['KeystoneAdmin', 'KeystoneServiceAdmin', 'Admin', 'admin']:
                print "    add user '%s' to role '%s'" % (user, r)
                rc, report = testlib.cmd(['keystone-manage', 'role', 'grant', \
                                          r, user])
                if rc != 0:
                    print >>sys.stderr, "Could not grant user '%s' the role '%s':\n%s" % (user, report)
                    sys.exit(1)
            # need to add the admin token via keystone-manage in Diablo (also
            # make it last for until the year 2100)
            rc, report = testlib.cmd(['keystone-manage', 'token', 'add', \
                                      admin_password, 'admin', \
                                      tenant_id, '2100-02-05T00:00'])
            if rc != 0:
                print >>sys.stderr, "Could not setup admin_token:\n%s" % (user, report)
                sys.exit(1)
        print "  done"

    users = ['glance', 'nova']
    if version >= 12.10:
        users.append('cinder')
    if version >= 13.10:
        users.append('heat')
    for user in users:
        print "  '%s'" % user
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'user', 'list'])
        else:
            rc, report = testlib.cmd(['keystone', 'user-list'])
        if user in report:
            print "already exists"
        else:
            tenant_id = _get_id(version, "tenant", "services")
            if version < 12.04:
                role_id = _get_id(version, "role", "Admin")
            else:
                role_id = _get_id(version, "role", "admin")
            add_user(version, tenant_id, role_id, user, user) # use <user> as password
        print "  done"

    # verify
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'user', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'user-list'])
    for user in ['admin'] + users:
        if not user in report:
            print >>sys.stderr, "Could not find '%s': \n%s" % (user, report)
            sys.exit(1)

    os.environ["SERVICE_ENDPOINT"] = ""
    os.environ["SERVICE_TOKEN"] = ""
    print "done"

def setup_services(version):
    print "Setting up services..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
    os.environ["SERVICE_TOKEN"] = keystone_admin_token

    services = ['glance image', 'nova compute', 'ec2 ec2', 'keystone identity']
    if version >= 13.04:
        services.append('cinder volume')
    else:
        services.append('nova-volume volume')

    if version >= 13.10:
        services.append('heat orchestration')
        services.append('heat-cfn cloudformation')

    for s in services:
        service_name, service_type = s.split()
        print "  '%s'" % service_name,
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'service', 'list'])
        else:
            rc, report = testlib.cmd(['keystone', 'service-list'])
        if service_name in report:
            print "already exists"
            continue
        description = '%s %s service' % (service_name.capitalize(), \
                                         service_type.capitalize())
        if service_name == "ec2":
            description = "EC2 compatibility layer"
        elif service_name == "nova-volume":
            description = "Nova volume service"
        elif service_name == "cinder":
            description = "Cinder volume service"

        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'service', 'add', \
                                      service_name, service_type, description])
        else:
            rc, report = testlib.cmd(['keystone', 'service-create', \
                                      '--name', service_name, \
                                      '--type', service_type, \
                                      '--description', description])
        if rc != 0:
            print >>sys.stderr, "Could not setup service '%s':\n%s" % (service_name, report)
            sys.exit(1)
        print "created"

    # verify
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'service', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'service-list'])
    for s in services:
        service_name, service_type = s.split()
        if not service_name in report:
            print >>sys.stderr, "Could not find '%s': \n%s" % (service_name, report)
            sys.exit(1)

    os.environ["SERVICE_ENDPOINT"] = ""
    os.environ["SERVICE_TOKEN"] = ""
    print "done"

def setup_endpoints(version):
    print "Setting up endpoints..."
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    os.environ["SERVICE_ENDPOINT"] = "http://localhost:35357/v2.0/"
    os.environ["SERVICE_TOKEN"] = keystone_admin_token

    def add_endpoint(public_url, internal_url, admin_url, service_id, region="RegionOne"):
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'endpointTemplates', \
                                      'add', \
                                      region, \
                                      service_id, \
                                      public_url, \
                                      admin_url,
                                      internal_url, \
                                      '1', # enabled
                                      '1'  # global
                                     ])
        else:
            rc, report = testlib.cmd(['keystone', 'endpoint-create', \
                                      '--region', region, \
                                      '--service_id', service_id, \
                                      '--publicurl', public_url, \
                                      '--internalurl', internal_url, \
                                      '--adminurl', admin_url])
        if rc != 0:
            print >>sys.stderr, "Could not setup endpoint '%s':\n%s" % (public_url, report)
            sys.exit(1)
        print "created"

    urls = ["http://localhost:9292/v1",
            #"http://localhost:8774/v1.1/$(tenant_id)s",
            "http://localhost:8773/services/Cloud",
            "http://localhost:5000/v2.0",
            #"http://localhost:8776/v1/$(tenant_id)s"
           ]
    if version < 12.04:
        urls.append("http://localhost:8774/v1.1/%tenant_id%")
        urls.append( "http://localhost:8776/v1/%tenant_id%")
    else:
        urls.append("http://localhost:8774/v1.1/$(tenant_id)s")
        urls.append("http://localhost:8776/v1/$(tenant_id)s")

    if version >= 13.10:
        urls.append("http://localhost:8004/v1/$(tenant_id\)s")
        urls.append("http://localhost:8000/v1")

    for public_url in urls:
        print "  '%s'" % public_url,
        if version < 12.04:
            rc, report = testlib.cmd(['keystone-manage', 'endpointTemplates', 'list'])
        else:
            rc, report = testlib.cmd(['keystone', 'endpoint-list'])
        if public_url in report:
            print "already exists"
            continue
        else:
            internal_url = public_url
            admin_url = public_url
            # keystone has a different admin url
            if public_url == "http://localhost:5000/v2.0":
                admin_url = "http://localhost:35357/v2.0"
            service = ""
            if "9292" in public_url:
                service = "glance"
            elif "8774" in public_url:
                service = "nova"
            elif "8773" in public_url:
                service = "ec2"
            elif "5000" in public_url:
                service = "keystone"
            elif "8776" in public_url:
                if version >= 13.04:
                    service = "cinder"
                else:
                    service = "nova-volume"
            elif "8004" in public_url:
                service = "heat"
            elif "8000" in public_url:
                service = "heat-cfn"
            else:
                print >>sys.stderr, "Unknown url '%s', skipping endpoint creation" % public_url
                continue
            service_id = _get_id(version, "service", service)
            add_endpoint(public_url, internal_url, admin_url, service_id)

    # verify
    if version < 12.04:
        rc, report = testlib.cmd(['keystone-manage', 'endpointTemplates', 'list'])
    else:
        rc, report = testlib.cmd(['keystone', 'endpoint-list'])
    if rc != 0:
        print >>sys.stderr, "Could not list endpoints:\n%s" % (report)
        sys.exit(1)
    for url in urls:
        if not url in report:
            print >>sys.stderr, "Could not find '%s': \n%s" % (url, report)
            sys.exit(1)

    os.environ["SERVICE_ENDPOINT"] = ""
    os.environ["SERVICE_TOKEN"] = ""

    if version < 12.04:
        # TODO: http://docs.openstack.org/diablo/openstack-compute/install/content/verifying-identity-install.html
        # version in 11.10 needs soemthing like this:
        # curl -d '{"passwordCredentials": {"username": "admin", "password": "adminpasswd"}}' -H "Content-type: application/json" http://localhost:35357/v2.0/tokens | python -mjson.tool
        # but newer Diablo's will follow the TODO ^
        pass
    else:
        #  'catalog' not available in Diablo
        os.environ["OS_USERNAME"] = "admin"
        os.environ["OS_PASSWORD"] = admin_password
        os.environ["OS_TENANT_NAME"] = "admin"
        os.environ["OS_AUTH_URL"] = "http://localhost:5000/v2.0/"

        rc, report = testlib.cmd(['keystone', 'catalog'])
        for url in urls:
            adj_url = url
            if "tenant_id" in url:
                adj_url = os.path.dirname(url)

            if not adj_url in report:
                print >>sys.stderr, "Could not find '%s': \n%s" % (adj_url, report)
                sys.exit(1)

        services = ['image', 'compute', 'ec2', 'identity', 'volume']
        for service in services:
            search = "Service: %s" % service
            if search not in report:
                print >>sys.stderr, "Could not find '%s': \n%s" % (search, report)
                sys.exit(1)

        os.environ["OS_USERNAME"] = ""
        os.environ["OS_PASSWORD"] = ""
        os.environ["OS_TENANT_NAME"] = ""
        os.environ["OS_AUTH_URL"] = ""

    print "done"

def setup_services_for_keystone(version):
    print "Setting up nova and glance to use keystone"
    if version < 12.04:
        print "  SKIPPED: keystone is broken on 11.10"
        return

    fn = "/etc/nova/api-paste.ini"
    print "  %s" % fn
    if version < 12.04:
        contents = '''
#
# testlib: for keystone
#


[filter:keystonecontext]
paste.filter_factory = keystone.middleware.nova_keystone_context:NovaKeystoneContext.factory

[filter:authtoken]
paste.filter_factory = keystone.middleware.auth_token:filter_factory
service_protocol = http
service_host = 127.0.0.1
service_port = 5000
auth_host = 127.0.0.1
auth_port = 35357
auth_protocol = http
auth_uri = http://127.0.0.1:5000/
admin_token = %s
''' % keystone_admin_token
        _config_append(fn, contents)
        rc, report = testlib.cmd(['sed', '-i', 's#^pipeline = logrequest authenticate cloudrequest authorizer ec2executor#pipeline = logrequest totoken authtoken keystonecontext cloudrequest authorizer ec2executor#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'pipeline':\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', 's#^pipeline = logrequest authenticate adminrequest authorizer ec2executor#pipeline = logrequest totoken authtoken keystonecontext adminrequest authorizer ec2executor#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'pipeline':\n%s" % report
            sys.exit(1)

        orig = file(fn).read()
        if "[filter:totoken]" not in orig:
            rc, report = testlib.cmd(['sed', '-i', 's#^\[filter:ec2noauth\]#[filter:totoken]\\npaste.filter_factory = keystone.middleware.ec2_token:EC2Token.factory\\n\\n[filter:ec2noauth]#', fn])
            if rc != 0:
                print >>sys.stderr, "Could not setup 'filter':\n%s" % report
                sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', 's#^pipeline = faultwrap auth ratelimit osapiapp10#pipeline = faultwrap authtoken keystonecontext ratelimit osapiapp10#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'pipeline':\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', 's#^pipeline = faultwrap auth ratelimit extensions osapiapp11#pipeline = faultwrap authtoken keystonecontext ratelimit extensions osapiapp11#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'pipeline':\n%s" % report
            sys.exit(1)


        rc, report = testlib.cmd(['sed', '-i', 's#^##', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'admin_user':\n%s" % report
            sys.exit(1)
    else:
        contents = '''admin_token = %s
''' % keystone_admin_token
        _config_append(fn, contents)
        rc, report = testlib.cmd(['sed', '-i', 's#^admin_user =.*#admin_user = nova#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'admin_user':\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', 's#^admin_password =.*#admin_password = nova#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'admin_password':\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', 's#^admin_tenant_name =.*#admin_tenant_name = services#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'admin_tenant_name':\n%s" % report
            sys.exit(1)

    if version >= 12.04:
        for fn in ["/etc/glance/glance-api-paste.ini", "/etc/glance/glance-registry-paste.ini"]:
            print "  %s" % fn
            contents = 'admin_token = %s\\n' % keystone_admin_token
            if version >= 12.10:
                contents += 'auth_host = 127.0.0.1\\nauth_port = 35357\\nauth_protocol = http\\nadmin_tenant_name = services\\nadmin_user = glance\\nadmin_password = glance'
            rc, report = testlib.cmd(['sed', '-i', 's#^\[filter:authtoken\]#[filter:authtoken]\\n%s#' % contents, fn])
            if rc != 0:
                print >>sys.stderr, "Could not setup '[filter:authtoken]':\n%s" % report
                sys.exit(1)
            _config_append(fn, contents)
            if version < 12.10:
                rc, report = testlib.cmd(['sed', '-i', 's#^admin_user =.*#admin_user = glance#', fn])
                if rc != 0:
                    print >>sys.stderr, "Could not setup 'admin_user':\n%s" % report
                    sys.exit(1)
                rc, report = testlib.cmd(['sed', '-i', 's#^admin_password =.*#admin_password = glance#', fn])
                if rc != 0:
                    print >>sys.stderr, "Could not setup 'admin_password':\n%s" % report
                    sys.exit(1)
                rc, report = testlib.cmd(['sed', '-i', 's#^admin_tenant_name =.*#admin_tenant_name = services#', fn])
                if rc != 0:
                    print >>sys.stderr, "Could not setup 'admin_tenant_name':\n%s" % report
                    sys.exit(1)



    # All we need for nova-volume is for the nova-volumes VG to be present.
    # cinder needs cinder-volumes, but also more and is setup elsewhere
    search = 'nova-volumes'
    if version >= 13.04:
        search = 'cinder-volumes'
    print "  verifying %s VG" % search
    rc, report = testlib.cmd(['vgdisplay'])
    if rc != 0:
        print >>sys.stderr, "vgdisplay failed:\n%s" % report
        sys.exit(1)
    if search not in report:
        print >>sys.stderr, "Could not find a VG named '%s':\n%s" % (search, report)
        sys.exit(1)

    services = ['glance-api', 'glance-registry', 'nova-api', 'nova-conductor', 'nova-compute']
    if version < 13.04:
        services.append('nova-volume')
    else:
        setup_cinder(ubuntu_version) # this restarts things for us
    for s in services:
        if s == 'nova-conductor' and version < 13.04: # only grizzly has cinder
            continue
        testlib.cmd(['stop', s])
        testlib.cmd(['start', s])

    print "done"

def setup_nova_networking(version):
    print "Setting up nova networking"

    rc, report = testlib.cmd(['ifconfig', 'eth1'])
    if rc != 0:
        print "  ifconfig eth1 up"
        rc, report = testlib.cmd(['ifconfig', 'eth1', 'up'])
        if rc != 0:
            print >> sys.stderr, "ifconfig eth1:\n%s" % report
            sys.exit(1)
    else:
        print "  eth1 already up"

    rc, report = testlib.cmd(['nova-manage', 'network', 'list'])
    if not "10.0.0.0" in report:
        print "  nova-manage network create private 10.0.0.0/24 1 256 --bridge=br100 --bridge_interface=eth1 --multi_host=True"
        rc, report = testlib.cmd(['nova-manage', 'network', 'create', 'private', '10.0.0.0/24', '1', '256', '--bridge=br100', '--bridge_interface=eth1', '--multi_host=True'])
        if rc != 0:
            print >> sys.stderr, report
            sys.exit(1)
    else:
        print "  nova-manage network create private 10.0.0.0/24 (already exists)"

    rc, report = testlib.cmd(['nova-manage', 'floating', 'list'])
    if not "192.168.122" in report:
        if version < 12.04:
            print "  nova-manage floating create --ip_range=192.168.122.224/27"
            rc, report = testlib.cmd(['nova-manage', 'floating', 'create', '--ip_range=192.168.122.224/27'])
        else:
            print "  nova-manage floating create 192.168.122.224/27"
            rc, report = testlib.cmd(['nova-manage', 'floating', 'create', '192.168.122.224/27'])
        if rc != 0:
            print >> sys.stderr, report
            sys.exit(1)
    else:
        print "  nova-manage floating create 192.168.122.224/27 (already exists)"

    print "  adjusting /etc/nova/nova.conf"
    if version < 12.04:
        # IP auto-assignment is broken on 11.10:
        # https://bugs.launchpad.net/nova/+bug/834633
#        contents = '''#--auto_assign_floating_ip=true
#'''
#        _config_append("/etc/nova/nova.conf", contents)
        pass
    elif version < 12.10:
        contents = '''--auto_assign_floating_ip
'''
        _config_append("/etc/nova/nova.conf", contents)
    else:
        contents = '''auto_assign_floating_ip=True
share_dhcp_address=True
'''
        _config_append("/etc/nova/nova.conf", contents)

    testlib.cmd(['restart', 'nova-network'])

    if version >= 12.10:
        print "  adjusting /etc/rc.local for iptables rule"
        testlib.config_replace("/etc/rc.local", '', append=True)
        rc, report = testlib.cmd(['sed', '-i', 's#^exit 0#/sbin/iptables -A POSTROUTING -t mangle -p udp --dport 68 -j CHECKSUM --checksum-fill\\n\\nexit 0#', "/etc/rc.local"])
        if rc != 0:
            print >>sys.stderr, "Could not update /etc/rc.local:\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['/sbin/iptables', '-A', 'POSTROUTING', '-t', 'mangle', '-p', 'udp', '--dport', '68', '-j', 'CHECKSUM', '--checksum-fill'])
        if rc != 0:
            print >>sys.stderr, "Could not run iptables rule:\n%s" % report
            sys.exit(1)
        os.chmod("/etc/rc.local", 0755)

    # verify
    rc, report = testlib.cmd(['nova-manage', 'network', 'list'])
    if rc != 0:
        print >> sys.stderr, "sudo nova-manage network list"
        print >> sys.stderr, report
        sys.exit(1)

    if not "10.0.0.0" in report:
        print >> sys.stderr, "sudo nova-manage network list"
        print >> sys.stderr, "could not find '10.0.0.0' in:\n%s" % report
        sys.exit(1)

    rc, report = testlib.cmd(['nova-manage', 'floating', 'list'])
    if rc != 0:
        print >> sys.stderr, "sudo nova-manage floating list"
        print >> sys.stderr, report
        sys.exit(1)

    if not "192.168.122" in report:
        print >> sys.stderr, "sudo nova-manage floating list"
        print >> sys.stderr, "could not find '192.168.122' in:\n%s" % report
        sys.exit(1)

    print "done"

def setup_horizon(version):
    print "Setting up horizon"
    if version >= 12.04:
        contents = """CACHE_BACKEND = 'memcached://127.0.0.1:11211/'
"""
        if version >= 12.10:
            contents = """CACHE_BACKEND = 'memcached://127.0.0.1:11211'
"""

        _config_append("/etc/openstack-dashboard/local_settings.py", contents)
    else:
        print "  SKIPPED: horizon is broken on 11.10"
        return
        rc, report = testlib.cmd(["a2enmod", "rewrite"])
        if rc != 0:
            print >>sys.stderr, "a2enmod failed:\n%s" % report

        rc, report = testlib.cmd(["a2dissite", "default"])
        if rc != 0:
            print >>sys.stderr, "a2dissite failed:\n%s" % report

        contents = """WSGIScriptAlias / /usr/share/openstack-dashboard/dashboard/wsgi/django.wsgi

<Directory /usr/share/openstack-dashboard/dashboard/wsgi>
  Order allow,deny
  Allow from all
  SetHandler python-program
  PythonHandler django.core.handlers.modpython
  SetEnv DJANGO_SETTINGS_MODULE dashboard.settings
  PythonOption django.root /horizon
  PythonPath "['/usr/share/openstack-dashboard'] + sys.path"

</Directory>
"""
        testlib.config_replace("/etc/apache2/sites-available/openstack-dashboard", contents)

        rc, report = testlib.cmd(["a2ensite", "openstack-dashboard"])
        if rc != 0:
            print >>sys.stderr, "a2ensite failed:\n%s" % report
            sys.exit(1)

        fn = "/usr/share/openstack-dashboard/local/local_settings.py"
        if not os.path.exists(fn):
            shutil.copy(fn + ".example", fn)

        rc, report = testlib.cmd(['sed', '-i', "s#^CACHE_BACKEND = 'dummy://'#CACHE_BACKEND = 'memcached://127.0.0.1:11211/'#", fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'CACHE_BACKEND':\n%s" % report
            sys.exit(1)

        rc, report = testlib.cmd(['sed', '-i', "s#^OPENSTACK_ADMIN_TOKEN = .*#OPENSTACK_ADMIN_TOKEN = %s#" % keystone_admin_token, fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'OPENSTACK_ADMIN_TOKEN':\n%s" % report
            sys.exit(1)

        rc, report = testlib.cmd(['sed', '-i', 's#^OPENSTACK_KEYSTONE_URL = .*#OPENSTACK_KEYSTONE_URL = "http://127.0.0.1:5000/v2.0/"#', fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'OPENSTACK_KEYSTONE_URL':\n%s" % report
            sys.exit(1)
        rc, report = testlib.cmd(['sed', '-i', "s#^CACHE_BACKEND = 'dummy://'#CACHE_BACKEND = 'memcached://127.0.0.1:11211/'#", fn])
        if rc != 0:
            print >>sys.stderr, "Could not setup 'CACHE_BACKEND':\n%s" % report
            sys.exit(1)

        rc, report = testlib.cmd(["/etc/init.d/apache2", "reload"])
        if rc != 0:
            print >>sys.stderr, "/etc/init.d/apache2 reload failed:\n%s" % report
            sys.exit(1)

def setup_flavors(version):
    if version >= 13.10:
        print "Setting up flavors"
        rc, report = testlib.cmd(['nova', 'flavor-delete', 'm1.tiny'])
        if rc != 0:
            print >>sys.stderr, "'nova flavor-delete m1.tiny' failed:\n%s" % report
            sys.exit(1)

        rc, report = testlib.cmd(['nova', 'flavor-create', 'm1.tiny', '1', '512', '0', '1'])
        if rc != 0:
            print >>sys.stderr, "'nova flavor-create m1.tiny 1 512 0 1' failed:\n%s" % report
            sys.exit(1)

def setup_packages(ubuntu_version):
    '''Setup packages for OpenStack'''
    setup_mysql(ubuntu_version)
    setup_rabbitmq()
    setup_nova(ubuntu_version)
    setup_glance(ubuntu_version)
    setup_heat(ubuntu_version)

    if ubuntu_version < 12.04:
        print "Skipping keystone setup (1.0~d4~20110909.1108-0ubuntu3.1 is broken)"
    else:
        setup_keystone(ubuntu_version)
        setup_tenants(ubuntu_version)
        setup_roles(ubuntu_version)
        setup_users(ubuntu_version)
        setup_services(ubuntu_version)
        setup_endpoints(ubuntu_version)
        setup_services_for_keystone(ubuntu_version)

    setup_nova_networking(ubuntu_version)

    if ubuntu_version < 12.04:
        print "Skipping horizon setup (it and the keystone in the archive are broken)"
    else:
        setup_horizon(ubuntu_version)

def post_package_setup(ubuntu_version):
    '''Miscellaneous setup for OpenStack'''
    if ubuntu_version < 12.04:
        return
    # miscellaneous things to do once keystone is running
    os.environ["OS_USERNAME"] = "admin"
    os.environ["OS_PASSWORD"] = admin_password
    os.environ["OS_TENANT_NAME"] = "admin"
    os.environ["OS_AUTH_URL"] = "http://localhost:5000/v2.0/"
    print "keystone token-get (post package setup)"
    rc, report = testlib.cmd(['keystone', 'token-get'])

    setup_flavors(ubuntu_version)

    os.environ["OS_USERNAME"] = ""
    os.environ["OS_PASSWORD"] = ""
    os.environ["OS_TENANT_NAME"] = ""
    os.environ["OS_AUTH_URL"] = ""

def verify_setup(version):
    os.environ["OS_USERNAME"] = "admin"
    os.environ["OS_PASSWORD"] = admin_password
    os.environ["OS_TENANT_NAME"] = "admin"
    os.environ["OS_AUTH_URL"] = "http://localhost:5000/v2.0/"

    if version >= 12.04:
        print "keystone token-get (verify_setup)"
        rc, report = testlib.cmd(['keystone', 'token-get'])
        print report

    print "sudo nova-manage service list"
    rc, report = testlib.cmd(['sudo', 'nova-manage', 'service', 'list'])
    print report

    print "nova flavor-list"
    rc, report = testlib.cmd(['nova', 'flavor-list'])
    print report

    if version >= 12.04:
        print "keystone catalog"
        rc, report = testlib.cmd(['keystone', 'catalog'])
        print report

        print "keystone service-list"
        rc, report = testlib.cmd(['keystone', 'service-list'])
        print report

        print "keystone catalog --service ec2"
        rc, report = testlib.cmd(['keystone', 'catalog', '--service', 'ec2'])
        print report

    os.environ["OS_USERNAME"] = ""
    os.environ["OS_PASSWORD"] = ""
    os.environ["OS_TENANT_NAME"] = ""
    os.environ["OS_AUTH_URL"] = ""

if __name__ == '__main__':
    ubuntu_version = testlib.manager.lsb_release["Release"]
    if ubuntu_version < 11.10:
        print >>sys.stderr, "<11.10 not currently supported by this script"
        sys.exit(1)
    elif ubuntu_version > 13.10:
        print >>sys.stderr, ">13.04 not currently supported by this script"
        sys.exit(1)

    if len(sys.argv) > 1 and sys.argv[1] == 'setup-all':
# TODO: set this up for static addressing
#        ip = setup_host_networking(ubuntu_version)
#        if ip:
#            print "Network updated to use '%s'." % ip
#            print "Please reboot and run this script again."
#            sys.exit(0)
        # install_packages(ubuntu_version)
        # setup_network()
        # setup_packages(ubuntu_version)
        post_package_setup(ubuntu_version)

        verify_setup(ubuntu_version)

        print '''Setup complete

If everything looks ok, you can start using OpenStack by going
to https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack#Using_OpenStack

You may also want to:
 * reboot to make sure everything comes up
 * setup network security groups:
   https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack# Networking_with_instances
'''
        sys.exit(0)
    elif len(sys.argv) > 1 and sys.argv[1] == 'verify':
        verify_setup(ubuntu_version)
        print "\nIf everything looks ok, you can start using OpenStack by going"
        print "to https://wiki.ubuntu.com/SecurityTeam/TestingOpenStack#Using_OpenStack"
        sys.exit(0)


    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MyTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(MyPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
