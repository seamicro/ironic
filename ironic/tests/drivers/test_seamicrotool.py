# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2012 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2012 NTT DOCOMO, INC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Test class for SeamicroTool driver module."""

import os
import stat
import unittest

import pkg_resources
from stevedore import dispatch

from ironic.conductor import resource_manager

from oslo.config import cfg

from ironic.openstack.common import jsonutils as json

from ironic.common import exception
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.db import api as db_api
from ironic.drivers.modules import seamicrotool as seamicro
from ironic.tests import base
from ironic.tests.conductor import utils as mgr_utils
from ironic.tests.db import base as db_base
from ironic.tests.db import utils as db_utils

CONF = cfg.CONF


class SeamicroToolPrivateMethodTestCase(base.TestCase):

    def setUp(self):
        super(SeamicroToolPrivateMethodTestCase, self).setUp()
        self.node = db_utils.get_test_node(
                driver='fake_seamicro',
                driver_info=db_utils.seamicro_info)
        self.info = seamicro._parse_driver_info(self.node)
	
	def test__parse_driver_info(self):
        # make sure we get back the expected things
		self.assertIsNotNone(self.info.get('address'))
		self.assertIsNotNone(self.info.get('username'))
		self.assertIsNotNone(self.info.get('password'))
		self.assertIsNotNone(self.info.get('ccard'))
		self.assertIsNotNone(self.info.get('uuid'))

        # make sure error is raised when info, eg. username, is missing
		_driver_info = json.dumps(
			{
				'seamicro': {
					"address": "1.2.3.4",
					"password": "fake",
				}
			})
		node = db_utils.get_test_node(driver_info=_driver_info)
		self.assertRaises(exception.InvalidParameterValue,seamicro._parse_driver_info,node)

    def test__exec_seamicrotool(self):
		self.mox.StubOutWithMock(seamicro, '_connect')
		seamicro._connect(self.info['address'],self.info['username'],self.info['password'],'enable;show server summary ' + self.info['ccard']).AndReturn((0, None))
		self.mox.ReplayAll()

		seamicro._exec_seamicrotool(self.info, 'enable;show server summary ' + self.info['ccard'])
		self.mox.VerifyAll()

class SeamicroToolDriverTestCase(db_base.DbTestCase):

    def setUp(self):
        super(SeamicroToolDriverTestCase, self).setUp()
        self.dbapi = db_api.get_instance()
        self.driver = mgr_utils.get_mocked_node_manager(driver='fake_seamicro')
        self.node = db_utils.get_test_node(
                driver='fake_seamicro',
                driver_info=db_utils.seamicro_info)
        self.info = seamicro._parse_driver_info(self.node)
        self.dbapi.create_node(self.node)

    def test_set_power_on_ok(self):
         self.config(seamicro_power_retry=0)
         self.mox.StubOutWithMock(seamicro, '_power_on')
         self.mox.StubOutWithMock(seamicro, '_power_off')

         seamicro._power_on(self.info).AndReturn(states.POWER_ON)
         self.mox.ReplayAll()

         with task_manager.acquire([self.node['uuid']]) as task:
            self.driver.power.set_power_state(
                    task, self.node, states.POWER_ON)
         self.mox.VerifyAll()

    def test_set_power_off_ok(self):
        self.config(seamicro_power_retry=0)
        self.mox.StubOutWithMock(seamicro, '_power_on')
        self.mox.StubOutWithMock(seamicro, '_power_off')

        seamicro._power_off(self.info).AndReturn(states.POWER_OFF)
        self.mox.ReplayAll()

        with task_manager.acquire([self.node['uuid']]) as task:
            self.driver.power.set_power_state(
                    task, self.node, states.POWER_OFF)
        self.mox.VerifyAll()

    def test_set_power_on_fail(self):
        self.config(seamicro_power_retry=0)

        self.mox.StubOutWithMock(seamicro, '_power_on')
        self.mox.StubOutWithMock(seamicro, '_power_off')

        seamicro._power_on(self.info).AndReturn(states.ERROR)
        self.mox.ReplayAll()

        with task_manager.acquire([self.node['uuid']]) as task:
            self.assertRaises(exception.PowerStateFailure,
                    self.driver.power.set_power_state,
                    task,
                    self.node,
                    states.POWER_ON)
        self.mox.VerifyAll()

    def test_set_power_invalid_state(self):
        with task_manager.acquire([self.node['uuid']]) as task:
            self.assertRaises(exception.IronicException,
                    self.driver.power.set_power_state,
                    task,
                    self.node,
                    "fake state")

    def test_set_boot_device_ok(self):
        self.mox.StubOutWithMock(seamicro, '_exec_seamicrotool')

        seamicro._exec_seamicrotool(self.info, 'enable;configure terminal;server id ' + self.info['ccard'] + '; bios boot-order pxe,hd0').\
        AndReturn([None,None])
        self.mox.ReplayAll()

        with task_manager.acquire([self.node['uuid']]) as task:
            self.driver.power._set_boot_device(task, self.node, 'pxe', persistent=True)
        self.mox.VerifyAll()

    def test_set_boot_device_bad_device(self):
        with task_manager.acquire([self.node['uuid']]) as task:
            self.assertRaises(exception.InvalidParameterValue,
                    self.driver.power._set_boot_device,
                    task,
                    self.node,
                    'fake-device')

    def test_reboot_ok(self):
        self.mox.StubOutWithMock(seamicro, '_power_off')
        self.mox.StubOutWithMock(seamicro, '_power_on')

        seamicro._power_off(self.info)
        seamicro._power_on(self.info).AndReturn(states.POWER_ON)
        self.mox.ReplayAll()

        with task_manager.acquire([self.node['uuid']]) as task:
            self.driver.power.reboot(task, self.node)

        self.mox.VerifyAll()

    def test_reboot_fail(self):
        self.mox.StubOutWithMock(seamicro, '_power_off')
        self.mox.StubOutWithMock(seamicro, '_power_on')

        seamicro._power_off(self.info)
        seamicro._power_on(self.info).AndReturn(states.ERROR)
        self.mox.ReplayAll()

        with task_manager.acquire([self.node['uuid']]) as task:
            self.assertRaises(exception.PowerStateFailure,
                    self.driver.power.reboot,
                    task,
                    self.node)

        self.mox.VerifyAll()

if __name__ == "__main__":
     unittest.main()
