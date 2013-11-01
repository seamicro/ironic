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

"""
Ironic AMD-Seamicro power manager.
"""

import contextlib
import os
import stat
import tempfile
import paramiko

from oslo.config import cfg

from ironic.common import exception
from ironic.common import paths
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.openstack.common import excutils
from ironic.openstack.common import jsonutils as json
from ironic.openstack.common import log as logging
from ironic.openstack.common import loopingcall
from ironic.db import api as db_api

opts = [
    cfg.StrOpt('terminal',
               default='shellinaboxd',
               help='path to baremetal terminal program'),
    cfg.StrOpt('terminal_cert_dir',
               default=None,
               help='path to baremetal terminal SSL cert(PEM)'),
    cfg.StrOpt('terminal_pid_dir',
               default=paths.state_path_def('baremetal/console'),
               help='path to directory stores pidfiles of baremetal_terminal'),
    cfg.IntOpt('seamicro_power_retry',
               default=3,
               help='Maximum retries for Seamicro operations'),
    ]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

VALID_BOOT_DEVICES = ['pxe', 'disk']

@contextlib.contextmanager
def _make_password_file(password):
    try:
        fd, path = tempfile.mkstemp()
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as f:
            f.write(password)

        yield path
        utils.delete_if_exists(path)
    except Exception:
        with excutils.save_and_reraise_exception():
            utils.delete_if_exists(path)


def _parse_driver_info(node):
    driver_info = node.get('driver_info', '')
    seamicro_info = driver_info
    address = seamicro_info.get('address', None)
    username = seamicro_info.get('username', None)
    password = seamicro_info.get('password', None)
    ccard = seamicro_info.get('ccard', None)

    if not address or not username or not password:
        raise exception.InvalidParameterValue(_(
            "Login credentials not supplied to Seamicro driver."))

    return {
            'address': address,
            'username': username,
            'password': password,
            'ccard': ccard,
            'uuid': node.get('uuid')
           }

def _connect(hostname, username, password, command):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
        try:
                ssh.connect(hostname,
                            username=username,
                            password=password,
                            timeout=30)
        except paramiko.AuthenticationException as ex:
                return 2, "Could not connect: %s" % ex
        except paramiko.BadAuthenticationType as ex:
                return 2, "The remote host doesn't allow password authentication: %s" % ex
        except paramiko.SSHException as ex:
                return 2, "The remote host doesn't allow password authentication: %s" % ex
        except:
                return 2, "Unhandled exception in ssh connection. Check paramaters passed in."

        try:
                stdin, stdout, stderr = ssh.exec_command(command,-1,60)
        except:
                return 2, "Command timedout or terminated unexpectedly"



        try:
                outputBuffer = stdout.read()
        except:
                return 2, "Command output could not be opened."

        ssh.close()

        return 0, outputBuffer

def _exec_seamicrotool(driver_info, command):
    returnCode, commandOutput = _connect(driver_info['address'], driver_info['username'], driver_info['password'], command)
    LOG.debug("seamicro command: %s returned: '%s', stderr: '%s'" % (command,commandOutput,returnCode))
    return commandOutput,returnCode

def _power_on(driver_info):
    """Turn the power to this node ON."""

    # use mutable objects so the looped method can change them
    state = [None]
    retries = [0]

    def _wait_for_power_on(state, retries):
        """Called at an interval until the node's power is on."""

        state[0] = _power_status(driver_info)
        if state[0] == states.POWER_ON:
            raise loopingcall.LoopingCallDone()

        if retries[0] > CONF.seamicro_power_retry:
            state[0] = states.ERROR
            raise loopingcall.LoopingCallDone()
        try:
            retries[0] += 1
			# either this or a REST APi call. 
            _exec_seamicrotool(driver_info, "enable;power-on server " + driver_info['ccard'] + " no-confirm")
        except Exception:
            # Log failures but keep trying
            LOG.warning(_("Seamicro Power on failed for node %s.")
                    % driver_info['uuid'])

    timer = loopingcall.FixedIntervalLoopingCall(_wait_for_power_on,
                                                 state, retries)
    timer.start(interval=30).wait()
    return state[0]


def _power_off(driver_info):
    """Turn the power to this node OFF."""

    # use mutable objects so the looped method can change them
    state = [None]
    retries = [0]

    def _wait_for_power_off(state, retries):
        """Called at an interval until the node's power is off."""

        state[0] = _power_status(driver_info)
        if state[0] == states.POWER_OFF:
            raise loopingcall.LoopingCallDone()

        if retries[0] > CONF.seamicro_power_retry:
            state[0] = states.ERROR
            raise loopingcall.LoopingCallDone()
        try:
            retries[0] += 1
			# Try for 3 times. Either this call or Vince's REST Api call
            _exec_seamicrotool(driver_info, "enable;power-off server " + driver_info['ccard'] + " force no-confirm")
        except Exception:
            # Log failures but keep trying
            LOG.warning(_("Seamicro Power off failed for node %s.")
                    % driver_info['uuid'])

    timer = loopingcall.FixedIntervalLoopingCall(_wait_for_power_off,
                                                 state=state, retries=retries)
    timer.start(interval=5).wait()
    return state[0]


def _power_status(driver_info):

    commandOutput,returnCode = _exec_seamicrotool(driver_info, "enable;show server summary " + driver_info['ccard'] + " | include " + driver_info['ccard'])
    # TODO(vikhub): parse the list and decide the status. Or use REST plugin from Vince
    
    status = commandOutput.split()
    LOG.debug(status)
    if status[4] == "up":
        return states.POWER_ON
    elif status[4] == "down":
        return states.POWER_OFF
    else:
        return states.ERROR

def _power_on_pxe_next_boot(driver_info):

    # use mutable objects so the looped method can change them
    state = [None]
    retries = [0]

    def _wait_for_power_on(state, retries):
        """Called at an interval until the node's power is on."""

        state[0] = _power_status(driver_info)
        if state[0] == states.POWER_ON:
            raise loopingcall.LoopingCallDone()

        if retries[0] > CONF.seamicro_power_retry:
            state[0] = states.ERROR
            raise loopingcall.LoopingCallDone()
        try:
            retries[0] += 1
            # either this or a REST APi call.
            _exec_seamicrotool(driver_info, "enable;power-on server " + driver_info['ccard'] + " using-pxe no-confirm")
        except Exception:
            # Log failures but keep trying
            LOG.warning(_("Seamicro Power on failed for node %s.")
                    % driver_info['uuid'])

    timer = loopingcall.FixedIntervalLoopingCall(_wait_for_power_on,
                                                 state, retries)
    timer.start(interval=30).wait()
    return state[0]


class SeamicroPower(base.PowerInterface):

    def validate(self, node):
        """Check that node['driver_info'] contains Seamicro credentials.

        :param node: Single node object.
        :raises: InvalidParameterValue
        """
        _parse_driver_info(node)

    def get_power_state(self, task, node):
        """Get the current power state."""
        driver_info = _parse_driver_info(node)
        return _power_status(driver_info)

    @task_manager.require_exclusive_lock
    def set_power_state(self, task, node, pstate):
        """Turn the power on or off."""
        driver_info = _parse_driver_info(node)

        if pstate == states.POWER_ON:
            state = _power_on(driver_info)
        elif pstate == states.POWER_OFF:
            state = _power_off(driver_info)
        else:
            raise exception.IronicException(_(
                "set_power_state called with invalid power state."))

        if state != pstate:
            raise exception.PowerStateFailure(pstate=pstate)

    @task_manager.require_exclusive_lock
    def reboot(self, task, node):
        """Cycles the power to a node."""
        driver_info = _parse_driver_info(node)
        _power_off(driver_info)
        state = _power_on(driver_info)

        if state != states.POWER_ON:
            raise exception.PowerStateFailure(pstate=states.POWER_ON)

	def activate_node(self, node):
		""" Turns power on to the node ON using the PXE flag. returns: status represented by one of the States"""

		driver_info = _parse_driver_info(node)
		if _power_status(driver_info) == states.POWER_ON:
			LOG.warning(_("Active node is called, but node %s is already powered up.") % driver_info['uuid'])
		
		return _power_on_pxe_next_boot(driver_info)

    @task_manager.require_exclusive_lock
    def _set_boot_device(self, task, node, device, persistent=False):
        """Set the boot device for a node.

        :param task: a TaskManager instance.
        :param node: The Node.
        :param device: Boot device. One of [pxe, disk].
        :param persistent: Whether to set next-boot, or make the change
            permanent. Default: False.
        :raises: InvalidParameterValue if an invalid boot device is specified.
        :raises: SeamicroFailure on an error from seamicrotool.

        """

        driver_info = _parse_driver_info(node)
        if device not in VALID_BOOT_DEVICES:
            raise exception.InvalidParameterValue(_(
                "Invalid boot device %s specified.") % device)
        ## If persistent we set it in the bios boot order, else we have to figure out to store using-pxe

        cmd1 = 'enable;configure terminal; server id'
        if persistent:
            if ( device == VALID_BOOT_DEVICES[0]): 
                cmd1 = 'enable;configure terminal;server id ' + driver_info['ccard'] + '; bios boot-order pxe,hd0'
            else:
                cmd1 = 'enable;configure terminal;server id ' + driver_info['ccard'] + '; bios boot-order hd0'
        try:
            out, err = _exec_seamicrotool(driver_info, cmd1)
            # TODO(deva): validate (out, err) and add unit test for failure
        except Exception:
            raise exception.SeamicroFailure(cmd=cmd1)

class VendorPassthru(base.VendorInterface):
    """Handle SeaMicro-specific APIs"""

    def validate(self, node, **kwargs):
        """
        Return True if method in list of implemented methods
        """
        LOG.debug("validate() called")
        
        allowedMethods = ['set_disk_size','set_vlan']
        method = kwargs['method']
        
        if method in allowedMethods:
            LOG.debug("validate() - allowed method called")
            return True
        else:
            raise exception.InvalidParameterValue(_(
                "Unsupported method (%s) passed to SeaMicro driver.")
                % method)

        return False
    
    def vendor_passthru(self, task, node, **kwargs):
        """
        Dispatch vendor API call to proper process
        """
        LOG.debug("vendor_passthru called")
        method = kwargs['method']
        if method == 'set_disk_size':
            return self.set_disk_size(node,**kwargs)
        elif method == 'set_vlan':
            return self.set_vlan(node,**kwargs)

    def power_on_using_pxe(self,node):
        LOG.debug("power_on_usin_pxe() function called")

        driver_info = _parse_driver_info(node)
        try:
            cmd1 = "enable;power-on server " + driver_info['ccard'] + " using-pxe no-confirm"
            out, err = _exec_seamicrotool(driver_info, cmd1)
        except Exception:
            raise exception.SeamicroFailure(cmd=cmd1)

    def set_disk_size(self, node, **kwargs):
        """
        Function to create & assign volume of requested size
        Size passed in as kwargs['size']
        Assumes S-Card in volume mode
        TODO: think about how to restrict to allowed S-cards
        """
        LOG.debug("set_disk_size() function called")
        
        driver_info = _parse_driver_info(node)
        disk_size_requested = kwargs.get('size')
        LOG.debug("size requested = %s" % (disk_size_requested))
        
        if not disk_size_requested:
            raise exception.InvalidParameterValue(_("No disk size specified"))
        
        """
          VIKRANT : we need the disk size to be mentioned in GB ex -- 30,40 instead of 
          30000,40000 etc
        """
        pool_dict = {}
        cmd = 'enable;show storage pool 6/all brief| exclude (entr\\|---\\|slot\\|Mounted)'
        cmdOutput, err = _exec_seamicrotool(driver_info, cmd)
        flag = 0
        found_a_pool_flag = 0
        pool_for_volume_creation = ""
        for line in cmdOutput.splitlines():
            if flag == 0:
                flag = 1
            else:
                # pool dictionary here
                pool_dict[line.split()[0] + "/" + line.split()[1]] = int(line.split()[3].split(".")[0])

        for names,freesize in pool_dict.items():
            # leave some space as backup
            if (freesize - disk_size_requested) > 5:
                pool_for_volume_creation = names
                found_a_pool_flag = 1
                break
            if found_a_pool_flag == 0:
                   LOG.debug(_("No free space on the scard."))
                
        """
        Vikrant : We have to come up with a unique volume name scheme uuid function in python               
        """
        if pool_for_volume_creation != "":
             cmd1 = 'enable;storage create volume ' + pool_for_volume_creation + '/ironic-volume size 30'
             try:
                 cmdOutput, err = _exec_seamicrotool(driver_info, cmd1)
             except Exception:
                 raise exception.SeamicroFailure(cmd=cmd1) 
             cmd1 = "enable;conf t;storage assign " + driver_info['ccard'] + " 0 volume " + pool_for_volume_creation + "/ironic-volume"
             try:
                 out, err = _exec_seamicrotool(driver_info, cmd1)
             except Exception:
                 raise exception.SeamicroFailure(cmd=cmd1)
        
        """
        Only set disk properties if operation succeeded
        Todo: figure out what value of 'out' needed to test
        Todo: may need to do this async
        """
        
        if True:
            dbapi = db_api.get_instance()
            properties = node['properties']
            properties['disk'] = disk_size_requested
            res = dbapi.update_node(node['id'],{'properties': properties})

        return True
    
    def set_vlan(self, node, **kwargs):
        """
        Function to set VLAN of node to specified value
        VLAN passed in as kwargs['vlan']
        Only untagged supported
        Assumes VLAN already created as system VLAN
        """
        LOG.debug("set_vlan() function called")
        
        driver_info = _parse_driver_info(node)
        vlan_requested = kwargs.get('vlan')
        LOG.debug("vlan requested = %s" % (vlan_requested))
        
        if not vlan_requested:
            raise exception.InvalidParameterValue(_("No VLAN specified"))
        
        """
          Make a call here for VLAN assignment. Just configure on NIC 0
        """
        basecmd = "enable;conf t;server id " + driver_info['ccard'] + ";nic 0;"
        cmd1 = "show configuration | include untagged-vlan"
        cmd2 = "untagged-vlan " + str(vlan_requested)
        try:
            out, err = _exec_seamicrotool(driver_info, basecmd + cmd1)
            out, err = _exec_seamicrotool(driver_info, basecmd + "no " + out)
            out, err = _exec_seamicrotool(driver_info, basecmd + cmd2)
        except Exception:
            raise exception.SeamicroFailure(cmd=cmd1)
        
        """
        Only set VLAN properties if operation succeeded
        Todo: figure out what value of 'out' needed to test
        Todo: may need to do this async
        """
        
        if True:
            dbapi = db_api.get_instance()
            properties = node['properties']
            properties['vlan'] = vlan_requested
            res = dbapi.update_node(node['id'],{'properties': properties})

        return True
