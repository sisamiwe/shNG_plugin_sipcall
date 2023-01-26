#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2023 -      Michael Wenzel             wenzel_michael@web.de
#########################################################################
#  This file is part of SmartHomeNG.
#  https://www.smarthomeNG.de
#  https://knx-user-forum.de/forum/supportforen/smarthome-py
#
#  SmartHomeNG is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  SmartHomeNG is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with SmartHomeNG. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from lib.model.smartplugin import SmartPlugin
from lib.item import Items

from .webif import WebInterface
from .femtosip import femtosip

DEFAULT_RING_TIME = 15


class SipCall(SmartPlugin):
    """
    Main class of the Plugin. Does all plugin specific stuff and provides
    the update functions for the items

    HINT: Please have a look at the SmartPlugin class to see which
    class properties and methods (class variables and class functions)
    are already available!
    """

    PLUGIN_VERSION = '1.0.0'

    def __init__(self, sh):
        """
        Initializes the plugin.
        """

        # Call init code of parent class (SmartPlugin)
        super().__init__()

        # get the parameters for the plugin (as defined in metadata plugin.yaml):
        try:
            self.webif_pagelength = self.get_parameter_value('webif_pagelength')
            self.user = self.get_parameter_value('sip_user')
            self.password = self.get_parameter_value('sip_user_password')
            self.gateway = self.get_parameter_value('sip_gateway')
            self.port = self.get_parameter_value('sip_port')
            self.display_name = self.get_parameter_value('display_name')
        except KeyError as e:
            self.logger.critical(f"Plugin '{self.get_shortname()}': Inconsistent plugin (invalid metadata definition: {e} not defined)")
            self._init_complete = False
            return

        self.alive = False

        # Init SIP Client
        self.sip = femtosip.SIP(self.user, self.password, self.gateway, self.port, self.display_name)

        # Init webinterface
        self.init_webinterface(WebInterface)
        return

    def run(self):
        """
        Run method for the plugin
        """
        self.logger.debug("Run method called")
        self.alive = True

    def stop(self):
        """
        Stop method for the plugin
        """
        self.logger.debug("Stop method called")
        self.alive = False

    def parse_item(self, item):
        """
        Default plugin parse_item method. Is called when the plugin is initialized.
        The plugin can, corresponding to its attribute keywords, decide what to do with
        the item in the future, like adding it to an internal array for future reference
        :param item:    The item to process.
        :return:        If the plugin needs to be informed of an items change you should return a call back function
                        like the function update_item down below. An example when this is needed is the knx plugin
                        where parse_item returns the update_item function when the attribute knx_send is found.
                        This means that when the items value is about to be updated, the call back function is called
                        with the item, caller, source and dest as arguments and in case of the knx plugin the value
                        can be sent to the knx with a knx write function within the knx plugin.
        """
        if self.has_iattr(item.conf, 'sipcall_extension'):
            self.logger.debug(f"parse item: {item.id()}")

            self._itemlist.append(item)
            return self.update_item

    def update_item(self, item, caller=None, source=None, dest=None):
        """
        Item has been updated

        This method is called, if the value of an item has been updated by SmartHomeNG.
        It should write the changed value out to the device (hardware/interface) that
        is managed by this plugin.

        :param item: item to be updated towards the plugin
        :param caller: if given it represents the callers name
        :param source: if given it represents the source
        :param dest: if given it represents the dest
        """
        if self.alive and caller != self.get_shortname() and bool(item()):
            self.logger.info(f"Update item: {item.property.path}, item has been changed outside this plugin from caller {caller}, source {source} and dest {dest}")

            _extension = str(self.get_iattr_value(item.conf, 'sipcall_extension'))
            _ring_time = self.get_iattr_value(item.conf, 'sipcall_ring_time')
            _ring_time = DEFAULT_RING_TIME if not _ring_time else _ring_time
            call = self.sip_call(_extension, _ring_time)
            self.logger.debug(f"{call=}")
            pass

    def sip_call(self, remote_id, ring_time=DEFAULT_RING_TIME, timeout=1.0):
        return self.sip.call(remote_id, ring_time, timeout)
