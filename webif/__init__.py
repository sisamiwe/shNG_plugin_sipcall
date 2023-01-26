#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2023 -      Michael Wenzel             wenzel_michael@web.de
#########################################################################
#  This file is part of SmartHomeNG.
#  https://www.smarthomeNG.de
#  https://knx-user-forum.de/forum/supportforen/smarthome-py
#
#  Sample plugin for new plugins to run with SmartHomeNG version 1.5 and
#  upwards.
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

import datetime
import time
import os
import json

from lib.item import Items
from lib.model.smartplugin import SmartPluginWebIf


# ------------------------------------------
#    Webinterface of the plugin
# ------------------------------------------

import cherrypy
import csv
from jinja2 import Environment, FileSystemLoader


class WebInterface(SmartPluginWebIf):

    def __init__(self, webif_dir, plugin):
        """
        Initialization of instance of class WebInterface

        :param webif_dir: directory where the webinterface of the plugin resides
        :param plugin: instance of the plugin
        :type webif_dir: str
        :type plugin: object
        """
        self.logger = plugin.logger
        self.webif_dir = webif_dir
        self.plugin = plugin
        self.items = Items.get_instance()
        self.tplenv = self.init_template_environment()

    @cherrypy.expose
    def index(self, reload=None):
        """
        Build index.html for cherrypy

        Render the template and return the html file to be delivered to the browser

        :return: contents of the template after beeing rendered
        """
        tmpl = self.tplenv.get_template('index.html')
        # try to get the webif pagelength from the module.yaml configuration
        global_pagelength = cherrypy.config.get("webif_pagelength")
        if global_pagelength:
            pagelength = global_pagelength
            self.logger.debug("Global pagelength {}".format(pagelength))
        # try to get the webif pagelength from the plugin specific plugin.yaml configuration
        try:
            pagelength = self.plugin.webif_pagelength
            self.logger.debug(f"Plugin pagelength {pagelength}")
        except Exception:
            pass
        # add values to be passed to the Jinja2 template eg: tmpl.render(p=self.plugin, interface=interface, ...)
        return tmpl.render(p=self.plugin,
                           webif_pagelength=pagelength,
                           items=self.plugin._itemlist,
                           item_count=len(self.plugin._itemlist))

    @cherrypy.expose
    def get_data_html(self, dataSet=None):
        """
        Return data to update the webpage

        For the standard update mechanism of the web interface, the dataSet to return the data for is None

        :param dataSet: Dataset for which the data should be returned (standard: None)
        :return: dict with the data needed to update the web page.
        """
        if dataSet is None:
            data = {}
            data['item'] = {}

            for item in self.plugin._itemlist:
                data['item'][item]['value'] = item()
                self.logger.debug(f"Plugin item {item}")

            # return it as json to the web page
            try:
                return json.dumps(data, default=str)
            except Exception as e:
                self.logger.error(f"get_data_html exception: {e}")

    @cherrypy.expose
    def get_data_html(self, dataSet=None):
        """
        Return data to update the webpage

        For the standard update mechanism of the web interface, the dataSet to return the data for is None

        :param dataSet: Dataset for which the data should be returned (standard: None)
        :return: dict with the data needed to update the web page.
        """
        if dataSet == 'overview':
            # get the new data from the plugin variable called _webdata
            data = self.plugin._webdata
            try:
                data = json.dumps(data)
                return data
            except Exception as e:
                self.logger.error(f"get_data_html exception: {e}")
        else:
            self.logger.debug(f"Create WebIF Update data for {dataSet}")
            # get the new data
            item_info = {}
            for item in self.plugin._itemlist:
                item_info[item.id()] = {}
                item_info[item.id()]['value'] = item()
                item_info[item.id()]['last_update'] = item.property.last_update.strftime('%d.%m.%Y %H:%M:%S')
                item_info[item.id()]['last_change'] = item.property.last_change.strftime('%d.%m.%Y %H:%M:%S')

            # return it as json to the web page
            try:
                return json.dumps(item_info)
            except Exception as e:
                self.logger.error("get_data_html exception: {}".format(e))
        return {}
