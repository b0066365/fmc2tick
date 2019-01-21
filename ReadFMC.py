#!/usr/bin/env python
# -*- coding: UTF-8 -*-# enable debugging

print """
--------------------
Copyright (c) 2018 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
---------------------
"""

__author__ = "Dirk Woellhaf <dwoellha@cisco.com>"
__contributors__ = [
    "Dirk Woellhaf <dwoellha@cisco.com>"
]
__copyright__ = "Copyright (c) 2018 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

import requests
import json
import sys
import os
import time
import ConfigParser
import getpass
import base64
import logging

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ScriptVersion = "0.1"
try:
  if os.environ['INIT'] == "TRUE":
   Setup = "True"
except:
  Setup = "False"


def FMC_Login(fmc_ip, fmc_user, fmc_password, logging):
  #print "FMC Login..."
  server = "https://"+fmc_ip

  r = None
  headers = {'Content-Type': 'application/json'}
  api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
  auth_url = server + api_auth_path
  try:
      r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(fmc_user, fmc_password), verify=False)
      auth_headers = r.headers
      auth_token = auth_headers.get('X-auth-access-token', default=None)
      if auth_token == None:
          print("auth_token not found. Exiting...")
          Logger(logging, "error", "FMC Login failed. auth_token not found. Exiting...")
          sys.exit()
  except Exception as err:
      print ("Error occurred in Login --> "+resp)
      print ("Error in generating auth token --> "+str(err))
      Logger(logging, "debug", "FMC Login failed. "+str(err))
      sys.exit()

  headers['X-auth-access-token']=auth_token
  Logger(logging, "debug", "FMC Login succesful. "+str(headers))
  #print headers
  return headers

def FMC_Logout(fmc_ip, fmc_token, logging):
    #print "FMC Logout..."
    # API path for generating token
    api_path = "/api/fmc_platform/v1/auth/revokeaccess"

    # Constructing the complete URL
    url = fmc_ip + api_path
    # Create custom header for revoke access
    headers = {'X-auth-access-token' : fmc_token['X-auth-access-token']}

    # log in to API
    post_response = requests.post("https://"+str(fmc_ip)+api_path, headers=headers, verify=False)
    if post_response.status_code == 204:
      Logger(logging, "debug", "FMC Logout succesful. "+str(headers))
    else:
      Logger(logging, "error", "FMC Logout failed. "+str(headers)+" "+post_response.text)

def FMC_Get(fmc_ip, fmc_token, url, logging):
  #print "Reading from FMC..."
  Logger(logging, "debug", "FMC GET Using type "+url)
  if (url[-1] == '/'):
      url = url[:-1]

  # GET OPERATION
  try:
      # REST call with SSL verification turned off:
      r = requests.get(url, headers=fmc_headers, verify=False)
      status_code = r.status_code
      resp = r.text
      if (status_code == 200):
          #print("GET successful. Response data --> ")
          json_resp = json.loads(resp)
          Logger(logging, "debug", "FMC GET succesful. "+str(json_resp))

          return json_resp
      else:
          r.raise_for_status()
          print("Error occurred in GET --> "+resp)
          Logger(logging, "error", "FMC GET failed. "+resp)
  except requests.exceptions.HTTPError as err:
      print ("Error in connection --> "+str(err))
      print ("Error occurred in GET --> "+resp)
      Logger(logging, "error", "FMC GET failed. "+resp)
  finally:
      if r : r.close()
  time.sleep(0.1)



def GetDeployableDevices(fmc_ip, fmc_headers, logging, metrics):
    DeployableDevices = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/deployment/deployabledevices", logging)
    if "items" in DeployableDevices:
        metrics["DeployableDevices"] = len(DeployableDevices["items"])
    else:
        metrics["DeployableDevices"] = 0
    return metrics

def GetDeviceGroups(fmc_ip, fmc_headers, logging, metrics):
    DeviceGroups = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/devicegroups/devicegrouprecords", logging)
    if "items" in DeviceGroups:
        metrics["DeviceGroups"] = len(DeviceGroups["items"])
    else:
        metrics["DeviceGroups"] = 0
    return metrics

def GetHAPairs(fmc_ip, fmc_headers, logging, metrics):
    HAPairs = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/devicehapairs/ftddevicehapairs", logging)
    if "items" in HAPairs:
        metrics["HAPairs"] = len(HAPairs["items"])
    else:
        metrics["HAPairs"] = 0
    return metrics

def GetUpgradePackages(fmc_ip, fmc_headers, logging, metrics):
    UpgradePackages = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_platform/v1/updates/upgradepackages", logging)
    if "items" in UpgradePackages:
        metrics["UpgradePackages"] = len(UpgradePackages["items"])
    else:
        metrics["UpgradePackages"] = 0
    return metrics

def GetAccessPolicies(fmc_ip, fmc_headers, logging, metrics):
    AccessPolicies = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/policy/accesspolicies", logging)
    if "items" in AccessPolicies:
        metrics["AccessPolicies"] = len(AccessPolicies["items"])
    else:
        metrics["AccessPolicies"] = 0
    return metrics

def GetHosts(fmc_ip, fmc_headers, logging, metrics):
    Hosts = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/object/hosts", logging)
    if "items" in Hosts:
        metrics["Hosts"] = len(Hosts["items"])
    else:
        metrics["Hosts"] = 0
    return metrics

def GetFQDN(fmc_ip, fmc_headers, logging, metrics):
    FQDN = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/object/fqdns", logging)
    if "items" in FQDN:
        metrics["FQDN"] = len(FQDN["items"])
    else:
        metrics["FQDN"] = 0
    return metrics

def GetGeoLoc(fmc_ip, fmc_headers, logging, metrics):
    GeoLoc = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/object/geolocations", logging)
    if "items" in GeoLoc:
        metrics["GeoLoc"] = len(GeoLoc["items"])
    else:
        metrics["GeoLoc"] = 0
    return metrics

def GetNetworkGroups(fmc_ip, fmc_headers, logging, metrics):
    NetworkGroups = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/object/networkgroups", logging)
    if "items" in NetworkGroups:
        metrics["NetworkGroups"] = len(NetworkGroups["items"])
    else:
        metrics["NetworkGroups"] = 0
    return metrics

def GetNetworks(fmc_ip, fmc_headers, logging, metrics):
    Networks = FMC_Get(fmc_ip, fmc_headers, "https://"+FMC_IP+"/api/fmc_config/v1/domain/default/object/networks", logging)
    if "items" in Networks:
        metrics["Networks"] = len(Networks["items"])
    else:
        metrics["Networks"] = 0
    return metrics

def Post_InfluxDB(metrics):
    print metrics
    for metric in metrics:
        post_response = requests.post("http://"+INFLUXDB_IP+"/write?db="+INFLUXDB_DB, data=metric+",source=fmc2tick,fmc="+FMC_IP+" value="+str(metrics[metric]))
        print metric+":"+str(metrics[metric])+":"+str(post_response)
    #time.sleep(0.5)

def Logger(logging, level, msg):
  if level == "debug":
    logging.debug(msg)
  elif level == "info":
    logging.info(msg)
  elif level == "warning":
    logging.warning(msg)
  elif level == "error":
    logging.error(msg)
  elif level == "critical":
    logging.critical(msg)

if __name__ == "__main__":
    if Setup == "True":
        print "."
    else:
      print "Starting..."

      i = 0
      while i == 0 :
        LOG_LEVEL="debug"

        config = ConfigParser.SafeConfigParser(allow_no_value=True)
        config.read('/mnt/scripts/fmc/config.cfg')
        UPDATE_INTERVAL = config.get('GLOBAL', 'UPDATE_INTERVAL')
        LOG_DIR = config.get('GLOBAL', 'LOG_DIR')
        LOG_LEVEL = config.get('GLOBAL', 'LOG_LEVEL')
        LOG_FILE = config.get('GLOBAL', 'LOG_FILE')

        FMC_IP = config.get('FMC', 'FMC_IP')
        FMC_USER = config.get('FMC', 'FMC_USER')
        FMC_PASSWORD = base64.b64decode(config.get('FMC', 'FMC_PASSWORD'))
        FMC_PREFIX = config.get('FMC', 'FMC_PREFIX')
        LOG_DIR=LOG_DIR+"/aci2fmc.log"


        INFLUXDB_IP = config.get('INFLUXDB', 'INFLUXDB_IP')
        INFLUXDB_DB = config.get('INFLUXDB', 'INFLUXDB_DB')

        if LOG_LEVEL == "debug":
          logging.basicConfig(filename=LOG_FILE,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)
        elif LOG_LEVEL == "info":
          logging.basicConfig(filename=LOG_FILE,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.INFO)
        else:
          logging.basicConfig(filename=LOG_FILE,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.WARNING)

        epg_config = ConfigParser.SafeConfigParser(allow_no_value=True)

        Logger(logging, "info", "Using: FMC IP: "+FMC_IP+", FMC User: "+FMC_USER+", INTERVAL: "+UPDATE_INTERVAL)
        Logger(logging, "info", "Current Log-Level: "+LOG_LEVEL)


        #print "Login..."
        fmc_headers = FMC_Login(FMC_IP, FMC_USER, FMC_PASSWORD, logging)

        metrics = {}

        metrics = GetDeployableDevices(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetDeviceGroups(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetHAPairs(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetUpgradePackages(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetAccessPolicies(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetHosts(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetFQDN(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetGeoLoc(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetNetworkGroups(FMC_IP, fmc_headers, logging, metrics)
        metrics = GetNetworks(FMC_IP, fmc_headers, logging, metrics)

        Post_InfluxDB(metrics)

        #print "Logout..."
        FMC_Logout(FMC_IP, fmc_headers, logging)

        metrics = {}

        #print "Sleeping for "+UPDATE_INTERVAL+"s..."
        Logger(logging, "info", "Sleeping for "+UPDATE_INTERVAL+"s...")

        time.sleep(int(UPDATE_INTERVAL))
