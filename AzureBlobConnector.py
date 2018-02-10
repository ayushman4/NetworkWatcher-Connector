from azure.storage.blob import BlockBlobService
import requests
import json
from multiprocessing import Pool
import logging
import logging.handlers
import datetime
import hvac
import platform
from os import getenv

#To be used with hashicorp valut for blob key storage

# vault_url = os.environ.get('VAULT_ADDR'),
# token = os.environ.get('VAULT_TOKEN')
# vault = hvac.Client( vault_url, token)
# secrets = vault.read('secret/networkwatcher/BlobEngine')['data']
# account_name = secrets['blob_account_name']
# account_key = secrets['blob_account_key']
# account_key = str(account_key).split(",")
# account_name = str(account_name).split(",")

#To be used with environment variables for blob key storage

#account_name = getenv('blob_account_name')
#account_key = getenv('blob_account_key')
#account_key = str(account_key).split(",")
#account_name = str(account_name).split(",")

#To store blob storage keys in plain text in source code. Do not do this please!

account_key = ["AccountKey1","AccountKey2","AccountKey3"]
account_name = ["StroageAccount1","StorageAccount2","StorageAccount3"]

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

def connect_to_blob_account(account_name,account_key):

    block_blob_service = BlockBlobService (account_name=account_name, account_key=account_key)
    blobs = block_blob_service.list_blobs("insights-logs-networksecuritygroupflowevent",marker=None)
    for b in blobs:
        print "Data Sent from-> "+account_name
        stream = block_blob_service.get_blob_to_text("insights-logs-networksecuritygroupflowevent",b.name)
        data =json.loads(stream.content)
        send_json_payload_http(stream.content)
        json_to_cef_network_watcher(data)

def send_json_payload_http(data):

    headers = {'Content-type': 'application/json'}
    print "Sending JSON data over HTTP/HTTPS"
    response = requests.post ("http://10.135.1.5:6900", data=data, headers=headers)
    print response.status_code
    if response.status_code != 200:
        print("Error in request response")
        exit(1)


def json_to_cef_network_watcher(data):
    print"Converting Data"
    for i in xrange (0, len (data['records'])):
        for j in xrange (0, len (data['records'][i]['properties']['flows'])):
            for k in xrange (0, len (data['records'][i]['properties']['flows'][j]['flows'])):
                for l in xrange (0, len (data['records'][i]['properties']['flows'][j]['flows'][k]['flowTuples'])):
                    flow_data = str (
                        data['records'][i]['properties']['flows'][j]['flows'][k]['flowTuples'][l]).split (",")
                    cef_data = datetime.datetime.now ().__str__ () + " " + platform.node () + " " + "CEF:0" + "|" + "JetSecurity" + "|" + "AzureNetworkWatcher" + "|" + "1.0" + "|" + "1000000" + "|" + "NetworkWatcher Azure NSG Flow Logs" + "|" + "10" + "|" + "cs1=" + \
                               data['records'][i]['properties']['flows'][j][
                                   'rule'] + " " + "cs1Label=NSG Rule Name" + " " + "cs2=" + \
                               str (data['records'][i]['resourceId']).split ("/")[
                                   2] + " " + "cs2Label=Azure Subscription ID" + " " + "cs3=" + \
                               str (data['records'][i]['resourceId']).split ("/")[
                                   4] + " " + "cs3Label=Resource Group Name" + " " + "cs4=" + data['records'][i][
                                   'systemId'] + " " + "cs4Label=Resource ID" + " " + "cs5=" + data['records'][i][
                                   'time'] + " " + "cs5Label=Event Time" + " " + "cs6=" + data['records'][i][
                                   'operationName'] + " " + "cs6Label=Operation Event Name" + " " + "start=" + \
                               flow_data[0] + " " + "smac=" + \
                               data['records'][i]['properties']['flows'][j]['flows'][k]['mac'] + " " + "src=" + \
                               flow_data[1] + " " + "dst=" + flow_data[2] + " " + "spt=" + flow_data[
                                   3] + " " + "dpt=" + flow_data[4] + " " + "proto=" + flow_data[5] + " " + "act=" + \
                               flow_data[7]
                    print "Converted JSON -> CEF " + cef_data
                    send_syslog (cef_data)

def send_syslog(cef_data):

    try:
        print "Sending Data CEF Data over Syslog"
        my_logger = logging.getLogger ('NetworkWatcher')
        my_logger.setLevel (logging.INFO)
        handler = logging.handlers.SysLogHandler(address=('localhost', 514))
        my_logger.addHandler(handler)
        my_logger.info(cef_data)
    except Exception as e:
        print e
        exit(1)

def main():

    process_to_create = len(account_name)
    print "Creating "+str(process_to_create)+" proesses"
    pool = Pool(processes=process_to_create)
    for i in range(0,len(account_name)):
        result = pool.apply_async(connect_to_blob_account, (account_name[i],account_key[i]))
        try:
            print(result.get (timeout=None))
        except:
            print "Oops! Workers Are Leaving."
            pool.close()
            pool.terminate ()
            pool.join()
            exit(1)
    pool.close()
    pool.terminate ()
    pool.join()

if __name__ == "__main__":

    try:
        main()
    except:
        print "Shutting Down the Tool."
        exit(1)
