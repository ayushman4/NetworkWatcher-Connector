# Azure NetworkWatcher-Connector ( ELK/ArcSight | JSON/CEF | HTTP/Syslog)

This connector is for Azure Network Watcher logs which can be pushed to Logstash or ArcSight. This connector accesses the Azure Network Watcher logs in Blob Storage, extracts the JSON data and pushes the JSON payload over HTTP or converts the JSON payload to CEF format and pushes it over Syslog.

The JSON over HTTP payload has been tested to be pushed to an ELK stack

The CEF over Syslog has been tested to be pushed to ArcSight

Storage Account credentials can be stored and accessed from HashiCorp Vault, Environemnt Variables or from the source code :P

Differential log push has not been implemented yet, but is a feature in the process to be implemented. At this point the tool goes through all the logs and pushes it.

Store credentials as follows in environemnt variables or vault:

blob_account_name= StorageAccount1,StorageAccount2,StorageAccount3

blob_account_key = StorageAccountKey1,StorageAccountKey2,StorageAccountKey3

If you find this useful, please create issues or feature requests here https://github.com/ayushman4/NetworkWatcher-Connector/issues
