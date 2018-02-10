# NetworkWatcher-Connector ( ELK/ArcSight | JSON/CEF | HTTP/Syslog)

This connector is a connector for Azure Network Watcher Logs which can be pushed to Logstash or ArcSight. This connector accesses to the Azure Network Watcher Logs in Blob Storage, extracts the JSON and pushes JSON payload over HTTP or CEF format over Syslog.

The JSON over HTTP payload has been tested to be pushed to an ELK stack

The CEF over Syslog has been tested to be pushed to ArcSight

Storage Account credentials can be stored and accessed from HashiCorp Vault, Environemnt Variables or from the source code :P

Differential log push has not been implemented yet, but is a feature in the process to be implemented. At this point the tool goes through all the logs and pushes it.

Store credentials as follows in environemnt variables or vault:

blob_account_name= StorageAccount1,StorageAccount2,StorageAccount3
blob_account_key = StorageAccountKey1,StorageAccountKey2,StorageAccountKey3
