# OMCI

OMCI gopacket library supports the encoding and decoding of ITU G.988 OMCI
messages. It is currently a work in progress.

## Message Types supported and under unit test
The following OMCI message types currently have been coded and are covered
by unit tests.

 - CreateRequest
 - MibResetRequest
 - MibResetResponse

 

## Message Types supported but lacking full unit test
The following OMCI message types currently have been coded and are partially covered
by unit tests, but work still remains for sufficient unit test coverage.

 - CreateResponse
 - SetRequest
 - SetResponse
 - GetRequest
 - GetResponse
 - GetAllAlarmsRequest
 - GetAllAlarmsResponse
 - MibUploadRequest
 - MibUploadResponse
 - MibUploadNextRequest
 - MibUploadNextResponse
 - SynchronizeTimeRequest
 - SynchronizeTimeResponse
 - AttributeValueChange

## Message Types supported but lacking any unit test
The following OMCI message types currently have been coded but any unit test coverage.

 - DeleteRequest
 - DeleteResponse
 - GetAllAlarmsNextRequest
 - GetAllAlarmsNextResponse
 - StartSoftwareDownloadResponse
 - StartSoftwareDownloadRequest
 - DownloadSectionRequest
 - DownloadSectionResponse
 - AlarmNotification
 
## Message Types not yet supported

The following OMCI message types currently have not been coded.

 - TestResult
 - TestRequest
 - TestResponse
 - EndSoftwareDownloadRequest
 - EndSoftwareDownloadResponse
 - ActivateSoftwareRequest
 - ActivateSoftwareResponse
 - CommitSoftwareRequest
 - CommitSoftwareResponse
 - RebootRequest
 - RebootResponse
 - GetNextRequest
 - GetNextResponse
 - GetCurrentDataRequest
 - GetCurrentDataResponse
 - SetTableRequest
 - SetTableResponse

