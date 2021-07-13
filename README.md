# OMCI

OMCI gopacket library supports the encoding and decoding of ITU G.988 OMCI
messages.  Support for the Baseline Message Set has been completed and work
is underway to support the Extended Message Set format.

# Recent Changes

In v2.0.0, the directory/package structure was reorganized (no API changes otherwise)
in order to separate message type functionality on a filename basis. This will allow
for future features and bug fixes to be better localized and to allow for better
unit test coverage reporting.

## Message Types supported and under unit test
The following OMCI message types currently have been coded and are covered
satisfactory by unit tests.

 - CreateRequest
 - CreateResponse
 - DeleteRequest
 - DeleteResponse
 - SetRequest
 - GetRequest
 - GetAllAlarmsRequest
 - GetAllAlarmsResponse
 - GetAllAlarmsNextRequest
 - MibUploadRequest
 - MibUploadResponse
 - MibUploadNextRequest
 - MibResetRequest
 - MibResetResponse
 - SynchronizeTimeRequest
 - DownloadSectionRequest
 - DownloadSectionResponse
 - EndSoftwareDownloadRequest
 - EndSoftwareDownloadResponse
 - CommitSoftwareRequest
 - CommitSoftwareResponse
 - AlarmNotification

## Message Types supported but lacking full unit test
The following OMCI message types currently have been coded and are partially covered
by unit tests, but work still remains for sufficient/better unit test coverage.

 - SetResponse
 - GetResponse
 - GetAllAlarmsNextResponse
 - MibUploadNextResponse
 - SynchronizeTimeResponse
 - AttributeValueChange
 - RebootRequest
 - RebootResponse
 - StartSoftwareDownloadRequest
 - GetNextRequest
 - GetNextResponse
 - TestResult
 - TestRequest
 - TestResponse
 - GetCurrentDataRequest
 - GetCurrentDataResponse

## Message Types supported but lacking any unit test
The following OMCI message types currently have been coded but do not
have any unit test coverage.

 - StartSoftwareDownloadResponse
 - ActivateSoftwareRequest
 - ActivateSoftwareResponse
 
## Message Types not yet supported

The following OMCI message types currently have not been coded.


## Extended Message Set Support

As mentioned earlier, support for the Extended Message Set is underway.  Currently,
the following Message Types have this support and are covered by unit tests:

 - CreateRequest/Response
 - DeleteRequest/Response
 - SetRequest/Response
 - GetRequest/Response
 - GetNextRequest/Response
 - MibResetRequest/Response
 - AlarmNotification
 - AttributeValueChange
 - DownloadSectionRequest/Response
 - SynchronizeTimeRequest/Response
 - RebootRequest/Response
 - GetCurrentDataRequest/Response
 - TestRequest/Response/Result
 - SetTableRequest/Response
 - MibUploadRequest/Response
 - MibUploadNextRequest/Response
 - TestRequest/Response/Result

### Upcoming message types that will be supported

The following provides a list of the remaining message types that will eventually support the _Extended Message Set_
in the expected order of implementation.  The priority was chosen based on speed improvement requests
of operations and ease of implementation.

 - GetAllAlarmsRequest/Response
 - GetAllAlarmsNextRequest/Response
 - StartSoftwareDownloadRequest/Response
 - EndSoftwareDownloadRequest/Response
 - CommitSoftwareRequest/Response
 - ActivateSoftwareRequest/Response

## Current user-test coverage

The _**make** test_ command can be used to create code coverage support for the
library.  The current coverage for version 2.3.0 (as of 7/13/2021) is:

| File            | Coverage |
| --------------: | :---: |
| alarms.go       | 65.6% |
| avc.go          | 86%   |
| create.go       | 80.2% |
| delete.go       | 82%   |
| get.go          | 77.6% |
| getcurrent.go   | 68.1% |
| getnext.go      | 78.3% |
| layers.go       | 100%  |
| mebase.go       | 87.5% |
| messagetypes.go | 100%  |
| mibreset.go     | 74%   |
| mibupload.go    | 75%   |
| omci.go         | 84%   |
| reboot.go       | 78.5% |
| set.go          | 75.4% |
| settable.go     | 80.5% |
| software.go     | 53.9% |
| synctime.go     | 78.3% |
| test.go         | 79.9% |

## Other outstanding items

Besides OMCI Message decode/serialization, and associated unit tests, the following items
would be needed or useful in a first official release of this library. Some changes are
to be done in the generated OMCI ME code as well.

 - Constraint checking (these are not yet fully parsed/provided by the OMCI code generated
   structs). This feature will hopefully be available in the near future.
 - Add AVC flag for appropriate attributes
 - Add some type of logging support
 
Also searching through the code for _TODO_ statements will also yield additional areas of
work to be performed.

## What is not provided by this library

This library is not a full OMCI stack for either an OLT or an ONU. It is focused primarily on
packet decode/serialization and a variety of structs and functions that are useful for handling
the creation of OMCI frames and handling decoded frames from the PON.

For an OLT-side OMCI stack, you would still need to write:
 - OMCI CC sender & receiver (stop & wait protocol) with appropriate timeout support
 - OLT State machines to support 
   - MIB Uploads/Audits/Resynchronization (and a MIB database implemention),
   - More sophisticated get & get-next support to make handle of MEs with
     lots of attributes or table attributes easy to handle and code,
   - Alarm Table support,
   - OMCI ME/Msg-Type capabilities inquiry,
   - Performance Monitoring collection (and initial time synchronization), 
   - Service implementation

For an ONU-side OMCI stack, you would still need to write:
   - OMCC implementation,
   - MIB Database,
   - Get-Next cache for table attributes,
   - MIB upload next cache for MIB uploads,
   - Generation of any alarms/AVC notifications,
   - Actually acting on the create/delete/get/set/... requests from an OLT
