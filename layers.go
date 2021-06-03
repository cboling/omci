/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package omci

import (
	"errors"
	me "github.com/cboling/omci/generated"
	"github.com/google/gopacket"
)

var nextLayerMapping map[MessageType]gopacket.LayerType

var (
	// Baseline Message Types
	LayerTypeCreateRequest                gopacket.LayerType
	LayerTypeDeleteRequest                gopacket.LayerType
	LayerTypeSetRequest                   gopacket.LayerType
	LayerTypeGetRequest                   gopacket.LayerType
	LayerTypeGetAllAlarmsRequest          gopacket.LayerType
	LayerTypeGetAllAlarmsNextRequest      gopacket.LayerType
	LayerTypeMibUploadRequest             gopacket.LayerType
	LayerTypeMibUploadNextRequest         gopacket.LayerType
	LayerTypeMibResetRequest              gopacket.LayerType
	LayerTypeTestRequest                  gopacket.LayerType
	LayerTypeStartSoftwareDownloadRequest gopacket.LayerType
	LayerTypeDownloadSectionRequest       gopacket.LayerType
	LayerTypeDownloadSectionLastRequest   gopacket.LayerType
	LayerTypeEndSoftwareDownloadRequest   gopacket.LayerType
	LayerTypeActivateSoftwareRequest      gopacket.LayerType
	LayerTypeCommitSoftwareRequest        gopacket.LayerType
	LayerTypeSynchronizeTimeRequest       gopacket.LayerType
	LayerTypeRebootRequest                gopacket.LayerType
	LayerTypeGetNextRequest               gopacket.LayerType
	LayerTypeGetCurrentDataRequest        gopacket.LayerType
	LayerTypeSetTableRequest              gopacket.LayerType

	// Extended Request Message Types
	LayerTypeCreateRequestExtended              gopacket.LayerType
	LayerTypeDeleteRequestExtended              gopacket.LayerType
	LayerTypeSetRequestExtended                 gopacket.LayerType
	LayerTypeMibResetRequestExtended            gopacket.LayerType
	LayerTypeGetRequestExtended                 gopacket.LayerType
	LayerTypeDownloadSectionRequestExtended     gopacket.LayerType
	LayerTypeDownloadSectionLastRequestExtended gopacket.LayerType
	LayerTypeSynchronizeTimeRequestExtended     gopacket.LayerType
	LayerTypeRebootRequestExtended              gopacket.LayerType
	LayerTypeGetCurrentDataRequestExtended      gopacket.LayerType
)
var (
	// Baseline Message Types
	LayerTypeCreateResponse                gopacket.LayerType
	LayerTypeDeleteResponse                gopacket.LayerType
	LayerTypeSetResponse                   gopacket.LayerType
	LayerTypeGetResponse                   gopacket.LayerType
	LayerTypeGetAllAlarmsResponse          gopacket.LayerType
	LayerTypeGetAllAlarmsNextResponse      gopacket.LayerType
	LayerTypeMibUploadResponse             gopacket.LayerType
	LayerTypeMibUploadNextResponse         gopacket.LayerType
	LayerTypeMibResetResponse              gopacket.LayerType
	LayerTypeAlarmNotification             gopacket.LayerType
	LayerTypeAttributeValueChange          gopacket.LayerType
	LayerTypeTestResponse                  gopacket.LayerType
	LayerTypeStartSoftwareDownloadResponse gopacket.LayerType
	LayerTypeDownloadSectionResponse       gopacket.LayerType
	LayerTypeEndSoftwareDownloadResponse   gopacket.LayerType
	LayerTypeActivateSoftwareResponse      gopacket.LayerType
	LayerTypeCommitSoftwareResponse        gopacket.LayerType
	LayerTypeSynchronizeTimeResponse       gopacket.LayerType
	LayerTypeRebootResponse                gopacket.LayerType
	LayerTypeGetNextResponse               gopacket.LayerType
	LayerTypeTestResult                    gopacket.LayerType
	LayerTypeGetCurrentDataResponse        gopacket.LayerType
	LayerTypeSetTableResponse              gopacket.LayerType

	// Extended Response/Notification Message Types
	LayerTypeCreateResponseExtended          gopacket.LayerType
	LayerTypeDeleteResponseExtended          gopacket.LayerType
	LayerTypeSetResponseExtended             gopacket.LayerType
	LayerTypeMibResetResponseExtended        gopacket.LayerType
	LayerTypeGetResponseExtended             gopacket.LayerType
	LayerTypeDownloadSectionResponseExtended gopacket.LayerType
	LayerTypeAlarmNotificationExtended       gopacket.LayerType
	LayerTypeAttributeValueChangeExtended    gopacket.LayerType
	LayerTypeTestResultExtended              gopacket.LayerType
	LayerTypeSynchronizeTimeResponseExtended gopacket.LayerType
	LayerTypeRebootResponseExtended          gopacket.LayerType
	LayerTypeGetCurrentDataResponseExtended  gopacket.LayerType
)

func mkReqLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(me.AR)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkRespLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(me.AK)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkLayer(mt me.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func init() {
	// Create layers for message_type & action
	LayerTypeCreateRequest = mkReqLayer(me.Create, "CreateRequest", gopacket.DecodeFunc(decodeCreateRequest))
	LayerTypeDeleteRequest = mkReqLayer(me.Delete, "DeleteRequest", gopacket.DecodeFunc(decodeDeleteRequest))
	LayerTypeSetRequest = mkReqLayer(me.Set, "SetRequest", gopacket.DecodeFunc(decodeSetRequest))
	LayerTypeGetRequest = mkReqLayer(me.Get, "GetRequest", gopacket.DecodeFunc(decodeGetRequest))
	LayerTypeGetAllAlarmsRequest = mkReqLayer(me.GetAllAlarms, "GetAllAlarmsRequest", gopacket.DecodeFunc(decodeGetAllAlarmsRequest))
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextRequest", gopacket.DecodeFunc(decodeGetAllAlarmsNextRequest))
	LayerTypeMibUploadRequest = mkReqLayer(me.MibUpload, "MibUploadRequest", gopacket.DecodeFunc(decodeMibUploadRequest))
	LayerTypeMibUploadNextRequest = mkReqLayer(me.MibUploadNext, "MibUploadNextRequest", gopacket.DecodeFunc(decodeMibUploadNextRequest))
	LayerTypeMibResetRequest = mkReqLayer(me.MibReset, "MibResetRequest", gopacket.DecodeFunc(decodeMibResetRequest))
	LayerTypeTestRequest = mkReqLayer(me.Test, "TestRequest", gopacket.DecodeFunc(decodeTestRequest))
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(me.StartSoftwareDownload, "StartSoftwareDownloadRequest", gopacket.DecodeFunc(decodeStartSoftwareDownloadRequest))

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	LayerTypeDownloadSectionRequest = mkLayer(me.DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeDownloadSectionLastRequest = mkReqLayer(me.DownloadSection, "DownloadLastSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(me.EndSoftwareDownload, "EndSoftwareDownloadRequest", gopacket.DecodeFunc(decodeEndSoftwareDownloadRequest))
	LayerTypeActivateSoftwareRequest = mkReqLayer(me.ActivateSoftware, "ActivateSoftwareRequest", gopacket.DecodeFunc(decodeActivateSoftwareRequest))
	LayerTypeCommitSoftwareRequest = mkReqLayer(me.CommitSoftware, "CommitSoftwareRequest", gopacket.DecodeFunc(decodeCommitSoftwareRequest))
	LayerTypeSynchronizeTimeRequest = mkReqLayer(me.SynchronizeTime, "SynchronizeTimeRequest", gopacket.DecodeFunc(decodeSynchronizeTimeRequest))
	LayerTypeRebootRequest = mkReqLayer(me.Reboot, "RebootRequest", gopacket.DecodeFunc(decodeRebootRequest))
	LayerTypeGetNextRequest = mkReqLayer(me.GetNext, "GetNextRequest", gopacket.DecodeFunc(decodeGetNextRequest))
	LayerTypeGetCurrentDataRequest = mkReqLayer(me.GetCurrentData, "GetCurrentDataRequest", gopacket.DecodeFunc(decodeGetCurrentDataRequest))
	LayerTypeSetTableRequest = mkReqLayer(me.SetTable, "SetTableRequest", gopacket.DecodeFunc(decodeSetTableRequest))

	LayerTypeCreateResponse = mkRespLayer(me.Create, "CreateResponse", gopacket.DecodeFunc(decodeCreateResponse))
	LayerTypeDeleteResponse = mkRespLayer(me.Delete, "DeleteResponse", gopacket.DecodeFunc(decodeDeleteResponse))
	LayerTypeSetResponse = mkRespLayer(me.Set, "SetResponse", gopacket.DecodeFunc(decodeSetResponse))
	LayerTypeGetResponse = mkRespLayer(me.Get, "GetResponse", gopacket.DecodeFunc(decodeGetResponse))
	LayerTypeGetAllAlarmsResponse = mkRespLayer(me.GetAllAlarms, "GetAllAlarmsResponse", gopacket.DecodeFunc(decodeGetAllAlarmsResponse))
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(me.GetAllAlarmsNext, "GetAllAlarmsNextResponse", gopacket.DecodeFunc(decodeGetAllAlarmsNextResponse))
	LayerTypeMibUploadResponse = mkRespLayer(me.MibUpload, "MibUploadResponse", gopacket.DecodeFunc(decodeMibUploadResponse))
	LayerTypeMibUploadNextResponse = mkRespLayer(me.MibUploadNext, "MibUploadNextResponse", gopacket.DecodeFunc(decodeMibUploadNextResponse))
	LayerTypeMibResetResponse = mkRespLayer(me.MibReset, "MibResetResponse", gopacket.DecodeFunc(decodeMibResetResponse))
	LayerTypeAlarmNotification = mkLayer(me.AlarmNotification, "AlarmNotification", gopacket.DecodeFunc(decodeAlarmNotification))
	LayerTypeAttributeValueChange = mkLayer(me.AttributeValueChange, "AttributeValueChange", gopacket.DecodeFunc(decodeAttributeValueChange))
	LayerTypeTestResponse = mkRespLayer(me.Test, "TestResponse", gopacket.DecodeFunc(decodeTestResponse))
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(me.StartSoftwareDownload, "StartSoftwareDownloadResponse", gopacket.DecodeFunc(decodeStartSoftwareDownloadResponse))
	LayerTypeDownloadSectionResponse = mkRespLayer(me.DownloadSection, "DownloadSectionResponse", gopacket.DecodeFunc(decodeDownloadSectionResponse))
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(me.EndSoftwareDownload, "EndSoftwareDownloadResponse", gopacket.DecodeFunc(decodeEndSoftwareDownloadResponse))
	LayerTypeActivateSoftwareResponse = mkRespLayer(me.ActivateSoftware, "ActivateSoftwareResponse", gopacket.DecodeFunc(decodeActivateSoftwareResponse))
	LayerTypeCommitSoftwareResponse = mkRespLayer(me.CommitSoftware, "CommitSoftwareResponse", gopacket.DecodeFunc(decodeCommitSoftwareResponse))
	LayerTypeSynchronizeTimeResponse = mkRespLayer(me.SynchronizeTime, "SynchronizeTimeResponse", gopacket.DecodeFunc(decodeSynchronizeTimeResponse))
	LayerTypeRebootResponse = mkRespLayer(me.Reboot, "RebootResponse", gopacket.DecodeFunc(decodeRebootResponse))
	LayerTypeGetNextResponse = mkRespLayer(me.GetNext, "GetNextResponse", gopacket.DecodeFunc(decodeGetNextResponse))
	LayerTypeTestResult = mkRespLayer(me.TestResult, "TestResult", gopacket.DecodeFunc(decodeTestResult))
	LayerTypeGetCurrentDataResponse = mkRespLayer(me.GetCurrentData, "GetCurrentDataResponse", gopacket.DecodeFunc(decodeGetCurrentDataResponse))
	LayerTypeSetTableResponse = mkRespLayer(me.SetTable, "SetTableResponse", gopacket.DecodeFunc(decodeSetTableResponse))

	// Extended message set support

	LayerTypeCreateRequestExtended = mkReqLayer(me.Create|me.ExtendedOffset, "CreateRequest-Ext", gopacket.DecodeFunc(decodeCreateRequestExtended))
	LayerTypeDeleteRequestExtended = mkReqLayer(me.Delete|me.ExtendedOffset, "DeleteRequest-Ext", gopacket.DecodeFunc(decodeDeleteRequestExtended))
	LayerTypeSetRequestExtended = mkReqLayer(me.Set|me.ExtendedOffset, "SetRequest-Ext", gopacket.DecodeFunc(decodeSetRequestExtended))
	LayerTypeGetRequestExtended = mkReqLayer(me.Get|me.ExtendedOffset, "GetRequest-Ext", gopacket.DecodeFunc(decodeGetRequestExtended))
	LayerTypeMibResetRequestExtended = mkReqLayer(me.MibReset|me.ExtendedOffset, "MibResetRequest-Ext", gopacket.DecodeFunc(decodeMibResetRequestExtended))
	LayerTypeDownloadSectionRequestExtended = mkLayer(me.DownloadSection|me.ExtendedOffset, "DownloadSectionRequest-Ext", gopacket.DecodeFunc(decodeDownloadSectionRequestExtended))
	LayerTypeDownloadSectionLastRequestExtended = mkReqLayer(me.DownloadSection|me.ExtendedOffset, "DownloadLastSectionRequest-Ext", gopacket.DecodeFunc(decodeDownloadSectionRequestExtended))
	LayerTypeSynchronizeTimeRequestExtended = mkReqLayer(me.SynchronizeTime|me.ExtendedOffset, "SynchronizeTimeRequest-Ext", gopacket.DecodeFunc(decodeSynchronizeTimeRequestExtended))
	LayerTypeRebootRequestExtended = mkReqLayer(me.Reboot|me.ExtendedOffset, "RebootRequest-Ext", gopacket.DecodeFunc(decodeRebootRequestExtended))
	LayerTypeGetCurrentDataRequestExtended = mkReqLayer(me.GetCurrentData|me.ExtendedOffset, "GetCurrentDataRequest-Ext", gopacket.DecodeFunc(decodeGetCurrentDataRequestExtended))

	LayerTypeCreateResponseExtended = mkRespLayer(me.Create|me.ExtendedOffset, "CreateResponse-Ext", gopacket.DecodeFunc(decodeCreateResponseExtended))
	LayerTypeDeleteResponseExtended = mkRespLayer(me.Delete|me.ExtendedOffset, "DeleteResponse-Ext", gopacket.DecodeFunc(decodeDeleteResponseExtended))
	LayerTypeSetResponseExtended = mkRespLayer(me.Set|me.ExtendedOffset, "SetResponse-Ext", gopacket.DecodeFunc(decodeSetResponseExtended))
	LayerTypeGetResponseExtended = mkRespLayer(me.Get|me.ExtendedOffset, "GetResponse-Ext", gopacket.DecodeFunc(decodeGetResponseExtended))
	LayerTypeMibResetResponseExtended = mkRespLayer(me.MibReset|me.ExtendedOffset, "MibResetResponse-Ext", gopacket.DecodeFunc(decodeMibResetResponseExtended))
	LayerTypeDownloadSectionResponseExtended = mkRespLayer(me.DownloadSection|me.ExtendedOffset, "DownloadSectionResponse-Ext", gopacket.DecodeFunc(decodeDownloadSectionResponseExtended))
	LayerTypeSynchronizeTimeResponseExtended = mkRespLayer(me.SynchronizeTime|me.ExtendedOffset, "SynchronizeTimeResponse-Ext", gopacket.DecodeFunc(decodeSynchronizeTimeResponseExtended))
	LayerTypeRebootResponseExtended = mkRespLayer(me.Reboot|me.ExtendedOffset, "RebootResponse-Ext", gopacket.DecodeFunc(decodeRebootResponseExtended))
	LayerTypeGetCurrentDataResponseExtended = mkRespLayer(me.GetCurrentData|me.ExtendedOffset, "GetCurrentDataResponse-Ext", gopacket.DecodeFunc(decodeGetCurrentDataResponseExtended))

	LayerTypeAlarmNotificationExtended = mkLayer(me.AlarmNotification|me.ExtendedOffset, "AlarmNotification-Ext", gopacket.DecodeFunc(decodeAlarmNotificationExtended))
	LayerTypeAttributeValueChangeExtended = mkLayer(me.AttributeValueChange|me.ExtendedOffset, "AttributeValueChange-Ext", gopacket.DecodeFunc(decodeAttributeValueChangeExtended))
	LayerTypeTestResultExtended = mkLayer(me.TestResult|me.ExtendedOffset, "TestResult-Ext", gopacket.DecodeFunc(decodeTestResultExtended))

	// Map message_type and action to layer
	nextLayerMapping = make(map[MessageType]gopacket.LayerType)

	nextLayerMapping[CreateRequestType] = LayerTypeCreateRequest
	nextLayerMapping[DeleteRequestType] = LayerTypeDeleteRequest
	nextLayerMapping[SetRequestType] = LayerTypeSetRequest
	nextLayerMapping[GetRequestType] = LayerTypeGetRequest
	nextLayerMapping[GetAllAlarmsRequestType] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[GetAllAlarmsNextRequestType] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[MibUploadRequestType] = LayerTypeMibUploadRequest
	nextLayerMapping[MibUploadNextRequestType] = LayerTypeMibUploadNextRequest
	nextLayerMapping[MibResetRequestType] = LayerTypeMibResetRequest
	nextLayerMapping[TestRequestType] = LayerTypeTestRequest
	nextLayerMapping[StartSoftwareDownloadRequestType] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[DownloadSectionRequestType] = LayerTypeDownloadSectionRequest
	nextLayerMapping[DownloadSectionRequestWithResponseType] = LayerTypeDownloadSectionRequest
	nextLayerMapping[EndSoftwareDownloadRequestType] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[ActivateSoftwareRequestType] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[CommitSoftwareRequestType] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[SynchronizeTimeRequestType] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[RebootRequestType] = LayerTypeRebootRequest
	nextLayerMapping[GetNextRequestType] = LayerTypeGetNextRequest
	nextLayerMapping[GetCurrentDataRequestType] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[SetTableRequestType] = LayerTypeSetTableRequest

	nextLayerMapping[CreateResponseType] = LayerTypeCreateResponse
	nextLayerMapping[DeleteResponseType] = LayerTypeDeleteResponse
	nextLayerMapping[SetResponseType] = LayerTypeSetResponse
	nextLayerMapping[GetResponseType] = LayerTypeGetResponse
	nextLayerMapping[GetAllAlarmsResponseType] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[GetAllAlarmsNextResponseType] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[MibUploadResponseType] = LayerTypeMibUploadResponse
	nextLayerMapping[MibUploadNextResponseType] = LayerTypeMibUploadNextResponse
	nextLayerMapping[MibResetResponseType] = LayerTypeMibResetResponse
	nextLayerMapping[TestResponseType] = LayerTypeTestResponse
	nextLayerMapping[StartSoftwareDownloadResponseType] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[DownloadSectionResponseType] = LayerTypeDownloadSectionResponse
	nextLayerMapping[EndSoftwareDownloadResponseType] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[ActivateSoftwareResponseType] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[CommitSoftwareResponseType] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[SynchronizeTimeResponseType] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[RebootResponseType] = LayerTypeRebootResponse
	nextLayerMapping[GetNextResponseType] = LayerTypeGetNextResponse
	nextLayerMapping[GetCurrentDataResponseType] = LayerTypeGetCurrentDataResponse
	nextLayerMapping[SetTableResponseType] = LayerTypeSetTableResponse

	nextLayerMapping[AttributeValueChangeType] = LayerTypeAttributeValueChange
	nextLayerMapping[AlarmNotificationType] = LayerTypeAlarmNotification
	nextLayerMapping[TestResultType] = LayerTypeTestResult

	// Extended message support
	nextLayerMapping[CreateRequestType+ExtendedTypeDecodeOffset] = LayerTypeCreateRequestExtended
	nextLayerMapping[CreateResponseType+ExtendedTypeDecodeOffset] = LayerTypeCreateResponseExtended
	nextLayerMapping[DeleteResponseType+ExtendedTypeDecodeOffset] = LayerTypeDeleteResponseExtended
	nextLayerMapping[DeleteRequestType+ExtendedTypeDecodeOffset] = LayerTypeDeleteRequestExtended
	nextLayerMapping[SetRequestType+ExtendedTypeDecodeOffset] = LayerTypeSetRequestExtended
	nextLayerMapping[SetResponseType+ExtendedTypeDecodeOffset] = LayerTypeSetResponseExtended
	nextLayerMapping[GetRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetRequestExtended
	nextLayerMapping[GetResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetResponseExtended
	nextLayerMapping[MibResetRequestType+ExtendedTypeDecodeOffset] = LayerTypeMibResetRequestExtended
	nextLayerMapping[MibResetResponseType+ExtendedTypeDecodeOffset] = LayerTypeMibResetResponseExtended
	nextLayerMapping[SynchronizeTimeRequestType+ExtendedTypeDecodeOffset] = LayerTypeSynchronizeTimeRequestExtended
	nextLayerMapping[SynchronizeTimeResponseType+ExtendedTypeDecodeOffset] = LayerTypeSynchronizeTimeResponseExtended
	nextLayerMapping[RebootRequestType+ExtendedTypeDecodeOffset] = LayerTypeRebootRequestExtended
	nextLayerMapping[RebootResponseType+ExtendedTypeDecodeOffset] = LayerTypeRebootResponseExtended
	nextLayerMapping[GetCurrentDataRequestType+ExtendedTypeDecodeOffset] = LayerTypeGetCurrentDataRequestExtended
	nextLayerMapping[GetCurrentDataResponseType+ExtendedTypeDecodeOffset] = LayerTypeGetCurrentDataResponseExtended

	// For Download section, AR=0 if not response expected, AR=1 if response expected (last section of a window)
	nextLayerMapping[DownloadSectionRequestType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionRequestExtended
	nextLayerMapping[DownloadSectionRequestWithResponseType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionLastRequestExtended
	nextLayerMapping[DownloadSectionResponseType+ExtendedTypeDecodeOffset] = LayerTypeDownloadSectionResponseExtended

	nextLayerMapping[AlarmNotificationType+ExtendedTypeDecodeOffset] = LayerTypeAlarmNotificationExtended
	nextLayerMapping[AttributeValueChangeType+ExtendedTypeDecodeOffset] = LayerTypeAttributeValueChangeExtended
	nextLayerMapping[TestResultType+ExtendedTypeDecodeOffset] = LayerTypeTestResultExtended
}

func MsgTypeToNextLayer(mt MessageType, isExtended bool) (gopacket.LayerType, error) {
	if isExtended {
		mt |= ExtendedTypeDecodeOffset
	}
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown/unsupported message type")
}
