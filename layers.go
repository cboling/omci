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
	me "./generated"
	"errors"
	"github.com/google/gopacket"
)

var nextLayerMapping map[byte]gopacket.LayerType

var (
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
	LayerTypeEndSoftwareDownloadRequest   gopacket.LayerType
	LayerTypeActivateSoftwareRequest      gopacket.LayerType
	LayerTypeCommitSoftwareRequest        gopacket.LayerType
	LayerTypeSynchronizeTimeRequest       gopacket.LayerType
	LayerTypeRebootRequest                gopacket.LayerType
	LayerTypeGetNextRequest               gopacket.LayerType
	LayerTypeGetCurrentDataRequest        gopacket.LayerType
	LayerTypeSetTableRequest              gopacket.LayerType
)
var (
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
	LayerTypeDownloadSectionRequest = mkReqLayer(me.DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
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

	// Map message_type and action to layer
	nextLayerMapping = make(map[byte]gopacket.LayerType)

	nextLayerMapping[byte(me.Create)|me.AR] = LayerTypeCreateRequest
	nextLayerMapping[byte(me.Delete)|me.AR] = LayerTypeDeleteRequest
	nextLayerMapping[byte(me.Set)|me.AR] = LayerTypeSetRequest
	nextLayerMapping[byte(me.Get)|me.AR] = LayerTypeGetRequest
	nextLayerMapping[byte(me.GetAllAlarms)|me.AR] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[byte(me.GetAllAlarmsNext)|me.AR] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[byte(me.MibUpload)|me.AR] = LayerTypeMibUploadRequest
	nextLayerMapping[byte(me.MibUploadNext)|me.AR] = LayerTypeMibUploadNextRequest
	nextLayerMapping[byte(me.MibReset)|me.AR] = LayerTypeMibResetRequest
	nextLayerMapping[byte(me.Test)|me.AR] = LayerTypeTestRequest
	nextLayerMapping[byte(me.StartSoftwareDownload)|me.AR] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[byte(me.DownloadSection)|me.AR] = LayerTypeDownloadSectionRequest
	nextLayerMapping[byte(me.EndSoftwareDownload)|me.AR] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[byte(me.ActivateSoftware)|me.AR] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[byte(me.CommitSoftware)|me.AR] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[byte(me.SynchronizeTime)|me.AR] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[byte(me.Reboot)|me.AR] = LayerTypeRebootRequest
	nextLayerMapping[byte(me.GetNext)|me.AR] = LayerTypeGetNextRequest
	nextLayerMapping[byte(me.GetCurrentData)|me.AR] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[byte(me.SetTable)|me.AR] = LayerTypeSetTableRequest

	nextLayerMapping[byte(me.Create)|me.AK] = LayerTypeCreateResponse
	nextLayerMapping[byte(me.Delete)|me.AK] = LayerTypeDeleteResponse
	nextLayerMapping[byte(me.Set)|me.AK] = LayerTypeSetResponse
	nextLayerMapping[byte(me.Get)|me.AK] = LayerTypeGetResponse
	nextLayerMapping[byte(me.GetAllAlarms)|me.AK] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[byte(me.GetAllAlarmsNext)|me.AK] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[byte(me.MibUpload)|me.AK] = LayerTypeMibUploadResponse
	nextLayerMapping[byte(me.MibUploadNext)|me.AK] = LayerTypeMibUploadNextResponse
	nextLayerMapping[byte(me.MibReset)|me.AK] = LayerTypeMibResetResponse
	nextLayerMapping[byte(me.Test)|me.AK] = LayerTypeTestResponse
	nextLayerMapping[byte(me.StartSoftwareDownload)|me.AK] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[byte(me.DownloadSection)|me.AK] = LayerTypeDownloadSectionResponse
	nextLayerMapping[byte(me.EndSoftwareDownload)|me.AK] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[byte(me.ActivateSoftware)|me.AK] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[byte(me.CommitSoftware)|me.AK] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[byte(me.SynchronizeTime)|me.AK] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[byte(me.Reboot)|me.AK] = LayerTypeRebootResponse
	nextLayerMapping[byte(me.GetNext)|me.AK] = LayerTypeGetNextResponse
	nextLayerMapping[byte(me.GetCurrentData)|me.AK] = LayerTypeGetCurrentDataResponse
	nextLayerMapping[byte(me.SetTable)|me.AK] = LayerTypeSetTableResponse

	nextLayerMapping[byte(me.AttributeValueChange)] = LayerTypeAttributeValueChange
	nextLayerMapping[byte(me.AlarmNotification)] = LayerTypeAlarmNotification
	nextLayerMapping[byte(me.TestResult)|me.AK] = LayerTypeTestResult
}

func MsgTypeToNextLayer(mt byte) (gopacket.LayerType, error) {
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown message type")
}
