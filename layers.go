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
	"./generated"
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

func mkReqLayer(mt generated.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(generated.AR)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkRespLayer(mt generated.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(generated.AK)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func init() {
	// Create layers for message_type & action
	LayerTypeCreateRequest = mkReqLayer(generated.Create, "CreateRequest", gopacket.DecodeFunc(decodeCreateRequest))
	LayerTypeDeleteRequest = mkReqLayer(generated.Delete, "DeleteRequest", gopacket.DecodeFunc(decodeDeleteRequest))
	LayerTypeSetRequest = mkReqLayer(generated.Set, "SetRequest", gopacket.DecodeFunc(decodeSetRequest))
	LayerTypeGetRequest = mkReqLayer(generated.Get, "GetRequest", gopacket.DecodeFunc(decodeGetRequest))
	LayerTypeGetAllAlarmsRequest = mkReqLayer(generated.GetAllAlarms, "GetAllAlarmsRequest", gopacket.DecodeFunc(decodeGetAllAlarmsRequest))
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(generated.GetAllAlarmsNext, "GetAllAlarmsNextRequest", gopacket.DecodeFunc(decodeGetAllAlarmsNextRequest))
	LayerTypeMibUploadRequest = mkReqLayer(generated.MibUpload, "MibUploadRequest", gopacket.DecodeFunc(decodeMibUploadRequest))
	LayerTypeMibUploadNextRequest = mkReqLayer(generated.MibUploadNext, "MibUploadNextRequest", gopacket.DecodeFunc(decodeMibUploadNextRequest))
	LayerTypeMibResetRequest = mkReqLayer(generated.MibReset, "MibResetRequest", gopacket.DecodeFunc(decodeMibResetRequest))
	LayerTypeTestRequest = mkReqLayer(generated.Test, "TestRequest", gopacket.DecodeFunc(decodeTestRequest))
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(generated.StartSoftwareDownload, "StartSoftwareDownloadRequest", gopacket.DecodeFunc(decodeStartSoftwareDownloadRequest))
	LayerTypeDownloadSectionRequest = mkReqLayer(generated.DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(generated.EndSoftwareDownload, "EndSoftwareDownloadRequest", gopacket.DecodeFunc(decodeEndSoftwareDownloadRequest))
	LayerTypeActivateSoftwareRequest = mkReqLayer(generated.ActivateSoftware, "ActivateSoftwareRequest", gopacket.DecodeFunc(decodeActivateSoftwareRequest))
	LayerTypeCommitSoftwareRequest = mkReqLayer(generated.CommitSoftware, "CommitSoftwareRequest", gopacket.DecodeFunc(decodeCommitSoftwareRequest))
	LayerTypeSynchronizeTimeRequest = mkReqLayer(generated.SynchronizeTime, "SynchronizeTimeRequest", gopacket.DecodeFunc(decodeSynchronizeTimeRequest))
	LayerTypeRebootRequest = mkReqLayer(generated.Reboot, "RebootRequest", gopacket.DecodeFunc(decodeRebootRequest))
	LayerTypeGetNextRequest = mkReqLayer(generated.GetNext, "GetNextRequest", gopacket.DecodeFunc(decodeGetNextRequest))
	LayerTypeGetCurrentDataRequest = mkReqLayer(generated.GetCurrentData, "GetCurrentDataRequest", gopacket.DecodeFunc(decodeGetCurrentDataRequest))
	LayerTypeSetTableRequest = mkReqLayer(generated.SetTable, "SetTableRequest", gopacket.DecodeFunc(decodeSetTableRequest))

	LayerTypeCreateResponse = mkRespLayer(generated.Create, "CreateResponse", gopacket.DecodeFunc(decodeCreateResponse))
	LayerTypeDeleteResponse = mkRespLayer(generated.Delete, "DeleteResponse", gopacket.DecodeFunc(decodeDeleteResponse))
	LayerTypeSetResponse = mkRespLayer(generated.Set, "SetResponse", gopacket.DecodeFunc(decodeSetResponse))
	LayerTypeGetResponse = mkRespLayer(generated.Get, "GetResponse", gopacket.DecodeFunc(decodeGetResponse))
	LayerTypeGetAllAlarmsResponse = mkRespLayer(generated.GetAllAlarms, "GetAllAlarmsResponse", gopacket.DecodeFunc(decodeGetAllAlarmsResponse))
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(generated.GetAllAlarmsNext, "GetAllAlarmsNextResponse", gopacket.DecodeFunc(decodeGetAllAlarmsNextResponse))
	LayerTypeMibUploadResponse = mkRespLayer(generated.MibUpload, "MibUploadResponse", gopacket.DecodeFunc(decodeMibUploadResponse))
	LayerTypeMibUploadNextResponse = mkRespLayer(generated.MibUploadNext, "MibUploadNextResponse", gopacket.DecodeFunc(decodeMibUploadNextResponse))
	LayerTypeMibResetResponse = mkRespLayer(generated.MibReset, "MibResetResponse", gopacket.DecodeFunc(decodeMibResetResponse))
	LayerTypeAlarmNotification = mkRespLayer(generated.AlarmNotification, "AlarmNotification", gopacket.DecodeFunc(decodeAlarmNotification))
	LayerTypeAttributeValueChange = mkRespLayer(generated.AttributeValueChange, "AttributeValueChange", gopacket.DecodeFunc(decodeAttributeValueChange))
	LayerTypeTestResponse = mkRespLayer(generated.Test, "TestResponse", gopacket.DecodeFunc(decodeTestResponse))
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(generated.StartSoftwareDownload, "StartSoftwareDownloadResponse", gopacket.DecodeFunc(decodeStartSoftwareDownloadResponse))
	LayerTypeDownloadSectionResponse = mkRespLayer(generated.DownloadSection, "DownloadSectionResponse", gopacket.DecodeFunc(decodeDownloadSectionResponse))
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(generated.EndSoftwareDownload, "EndSoftwareDownloadResponse", gopacket.DecodeFunc(decodeEndSoftwareDownloadResponse))
	LayerTypeActivateSoftwareResponse = mkRespLayer(generated.ActivateSoftware, "ActivateSoftwareResponse", gopacket.DecodeFunc(decodeActivateSoftwareResponse))
	LayerTypeCommitSoftwareResponse = mkRespLayer(generated.CommitSoftware, "CommitSoftwareResponse", gopacket.DecodeFunc(decodeCommitSoftwareResponse))
	LayerTypeSynchronizeTimeResponse = mkRespLayer(generated.SynchronizeTime, "SynchronizeTimeResponse", gopacket.DecodeFunc(decodeSynchronizeTimeResponse))
	LayerTypeRebootResponse = mkRespLayer(generated.Reboot, "RebootResponse", gopacket.DecodeFunc(decodeRebootResponse))
	LayerTypeGetNextResponse = mkRespLayer(generated.GetNext, "GetNextResponse", gopacket.DecodeFunc(decodeGetNextResponse))
	LayerTypeTestResult = mkRespLayer(generated.TestResult, "TestResult", gopacket.DecodeFunc(decodeTestResult))
	LayerTypeGetCurrentDataResponse = mkRespLayer(generated.GetCurrentData, "GetCurrentDataResponse", gopacket.DecodeFunc(decodeGetCurrentDataResponse))
	LayerTypeSetTableResponse = mkRespLayer(generated.SetTable, "SetTableResponse", gopacket.DecodeFunc(decodeSetTableResponse))

	// Map message_type and action to layer
	nextLayerMapping = make(map[byte]gopacket.LayerType)

	nextLayerMapping[byte(generated.Create)|generated.AR] = LayerTypeCreateRequest
	nextLayerMapping[byte(generated.Delete)|generated.AR] = LayerTypeDeleteRequest
	nextLayerMapping[byte(generated.Set)|generated.AR] = LayerTypeSetRequest
	nextLayerMapping[byte(generated.Get)|generated.AR] = LayerTypeGetRequest
	nextLayerMapping[byte(generated.GetAllAlarms)|generated.AR] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[byte(generated.GetAllAlarmsNext)|generated.AR] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[byte(generated.MibUpload)|generated.AR] = LayerTypeMibUploadRequest
	nextLayerMapping[byte(generated.MibUploadNext)|generated.AR] = LayerTypeMibUploadNextRequest
	nextLayerMapping[byte(generated.MibReset)|generated.AR] = LayerTypeMibResetRequest
	nextLayerMapping[byte(generated.Test)|generated.AR] = LayerTypeTestRequest
	nextLayerMapping[byte(generated.StartSoftwareDownload)|generated.AR] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[byte(generated.DownloadSection)|generated.AR] = LayerTypeDownloadSectionRequest
	nextLayerMapping[byte(generated.EndSoftwareDownload)|generated.AR] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[byte(generated.ActivateSoftware)|generated.AR] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[byte(generated.CommitSoftware)|generated.AR] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[byte(generated.SynchronizeTime)|generated.AR] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[byte(generated.Reboot)|generated.AR] = LayerTypeRebootRequest
	nextLayerMapping[byte(generated.GetNext)|generated.AR] = LayerTypeGetNextRequest
	nextLayerMapping[byte(generated.GetCurrentData)|generated.AR] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[byte(generated.SetTable)|generated.AR] = LayerTypeSetTableRequest

	nextLayerMapping[byte(generated.Create)|generated.AK] = LayerTypeCreateResponse
	nextLayerMapping[byte(generated.Delete)|generated.AK] = LayerTypeDeleteResponse
	nextLayerMapping[byte(generated.Set)|generated.AK] = LayerTypeSetResponse
	nextLayerMapping[byte(generated.Get)|generated.AK] = LayerTypeGetResponse
	nextLayerMapping[byte(generated.GetAllAlarms)|generated.AK] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[byte(generated.GetAllAlarmsNext)|generated.AK] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[byte(generated.MibUpload)|generated.AK] = LayerTypeMibUploadResponse
	nextLayerMapping[byte(generated.MibUploadNext)|generated.AK] = LayerTypeMibUploadNextResponse
	nextLayerMapping[byte(generated.MibReset)|generated.AK] = LayerTypeMibResetResponse
	nextLayerMapping[byte(generated.Test)|generated.AK] = LayerTypeTestResponse
	nextLayerMapping[byte(generated.StartSoftwareDownload)|generated.AK] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[byte(generated.DownloadSection)|generated.AK] = LayerTypeDownloadSectionResponse
	nextLayerMapping[byte(generated.EndSoftwareDownload)|generated.AK] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[byte(generated.ActivateSoftware)|generated.AK] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[byte(generated.CommitSoftware)|generated.AK] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[byte(generated.SynchronizeTime)|generated.AK] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[byte(generated.Reboot)|generated.AK] = LayerTypeRebootResponse
	nextLayerMapping[byte(generated.GetNext)|generated.AK] = LayerTypeGetNextResponse
	nextLayerMapping[byte(generated.GetCurrentData)|generated.AK] = LayerTypeGetCurrentDataResponse
	nextLayerMapping[byte(generated.TestResult)|generated.AK] = LayerTypeTestResult
	nextLayerMapping[byte(generated.SetTable)|generated.AK] = LayerTypeSetTableResponse
}

func MsgTypeToNextLayer(mt byte) (gopacket.LayerType, error) {
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown message type")
}
