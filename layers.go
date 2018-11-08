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
	gen "./generated"
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

func mkReqLayer(mt gen.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(gen.AR)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkRespLayer(mt gen.MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+(int(mt)|int(gen.AK)),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func init() {
	// Create layers for message_type & action
	LayerTypeCreateRequest = mkReqLayer(gen.Create, "CreateRequest", gopacket.DecodeFunc(decodeCreateRequest))
	LayerTypeDeleteRequest = mkReqLayer(gen.Delete, "DeleteRequest", gopacket.DecodeFunc(decodeDeleteRequest))
	LayerTypeSetRequest = mkReqLayer(gen.Set, "SetRequest", gopacket.DecodeFunc(decodeSetRequest))
	LayerTypeGetRequest = mkReqLayer(gen.Get, "GetRequest", gopacket.DecodeFunc(decodeGetRequest))
	LayerTypeGetAllAlarmsRequest = mkReqLayer(gen.GetAllAlarms, "GetAllAlarmsRequest", gopacket.DecodeFunc(decodeGetAllAlarmsRequest))
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(gen.GetAllAlarmsNext, "GetAllAlarmsNextRequest", gopacket.DecodeFunc(decodeGetAllAlarmsNextRequest))
	LayerTypeMibUploadRequest = mkReqLayer(gen.MibUpload, "MibUploadRequest", gopacket.DecodeFunc(decodeMibUploadRequest))
	LayerTypeMibUploadNextRequest = mkReqLayer(gen.MibUploadNext, "MibUploadNextRequest", gopacket.DecodeFunc(decodeMibUploadNextRequest))
	LayerTypeMibResetRequest = mkReqLayer(gen.MibReset, "MibResetRequest", gopacket.DecodeFunc(decodeMibResetRequest))
	LayerTypeTestRequest = mkReqLayer(gen.Test, "TestRequest", gopacket.DecodeFunc(decodeTestRequest))
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(gen.StartSoftwareDownload, "StartSoftwareDownloadRequest", gopacket.DecodeFunc(decodeStartSoftwareDownloadRequest))
	LayerTypeDownloadSectionRequest = mkReqLayer(gen.DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(gen.EndSoftwareDownload, "EndSoftwareDownloadRequest", gopacket.DecodeFunc(decodeEndSoftwareDownloadRequest))
	LayerTypeActivateSoftwareRequest = mkReqLayer(gen.ActivateSoftware, "ActivateSoftwareRequest", gopacket.DecodeFunc(decodeActivateSoftwareRequest))
	LayerTypeCommitSoftwareRequest = mkReqLayer(gen.CommitSoftware, "CommitSoftwareRequest", gopacket.DecodeFunc(decodeCommitSoftwareRequest))
	LayerTypeSynchronizeTimeRequest = mkReqLayer(SynchronizeTime, "SynchronizeTimeRequest", gopacket.DecodeFunc(decodeSynchronizeTimeRequest))
	LayerTypeRebootRequest = mkReqLayer(gen.Reboot, "RebootRequest", gopacket.DecodeFunc(decodeRebootRequest))
	LayerTypeGetNextRequest = mkReqLayer(gen.GetNext, "GetNextRequest", gopacket.DecodeFunc(decodeGetNextRequest))
	LayerTypeGetCurrentDataRequest = mkReqLayer(gen.GetCurrentData, "GetCurrentDataRequest", gopacket.DecodeFunc(decodeGetCurrentDataRequest))
	LayerTypeSetTableRequest = mkReqLayer(gen.SetTable, "SetTableRequest", gopacket.DecodeFunc(decodeSetTableRequest))

	LayerTypeCreateResponse = mkRespLayer(gen.Create, "CreateResponse", gopacket.DecodeFunc(decodeCreateResponse))
	LayerTypeDeleteResponse = mkRespLayer(gen.Delete, "DeleteResponse", gopacket.DecodeFunc(decodeDeleteResponse))
	LayerTypeSetResponse = mkRespLayer(gen.Set, "SetResponse", gopacket.DecodeFunc(decodeSetResponse))
	LayerTypeGetResponse = mkRespLayer(gen.Get, "GetResponse", gopacket.DecodeFunc(decodeGetResponse))
	LayerTypeGetAllAlarmsResponse = mkRespLayer(gen.GetAllAlarms, "GetAllAlarmsResponse", gopacket.DecodeFunc(decodeGetAllAlarmsResponse))
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(gen.GetAllAlarmsNext, "GetAllAlarmsNextResponse", gopacket.DecodeFunc(decodeGetAllAlarmsNextResponse))
	LayerTypeMibUploadResponse = mkRespLayer(gen.MibUpload, "MibUploadResponse", gopacket.DecodeFunc(decodeMibUploadResponse))
	LayerTypeMibUploadNextResponse = mkRespLayer(gen.MibUploadNext, "MibUploadNextResponse", gopacket.DecodeFunc(decodeMibUploadNextResponse))
	LayerTypeMibResetResponse = mkRespLayer(gen.MibReset, "MibResetResponse", gopacket.DecodeFunc(decodeMibResetResponse))
	LayerTypeAlarmNotification = mkRespLayer(gen.AlarmNotification, "AlarmNotification", gopacket.DecodeFunc(decodeAlarmNotification))
	LayerTypeAttributeValueChange = mkRespLayer(gen.AttributeValueChange, "AttributeValueChange", gopacket.DecodeFunc(decodeAttributeValueChange))
	LayerTypeTestResponse = mkRespLayer(gen.Test, "TestResponse", gopacket.DecodeFunc(decodeTestResponse))
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(gen.StartSoftwareDownload, "StartSoftwareDownloadResponse", gopacket.DecodeFunc(decodeStartSoftwareDownloadResponse))
	LayerTypeDownloadSectionResponse = mkRespLayer(gen.DownloadSection, "DownloadSectionResponse", gopacket.DecodeFunc(decodeDownloadSectionResponse))
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(gen.EndSoftwareDownload, "EndSoftwareDownloadResponse", gopacket.DecodeFunc(decodeEndSoftwareDownloadResponse))
	LayerTypeActivateSoftwareResponse = mkRespLayer(gen.ActivateSoftware, "ActivateSoftwareResponse", gopacket.DecodeFunc(decodeActivateSoftwareResponse))
	LayerTypeCommitSoftwareResponse = mkRespLayer(gen.CommitSoftware, "CommitSoftwareResponse", gopacket.DecodeFunc(decodeCommitSoftwareResponse))
	LayerTypeSynchronizeTimeResponse = mkRespLayer(gen.SynchronizeTime, "SynchronizeTimeResponse", gopacket.DecodeFunc(decodeSynchronizeTimeResponse))
	LayerTypeRebootResponse = mkRespLayer(gen.Reboot, "RebootResponse", gopacket.DecodeFunc(decodeRebootResponse))
	LayerTypeGetNextResponse = mkRespLayer(gen.GetNext, "GetNextResponse", gopacket.DecodeFunc(decodeGetNextResponse))
	LayerTypeTestResult = mkRespLayer(gen.TestResult, "TestResult", gopacket.DecodeFunc(decodeTestResult))
	LayerTypeGetCurrentDataResponse = mkRespLayer(gen.GetCurrentData, "GetCurrentDataResponse", gopacket.DecodeFunc(decodeGetCurrentDataResponse))
	LayerTypeSetTableResponse = mkRespLayer(gen.SetTable, "SetTableResponse", gopacket.DecodeFunc(decodeSetTableResponse))

	// Map message_type and action to layer
	nextLayerMapping = make(map[byte]gopacket.LayerType)

	nextLayerMapping[byte(gen.Create)|gen.AR] = LayerTypeCreateRequest
	nextLayerMapping[byte(gen.Delete)|gen.AR] = LayerTypeDeleteRequest
	nextLayerMapping[byte(gen.Set)|gen.AR] = LayerTypeSetRequest
	nextLayerMapping[byte(gen.Get)|gen.AR] = LayerTypeGetRequest
	nextLayerMapping[byte(gen.GetAllAlarms)|gen.AR] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[byte(gen.GetAllAlarmsNext)|gen.AR] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[byte(gen.MibUpload)|gen.AR] = LayerTypeMibUploadRequest
	nextLayerMapping[byte(gen.MibUploadNext)|gen.AR] = LayerTypeMibUploadNextRequest
	nextLayerMapping[byte(gen.MibReset)|gen.AR] = LayerTypeMibResetRequest
	nextLayerMapping[byte(gen.Test)|gen.AR] = LayerTypeTestRequest
	nextLayerMapping[byte(gen.StartSoftwareDownload)|gen.AR] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[byte(gen.DownloadSection)|gen.AR] = LayerTypeDownloadSectionRequest
	nextLayerMapping[byte(gen.EndSoftwareDownload)|gen.AR] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[byte(gen.ActivateSoftware)|gen.AR] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[byte(gen.CommitSoftware)|gen.AR] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[byte(gen.SynchronizeTime)|gen.AR] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[byte(gen.Reboot)|gen.AR] = LayerTypeRebootRequest
	nextLayerMapping[byte(gen.GetNext)|gen.AR] = LayerTypeGetNextRequest
	nextLayerMapping[byte(gen.GetCurrentData)|gen.AR] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[byte(gen.SetTable)|gen.AR] = LayerTypeSetTableRequest

	nextLayerMapping[byte(gen.Create)|gen.AK] = LayerTypeCreateResponse
	nextLayerMapping[byte(gen.Delete)|gen.AK] = LayerTypeDeleteResponse
	nextLayerMapping[byte(gen.Set)|gen.AK] = LayerTypeSetResponse
	nextLayerMapping[byte(gen.Get)|gen.AK] = LayerTypeGetResponse
	nextLayerMapping[byte(gen.GetAllAlarms)|gen.AK] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[byte(gen.GetAllAlarmsNext)|gen.AK] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[byte(gen.MibUpload)|gen.AK] = LayerTypeMibUploadResponse
	nextLayerMapping[byte(gen.MibUploadNext)|gen.AK] = LayerTypeMibUploadNextResponse
	nextLayerMapping[byte(gen.MibReset)|gen.AK] = LayerTypeMibResetResponse
	nextLayerMapping[byte(gen.Test)|gen.AK] = LayerTypeTestResponse
	nextLayerMapping[byte(gen.StartSoftwareDownload)|gen.AK] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[byte(gen.DownloadSection)|gen.AK] = LayerTypeDownloadSectionResponse
	nextLayerMapping[byte(gen.EndSoftwareDownload)|gen.AK] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[byte(gen.ActivateSoftware)|gen.AK] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[byte(gen.CommitSoftware)|gen.AK] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[byte(gen.SynchronizeTime)|gen.AK] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[byte(gen.Reboot)|gen.AK] = LayerTypeRebootResponse
	nextLayerMapping[byte(gen.GetNext)|gen.AK] = LayerTypeGetNextResponse
	nextLayerMapping[byte(gen.GetCurrentData)|gen.AK] = LayerTypeGetCurrentDataResponse
	nextLayerMapping[byte(gen.TestResult)|gen.AK] = LayerTypeTestResult
	nextLayerMapping[byte(gen.SetTable)|gen.AK] = LayerTypeSetTableResponse
}

func gen.MsgTypeToNextLayer(mt byte) (gopacket.LayerType, error) {
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown message type")
}
