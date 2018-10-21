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
	"encoding/binary"
	"errors"
	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

type Results byte

// MsgType represents a OMCI message-type
type MsgType byte

const (
	// AK (Bit 6), indicates whether this message is an AK to an action request.
	// If a message is an AK, this bit is set to 1. If the message is not a
	// response to a command, this bit is set to 0. In messages sent by the OLT,
	// this bit is always 0.
	AK byte = 0x20

	// AR (Bit 7), acknowledge request, indicates whether the message requires an
	// AK. An AK is a response to an action request, not a link layer handshake.
	// If an AK is expected, this bit is set to 1. If no AK is expected, this bit
	// is 0. In messages sent by the ONU, this bit is always 0
	AR byte = 0x40

	// MsgTypeMask provides a mask to get the base message type
	MsgTypeMask = 0x1F
)

const (
	// Message Types
	_                             = iota
	Create                MsgType = 4
	Delete                        = 6
	Set                           = 8
	Get                           = 9
	GetAllAlarms                  = 11
	GetAllAlarmsNext              = 12
	MibUpload                     = 13
	MibUploadNext                 = 14
	MibReset                      = 15
	AlarmNotification             = 16
	AttributeValueChange          = 17
	Test                          = 18
	StartSoftwareDownload         = 19
	DownloadSection               = 20
	EndSoftwareDownload           = 21
	ActivateSoftware              = 22
	CommitSoftware                = 23
	SynchronizeTime               = 24
	Reboot                        = 25
	GetNext                       = 26
	TestResult                    = 27
	GetCurrentData                = 28
	SetTable                      = 29 // Defined in Extended Message Set Only
)

func (mt MsgType) String() string {
	switch mt {
	default:
		return "Unknown"
	case Create:
		return "Create"
	case Delete:
		return "Delete"
	case Set:
		return "Set"
	case Get:
		return "Get"
	case GetAllAlarms:
		return "Get All Alarms"
	case GetAllAlarmsNext:
		return "Get All Alarms Next"
	case MibUpload:
		return "MIB Upload"
	case MibUploadNext:
		return "MIB Upload Next"
	case MibReset:
		return "MIB Reset"
	case AlarmNotification:
		return "Alarm Notification"
	case AttributeValueChange:
		return "Attribute Value Change"
	case Test:
		return "Test"
	case StartSoftwareDownload:
		return "Start Software Download"
	case DownloadSection:
		return "Download Section"
	case EndSoftwareDownload:
		return "EndSoftware Download"
	case ActivateSoftware:
		return "Activate Software"
	case CommitSoftware:
		return "Commit Software"
	case SynchronizeTime:
		return "Synchronize Time"
	case Reboot:
		return "Reboot"
	case GetNext:
		return "Get Next"
	case TestResult:
		return "Test Result"
	case GetCurrentData:
		return "Get Current Data"
	case SetTable:
		return "Set Table"
	}
}

const (
	// Response status codes
	_                        = iota
	Success          Results = 0 // command processed successfully
	ProcessingError          = 1 // command processing error
	NotSupported             = 2 // command not supported
	ParameterError           = 3 // parameter error
	UnknownEntity            = 4 // unknown managed entity
	UnknownInstance          = 5 // unknown managed entity instance
	DeviceBusy               = 6 // device busy
	InstanceExists           = 7 // instance exists
	AttributeFailure         = 9 // Attribute(s) failed or unknown
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

func mkReqLayer(mt MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+int(mt)|int(AR),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func mkRespLayer(mt MsgType, mts string, decode gopacket.DecodeFunc) gopacket.LayerType {
	return gopacket.RegisterLayerType(1000+int(mt)|int(AK),
		gopacket.LayerTypeMetadata{Name: mts, Decoder: decode})
}

func init() {
	LayerTypeCreateRequest = mkReqLayer(Create, "CreateRequest", gopacket.DecodeFunc(decodeCreateRequest))
	LayerTypeDeleteRequest = mkReqLayer(Delete, "DeleteRequest", gopacket.DecodeFunc(decodeDeleteRequest))
	LayerTypeSetRequest = mkReqLayer(Set, "SetRequest", gopacket.DecodeFunc(decodeSetRequest))
	LayerTypeGetRequest = mkReqLayer(Get, "GetRequest", gopacket.DecodeFunc(decodeGetRequest))
	LayerTypeGetAllAlarmsRequest = mkReqLayer(GetAllAlarms, "GetAllAlarmsRequest", gopacket.DecodeFunc(decodeGetAllAlarmsRequest))
	LayerTypeGetAllAlarmsNextRequest = mkReqLayer(GetAllAlarmsNext, "GetAllAlarmsNextRequest", gopacket.DecodeFunc(decodeGetAllAlarmsNextRequest))
	LayerTypeMibUploadRequest = mkReqLayer(MibUpload, "MibUploadRequest", gopacket.DecodeFunc(decodeMibUploadRequest))
	LayerTypeMibUploadNextRequest = mkReqLayer(MibUploadNext, "MibUploadNextRequest", gopacket.DecodeFunc(decodeMibUploadNextRequest))
	LayerTypeMibResetRequest = mkReqLayer(MibReset, "MibResetRequest", gopacket.DecodeFunc(decodeMibResetRequest))
	LayerTypeTestRequest = mkReqLayer(Test, "TestRequest", gopacket.DecodeFunc(decodeTestRequest))
	LayerTypeStartSoftwareDownloadRequest = mkReqLayer(StartSoftwareDownload, "StartSoftwareDownloadRequest", gopacket.DecodeFunc(decodeStartSoftwareDownloadRequest))
	LayerTypeDownloadSectionRequest = mkReqLayer(DownloadSection, "DownloadSectionRequest", gopacket.DecodeFunc(decodeDownloadSectionRequest))
	LayerTypeEndSoftwareDownloadRequest = mkReqLayer(EndSoftwareDownload, "EndSoftwareDownloadRequest", gopacket.DecodeFunc(decodeEndSoftwareDownloadRequest))
	LayerTypeActivateSoftwareRequest = mkReqLayer(ActivateSoftware, "ActivateSoftwareRequest", gopacket.DecodeFunc(decodeActivateSoftwareRequest))
	LayerTypeCommitSoftwareRequest = mkReqLayer(CommitSoftware, "CommitSoftwareRequest", gopacket.DecodeFunc(decodeCommitSoftwareRequest))
	LayerTypeSynchronizeTimeRequest = mkReqLayer(SynchronizeTime, "SynchronizeTimeRequest", gopacket.DecodeFunc(decodeSynchronizeTimeRequest))
	LayerTypeRebootRequest = mkReqLayer(Reboot, "RebootRequest", gopacket.DecodeFunc(decodeRebootRequest))
	LayerTypeGetNextRequest = mkReqLayer(GetNext, "GetNextRequest", gopacket.DecodeFunc(decodeGetNextRequest))
	LayerTypeGetCurrentDataRequest = mkReqLayer(GetCurrentData, "GetCurrentDataRequest", gopacket.DecodeFunc(decodeGetCurrentDataRequest))
	LayerTypeSetTableRequest = mkReqLayer(SetTable, "SetTableRequest", gopacket.DecodeFunc(decodeSetTableRequest))

	LayerTypeCreateResponse = mkRespLayer(Create, "CreateResponse", gopacket.DecodeFunc(decodeCreateResponse))
	LayerTypeDeleteResponse = mkRespLayer(Delete, "DeleteResponse", gopacket.DecodeFunc(decodeDeleteResponse))
	LayerTypeSetResponse = mkRespLayer(Set, "SetResponse", gopacket.DecodeFunc(decodeSetResponse))
	LayerTypeGetResponse = mkRespLayer(Get, "GetResponse", gopacket.DecodeFunc(decodeGetResponse))
	LayerTypeGetAllAlarmsResponse = mkRespLayer(GetAllAlarms, "GetAllAlarmsResponse", gopacket.DecodeFunc(decodeGetAllAlarmsResponse))
	LayerTypeGetAllAlarmsNextResponse = mkRespLayer(GetAllAlarmsNext, "GetAllAlarmsNextResponse", gopacket.DecodeFunc(decodeGetAllAlarmsNextResponse))
	LayerTypeMibUploadResponse = mkRespLayer(MibUpload, "MibUploadResponse", gopacket.DecodeFunc(decodeMibUploadResponse))
	LayerTypeMibUploadNextResponse = mkRespLayer(MibUploadNext, "MibUploadNextResponse", gopacket.DecodeFunc(decodeMibUploadNextResponse))
	LayerTypeMibResetResponse = mkRespLayer(MibReset, "MibResetResponse", gopacket.DecodeFunc(decodeMibResetResponse))
	LayerTypeAlarmNotification = mkRespLayer(AlarmNotification, "AlarmNotification", gopacket.DecodeFunc(decodeAlarmNotification))
	LayerTypeAttributeValueChange = mkRespLayer(MibReset, "AttributeValueChange", gopacket.DecodeFunc(decodeAttributeValueChange))
	LayerTypeTestResponse = mkRespLayer(Test, "TestResponse", gopacket.DecodeFunc(decodeTestResponse))
	LayerTypeStartSoftwareDownloadResponse = mkRespLayer(StartSoftwareDownload, "StartSoftwareDownloadResponse", gopacket.DecodeFunc(decodeStartSoftwareDownloadResponse))
	LayerTypeDownloadSectionResponse = mkRespLayer(DownloadSection, "DownloadSectionResponse", gopacket.DecodeFunc(decodeDownloadSectionResponse))
	LayerTypeEndSoftwareDownloadResponse = mkRespLayer(EndSoftwareDownload, "EndSoftwareDownloadResponse", gopacket.DecodeFunc(decodeEndSoftwareDownloadResponse))
	LayerTypeActivateSoftwareResponse = mkRespLayer(ActivateSoftware, "ActivateSoftwareResponse", gopacket.DecodeFunc(decodeActivateSoftwareResponse))
	LayerTypeCommitSoftwareResponse = mkRespLayer(CommitSoftware, "CommitSoftwareResponse", gopacket.DecodeFunc(decodeCommitSoftwareResponse))
	LayerTypeSynchronizeTimeResponse = mkRespLayer(SynchronizeTime, "SynchronizeTimeResponse", gopacket.DecodeFunc(decodeSynchronizeTimeResponse))
	LayerTypeRebootResponse = mkRespLayer(Reboot, "RebootResponse", gopacket.DecodeFunc(decodeRebootResponse))
	LayerTypeGetNextResponse = mkRespLayer(GetNext, "GetNextResponse", gopacket.DecodeFunc(decodeGetNextResponse))
	LayerTypeTestResult = mkRespLayer(TestResult, "TestResult", gopacket.DecodeFunc(decodeTestResult))
	LayerTypeGetCurrentDataResponse = mkRespLayer(GetCurrentData, "GetCurrentDataResponse", gopacket.DecodeFunc(decodeGetCurrentDataResponse))
	LayerTypeSetTableResponse = mkRespLayer(SetTable, "SetTableResponse", gopacket.DecodeFunc(decodeSetTableResponse))

	nextLayerMapping = make(map[byte]gopacket.LayerType)

	nextLayerMapping[byte(Create)|AR] = LayerTypeCreateRequest
	nextLayerMapping[byte(Delete)|AR] = LayerTypeDeleteRequest
	nextLayerMapping[byte(Set)|AR] = LayerTypeSetRequest
	nextLayerMapping[byte(Get)|AR] = LayerTypeGetRequest
	nextLayerMapping[byte(GetAllAlarms)|AR] = LayerTypeGetAllAlarmsRequest
	nextLayerMapping[byte(GetAllAlarmsNext)|AR] = LayerTypeGetAllAlarmsNextRequest
	nextLayerMapping[byte(MibUpload)|AR] = LayerTypeMibUploadRequest
	nextLayerMapping[byte(MibUploadNext)|AR] = LayerTypeMibUploadNextRequest
	nextLayerMapping[byte(MibReset)|AR] = LayerTypeMibResetRequest
	nextLayerMapping[byte(Test)|AR] = LayerTypeTestRequest
	nextLayerMapping[byte(StartSoftwareDownload)|AR] = LayerTypeStartSoftwareDownloadRequest
	nextLayerMapping[byte(DownloadSection)|AR] = LayerTypeDownloadSectionRequest
	nextLayerMapping[byte(EndSoftwareDownload)|AR] = LayerTypeEndSoftwareDownloadRequest
	nextLayerMapping[byte(ActivateSoftware)|AR] = LayerTypeActivateSoftwareRequest
	nextLayerMapping[byte(CommitSoftware)|AR] = LayerTypeCommitSoftwareRequest
	nextLayerMapping[byte(SynchronizeTime)|AR] = LayerTypeSynchronizeTimeRequest
	nextLayerMapping[byte(Reboot)|AR] = LayerTypeRebootRequest
	nextLayerMapping[byte(GetNext)|AR] = LayerTypeGetNextRequest
	nextLayerMapping[byte(GetCurrentData)|AR] = LayerTypeGetCurrentDataRequest
	nextLayerMapping[byte(SetTable)|AR] = LayerTypeSetTableRequest

	nextLayerMapping[byte(Create)|AK] = LayerTypeCreateResponse
	nextLayerMapping[byte(Delete)|AK] = LayerTypeDeleteResponse
	nextLayerMapping[byte(Set)|AK] = LayerTypeSetResponse
	nextLayerMapping[byte(Get)|AK] = LayerTypeGetResponse
	nextLayerMapping[byte(GetAllAlarms)|AK] = LayerTypeGetAllAlarmsResponse
	nextLayerMapping[byte(GetAllAlarmsNext)|AK] = LayerTypeGetAllAlarmsNextResponse
	nextLayerMapping[byte(MibUpload)|AK] = LayerTypeMibUploadResponse
	nextLayerMapping[byte(MibUploadNext)|AK] = LayerTypeMibUploadNextResponse
	nextLayerMapping[byte(MibReset)|AK] = LayerTypeMibResetResponse
	nextLayerMapping[byte(Test)|AK] = LayerTypeTestResponse
	nextLayerMapping[byte(StartSoftwareDownload)|AK] = LayerTypeStartSoftwareDownloadResponse
	nextLayerMapping[byte(DownloadSection)|AK] = LayerTypeDownloadSectionResponse
	nextLayerMapping[byte(EndSoftwareDownload)|AK] = LayerTypeEndSoftwareDownloadResponse
	nextLayerMapping[byte(ActivateSoftware)|AK] = LayerTypeActivateSoftwareResponse
	nextLayerMapping[byte(CommitSoftware)|AK] = LayerTypeCommitSoftwareResponse
	nextLayerMapping[byte(SynchronizeTime)|AK] = LayerTypeSynchronizeTimeResponse
	nextLayerMapping[byte(Reboot)|AK] = LayerTypeRebootResponse
	nextLayerMapping[byte(GetNext)|AK] = LayerTypeGetNextResponse
	nextLayerMapping[byte(GetCurrentData)|AK] = LayerTypeGetCurrentDataResponse
	nextLayerMapping[byte(TestResult)|AK] = LayerTypeTestResult
	nextLayerMapping[byte(SetTable)|AK] = LayerTypeSetTableResponse
}

var allNotificationTypes = [...]MsgType{
	AlarmNotification,
	AttributeValueChange,
	TestResult,
}

func isAutonomousNotification(mt MsgType) bool {
	for _, m := range allNotificationTypes {
		if mt == m {
			return true
		}
	}
	return false
}

func (rc Results) String() string {
	switch rc {
	default:
		return "Unknown"
	case Success:
		return "Success"
	case ProcessingError:
		return "Processing Error"
	case NotSupported:
		return "Not Supported"
	case ParameterError:
		return "Parameter Error"
	case UnknownEntity:
		return "Unknown Entity"
	case UnknownInstance:
		return "Unknown Instance"
	case DeviceBusy:
		return "Device Busy"
	case InstanceExists:
		return "Instance Exists"
	case AttributeFailure:
		return "Attribute Failure"
	}
}

func MsgTypeToNextLayer(mt byte) (gopacket.LayerType, error) {
	nextLayer, ok := nextLayerMapping[mt]
	if ok {
		return nextLayer, nil
	}
	return gopacket.LayerTypeZero, errors.New("unknown message type")
}

/////////////////////////////////////////////////////////////////////////////
// CreateRequest
type CreateRequest struct {
	msgBase
	// TODO: implement
}

func (omci *CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.layerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// CreateResponse
type CreateResponse struct {
	msgBase
	// TODO: implement
}

func (omci *CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeCreateResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateResponse{}
	omci.layerType = LayerTypeCreateResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// DeleteRequest
type DeleteRequest struct {
	msgBase
	// TODO: implement
}

func (omci *DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeDeleteRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// DeleteResponse
type DeleteResponse struct {
	msgBase
	// TODO: implement
}

func (omci *DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeDeleteResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DeleteResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// SetRequest
type SetRequest struct {
	msgBase
	// TODO: implement
}

func (omci *SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// SetResponse
type SetResponse struct {
	msgBase
	// TODO: implement
}

func (omci *SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetRequest
type GetRequest struct {
	msgBase
	// TODO: implement
}

func (omci *GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetRequest{}
	omci.layerType = LayerTypeDeleteRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetResponse
type GetResponse struct {
	msgBase
	// TODO: implement
}

func (omci *GetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetResponse{}
	omci.layerType = LayerTypeDeleteResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsRequest struct {
	msgBase
	// TODO: implement
}

func (omci *GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetAllAlarmsRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsRequest{}
	omci.layerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsResponse struct {
	msgBase
	// TODO: implement
}

func (omci *GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetAllAlarmsResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsResponse{}
	omci.layerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextRequest struct {
	msgBase
	// TODO: implement
}

func (omci *GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetAllAlarmsNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextRequest{}
	omci.layerType = LayerTypeGetAllAlarmsRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// GetAllAlarms
type GetAllAlarmsNextResponse struct {
	msgBase
	// TODO: implement
}

func (omci *GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetAllAlarmsNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetAllAlarmsNextResponse{}
	omci.layerType = LayerTypeGetAllAlarmsResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadRequest
type MibUploadRequest struct {
	msgBase
	// TODO: implement
}

func (omci *MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeMibUploadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadRequest{}
	omci.layerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// MibUploadResponse
type MibUploadResponse struct {
	msgBase
	// TODO: implement
}

func (omci *MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeMibUploadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadResponse{}
	omci.layerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct {
	msgBase
	// TODO: implement
}

func (omci *MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeMibUploadNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextRequest{}
	omci.layerType = LayerTypeMibUploadNextRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextResponse struct {
	msgBase
	// TODO: implement
}

func (omci *MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeMibUploadNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibUploadNextResponse{}
	omci.layerType = LayerTypeMibUploadNextResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetRequest
type MibResetRequest struct {
	msgBase
}

func (omci *MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}

	// MIB Reset request Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset request")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset request")
	}
	return nil
}

func decodeMibResetRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetRequest{}
	omci.layerType = LayerTypeMibResetRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// MibResetResponse
type MibResetResponse struct {
	msgBase
}

func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}

	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeMibResetResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &MibResetResponse{}
	omci.layerType = LayerTypeMibResetResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
type AlarmNotificationMsg struct {
	msgBase
}

func (omci *AlarmNotificationMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}

	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeAlarmNotification(data []byte, p gopacket.PacketBuilder) error {
	omci := &AlarmNotificationMsg{}
	omci.layerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
// AlarmNotificationMsg
type AttributeValueChangeMsg struct {
	msgBase
}

func (omci *AttributeValueChangeMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}

	// MIB Reset Response Entity Class always ONU DATA (2) and
	// Entity Instance of 0
	if omci.EntityClass != 2 {
		return errors.New("invalid Entity Class for MIB Reset Response")
	}
	if omci.EntityInstance != 0 {
		return errors.New("invalid Entity Instance for MIB Reset Response")
	}
	return nil
}

func decodeAttributeValueChange(data []byte, p gopacket.PacketBuilder) error {
	omci := &AttributeValueChangeMsg{}
	omci.layerType = LayerTypeAlarmNotification
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct {
	msgBase
	// TODO: implement
}

func (omci *TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeTestRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestRequest{}
	omci.layerType = LayerTypeTestRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResponse struct {
	msgBase
	// TODO: implement
}

func (omci *TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeTestResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResponse{}
	omci.layerType = LayerTypeTestResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct {
	msgBase
	// TODO: implement
}

func (omci *StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeStartSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadRequest{}
	omci.layerType = LayerTypeStartSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadResponse struct {
	msgBase
	// TODO: implement
}

func (omci *StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeStartSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &StartSoftwareDownloadResponse{}
	omci.layerType = LayerTypeStartSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct {
	msgBase
	// TODO: implement
}

func (omci *DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeDownloadSectionRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionRequest{}
	omci.layerType = LayerTypeDownloadSectionRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionResponse struct {
	msgBase
	// TODO: implement
}

func (omci *DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeDownloadSectionResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &DownloadSectionResponse{}
	omci.layerType = LayerTypeDownloadSectionResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct {
	msgBase
	// TODO: implement
}

func (omci *EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeEndSoftwareDownloadRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadRequest{}
	omci.layerType = LayerTypeEndSoftwareDownloadRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadResponse struct {
	msgBase
	// TODO: implement
}

func (omci *EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeEndSoftwareDownloadResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &EndSoftwareDownloadResponse{}
	omci.layerType = LayerTypeEndSoftwareDownloadResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct {
	msgBase
	// TODO: implement
}

func (omci *ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeActivateSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareRequest{}
	omci.layerType = LayerTypeActivateSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareResponse struct {
	msgBase
	// TODO: implement
}

func (omci *ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeActivateSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &ActivateSoftwareResponse{}
	omci.layerType = LayerTypeActivateSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct {
	msgBase
	// TODO: implement
}

func (omci *CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeCommitSoftwareRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareRequest{}
	omci.layerType = LayerTypeCommitSoftwareRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareResponse struct {
	msgBase
	// TODO: implement
}

func (omci *CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeCommitSoftwareResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &CommitSoftwareResponse{}
	omci.layerType = LayerTypeCommitSoftwareResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct {
	msgBase
	// TODO: implement
}

func (omci *SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSynchronizeTimeRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeRequest{}
	omci.layerType = LayerTypeSynchronizeTimeRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeResponse struct {
	msgBase
	// TODO: implement
}

func (omci *SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSynchronizeTimeResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SynchronizeTimeResponse{}
	omci.layerType = LayerTypeSynchronizeTimeResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct {
	msgBase
}

func (omci *RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeRebootRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootRequest{}
	omci.layerType = LayerTypeRebootRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootResponse struct {
	msgBase
}

func (omci *RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeRebootResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &RebootResponse{}
	omci.layerType = LayerTypeRebootResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct {
	msgBase
	// TODO: implement
}

func (omci *GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetNextRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextRequest{}
	omci.layerType = LayerTypeGetNextRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextResponse struct {
	msgBase
	// TODO: implement
}

func (omci *GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetNextResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetNextResponse{}
	omci.layerType = LayerTypeGetNextResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResultMsg struct {
	msgBase
	// TODO: implement
}

func (omci *TestResultMsg) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeTestResult(data []byte, p gopacket.PacketBuilder) error {
	omci := &TestResultMsg{}
	omci.layerType = LayerTypeTestResult
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct {
	msgBase
	// TODO: implement
}

func (omci *GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetCurrentDataRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataRequest{}
	omci.layerType = LayerTypeGetCurrentDataRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataResponse struct {
	msgBase
	// TODO: implement
}

func (omci *GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeGetCurrentDataResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &GetCurrentDataResponse{}
	omci.layerType = LayerTypeGetCurrentDataResponse
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct {
	msgBase
	// TODO: implement
}

func (omci *SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSetTableRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableRequest{}
	omci.layerType = LayerTypeSetTableRequest
	return decodingLayerDecoder(omci, data, p)
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableResponse struct {
	msgBase
	// TODO: implement
}

func (omci *SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{data[:4], nil}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.layerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}
