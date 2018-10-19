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
	"github.com/google/gopacket"
)

type Decoder interface {
	// Name is the attribute name
	DecodeFromBytes([]byte, gopacket.PacketBuilder) error
}

type Encoder interface {
	// Name is the attribute name
	SerializeTo(gopacket.SerializeBuffer, gopacket.SerializeOptions) error
}

var msgTypeDecoderMapping map[byte]interface{}
var msgTypeEncoderMapping map[byte]interface{}

func init() {

	msgTypeDecoderMapping = make(map[byte]interface{})
	msgTypeDecoderMapping[byte(Create)|0x00] = CreateRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Create)|0x20] = CreateResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(Delete)|0x00] = DeleteRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Delete)|0x20] = DeleteResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(Set)|0x00] = SetRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Set)|0x20] = SetResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(Get)|0x00] = GetRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Get)|0x20] = GetResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(GetAllAlarms)|0x00] = GetAllAlarmsRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(GetAllAlarms)|0x20] = GetAllAlarmsResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(GetAllAlarmsNext)|0x00] = GetAllAlarmsNextRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(GetAllAlarmsNext)|0x20] = GetAllAlarmsNextResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(MibUpload)|0x00] = MibUploadRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(MibUpload)|0x20] = MibUploadResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(MibUploadNext)|0x00] = MibUploadNextRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(MibUploadNext)|0x20] = MibUploadNextResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(MibReset)|0x00] = MibResetRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(MibReset)|0x20] = MibResetResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(AlarmNotification)|0x00] = AlarmNotificationRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(AlarmNotification)|0x20] = AlarmNotificationResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(AttributeValueChange)|0x00] = AttributeValueChangeRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(AttributeValueChange)|0x20] = AttributeValueChangeResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(Test)|0x00] = TestRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Test)|0x20] = TestRequest.DecodeFromBytes

	msgTypeDecoderMapping[byte(StartSoftwareDownload)|0x00] = StartSoftwareDownloadRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(StartSoftwareDownload)|0x20] = StartSoftwareDownloadResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(DownloadSection)|0x00] = DownloadSectionRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(DownloadSection)|0x20] = DownloadSectionResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(EndSoftwareDownload)|0x00] = EndSoftwareDownloadRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(EndSoftwareDownload)|0x20] = EndSoftwareDownloadResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(ActivateSoftware)|0x00] = ActivateSoftwareRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(ActivateSoftware)|0x20] = ActivateSoftwareResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(CommitSoftware)|0x00] = CommitSoftwareRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(CommitSoftware)|0x20] = CommitSoftwareResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(SynchronizeTime)|0x00] = SynchronizeTimeRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(SynchronizeTime)|0x20] = SynchronizeTimeResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(Reboot)|0x00] = RebootRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(Reboot)|0x20] = RebootResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(GetNext)|0x00] = GetNextRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(GetNext)|0x20] = GetNextResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(TestResult)|0x00] = TestResultRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(TestResult)|0x20] = TestResultResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(GetCurrentData)|0x00] = GetCurrentDataRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(GetCurrentData)|0x20] = GetCurrentDataResponse.DecodeFromBytes

	msgTypeDecoderMapping[byte(SetTable)|0x00] = SetTableRequest.DecodeFromBytes
	msgTypeDecoderMapping[byte(SetTable)|0x20] = SetTableResponse.DecodeFromBytes

	/////////////////////////////////////////////////////////////////////////
	// Encoder mappings
	msgTypeEncoderMapping = make(map[byte]interface{})
	msgTypeEncoderMapping[byte(Create)|0x00] = CreateRequest.SerializeTo
	msgTypeEncoderMapping[byte(Create)|0x20] = CreateResponse.SerializeTo

	msgTypeEncoderMapping[byte(Delete)|0x00] = DeleteRequest.SerializeTo
	msgTypeEncoderMapping[byte(Delete)|0x20] = DeleteResponse.SerializeTo

	msgTypeEncoderMapping[byte(Set)|0x00] = SetRequest.SerializeTo
	msgTypeEncoderMapping[byte(Set)|0x20] = SetResponse.SerializeTo

	msgTypeEncoderMapping[byte(Get)|0x00] = GetRequest.SerializeTo
	msgTypeEncoderMapping[byte(Get)|0x20] = GetResponse.SerializeTo

	msgTypeEncoderMapping[byte(GetAllAlarms)|0x00] = GetAllAlarmsRequest.SerializeTo
	msgTypeEncoderMapping[byte(GetAllAlarms)|0x20] = GetAllAlarmsResponse.SerializeTo

	msgTypeEncoderMapping[byte(GetAllAlarmsNext)|0x00] = GetAllAlarmsNextRequest.SerializeTo
	msgTypeEncoderMapping[byte(GetAllAlarmsNext)|0x20] = GetAllAlarmsNextResponse.SerializeTo

	msgTypeEncoderMapping[byte(MibUpload)|0x00] = MibUploadRequest.SerializeTo
	msgTypeEncoderMapping[byte(MibUpload)|0x20] = MibUploadResponse.SerializeTo

	msgTypeEncoderMapping[byte(MibUploadNext)|0x00] = MibUploadNextRequest.SerializeTo
	msgTypeEncoderMapping[byte(MibUploadNext)|0x20] = MibUploadNextResponse.SerializeTo

	msgTypeEncoderMapping[byte(MibReset)|0x00] = MibResetRequest.SerializeTo
	msgTypeEncoderMapping[byte(MibReset)|0x20] = MibResetResponse.SerializeTo

	msgTypeEncoderMapping[byte(AlarmNotification)|0x00] = AlarmNotificationRequest.SerializeTo
	msgTypeEncoderMapping[byte(AlarmNotification)|0x20] = AlarmNotificationResponse.SerializeTo

	msgTypeEncoderMapping[byte(AttributeValueChange)|0x00] = AttributeValueChangeRequest.SerializeTo
	msgTypeEncoderMapping[byte(AttributeValueChange)|0x20] = AttributeValueChangeResponse.SerializeTo

	msgTypeEncoderMapping[byte(Test)|0x00] = TestRequest.SerializeTo
	msgTypeEncoderMapping[byte(Test)|0x20] = TestResponse.SerializeTo

	msgTypeEncoderMapping[byte(StartSoftwareDownload)|0x00] = StartSoftwareDownloadRequest.SerializeTo
	msgTypeEncoderMapping[byte(StartSoftwareDownload)|0x20] = StartSoftwareDownloadResponse.SerializeTo

	msgTypeEncoderMapping[byte(DownloadSection)|0x00] = DownloadSectionRequest.SerializeTo
	msgTypeEncoderMapping[byte(DownloadSection)|0x20] = DownloadSectionResponse.SerializeTo

	msgTypeEncoderMapping[byte(EndSoftwareDownload)|0x00] = EndSoftwareDownloadRequest.SerializeTo
	msgTypeEncoderMapping[byte(EndSoftwareDownload)|0x20] = EndSoftwareDownloadResponse.SerializeTo

	msgTypeEncoderMapping[byte(ActivateSoftware)|0x00] = ActivateSoftwareRequest.SerializeTo
	msgTypeEncoderMapping[byte(ActivateSoftware)|0x20] = ActivateSoftwareResponse.SerializeTo

	msgTypeEncoderMapping[byte(CommitSoftware)|0x00] = CommitSoftwareRequest.SerializeTo
	msgTypeEncoderMapping[byte(CommitSoftware)|0x20] = CommitSoftwareResponse.SerializeTo

	msgTypeEncoderMapping[byte(SynchronizeTime)|0x00] = SynchronizeTimeRequest.SerializeTo
	msgTypeEncoderMapping[byte(SynchronizeTime)|0x20] = SynchronizeTimeResponse.SerializeTo

	msgTypeEncoderMapping[byte(Reboot)|0x00] = RebootRequest.SerializeTo
	msgTypeEncoderMapping[byte(Reboot)|0x20] = RebootResponse.SerializeTo

	msgTypeEncoderMapping[byte(GetNext)|0x00] = GetNextRequest.SerializeTo
	msgTypeEncoderMapping[byte(GetNext)|0x20] = GetNextResponse.SerializeTo

	msgTypeEncoderMapping[byte(TestResult)|0x00] = TestResultRequest.SerializeTo
	msgTypeEncoderMapping[byte(TestResult)|0x20] = TestResultResponse.SerializeTo

	msgTypeEncoderMapping[byte(GetCurrentData)|0x00] = GetCurrentDataRequest.SerializeTo
	msgTypeEncoderMapping[byte(GetCurrentData)|0x20] = GetCurrentDataResponse.SerializeTo

	msgTypeEncoderMapping[byte(SetTable)|0x00] = SetTableRequest.SerializeTo
	msgTypeEncoderMapping[byte(SetTable)|0x20] = SetTableResponse.SerializeTo
}

type Results byte

// MsgType represents a OMCI message-type
type MsgType byte

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
		return "Attribute  Failure"
	}
}

/////////////////////////////////////////////////////////////////////////////
//
func MsgTypeToStructDecoder(mt byte) (Decoder, error) {
	decoder, ok := msgTypeDecoderMapping[mt]
	if ok {
		return decoder.(Decoder), nil
	}
	return nil, errors.New("unknown message type")
}

func MsgTypeToStructEncoder(mt byte) (Encoder, error) {
	encoder, ok := msgTypeEncoderMapping[mt]
	if ok {
		return encoder.(Encoder), nil
	}
	return nil, errors.New("unknown message type")
}

/////////////////////////////////////////////////////////////////////////////
//
type CreateRequest struct {
	// Attributes for a create are the set-by-create values for the ME in the
	// order that they are defined for the ME
	Attributes []Attribute
	padding    []byte
}

func (msg CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CreateResponse struct {
	Results                      byte
	ParameterErrorAttributesMask uint16
	padding                      []byte
}

func (msg CreateResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CreateResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DeleteRequest struct{ Dummy byte }

func (msg DeleteRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg DeleteRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DeleteResponse struct{ Dummy byte }

func (msg DeleteResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg DeleteResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetRequest struct{ Dummy byte }

func (msg SetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg SetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetResponse struct{ Dummy byte }

func (msg SetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg SetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetRequest struct{ Dummy byte }

func (msg GetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetResponse struct{ Dummy byte }

func (msg GetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsRequest struct{ Dummy byte }

func (msg GetAllAlarmsRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetAllAlarmsRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsResponse struct{ Dummy byte }

func (msg GetAllAlarmsResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetAllAlarmsResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsNextRequest struct{ Dummy byte }

func (msg GetAllAlarmsNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetAllAlarmsNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsNextResponse struct{ Dummy byte }

func (msg GetAllAlarmsNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg GetAllAlarmsNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadRequest struct{ Dummy byte }

func (msg MibUploadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg MibUploadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadResponse struct{ Dummy byte }

func (msg MibUploadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg MibUploadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct{ Dummy byte }

func (msg MibUploadNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg MibUploadNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadNextResponse struct{ Dummy byte }

func (msg MibUploadNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func (msg MibUploadNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibResetRequest struct {
	padding []byte
}

func (msg MibResetRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibResetResponse struct {
	padding []byte
}

func (msg MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg MibResetResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type AlarmNotificationRequest struct{ Dummy byte }

func (msg AlarmNotificationRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg AlarmNotificationRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type AlarmNotificationResponse struct{ Dummy byte }

func (msg AlarmNotificationResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg AlarmNotificationResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type AttributeValueChangeRequest struct{ Dummy byte }

func (msg AttributeValueChangeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg AttributeValueChangeRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type AttributeValueChangeResponse struct{ Dummy byte }

func (msg AttributeValueChangeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg AttributeValueChangeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct{ Dummy byte }

func (msg TestRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg TestRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type TestResponse struct{ Dummy byte }

func (msg TestResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg TestResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct{ Dummy byte }

func (msg StartSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg StartSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type StartSoftwareDownloadResponse struct{ Dummy byte }

func (msg StartSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg StartSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct{ Dummy byte }

func (msg DownloadSectionRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg DownloadSectionRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DownloadSectionResponse struct{ Dummy byte }

func (msg DownloadSectionResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg DownloadSectionResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct{ Dummy byte }

func (msg EndSoftwareDownloadRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg EndSoftwareDownloadRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type EndSoftwareDownloadResponse struct{ Dummy byte }

func (msg EndSoftwareDownloadResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg EndSoftwareDownloadResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct{ Dummy byte }

func (msg ActivateSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg ActivateSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type ActivateSoftwareResponse struct{ Dummy byte }

func (msg ActivateSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg ActivateSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct{ Dummy byte }

func (msg CommitSoftwareRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CommitSoftwareRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CommitSoftwareResponse struct{ Dummy byte }

func (msg CommitSoftwareResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg CommitSoftwareResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct{ Dummy byte }

func (msg SynchronizeTimeRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg SynchronizeTimeRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SynchronizeTimeResponse struct{ Dummy byte }

func (msg SynchronizeTimeResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg SynchronizeTimeResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct{ Dummy byte }

func (msg RebootRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg RebootRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type RebootResponse struct{ Dummy byte }

func (msg RebootResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg RebootResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct{ Dummy byte }

func (msg GetNextRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg GetNextRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetNextResponse struct{ Dummy byte }

func (msg GetNextResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg GetNextResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResultRequest struct{ Dummy byte }

func (msg TestResultRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg TestResultRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type TestResultResponse struct{ Dummy byte }

func (msg TestResultResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg TestResultResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct{ Dummy byte }

func (msg GetCurrentDataRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg GetCurrentDataRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetCurrentDataResponse struct{ Dummy byte }

func (msg GetCurrentDataResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg GetCurrentDataResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct{ Dummy byte }

func (msg SetTableRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg SetTableRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetTableResponse struct{ Dummy byte }

func (msg SetTableResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func (msg SetTableResponse) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}
