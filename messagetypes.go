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

type Encoder interface {
	// Name is the attribute name
	SerializeTo(gopacket.SerializeBuffer, gopacket.SerializeOptions) error
}

// EncodeFunc wraps a function to make it a Encoder.
type EncodeFunc func(gopacket.SerializeBuffer, gopacket.SerializeOptions) error

var msgTypeDecoderMapping map[byte]gopacket.DecodeFunc
var msgTypeEncoderMapping map[byte]EncodeFunc

func init() {
	/////////////////////////////////////////////////////////////////////////
	// Decoder mappings
	msgTypeDecoderMapping = make(map[byte]gopacket.DecodeFunc)
	msgTypeDecoderMapping[byte(Create)|0x00] = gopacket.DecodeFunc(CreateRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Create)|0x20] = gopacket.DecodeFunc(CreateResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(Delete)|0x00] = gopacket.DecodeFunc(DeleteRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Delete)|0x20] = gopacket.DecodeFunc(DeleteResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(Set)|0x00] = gopacket.DecodeFunc(SetRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Set)|0x20] = gopacket.DecodeFunc(SetResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(Get)|0x00] = gopacket.DecodeFunc(GetRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Get)|0x20] = gopacket.DecodeFunc(GetResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(GetAllAlarms)|0x00] = gopacket.DecodeFunc(GetAllAlarmsRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(GetAllAlarms)|0x20] = gopacket.DecodeFunc(GetAllAlarmsResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(GetAllAlarmsNext)|0x00] = gopacket.DecodeFunc(GetAllAlarmsNextRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(GetAllAlarmsNext)|0x20] = gopacket.DecodeFunc(GetAllAlarmsNextResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(MibUpload)|0x00] = gopacket.DecodeFunc(MibUploadRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(MibUpload)|0x20] = gopacket.DecodeFunc(MibUploadResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(MibUploadNext)|0x00] = gopacket.DecodeFunc(MibUploadNextRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(MibUploadNext)|0x20] = gopacket.DecodeFunc(MibUploadNextResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(MibReset)|0x00] = gopacket.DecodeFunc(MibResetRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(MibReset)|0x20] = gopacket.DecodeFunc(MibResetResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(Test)|0x00] = gopacket.DecodeFunc(TestRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Test)|0x20] = gopacket.DecodeFunc(TestRequestDecodeFromBytes)

	msgTypeDecoderMapping[byte(StartSoftwareDownload)|0x00] = gopacket.DecodeFunc(StartSoftwareDownloadRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(StartSoftwareDownload)|0x20] = gopacket.DecodeFunc(StartSoftwareDownloadResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(DownloadSection)|0x00] = gopacket.DecodeFunc(DownloadSectionRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(DownloadSection)|0x20] = gopacket.DecodeFunc(DownloadSectionResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(EndSoftwareDownload)|0x00] = gopacket.DecodeFunc(EndSoftwareDownloadRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(EndSoftwareDownload)|0x20] = gopacket.DecodeFunc(EndSoftwareDownloadResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(ActivateSoftware)|0x00] = gopacket.DecodeFunc(ActivateSoftwareRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(ActivateSoftware)|0x20] = gopacket.DecodeFunc(ActivateSoftwareResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(CommitSoftware)|0x00] = gopacket.DecodeFunc(CommitSoftwareRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(CommitSoftware)|0x20] = gopacket.DecodeFunc(CommitSoftwareResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(SynchronizeTime)|0x00] = gopacket.DecodeFunc(SynchronizeTimeRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(SynchronizeTime)|0x20] = gopacket.DecodeFunc(SynchronizeTimeResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(Reboot)|0x00] = gopacket.DecodeFunc(RebootRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(Reboot)|0x20] = gopacket.DecodeFunc(RebootResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(GetNext)|0x00] = gopacket.DecodeFunc(GetNextRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(GetNext)|0x20] = gopacket.DecodeFunc(GetNextResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(GetCurrentData)|0x00] = gopacket.DecodeFunc(GetCurrentDataRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(GetCurrentData)|0x20] = gopacket.DecodeFunc(GetCurrentDataResponseDecodeFromBytes)

	msgTypeDecoderMapping[byte(SetTable)|0x00] = gopacket.DecodeFunc(SetTableRequestDecodeFromBytes)
	msgTypeDecoderMapping[byte(SetTable)|0x20] = gopacket.DecodeFunc(SetTableResponseDecodeFromBytes)

	// Autonomous notifications
	msgTypeDecoderMapping[byte(AlarmNotification)|0x20] = gopacket.DecodeFunc(AlarmNotificationMsgDecodeFromBytes)
	msgTypeDecoderMapping[byte(AttributeValueChange)|0x20] = gopacket.DecodeFunc(AttributeValueChangeMsgDecodeFromBytes)
	msgTypeDecoderMapping[byte(TestResult)|0x20] = gopacket.DecodeFunc(TestResultMsgDecodeFromBytes)

	////////////////////////////////////////////////////////////////////////
	// Encoder mappings
	msgTypeEncoderMapping = make(map[byte]EncodeFunc)

	msgTypeEncoderMapping[byte(Create)|0x00] = EncodeFunc(CreateRequestSerializeTo)
	msgTypeEncoderMapping[byte(Create)|0x20] = EncodeFunc(CreateResponseSerializeTo)

	msgTypeEncoderMapping[byte(Delete)|0x00] = EncodeFunc(DeleteRequestSerializeTo)
	msgTypeEncoderMapping[byte(Delete)|0x20] = EncodeFunc(DeleteResponseSerializeTo)

	msgTypeEncoderMapping[byte(Set)|0x00] = EncodeFunc(SetRequestSerializeTo)
	msgTypeEncoderMapping[byte(Set)|0x20] = EncodeFunc(SetResponseSerializeTo)

	msgTypeEncoderMapping[byte(Get)|0x00] = EncodeFunc(GetRequestSerializeTo)
	msgTypeEncoderMapping[byte(Get)|0x20] = EncodeFunc(GetResponseSerializeTo)

	msgTypeEncoderMapping[byte(GetAllAlarms)|0x00] = EncodeFunc(GetAllAlarmsRequestSerializeTo)
	msgTypeEncoderMapping[byte(GetAllAlarms)|0x20] = EncodeFunc(GetAllAlarmsResponseSerializeTo)

	msgTypeEncoderMapping[byte(GetAllAlarmsNext)|0x00] = EncodeFunc(GetAllAlarmsNextRequestSerializeTo)
	msgTypeEncoderMapping[byte(GetAllAlarmsNext)|0x20] = EncodeFunc(GetAllAlarmsNextResponseSerializeTo)

	msgTypeEncoderMapping[byte(MibUpload)|0x00] = EncodeFunc(MibUploadRequestSerializeTo)
	msgTypeEncoderMapping[byte(MibUpload)|0x20] = EncodeFunc(MibUploadResponseSerializeTo)

	msgTypeEncoderMapping[byte(MibUploadNext)|0x00] = EncodeFunc(MibUploadNextRequestSerializeTo)
	msgTypeEncoderMapping[byte(MibUploadNext)|0x20] = EncodeFunc(MibUploadNextResponseSerializeTo)

	msgTypeEncoderMapping[byte(MibReset)|0x00] = EncodeFunc(MibResetRequestSerializeTo)
	msgTypeEncoderMapping[byte(MibReset)|0x20] = EncodeFunc(MibResetResponseSerializeTo)

	msgTypeEncoderMapping[byte(Test)|0x00] = EncodeFunc(TestRequestSerializeTo)
	msgTypeEncoderMapping[byte(Test)|0x20] = EncodeFunc(TestResponseSerializeTo)

	msgTypeEncoderMapping[byte(StartSoftwareDownload)|0x00] = EncodeFunc(StartSoftwareDownloadRequestSerializeTo)
	msgTypeEncoderMapping[byte(StartSoftwareDownload)|0x20] = EncodeFunc(StartSoftwareDownloadResponseSerializeTo)

	msgTypeEncoderMapping[byte(DownloadSection)|0x00] = EncodeFunc(DownloadSectionRequestSerializeTo)
	msgTypeEncoderMapping[byte(DownloadSection)|0x20] = EncodeFunc(DownloadSectionResponseSerializeTo)

	msgTypeEncoderMapping[byte(EndSoftwareDownload)|0x00] = EncodeFunc(EndSoftwareDownloadRequestSerializeTo)
	msgTypeEncoderMapping[byte(EndSoftwareDownload)|0x20] = EncodeFunc(EndSoftwareDownloadResponseSerializeTo)

	msgTypeEncoderMapping[byte(ActivateSoftware)|0x00] = EncodeFunc(ActivateSoftwareRequestSerializeTo)
	msgTypeEncoderMapping[byte(ActivateSoftware)|0x20] = EncodeFunc(ActivateSoftwareResponseSerializeTo)

	msgTypeEncoderMapping[byte(CommitSoftware)|0x00] = EncodeFunc(CommitSoftwareRequestSerializeTo)
	msgTypeEncoderMapping[byte(CommitSoftware)|0x20] = EncodeFunc(CommitSoftwareResponseSerializeTo)

	msgTypeEncoderMapping[byte(SynchronizeTime)|0x00] = EncodeFunc(SynchronizeTimeRequestSerializeTo)
	msgTypeEncoderMapping[byte(SynchronizeTime)|0x20] = EncodeFunc(SynchronizeTimeResponseSerializeTo)

	msgTypeEncoderMapping[byte(Reboot)|0x00] = EncodeFunc(RebootRequestSerializeTo)
	msgTypeEncoderMapping[byte(Reboot)|0x20] = EncodeFunc(RebootResponseSerializeTo)

	msgTypeEncoderMapping[byte(GetNext)|0x00] = EncodeFunc(GetNextRequestSerializeTo)
	msgTypeEncoderMapping[byte(GetNext)|0x20] = EncodeFunc(GetNextResponseSerializeTo)

	msgTypeEncoderMapping[byte(GetCurrentData)|0x00] = EncodeFunc(GetCurrentDataRequestSerializeTo)
	msgTypeEncoderMapping[byte(GetCurrentData)|0x20] = EncodeFunc(GetCurrentDataResponseSerializeTo)

	msgTypeEncoderMapping[byte(SetTable)|0x00] = EncodeFunc(SetTableRequestSerializeTo)
	msgTypeEncoderMapping[byte(SetTable)|0x20] = EncodeFunc(SetTableResponseSerializeTo)

	// Autonomous notifications
	msgTypeEncoderMapping[byte(AlarmNotification)|0x20] = EncodeFunc(AlarmNotificationMsgSerializeTo)
	msgTypeEncoderMapping[byte(AttributeValueChange)|0x20] = EncodeFunc(AttributeValueChangeMsgSerializeTo)
	msgTypeEncoderMapping[byte(TestResult)|0x20] = EncodeFunc(TestResultMsgSerializeTo)
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
		return "Attribute Failure"
	}
}

/////////////////////////////////////////////////////////////////////////////
//
func MsgTypeToStructDecoder(mt byte) (gopacket.DecodeFunc, error) {
	decoder, ok := msgTypeDecoderMapping[mt]
	if ok {
		return decoder, nil
	}
	return nil, errors.New("unknown message type")
}

func MsgTypeToStructEncoder(mt byte) (interface{}, error) {
	encoder, ok := msgTypeEncoderMapping[mt]
	if ok {
		return encoder, nil
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

func CreateRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CreateRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CreateResponse struct {
	Results                      byte
	ParameterErrorAttributesMask uint16
	padding                      []byte
}

func CreateResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CreateResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DeleteRequest struct{ Dummy byte }

func DeleteRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func DeleteRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DeleteResponse struct{ Dummy byte }

func DeleteResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func DeleteResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetRequest struct{ Dummy byte }

func SetRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func SetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetResponse struct{ Dummy byte }

func SetResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func SetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetRequest struct{ Dummy byte }

func GetRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetResponse struct{ Dummy byte }

func GetResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsRequest struct{ Dummy byte }

func GetAllAlarmsRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsResponse struct{ Dummy byte }

func GetAllAlarmsResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetAllAlarmsNextRequest struct{ Dummy byte }

func GetAllAlarmsNextRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetAllAlarmsNextResponse struct{ Dummy byte }

func GetAllAlarmsNextResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func GetAllAlarmsNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadRequest struct{ Dummy byte }

func MibUploadRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadResponse struct{ Dummy byte }

func MibUploadResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibUploadNextRequest struct{ Dummy byte }

func MibUploadNextRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibUploadNextResponse struct{ Dummy byte }

func MibUploadNextResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}
func MibUploadNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type MibResetRequest struct {
	padding []byte
}

func MibResetRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func MibResetRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type MibResetResponse struct {
	padding []byte
}

func MibResetResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func MibResetResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//

type AlarmNotificationMsg struct{ Dummy byte }

func AlarmNotificationMsgDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func AlarmNotificationMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//

type AttributeValueChangeMsg struct{ Dummy byte }

func AttributeValueChangeMsgDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func AttributeValueChangeMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestRequest struct{ Dummy byte }

func TestRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type TestResponse struct{ Dummy byte }

func TestResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type StartSoftwareDownloadRequest struct{ Dummy byte }

func StartSoftwareDownloadRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func StartSoftwareDownloadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type StartSoftwareDownloadResponse struct{ Dummy byte }

func StartSoftwareDownloadResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func StartSoftwareDownloadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type DownloadSectionRequest struct{ Dummy byte }

func DownloadSectionRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func DownloadSectionRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type DownloadSectionResponse struct{ Dummy byte }

func DownloadSectionResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func DownloadSectionResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type EndSoftwareDownloadRequest struct{ Dummy byte }

func EndSoftwareDownloadRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func EndSoftwareDownloadRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type EndSoftwareDownloadResponse struct{ Dummy byte }

func EndSoftwareDownloadResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func EndSoftwareDownloadResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type ActivateSoftwareRequest struct{ Dummy byte }

func ActivateSoftwareRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func ActivateSoftwareRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type ActivateSoftwareResponse struct{ Dummy byte }

func ActivateSoftwareResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func ActivateSoftwareResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type CommitSoftwareRequest struct{ Dummy byte }

func CommitSoftwareRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CommitSoftwareRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type CommitSoftwareResponse struct{ Dummy byte }

func CommitSoftwareResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func CommitSoftwareResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SynchronizeTimeRequest struct{ Dummy byte }

func SynchronizeTimeRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SynchronizeTimeRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SynchronizeTimeResponse struct{ Dummy byte }

func SynchronizeTimeResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SynchronizeTimeResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type RebootRequest struct{ Dummy byte }

func RebootRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func RebootRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type RebootResponse struct{ Dummy byte }

func RebootResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func RebootResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetNextRequest struct{ Dummy byte }

func GetNextRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetNextRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetNextResponse struct{ Dummy byte }

func GetNextResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetNextResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type TestResultMsg struct{ Dummy byte }

func TestResultMsgDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func TestResultMsgSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type GetCurrentDataRequest struct{ Dummy byte }

func GetCurrentDataRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetCurrentDataRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type GetCurrentDataResponse struct{ Dummy byte }

func GetCurrentDataResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func GetCurrentDataResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

/////////////////////////////////////////////////////////////////////////////
//
type SetTableRequest struct{ Dummy byte }

func SetTableRequestDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SetTableRequestSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}

type SetTableResponse struct{ Dummy byte }

func SetTableResponseDecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	return errors.New("TODO: Not yet implemented")
}

func SetTableResponseSerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Not yet implemented")
}
