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

/////////////////////////////////////////////////////////////////////////////
// CreateRequest
type CreateRequest struct {
	msgBase
	Attributes []IAttribute // Set-by-create attributes

	// Cache any ME decoded from the request  (TODO: Should be public?)
	cachedME IManagedEntity
}

func (omci *CreateRequest) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4], Payload: data[4:]}

	// Create attribute mask for all set-by-create entries
	var err error
	omci.cachedME, err = LoadManagedEntityDefinition(omci.EntityClass, omci.EntityInstance)
	if err != nil {
		return err
	}
	// ME needs to support Create
	if !SupportsMsgType(omci.cachedME, Create) {
		return errors.New("managed entity does not support Create Message-Type")
	}
	var sbcMask uint16
	for index, attr := range omci.cachedME.Attributes() {
		if SupportsAttributeAccess(attr, SetByCreate) {
			sbcMask |= 1 << (15 - uint(index))
		}
	}
	// Attribute decode
	err = omci.cachedME.Decode(sbcMask, data[4:], p)
	if err != nil {
		return err
	}
	omci.Attributes = omci.cachedME.Attributes()
	return nil
}

func decodeCreateRequest(data []byte, p gopacket.PacketBuilder) error {
	omci := &CreateRequest{}
	omci.layerType = LayerTypeCreateRequest
	return decodingLayerDecoder(omci, data, p)
}

func (omci *CreateRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return errors.New("TODO: Implement me")
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}

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

func (omci *MibResetRequest) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	length := MaxBaselineLength - 8 - 4 - 4
	if opts.FixLengths {
		length += 4

		if opts.ComputeChecksums {
			length += 4
		}
	}
	padding, err := b.AppendBytes(MaxBaselineLength - 8)
	if err != nil {
		return err
	}
	copy(padding, lotsOfZeros[:])

	//encoder, err := MsgTypeToStructEncoder(omci.MessageType)
	//if err != nil {
	//	return err
	//}
	// Serialize the message type part
	//err = encoder.SerializeTo(b, opts)
	// TODO: Implement serialization

	if opts.FixLengths {
		buffer := b.Bytes()
		binary.BigEndian.PutUint32(buffer[MaxBaselineLength-8:], 40)

		if opts.ComputeChecksums {
			// TODO: Calculate MIC
			buffer := b.Bytes()
			mic := calculateMic(buffer[length-4:])
			binary.BigEndian.PutUint32(buffer[length-4:], mic)
		}
	}
	return nil
}

/////////////////////////////////////////////////////////////////////////////
// MibResetResponse
type MibResetResponse struct {
	msgBase
}

func (omci *MibResetResponse) DecodeFromBytes(data []byte, p gopacket.PacketBuilder) error {
	omci.EntityClass = binary.BigEndian.Uint16(data[0:])
	omci.EntityInstance = binary.BigEndian.Uint16(data[2:])
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}

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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}

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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}

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
	omci.layerType = LayerTypeAttributeValueChange
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
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
	omci.BaseLayer = layers.BaseLayer{Contents: data[:4]}
	return errors.New("TODO: Need to implement") // return nil
}
func decodeSetTableResponse(data []byte, p gopacket.PacketBuilder) error {
	omci := &SetTableResponse{}
	omci.layerType = LayerTypeSetTableResponse
	return decodingLayerDecoder(omci, data, p)
}
