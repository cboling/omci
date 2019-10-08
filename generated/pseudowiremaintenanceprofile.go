/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */

package generated

import "github.com/deckarep/golang-set"

// PseudowireMaintenanceProfileClassId is the 16-bit ID for the OMCI
// Managed entity Pseudowire maintenance profile
const PseudowireMaintenanceProfileClassId ClassID = ClassID(284)

var pseudowiremaintenanceprofileBME *ManagedEntityDefinition

// PseudowireMaintenanceProfile (class ID #284)
//	The pseudowire maintenance profile permits the configuration of pseudowire service exception
//	handling. It is created and deleted by the OLT.
//
//	The settings, and indeed existence, of a pseudowire maintenance profile affect the behaviour of
//	the pseudowire PM history data ME only in establishing criteria for counting SESs, but in no
//	other way. The pseudowire maintenance profile primarily affects the alarms declared by the
//	subscribing pseudowire TP.
//
//	Relationships
//		One or more instances of the pseudowire TP may point to an instance of the pseudowire
//		maintenance profile. If the pseudowire TP does not refer to a pseudowire maintenance profile,
//		the ONU's default exception handling is implied.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The value 0 is
//			reserved. (R, setbycreate) (mandatory) (2-bytes)
//
//		Jitter Buffer Maximum Depth
//			Jitter buffer maximum depth: This attribute specifies the desired maximum depth of the playout
//			buffer in the PSN to the TDM direction. The value is expressed as a multiple of the 125-vs frame
//			rate. The default value 0 selects the ONU's internal policy. (R,-W, setbycreate) (optional)
//			(2-bytes)
//
//		Jitter Buffer Desired Depth
//			Jitter buffer desired depth: This attribute specifies the desired nominal fill depth of the
//			playout buffer in the PSN to the TDM direction. The value is expressed as a multiple of the
//			125-vs frame rate. The default value 0 selects the ONU's internal policy. (R,-W, setbycreate)
//			(optional) (2-bytes)
//
//		Fill Policy
//			(R,-W, setbycreate) (optional) (1-byte)
//
//		Misconnected Packets Declaration Policy
//			Misconnected packets declaration policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Misconnected Packets Clear Policy
//			Misconnected packets clear policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Loss Of Packets Declaration Policy
//			Loss of packets declaration policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Loss Of Packets Clear Policy
//			Loss of packets clear policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Buffer Overrun_Underrun Declaration Policy
//			Buffer overrun/underrun declaration policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Buffer Overrun_Underrun Clear Policy
//			Buffer overrun/underrun clear policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Malformed Packets Declaration Policy
//			Malformed packets declaration policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		Malformed Packets Clear Policy
//			Malformed packets clear policy: (R,-W, setbycreate) (optional) (1-byte)
//
//		R_Bit Transmit Set Policy
//			R-bit transmit set policy: This attribute defines the number of consecutive lost packets that
//			causes the transmitted R bit to be set in the TDM to the PSN direction, indicating lost packets
//			to the far end. The default value 0 selects the ONU's internal policy. (R,-W, setbycreate)
//			(optional) (1-byte)
//
//		R_Bit Transmit Clear Policy
//			R-bit transmit clear policy: This attribute defines the number of consecutive valid packets that
//			causes the transmitted R bit to be cleared in the TDM to the PSN direction, removing the remote
//			failure indication to the far end. The default value 0 selects the ONU's internal policy. (R,-W,
//			setbycreate) (optional) (1-byte)
//
//		R_Bit Receive Policy
//			(R,-W, setbycreate) (optional) (1-byte)
//
//		L Bit Receive Policy
//			(R,-W, setbycreate) (optional) (1-byte)
//
//		Ses Threshold
//			SES threshold: Number of lost, malformed or otherwise unusable packets expected in the PSN to
//			the TDM direction within a 1-s interval that causes an SES to be counted. Stray packets do not
//			count towards an SES, nor do packets whose L bit is set at the far end. The value 0 specifies
//			that the ONU uses its internal default, which is not necessarily the same as the recommended
//			default value 3. (R, W, set-by-create) (optional) (2 bytes)
//
type PseudowireMaintenanceProfile struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	pseudowiremaintenanceprofileBME = &ManagedEntityDefinition{
		Name:    "PseudowireMaintenanceProfile",
		ClassID: 284,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  Uint16Field("JitterBufferMaximumDepth", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 1),
			2:  Uint16Field("JitterBufferDesiredDepth", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 2),
			3:  ByteField("FillPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 3),
			4:  ByteField("MisconnectedPacketsDeclarationPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 4),
			5:  ByteField("MisconnectedPacketsClearPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 5),
			6:  ByteField("LossOfPacketsDeclarationPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 6),
			7:  ByteField("LossOfPacketsClearPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 7),
			8:  ByteField("BufferOverrunUnderrunDeclarationPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 8),
			9:  ByteField("BufferOverrunUnderrunClearPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 9),
			10: ByteField("MalformedPacketsDeclarationPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 10),
			11: ByteField("MalformedPacketsClearPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 11),
			12: ByteField("RBitTransmitSetPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 12),
			13: ByteField("RBitTransmitClearPolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 13),
			14: ByteField("RBitReceivePolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 14),
			15: ByteField("LBitReceivePolicy", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 15),
			16: Uint16Field("SesThreshold", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, true, false, 16),
		},
	}
}

// NewPseudowireMaintenanceProfile (class ID 284 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPseudowireMaintenanceProfile(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*pseudowiremaintenanceprofileBME, params...)
}
