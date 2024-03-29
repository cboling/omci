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
 */
/*
 * NOTE: This file was generated, manual edits will be overwritten!
 *
 * Generated by 'goCodeGenerator.py':
 *              https://github.com/cboling/OMCI-parser/README.md
 */

package generated

import "github.com/deckarep/golang-set"

// PwAtmConfigurationDataClassID is the 16-bit ID for the OMCI
// Managed entity PW ATM configuration data
const PwAtmConfigurationDataClassID = ClassID(337) // 0x0151

var pwatmconfigurationdataBME *ManagedEntityDefinition

// PwAtmConfigurationData (Class ID: #337 / 0x0151)
//	This ME contains generic configuration data for an ATM pseudowire. Definitions of attributes are
//	from PW-ATM-MIB [IETF RFC 5605]. Instances of this ME are created and deleted by the OLT.
//
//	Relationships
//		An instance of this ME is associated with an instance of the MPLS pseudowire TP ME with a
//		pseudowire type attribute equal to one of the following.////		2	ATM AAL5 SDU VCC transport////		3	ATM transparent cell transport////		9	ATM n-to-one VCC cell transport////		10	ATM n-to-one VPC cell transport////		12	ATM one-to-one VCC cell mode////		13	ATM one-to-one VPC cell mode////		14	ATM AAL5 PDU VCC transport////		Alternatively, an instance of this ME may be associated with an Ethernet flow TP or a TCP/UDP
//		config data ME, depending on the transport layer of the pseudowire.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. (R, setbycreate)-(mandatory) (2
//			bytes)
//
//		Tp Type
//			This attribute specifies the type of the underlying transport layer. (R, W, setbycreate)
//			(mandatory) (1 byte)
//
//			0	MPLS pseudowire termination point
//
//			1	Ethernet flow termination point
//
//			2	TCP/UDP config data
//
//		Transport Tp Pointer
//			This attribute points to an associated instance of the transport layer TP, whose type is
//			specified by the TP type attribute. (R, W, setbycreate) (mandatory) (2 bytes)
//
//		Pptp Atm Uni Pointer
//			This attribute points to an associated instance of the ITU-T G.983.2 PPTP ATM UNI. Refer to
//			[ITUT G.983.2] for the definition of the target ME. (R, W, setbycreate) (mandatory) (2 bytes)
//
//		Max C Ell C Oncatenation
//			Max cell concatenation: This attribute specifies the maximum number of ATM cells that can be
//			concatenated into one PW packet in the upstream direction. (R, W, setbycreate) (mandatory) (2
//			bytes)
//
//		Far End M Ax C Ell C Oncatenation
//			Far-end max cell concatenation: This attribute specifies the maximum number of ATM cells that
//			can be concatenated into one PW packet as provisioned at the far end. This attribute may be used
//			for error checking of downstream traffic. The value 0 specifies that the ONU uses its internal
//			default. (R, W, set-by-create) (optional) (2 bytes)
//
//		Atm Cell Loss Priority Clp Qos Mapping
//			ATM cell loss priority (CLP) QoS mapping: This attribute specifies whether the CLP bits should
//			be considered when setting the value in the QoS fields of the encapsulating protocol (e.g., TC
//			fields of the MPLS label stack).
//
//			1	ATM CLP bits mapping to QoS fields of the encapsulating protocol
//
//			2	Not applicable
//
//			The value 0 specifies that the ONU uses its internal default. (R, W, setbycreate) (optional) (1
//			byte)
//
//		Timeout Mode
//			The value 0 specifies that the ONU uses its internal default. (R, W, setbycreate) (optional) (1
//			byte)
//
//			This attribute specifies whether a packet is transmitted in the upstream direction based on
//			timeout expiration for collecting cells. The actual handling of the timeout is implementation
//			specific; as such, this attribute may be changed at any time with proper consideration of the
//			traffic disruption effect.
//
//			1	Disabled. The ONU does not generate packets based on timeout cells.
//
//			2	Enabled. The ONU generates packets based on timeout cells.
//
//		Pw Atm Mapping Table
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			14	ATM AAL5 PDU VCC transport
//
//			Each entry contains:
//
//			Entry number: (1-byte), the index of this row. A set operation with all fields zero has the
//			effect of clearing the table. A set operation with a non-zero entry number and all other fields
//			zero, has the effect of deleting one row.
//
//			Upstream VPI: (2 bytes)
//
//			The VPI value of this ATM PW at the UNI. When pseudowire type-= ATM transparent cell transport
//			(3), this field is ignored.
//
//			Upstream VCI: (2 bytes)
//
//			The VCI value of this ATM PW at the UNI. When pseudowire type-= ATM transparent cell transport
//			(3), or in virtual path (VP) cases, this field is ignored.
//
//			Upstream traffic descriptor profile pointer: (2 bytes)
//
//			A pointer to an instance of an ITU-T G.983.2 traffic descriptor profile ME that contains the
//			traffic parameters used for the ATM upstream traffic. Refer to clause 7.5.2 of [ITUT-G.983.2]
//			for the definition of this class of MEs. A null pointer indicates BE.
//
//			Upstream mapped VPI: (2 bytes)
//
//			The VPI value of the upstream MPLS ATM PW. This field is valid when the pseudowire type is as
//			follows.
//
//			9	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			This field is not used for other pseudowire types.
//
//			Upstream mapped VCI: (2 bytes)
//
//			The VCI value of the upstream MPLS ATM PW. This field is valid when the pseudowire type is as
//			follows.
//
//			9	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			This field is not used for other pseudowire types.
//
//			Downstream VPI: (2 bytes)
//
//			The downstream VPI value of this MPLS ATM PW. When pseudowire type-= ATM transparent cell
//			transport (3), this field is ignored.
//
//			Downstream VCI: (2 bytes)
//
//			The downstream VCI value of this MPLS ATM PW. When pseudowire type-= ATM transparent cell
//			transport (3) or in the VP case, this field is ignored.
//
//			Downstream traffic descriptor profile pointer: (2 bytes)
//
//			A pointer to an instance of an ITU-T G.983.2 traffic descriptor profile ME that contains the
//			traffic parameters used for the ATM downstream traffic. Refer to clause 7.5.2 of [ITUT-G.983.2]
//			for definition of this class of MEs. A null pointer indicates BE.
//
//			Downstream mapped VPI: (2 bytes)
//
//			The VPI value of this ATM PW at the UNI. This field is valid when the pseudowire type is as
//			follows.
//
//			9	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			This field is not used for other pseudowire types.
//
//			Downstream mapped VCI: (2 bytes)
//
//			The VCI value of this ATM PW at the UNI. This field is valid when the pseudowire type is as
//			follows.
//
//			9	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			12	ATM one-to-one VCC cell mode
//
//			13	ATM one-to-one VPC cell mode
//
//			This field is not used for other pseudowire types.
//
//			(R,-W) (mandatory) (21N bytes, where N is the number of entries in the list)
//
//			This attribute lists ATM VPI/VCI mapping entries in both the upstream and downstream directions.
//			In the upstream direction, ATM cells that match no entry's upstream VPI (and conditionally VCI)
//			values are discarded; conversely in the downstream direction. Upon ME instantiation, the ONU
//			sets this attribute to an empty table, which discards all cells in both directions.
//
//			The table can contain up to N entries when the pseudowire type is equal to one of the following:
//
//			9 	ATM n-to-one VCC cell transport
//
//			10	ATM n-to-one VPC cell transport
//
//			The table contains only one entry when the pseudowire type is equal to one of the following.
//
//			2 	ATM AAL5 SDU VCC transport
//
//			3 	ATM transparent cell transport
//
type PwAtmConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const PwAtmConfigurationData_TpType = "TpType"
const PwAtmConfigurationData_TransportTpPointer = "TransportTpPointer"
const PwAtmConfigurationData_PptpAtmUniPointer = "PptpAtmUniPointer"
const PwAtmConfigurationData_MaxCEllCOncatenation = "MaxCEllCOncatenation"
const PwAtmConfigurationData_FarEndMAxCEllCOncatenation = "FarEndMAxCEllCOncatenation"
const PwAtmConfigurationData_AtmCellLossPriorityClpQosMapping = "AtmCellLossPriorityClpQosMapping"
const PwAtmConfigurationData_TimeoutMode = "TimeoutMode"
const PwAtmConfigurationData_PwAtmMappingTable = "PwAtmMappingTable"

func init() {
	pwatmconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "PwAtmConfigurationData",
		ClassID: PwAtmConfigurationDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
			SetTable,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: ByteField(PwAtmConfigurationData_TpType, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: Uint16Field(PwAtmConfigurationData_TransportTpPointer, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint16Field(PwAtmConfigurationData_PptpAtmUniPointer, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4: Uint16Field(PwAtmConfigurationData_MaxCEllCOncatenation, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5: Uint16Field(PwAtmConfigurationData_FarEndMAxCEllCOncatenation, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 5),
			6: ByteField(PwAtmConfigurationData_AtmCellLossPriorityClpQosMapping, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 6),
			7: ByteField(PwAtmConfigurationData_TimeoutMode, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, true, false, 7),
			8: TableField(PwAtmConfigurationData_PwAtmMappingTable, TableAttributeType, 0x0100, TableInfo{nil, 21}, mapset.NewSetWith(Read, Write), false, false, false, 8),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewPwAtmConfigurationData (class ID 337) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewPwAtmConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*pwatmconfigurationdataBME, params...)
}
