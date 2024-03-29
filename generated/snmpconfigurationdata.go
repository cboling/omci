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

// SnmpConfigurationDataClassID is the 16-bit ID for the OMCI
// Managed entity SNMP configuration data
const SnmpConfigurationDataClassID = ClassID(335) // 0x014f

var snmpconfigurationdataBME *ManagedEntityDefinition

// SnmpConfigurationData (Class ID: #335 / 0x014f)
//	The SNMP configuration data ME provides a way for the OLT to provision an IP path for an SNMP
//	management agent.
//
//	The SNMP configuration data ME is created and deleted by the OLT.
//
//	Relationships
//		One instance of this ME is created by the OLT for each SNMP management path termination.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. The ME IDs 0 and 0xFFFF are
//			reserved. (R, setbycreate) (mandatory) (2-bytes)
//
//		Snmp Version
//			This integer attribute is the SNMP protocol version to be supported. (R,-W, setbycreate)
//			(mandatory) (2-bytes)
//
//		Snmp Agent Address
//			This attribute is a pointer to a TCP/UDP config data ME, which provides the SNMP agent. (R, W,
//			setbycreate) (mandatory) (2 bytes)
//
//		Snmp Server Address
//			This attribute is the IP address of the SNMP server. (R, W, setbycreate) (mandatory) (4 bytes)
//
//		Snmp Server Port
//			This attribute is the UDP port number of the SNMP server. (R, W, setbycreate) (mandatory) (2
//			bytes)
//
//		Security Name Pointer
//			This attribute points to a large string whose content represents the SNMP security name in a
//			human-readable format that is independent of the security model. SecurityName is defined in
//			[b-IETF RFC 2571]. (R, W, setbycreate) (mandatory) (2 bytes)
//
//		Community For Read
//			This attribute is a pointer to a large string that contains the name of the read community. (R,
//			W, setbycreate) (mandatory) (2 bytes)
//
//		Community For Write
//			This attribute is a pointer to a large string that contains the name of the write community. (R,
//			W, setbycreate) (mandatory) (2 bytes)
//
//		Sys Name Pointer
//			This attribute points to a large string whose content identifies the SNMP system name. SysName
//			is defined in [b-IETF RFC-3418]. (R, W, setbycreate) (mandatory) (2 bytes)
//
type SnmpConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const SnmpConfigurationData_SnmpVersion = "SnmpVersion"
const SnmpConfigurationData_SnmpAgentAddress = "SnmpAgentAddress"
const SnmpConfigurationData_SnmpServerAddress = "SnmpServerAddress"
const SnmpConfigurationData_SnmpServerPort = "SnmpServerPort"
const SnmpConfigurationData_SecurityNamePointer = "SecurityNamePointer"
const SnmpConfigurationData_CommunityForRead = "CommunityForRead"
const SnmpConfigurationData_CommunityForWrite = "CommunityForWrite"
const SnmpConfigurationData_SysNamePointer = "SysNamePointer"

func init() {
	snmpconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "SnmpConfigurationData",
		ClassID: SnmpConfigurationDataClassID,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0xff00,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1: Uint16Field(SnmpConfigurationData_SnmpVersion, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 1),
			2: Uint16Field(SnmpConfigurationData_SnmpAgentAddress, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3: Uint32Field(SnmpConfigurationData_SnmpServerAddress, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 3),
			4: Uint16Field(SnmpConfigurationData_SnmpServerPort, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 4),
			5: Uint16Field(SnmpConfigurationData_SecurityNamePointer, UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 5),
			6: Uint16Field(SnmpConfigurationData_CommunityForRead, UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 6),
			7: Uint16Field(SnmpConfigurationData_CommunityForWrite, UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 7),
			8: Uint16Field(SnmpConfigurationData_SysNamePointer, UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 8),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
	}
}

// NewSnmpConfigurationData (class ID 335) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewSnmpConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*snmpconfigurationdataBME, params...)
}
