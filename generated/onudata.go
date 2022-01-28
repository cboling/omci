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

// OnuDataClassID is the 16-bit ID for the OMCI
// Managed entity ONU data
const OnuDataClassID = ClassID(2) // 0x0002

var onudataBME *ManagedEntityDefinition

// OnuData (Class ID: #2 / 0x0002)
//	This ME models the MIB itself. Clause I.1.3 explains the use of this ME with respect to MIB
//	synchronization.
//
//	The ONU automatically creates an instance of this ME, and updates the associated attributes
//	according to data within the ONU itself.
//
//	Relationships
//		One instance of this ME is contained in an ONU.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. There is only one instance, number
//			0. (R) (mandatory) (2-bytes)
//
//		Mib Data Sync
//			This attribute is used to check the alignment of the MIB of the ONU with the corresponding MIB
//			in the OLT. MIB data sync relies on this attribute, which is a sequence number that can be
//			checked by the OLT to see if the MIB snapshots for the OLT and ONU match. Refer to clause
//			I.1.2.1 for a detailed description of this attribute. Upon ME instantiation, the ONU sets this
//			attribute to 0. (R,-W) (mandatory) (1-byte)
//
type OnuData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const OnuData_MibDataSync = "MibDataSync"

func init() {
	onudataBME = &ManagedEntityDefinition{
		Name:    "OnuData",
		ClassID: OnuDataClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			GetAllAlarms,
			GetAllAlarmsNext,
			MibReset,
			MibUpload,
			MibUploadNext,
			Set,
		),
		AllowedAttributeMask: 0x8000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: ByteField(OnuData_MibDataSync, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewOnuData (class ID 2) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewOnuData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*onudataBME, params...)
}
