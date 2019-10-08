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

// PwEthernetConfigurationDataClassId is the 16-bit ID for the OMCI
// Managed entity PW Ethernet configuration data
const PwEthernetConfigurationDataClassId ClassID = ClassID(339)

var pwethernetconfigurationdataBME *ManagedEntityDefinition

// PwEthernetConfigurationData (class ID #339)
//	This ME contains the Ethernet pseudowire configuration data. Instances of this ME are created
//	and deleted by the OLT.
//
//	Relationships
//		An instance of this ME is associated with an instance of the MPLS pseudowire TP ME with a
//		pseudowire type attribute equal to the following.////		5	Ethernet
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. (R,
//			setbycreate)-(mandatory) (2 bytes)
//
//		Mpls Pseudowire Tp Pointer
//			MPLS pseudowire TP pointer: This attribute points to an instance of the MPLS pseudowire TP ME
//			associated with this ME. (R, W, setbycreate) (mandatory) (2 bytes)
//
//		Tp Type
//			(R,-W, setbycreate) (mandatory) (1-byte)
//
//		Uni Pointer
//			UNI pointer: This attribute points to the associated instance of a UNI-side ME. The type of UNI
//			is determined by the TP type attribute. (R, W, setbycreate) (mandatory) (2 bytes)
//
type PwEthernetConfigurationData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	pwethernetconfigurationdataBME = &ManagedEntityDefinition{
		Name:    "PwEthernetConfigurationData",
		ClassID: 339,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XE000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1: Uint16Field("MplsPseudowireTpPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2: ByteField("TpType", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3: Uint16Field("UniPointer", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
		},
	}
}

// NewPwEthernetConfigurationData (class ID 339 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPwEthernetConfigurationData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*pwethernetconfigurationdataBME, params...)
}
