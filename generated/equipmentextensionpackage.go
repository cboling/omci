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

// EquipmentExtensionPackageClassID is the 16-bit ID for the OMCI
// Managed entity Equipment extension package
const EquipmentExtensionPackageClassID ClassID = ClassID(160)

var equipmentextensionpackageBME *ManagedEntityDefinition

// EquipmentExtensionPackage (class ID #160)
//	This ME supports optional extensions to circuit pack MEs. If the circuit pack supports these
//	features, the ONU creates and deletes this ME along with its associated real or virtual circuit
//	pack.
//
//	Relationships
//		An equipment extension package may be contained by an ONU-G or cardholder.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the ONU-G or cardholder. (R)
//			(mandatory) (2-bytes)
//
//		Environmental Sense
//			NOTE - Some specific sense point applications are already defined on the ONU-G ME. It is the
//			vendor's choice how to configure and report sense points that appear both generically and
//			specifically.
//
//		Contact Closure Output
//			On read, the left bit in each pair should be set to 0 at the ONU and ignored at the OLT. The
//			right bit indicates a released output point with 0 and an operated contact point with 1. (R,-W)
//			(optional) (2-bytes)
//
type EquipmentExtensionPackage struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	equipmentextensionpackageBME = &ManagedEntityDefinition{
		Name:    "EquipmentExtensionPackage",
		ClassID: 160,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xc000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: Uint16Field("EnvironmentalSense", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 1),
			2: Uint16Field("ContactClosureOutput", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 2),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewEquipmentExtensionPackage (class ID 160) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEquipmentExtensionPackage(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*equipmentextensionpackageBME, params...)
}
