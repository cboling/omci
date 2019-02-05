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

const PhysicalPathTerminationPointEthernetUniClassId uint16 = 11

// PhysicalPathTerminationPointEthernetUni (class ID #11) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type PhysicalPathTerminationPointEthernetUni struct {
	BaseManagedEntityDefinition
}

// NewPhysicalPathTerminationPointEthernetUni (class ID 11 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPhysicalPathTerminationPointEthernetUni(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "PhysicalPathTerminationPointEthernetUni",
		ClassID:  11,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, Read, false, false, false, false),
			1:  ByteField("ExpectedType", 0, Read|Write, false, false, false, false),
			2:  ByteField("SensedType", 0, Read, true, false, false, false),
			3:  ByteField("AutoDetectionConfiguration", 0, Read|Write, false, false, false, false),
			4:  ByteField("EthernetLoopbackConfiguration", 0, Read|Write, false, false, false, false),
			5:  ByteField("AdministrativeState", 0, Read|Write, false, false, false, false),
			6:  ByteField("OperationalState", 0, Read, true, false, false, true),
			7:  ByteField("ConfigurationInd", 0, Read, false, false, false, false),
			8:  Uint16Field("MaxFrameSize", 0, Read|Write, false, false, false, false),
			9:  ByteField("DteOrDceInd", 0, Read|Write, false, false, false, false),
			10: Uint16Field("PauseTime", 0, Read|Write, false, false, false, true),
			11: ByteField("BridgedOrIpInd", 0, Read|Write, false, false, false, true),
			12: ByteField("Arc", 0, Read|Write, true, false, false, true),
			13: ByteField("ArcInterval", 0, Read|Write, false, false, false, true),
			14: ByteField("PppoeFilter", 0, Read|Write, false, false, false, true),
			15: ByteField("PowerControl", 0, Read|Write, false, false, false, true),
		},
	}
	entity.computeAttributeMask()
	return &PhysicalPathTerminationPointEthernetUni{entity}, nil
}
