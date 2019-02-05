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

const PhysicalPathTerminationPointMocaUniClassId uint16 = 162

// PhysicalPathTerminationPointMocaUni (class ID #162) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type PhysicalPathTerminationPointMocaUni struct {
	BaseManagedEntityDefinition
}

// NewPhysicalPathTerminationPointMocaUni (class ID 162 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPhysicalPathTerminationPointMocaUni(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "PhysicalPathTerminationPointMocaUni",
		ClassID:  162,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, Read, false, false, false, false),
			1:  ByteField("LoopbackConfiguration", 0, Read|Write, false, false, false, true),
			2:  ByteField("AdministrativeState", 0, Read|Write, false, false, false, false),
			3:  ByteField("OperationalState", 0, Read, true, false, false, true),
			4:  Uint16Field("MaxFrameSize", 0, Read|Write, false, false, false, false),
			5:  ByteField("Arc", 0, Read|Write, true, false, false, true),
			6:  ByteField("ArcInterval", 0, Read|Write, false, false, false, true),
			7:  ByteField("PppoeFilter", 0, Read|Write, false, false, false, true),
			8:  ByteField("NetworkStatus", 0, Read, false, false, false, false),
			9:  MultiByteField("Password", 17, nil, Read|Write, false, false, false, false),
			10: ByteField("PrivacyEnabled", 0, Read|Write, false, false, false, false),
			11: Uint16Field("MinimumBandwidthAlarmThreshold", 0, Read|Write, false, false, false, true),
			12: Uint32Field("FrequencyMask", 0, Read|Write, false, false, false, true),
			13: Uint16Field("RfChannel", 0, Read, false, false, false, false),
			14: Uint16Field("LastOperationalFrequency", 0, Read, false, false, false, false),
		},
	}
	entity.computeAttributeMask()
	return &PhysicalPathTerminationPointMocaUni{entity}, nil
}
