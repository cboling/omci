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

const PhysicalPathTerminationPointXdslUniPart2ClassId uint16 = 99

// PhysicalPathTerminationPointXdslUniPart2 (class ID #99) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type PhysicalPathTerminationPointXdslUniPart2 struct {
	BaseManagedEntityDefinition
}

// NewPhysicalPathTerminationPointXdslUniPart2 (class ID 99 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPhysicalPathTerminationPointXdslUniPart2(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "PhysicalPathTerminationPointXdslUniPart2",
		ClassID:  99,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read),
			1: Uint16Field("XdslChannelConfigurationProfileForBearerChannel0Downstream", 0, Read|Write),
			2: Uint16Field("XdslChannelConfigurationProfileForBearerChannel1Downstream", 0, Read|Write),
			3: Uint16Field("XdslChannelConfigurationProfileForBearerChannel2Downstream", 0, Read|Write),
			4: Uint16Field("XdslChannelConfigurationProfileForBearerChannel3Downstream", 0, Read|Write),
			5: Uint16Field("XdslChannelConfigurationProfileForBearerChannel0Upstream", 0, Read|Write),
			6: Uint16Field("XdslChannelConfigurationProfileForBearerChannel1Upstream", 0, Read|Write),
			7: Uint16Field("XdslChannelConfigurationProfileForBearerChannel2Upstream", 0, Read|Write),
			8: Uint16Field("XdslChannelConfigurationProfileForBearerChannel3Upstream", 0, Read|Write),
		},
	}
	entity.computeAttributeMask()
	return &PhysicalPathTerminationPointXdslUniPart2{entity}, nil
}
