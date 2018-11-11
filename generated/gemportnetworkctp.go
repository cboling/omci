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

const GemPortNetworkCtpClassId uint16 = 268

// GemPortNetworkCtp (class ID #268) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type GemPortNetworkCtp struct {
	BaseManagedEntityDefinition
}

// NewGemPortNetworkCtp (class ID 268 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewGemPortNetworkCtp(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "GemPortNetworkCtp",
		ClassID:  268,
		EntityID: eid,
		MessageTypes: []MsgType{
			Set,
			Get,
			Create,
			Delete,
		},
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read|SetByCreate),
			1: Uint16Field("PortId", 0, Read|Write|SetByCreate),
			2: Uint16Field("TContPointer", 0, Read|Write|SetByCreate),
			3: ByteField("Direction", 0, Read|Write|SetByCreate),
			4: Uint16Field("TrafficManagementPointerForUpstream", 0, Read|Write|SetByCreate),
			5: Uint16Field("TrafficDescriptorProfilePointerForUpstream", 0, Read|Write|SetByCreate),
			6: ByteField("UniCounter", 0, Read),
			7: Uint16Field("PriorityQueuePointerForDownStream", 0, Read|Write|SetByCreate),
			8: ByteField("EncryptionState", 0, Read),
			9: Uint16Field("TrafficDescriptorProfilePointerForDownstream", 0, Read|Write|SetByCreate),
			10: ByteField("EncryptionKeyRing", 0, Read|Write|SetByCreate),
		},
	}
	entity.computeAttributeMask()
	return &GemPortNetworkCtp{entity}, nil
}
