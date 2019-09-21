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

const PriorityQueueClassId ClassID = ClassID(277)

var priorityqueueBME *ManagedEntityDefinition

// PriorityQueue (class ID #277) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type PriorityQueue struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	priorityqueueBME = &ManagedEntityDefinition{
		Name:    "PriorityQueue",
		ClassID: 277,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  ByteField("QueueConfigurationOption", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("MaximumQueueSize", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3:  Uint16Field("AllocatedQueueSize", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 3),
			4:  Uint16Field("DiscardBlockCounterResetInterval", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 4),
			5:  Uint16Field("ThresholdValueForDiscardedBlocksDueToBufferOverflow", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 5),
			6:  Uint32Field("RelatedPort", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 6),
			7:  Uint16Field("TrafficSchedulerPointer", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 7),
			8:  ByteField("Weight", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 8),
			9:  Uint16Field("BackPressureOperation", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 9),
			10: Uint32Field("BackPressureTime", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 10),
			11: Uint16Field("BackPressureOccurQueueThreshold", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 11),
			12: Uint16Field("BackPressureClearQueueThreshold", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 12),
			13: Uint64Field("PacketDropQueueThresholds", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 13),
			14: Uint16Field("PacketDropMaxP", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 14),
			15: ByteField("QueueDropWQ", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 15),
			16: ByteField("DropPrecedenceColourMarking", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 16),
		},
	}
}

// NewPriorityQueue (class ID 277 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewPriorityQueue(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(priorityqueueBME, params...)
}
