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

const MulticastSubscriberConfigInfoClassId uint16 = 310

// MulticastSubscriberConfigInfo (class ID #310) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type MulticastSubscriberConfigInfo struct {
	BaseManagedEntityDefinition
}

// NewMulticastSubscriberConfigInfo (class ID 310 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewMulticastSubscriberConfigInfo(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "MulticastSubscriberConfigInfo",
		ClassID:  310,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			GetNext,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read|SetByCreate, false, false, false, false),
			1: ByteField("MeType", 0, Read|SetByCreate|Write, false, false, false, false),
			2: Uint16Field("MulticastOperationsProfilePointer", 0, Read|SetByCreate|Write, false, false, false, false),
			3: Uint16Field("MaxSimultaneousGroups", 0, Read|SetByCreate|Write, false, false, false, true),
			4: Uint32Field("MaxMulticastBandwidth", 0, Read|SetByCreate|Write, false, false, false, true),
			5: ByteField("BandwidthEnforcement", 0, Read|SetByCreate|Write, false, false, false, true),
			6: MultiByteField("MulticastServicePackageTable", 22, nil, Read|Write, false, false, true, true),
		},
	}
	entity.computeAttributeMask()
	return &MulticastSubscriberConfigInfo{entity}, nil
}
