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

const Dot1RateLimiterClassId uint16 = 298

// Dot1RateLimiter (class ID #298) defines the basic
// Managed Entity definition that is further extended by types that support
// packet encode/decode and user create managed entities.
type Dot1RateLimiter struct {
	BaseManagedEntityDefinition
}

// NewDot1RateLimiter (class ID 298 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewDot1RateLimiter(params ...ParamData) (IManagedEntityDefinition, error) {
	eid := decodeEntityID(params...)
	entity := BaseManagedEntityDefinition{
		Name:     "Dot1RateLimiter",
		ClassID:  298,
		EntityID: eid,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, Read|SetByCreate, false, false, false, false),
			1: Uint16Field("ParentMePointer", 0, Read|SetByCreate|Write, false, false, false, false),
			2: ByteField("TpType", 0, Read|SetByCreate|Write, false, false, false, false),
			3: Uint16Field("UpstreamUnicastFloodRatePointer", 0, Read|SetByCreate|Write, false, false, false, true),
			4: Uint16Field("UpstreamBroadcastRatePointer", 0, Read|SetByCreate|Write, false, false, false, true),
			5: Uint16Field("UpstreamMulticastPayloadRatePointer", 0, Read|SetByCreate|Write, false, false, false, true),
		},
	}
	entity.computeAttributeMask()
	return &Dot1RateLimiter{entity}, nil
}
