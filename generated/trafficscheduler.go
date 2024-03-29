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

// TrafficSchedulerClassID is the 16-bit ID for the OMCI
// Managed entity Traffic scheduler
const TrafficSchedulerClassID = ClassID(278) // 0x0116

var trafficschedulerBME *ManagedEntityDefinition

// TrafficScheduler (Class ID: #278 / 0x0116)
//	NOTE 1 - In [ITU-T G.984.4], this ME is called a traffic scheduler-G.
//
//	An instance of this ME represents a logical object that can control upstream GEM packets. A
//	traffic scheduler can accommodate GEM packets after a priority queue or other traffic scheduler
//	and transfer them towards the next traffic scheduler or T-CONT. Because T-CONTs and traffic
//	schedulers are created autonomously by the ONU, the ONU vendor predetermines the most complex
//	traffic handling model it is prepared to support; the OLT may use less than the ONU's full
//	capabilities, but cannot ask for more. See Appendix II for more details.
//
//	After the ONU creates instances of the T-CONT ME, it then autonomously creates instances of the
//	traffic scheduler ME.
//
//	Relationships
//		The traffic scheduler ME may be related to a T-CONT or other traffic schedulers through pointer
//		attributes.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. This 2-byte number indicates the
//			physical capability that realizes the traffic scheduler. The first byte is the slot ID of the
//			circuit pack with which this traffic scheduler is associated. For a traffic scheduler that is
//			not associated with a circuit pack, the first byte is 0xFF. The second byte is the traffic
//			scheduler id, assigned by the ONU itself. Traffic schedulers are numbered in ascending order
//			with the range 0..0xFF in each circuit pack or in the ONU core. (R) (mandatory) (2-bytes)
//
//		T_Cont Pointer
//			T-CONT pointer: This attribute points to the T-CONT ME instance associated with this traffic
//			scheduler. This pointer is used when this traffic scheduler is connected to the T-CONT directly;
//			It is null (0) otherwise. (R, W) (mandatory) (2 bytes)
//
//			NOTE 2 - This attribute is read-only unless otherwise specified by the QoS configuration
//			flexibility attribute of the ONU2-G ME. If flexible configuration is not supported, the ONU
//			should reject an attempt to set the TCONT pointer attribute with a parameter error result-reason
//			code.
//
//		Traffic Scheduler Pointer
//			This attribute points to another traffic scheduler ME instance that may serve this traffic
//			scheduler. This pointer is used when this traffic scheduler is connected to another traffic
//			scheduler; it is null (0) otherwise. (R) (mandatory) (2-bytes)
//
//		Policy
//			This attribute represents scheduling policy. Valid values include:
//
//			0	Null
//
//			1	Strict priority
//
//			2	WRR (weighted round robin)
//
//			The traffic scheduler derives priority or weight values for its tributary traffic schedulers or
//			priority queues from the tributary MEs themselves.
//
//			(R, W) (mandatory) (1 byte)
//
//			NOTE 3 - This attribute is read-only unless otherwise specified by the QoS configuration
//			flexibility attribute of the ONU2-G ME. If flexible configuration is not supported, the ONU
//			should reject an attempt to set the policy attribute with a parameter error result-reason code.
//
//		Priority_Weight
//			Priority/weight: This attribute represents the priority for strict priority scheduling or the
//			weight for WRR scheduling. This value is used by the next upstream ME, as indicated by the
//			T-CONT pointer attribute or traffic scheduler pointer attribute.
//
//			If the indicated pointer has policy-=-strict priority, this value is interpreted as a priority
//			(0 is the highest priority, 255 the lowest).
//
//			If the indicated pointer has policy-=-WRR, this value is interpreted as a weight. Higher values
//			receive more bandwidth.
//
//			Upon ME instantiation, the ONU sets this attribute to 0. (R,-W) (mandatory) (1-byte)
//
type TrafficScheduler struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const TrafficScheduler_TContPointer = "TContPointer"
const TrafficScheduler_TrafficSchedulerPointer = "TrafficSchedulerPointer"
const TrafficScheduler_Policy = "Policy"
const TrafficScheduler_PriorityWeight = "PriorityWeight"

func init() {
	trafficschedulerBME = &ManagedEntityDefinition{
		Name:    "TrafficScheduler",
		ClassID: TrafficSchedulerClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xf000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1: Uint16Field(TrafficScheduler_TContPointer, PointerAttributeType, 0x8000, 0, mapset.NewSetWith(Read, Write), false, false, false, 1),
			2: Uint16Field(TrafficScheduler_TrafficSchedulerPointer, PointerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), false, false, false, 2),
			3: ByteField(TrafficScheduler_Policy, EnumerationAttributeType, 0x2000, 0, mapset.NewSetWith(Read, Write), false, false, false, 3),
			4: ByteField(TrafficScheduler_PriorityWeight, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read, Write), false, false, false, 4),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewTrafficScheduler (class ID 278) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewTrafficScheduler(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*trafficschedulerBME, params...)
}
