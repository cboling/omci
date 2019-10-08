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

// TrafficSchedulerClassId is the 16-bit ID for the OMCI
// Managed entity Traffic scheduler
const TrafficSchedulerClassId ClassID = ClassID(278)

var trafficschedulerBME *ManagedEntityDefinition

// TrafficScheduler (class ID #278)
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
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. This 2-byte
//			number indicates the physical capability that realizes the traffic scheduler. The first byte is
//			the slot ID of the circuit pack with which this traffic scheduler is associated. For a traffic
//			scheduler that is not associated with a circuit pack, the first byte is 0xFF. The second byte is
//			the traffic scheduler id, assigned by the ONU itself. Traffic schedulers are numbered in
//			ascending order with the range 0..0xFF in each circuit pack or in the ONU core. (R) (mandatory)
//			(2-bytes)
//
//		T_Cont Pointer
//			NOTE 2 - This attribute is read-only unless otherwise specified by the QoS configuration
//			flexibility attribute of the ONU2-G ME. If flexible configuration is not supported, the ONU
//			should reject an attempt to set the TCONT pointer attribute with a parameter error result-reason
//			code.
//
//		Traffic Scheduler Pointer
//			Traffic scheduler pointer: This attribute points to another traffic scheduler ME instance that
//			may serve this traffic scheduler. This pointer is used when this traffic scheduler is connected
//			to another traffic scheduler; it is null (0) otherwise. (R) (mandatory) (2-bytes)
//
//		Policy
//			NOTE 3 - This attribute is read-only unless otherwise specified by the QoS configuration
//			flexibility attribute of the ONU2-G ME. If flexible configuration is not supported, the ONU
//			should reject an attempt to set the policy attribute with a parameter error result-reason code.
//
//		Priority_Weight
//			Upon ME instantiation, the ONU sets this attribute to 0. (R,-W) (mandatory) (1-byte)
//
type TrafficScheduler struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	trafficschedulerBME = &ManagedEntityDefinition{
		Name:    "TrafficScheduler",
		ClassID: 278,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0XF000,
		AttributeDefinitions: AttributeDefinitionMap{
			0: Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1: Uint16Field("TContPointer", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 1),
			2: Uint16Field("TrafficSchedulerPointer", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3: ByteField("Policy", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 3),
			4: ByteField("PriorityWeight", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 4),
		},
	}
}

// NewTrafficScheduler (class ID 278 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewTrafficScheduler(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*trafficschedulerBME, params...)
}
