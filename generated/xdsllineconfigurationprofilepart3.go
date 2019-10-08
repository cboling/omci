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

// XdslLineConfigurationProfilePart3ClassId is the 16-bit ID for the OMCI
// Managed entity xDSL line configuration profile part 3
const XdslLineConfigurationProfilePart3ClassId ClassID = ClassID(106)

var xdsllineconfigurationprofilepart3BME *ManagedEntityDefinition

// XdslLineConfigurationProfilePart3 (class ID #106)
//	The overall xDSL line configuration profile is modelled in several parts, all of which are
//	associated together through a common ME ID (the client PPTP xDSL UNI part 1 has a single
//	pointer, which refers to the entire set of line configuration profile parts).
//
//	Relationships
//		An instance of this ME may be associated with zero or more instances of an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. All xDSL and
//			VDSL2 line configuration profiles and extensions that pertain to a given PPTP xDSL UNI must
//			share a common ME ID. (R, setbycreate) (mandatory) (2-bytes)
//
//		Loop Diagnostics Mode Forced Ldsf
//			Only while the line power management state is L3 can the line be forced into loop diagnostic
//			mode. When loop diagnostic procedures complete successfully, the ONU resets this attribute to 0.
//			The line remains in the L3 idle state. The loop diagnostics data are available at least until
//			the line is forced to the L0 state. As long as loop diagnostic procedures have not completed
//			successfully, attempts are made to do so, until the loop diagnostic mode is no longer forced on
//			the line through this configuration parameter. If loop diagnostic procedures cannot be completed
//			successfully after a vendordiscretionary number of retries or within a vendor-discretionary
//			timeout, then an initialization failure occurs. (R,-W, setbycreate) (mandatory) (1-byte)
//
//		Automode Cold Start Forced
//			Automode is defined as the case where multiple operation modes are enabled in xTSE (Table
//			9.7.12-1) and where the selection of the operation mode to be used for transmission depends, not
//			only on the common capabilities of both xTUs (as exchanged in [ITU-T G.994.1]), but also on
//			achievable data rates under given loop conditions. (R,-W, setbycreate) (mandatory if automode is
//			supported) (1-byte)
//
//		L2 Atpr
//			L2ATPR:	This parameter specifies the maximum aggregate transmit power reduction that can be
//			performed in the L2 request (i.e., at the transition of L0 to L2 state) or through a single
//			power trim in the L2 state. It is only valid for [ITUT-G.992.3], [ITUT-G.992.4] and
//			[ITUT-G.992.5]. This attribute ranges from 0 (0-dB) dB to 31 (31-dB). (R, W, setbycreate)
//			(mandatory) (1 byte)
//
//		L2 Atprt
//			L2ATPRT:	This parameter specifies the total maximum aggregate transmit power reduction (in
//			decibels) that can be performed in an L2 state. This is the sum of all reductions of L2 requests
//			(i.e., at transitions from L0 to L2 state) and power trims. This attribute ranges from 0 (0 dB)
//			dB to 31 (31 dB). (R, W, setbycreate) (mandatory) (1 byte)
//
//		Force Inp Downstream
//			Force INP downstream: When set to 1, the FORCEINPds attribute forces the framer settings of all
//			downstream bearer channels to be selected such that the impulse noise protection (INP) computed
//			according to the formula specified in the relevant Recommendation is greater than or equal to
//			the minimal INP requirement. The default value 0 disables this function. (R, W) (mandatory for
//			[ITU-T G.993.2], optional for other Recommendations that support it) (1 byte)
//
//		Force Inp Upstream
//			Force INP upstream: When set to 1, the FORCEINPus attribute forces the framer settings of all
//			upstream bearer channels to be selected such that the INP computed according to the formula
//			specified in the relevant Recommendation is greater than or equal to the minimal INP
//			requirement. The default value 0 disables this function. (R, W) (mandatory for [ITU-T G.993.2],
//			optional for other Recommendations that support it) (1 byte)
//
//		Update Request Flag For Near_End Test Parameters
//			Update request flag for near-end test parameters: The UPDATE-TEST-NE attribute forces an update
//			of all near-end test parameters that can be updated during showtime in [ITU-T G.993.2]. Update
//			is triggered by setting this attribute to 1, whereupon the near-end test parameters are expected
//			to be updated within 10-s, and the ONU should reset the attribute value to 0. The update request
//			flag is independent of any autonomous update process in the system. The update request attribute
//			must be prepared to accept another set after a period not to exceed 3-min, a period that starts
//			when the flag is set via the OMCI or by an autonomous process in the system. (R,-W) (optional)
//			(1-byte)
//
//		Update Request Flag For Far_End Test Parameters
//			Update request flag for far-end test parameters: The UPDATE-TEST-FE attribute forces an update
//			of all far-end test parameters that can be updated during showtime in [ITU-T G.993.2]. Update is
//			triggered by setting this attribute to 1, whereupon the far-end test parameters are expected to
//			be updated within 10-s, and the ONU should reset the attribute value to 0. The update request
//			flag is independent of any autonomous update process in the system. The update request attribute
//			must be prepared to accept another set after a period not to exceed 3-min, a period that starts
//			when the flag is set via the OMCI or by an autonomous process in the system. (R,-W) (optional)
//			(1-byte)
//
//		Inm Inter Arrival Time Offset Upstream
//			INM inter-arrival time offset upstream: INMIATOus is the inter-arrival time (IAT) offset that
//			the xTU-C receiver uses to determine in which bin of the IAT histogram the IAT is reported.
//			Valid values for INMIATO range from 3 to 511 discrete multi-tone (DMT) symbols in steps of 1 DMT
//			symbol. (R,-W) (optional) (2-bytes)
//
//		Inm Inter_Arrival Time Step Upstream
//			INM inter-arrival time step upstream: INMIATSus is the IAT step that the xTU-C receiver uses to
//			determine in which bin of the IAT histogram the IAT is reported. Valid values for INMIATS range
//			from 0 to 7 in steps of 1. (R,-W) (optional) (1-byte)
//
//		Inm Cluster Continuation Value Upstream
//			INM cluster continuation value upstream: INMCCus is the cluster continuation value that the
//			xTU-C receiver uses in the cluster indication process described in the applicable
//			Recommendation. Valid values for INMCC range from 0 to 64 DMT symbols in steps of 1 DMT symbol.
//			(R,-W) (optional) (1-byte)
//
//		Inm Equivalent Inp Mode Upstream
//			INM equivalent INP mode upstream: INM_INPEQ_MODEus is the INM equivalent INP mode that the xTU-C
//			receiver uses in the computation of the equivalent INP, as defined in the applicable
//			Recommendation. Valid values for INM_INPEQ_MODE are 0..4. (R,-W) (optional) (1-byte)
//
//		Inm Inter Arrival Time Offset Downstream
//			INM inter-arrival time offset downstream: INMIATOds is the IAT offset that the xTU-R receiver
//			uses to determine in which bin of the IAT histogram the IAT is reported. Valid values for
//			INMIATO range from 3 to 511 DMT symbols in steps of 1 DMT symbol. (R,-W) (optional) (2-bytes)
//
//		Inm Inter_Arrival Time Step Downstream
//			INM inter-arrival time step downstream: INMIATSds is the IAT step that the xTU-R receiver uses
//			to determine in which bin of the IAT histogram the IAT is reported. Valid values for INMIATS
//			range from 0 to 7 in steps of 1. (R,-W) (optional) (1-byte)
//
//		Inm Cluster Continuation Value Downstream
//			INM cluster continuation value downstream: INMCCds is the cluster continuation value that the
//			xTU-R receiver uses in the cluster indication process described in the applicable
//			Recommendation. Valid values for INMCC range from 0 to 64 DMT symbols in steps of 1 DMT symbol.
//			(R,-W) (optional) (1-byte)
//
//		Inm Equivalent Inp Mode Downstream
//			INM equivalent INP mode downstream: INM_INPEQ_MODEds is the INM equivalent INP mode that the
//			xTU-R receiver uses in the computation of the equivalent INP, as defined in the applicable
//			Recommendation. Valid values for INM_INPEQ_MODE are 0..4. (R,-W) (optional) (1-byte)
//
type XdslLineConfigurationProfilePart3 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdsllineconfigurationprofilepart3BME = &ManagedEntityDefinition{
		Name:    "XdslLineConfigurationProfilePart3",
		ClassID: 106,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, false, 0),
			1:  ByteField("LoopDiagnosticsModeForcedLdsf", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 1),
			2:  ByteField("AutomodeColdStartForced", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 2),
			3:  ByteField("L2Atpr", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 3),
			4:  ByteField("L2Atprt", 0, mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, false, 4),
			5:  ByteField("ForceInpDownstream", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 5),
			6:  ByteField("ForceInpUpstream", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 6),
			7:  ByteField("UpdateRequestFlagForNearEndTestParameters", 0, mapset.NewSetWith(Read, Write), true, false, true, false, 7),
			8:  ByteField("UpdateRequestFlagForFarEndTestParameters", 0, mapset.NewSetWith(Read, Write), true, false, true, false, 8),
			9:  Uint16Field("InmInterArrivalTimeOffsetUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 9),
			10: ByteField("InmInterArrivalTimeStepUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 10),
			11: ByteField("InmClusterContinuationValueUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 11),
			12: ByteField("InmEquivalentInpModeUpstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 12),
			13: Uint16Field("InmInterArrivalTimeOffsetDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 13),
			14: ByteField("InmInterArrivalTimeStepDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 14),
			15: ByteField("InmClusterContinuationValueDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 15),
			16: ByteField("InmEquivalentInpModeDownstream", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 16),
		},
	}
}

// NewXdslLineConfigurationProfilePart3 (class ID 106 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineConfigurationProfilePart3(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdsllineconfigurationprofilepart3BME, params...)
}
