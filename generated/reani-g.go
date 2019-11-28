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

// ReAniGClassID is the 16-bit ID for the OMCI
// Managed entity RE ANI-G
const ReAniGClassID ClassID = ClassID(313)

var reanigBME *ManagedEntityDefinition

// ReAniG (class ID #313)
//	This ME organizes data associated with each R'/S' physical interface of an RE if the RE supports
//	OEO regeneration in either direction. The management ONU automatically creates one instance of
//	this ME for each R'/S' physical port (uni- or bidirectional) as follows.
//
//	o	When the RE has mid-span PON RE ANI interface ports built into its 	factory configuration.
//
//	o	When a cardholder is provisioned to expect a circuit pack of the mid-span PON RE ANI type.
//
//	o	When a cardholder provisioned for plug-and-play is equipped with a circuit pack of the midspan
//	PON RE ANI type. Note that the installation of a plug-and-play card may indicate the presence of
//	a mid-span PON RE ANI port via equipment ID as well as its type attribute, and indeed may cause
//	the management ONU to instantiate a port-mapping package to specify the ports precisely.
//
//	The management ONU automatically deletes instances of this ME when a cardholder is neither
//	provisioned to expect a mid-span PON RE ANI circuit pack, nor is it equipped with a mid-span PON
//	RE ANI circuit pack.
//
//	As illustrated in Figure 8.2.10-4, an RE ANI-G may share the physical port with an RE downstream
//	amplifier. The ONU declares a shared configuration through the port-mapping package combined
//	port table, whose structure defines one ME as the master. It is recommended that the RE ANI-G be
//	the master, with the RE downstream amplifier as a secondary ME.
//
//	The administrative state, operational state and ARC attributes of the master ME override similar
//	attributes in secondary MEs associated with the same port. In the secondary ME, these attributes
//	are present, but cause no action when written and have undefined values when read. The RE
//	downstream amplifier should use its provisionable downstream alarm thresholds and should declare
//	downstream alarms as necessary; other isomorphic alarms should be declared by the RE ANI-G. The
//	test action should be addressed to the master ME.
//
//	Relationships
//		An instance of this ME is associated with each R'/S' physical interface of an RE that includes
//		OEO regeneration in either direction, and with one or more instances of the PPTP RE UNI. It may
//		also be associated with an RE downstream amplifier.
//
//	Attributes
//		Managed Entity Id
//			NOTE 1 - This ME ID may be identical to that of an RE downstream amplifier if it shares the same
//			physical slot and port.
//
//		Administrative State
//			NOTE 2 - When an RE supports multiple PONs, or protected access to a single PON, its primary
//			ANI-G cannot be completely shut down, due to a loss of the management communications capability.
//			Complete blocking of service and removal of power may nevertheless be appropriate for secondary
//			RE ANI-Gs. Administrative lock suppresses alarms and notifications for an RE ANI-G, be it either
//			primary or secondary.
//
//		Operational State
//			Operational state: This attribute indicates whether the ME is capable of performing its
//			function. Valid values are enabled (0) and disabled (1). (R) (optional) (1-byte)
//
//		Arc
//			ARC:	See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Arc Interval
//			ARC interval: See clause A.1.4.3. (R,-W) (optional) (1-byte)
//
//		Optical Signal Level
//			Optical signal level: This attribute reports the current measurement of total downstream optical
//			power. Its value is a 2s complement integer referred to 1-mW (i.e., dBm), with 0.002-dB
//			granularity. (R) (optional) (2-bytes)
//
//		Lower Optical Threshold
//			Lower optical threshold: This attribute specifies the optical level that the RE uses to declare
//			the downstream low received optical power alarm. Valid values are  -127-dBm (coded as 254) to
//			0-dBm (coded as 0) in 0.5-dB increments. The default value 0xFF selects the RE's internal
//			policy. (R,-W) (optional) (1-byte)
//
//		Upper Optical Threshold
//			Upper optical threshold: This attribute specifies the optical level that the RE uses to declare
//			the downstream high received optical power alarm. Valid values are  -127-dBm (coded as 254) to
//			0-dBm (coded as 0) in 0.5 dB increments. The default value 0xFF selects the RE's internal
//			policy. (R,-W) (optional) (1-byte)
//
//		Transmit Optical Level
//			Transmit optical level: This attribute reports the current measurement of mean optical launch
//			power. Its value is a 2s complement integer referred to 1-mW (i.e., dBm), with 0.002-dB
//			granularity. (R) (optional) (2-bytes)
//
//		Lower Transmit Power Threshold
//			Lower transmit power threshold: This attribute specifies the minimum mean optical launch power
//			that the RE uses to declare the low transmit optical power alarm. Its value is a 2s-complement
//			integer referred to 1-mW (i.e., dBm), with 0.5-dB granularity. The default value 0x7F selects
//			the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Upper Transmit Power Threshold
//			Upper transmit power threshold: This attribute specifies the maximum mean optical launch power
//			that the RE uses to declare the high transmit optical power alarm. Its value is a 2s-complement
//			integer referred to 1-mW (i.e., dBm), with 0.5-dB granularity. The default value 0x7F selects
//			the RE's internal policy. (R,-W) (optional) (1-byte)
//
//		Usage Mode
//			3	This R'/S' interface is used as the uplink for both the embedded management ONU and one or
//			more PPTP RE UNI(s) (in a time division fashion).
//
//		Target Upstream Frequency
//			Target upstream frequency: This attribute specifies the frequency of the converted upstream
//			signal on the optical trunk line (OTL), in gigahertz. The converted frequency must conform to
//			the frequency plan specified in [ITUT G.984.6]. The value 0 means that the upstream signal
//			frequency remains the same as the original frequency; no frequency conversion is done. If the RE
//			does not support provisionable upstream frequency (wavelength), this attribute should take the
//			fixed value representing the RE's capability and the RE should deny attempts to set the value of
//			the attribute. If the RE does support provisionable upstream frequency conversion, the default
//			value of this attribute is 0. (R, W) (optional) (4 bytes).
//
//		Target Downstream Frequency
//			Target downstream frequency: This attribute specifies the frequency of the downstream signal
//			received by the RE on the OTL, in gigahertz. The incoming frequency must conform to the
//			frequency plan specified in [ITUT G.984.6]. The default value 0 means that the downstream
//			frequency remains the same as its original frequency; no frequency conversion is done. If the RE
//			does not support provisionable downstream frequency selectivity, this attribute should take the
//			fixed value representing the RE's capability, and the RE should deny attempts to set the value
//			of the attribute. If the RE does support provisionable downstream frequency selectivity, the
//			default value of this attribute is 0. (R, W) (optional) (4 bytes).
//
//		Upstream Signal Transmission Mode
//			Upstream signal transmission mode: When true, this Boolean attribute enables conversion from
//			burst mode to continuous mode. The default value false specifies burst mode upstream
//			transmission. If the RE does not have the ability to convert from burst to continuous mode
//			transmission, it should deny attempts to set this attribute to true. (R, W) (optional) (1 byte)
//
type ReAniG struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	reanigBME = &ManagedEntityDefinition{
		Name:    "ReAniG",
		ClassID: 313,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfffc,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  ByteField("AdministrativeState", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 1),
			2:  ByteField("OperationalState", 0, mapset.NewSetWith(Read), true, false, true, false, 2),
			3:  ByteField("Arc", 0, mapset.NewSetWith(Read, Write), true, false, true, false, 3),
			4:  ByteField("ArcInterval", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 4),
			5:  Uint16Field("OpticalSignalLevel", 0, mapset.NewSetWith(Read), false, false, true, false, 5),
			6:  ByteField("LowerOpticalThreshold", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 6),
			7:  ByteField("UpperOpticalThreshold", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 7),
			8:  Uint16Field("TransmitOpticalLevel", 0, mapset.NewSetWith(Read), false, false, true, false, 8),
			9:  ByteField("LowerTransmitPowerThreshold", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 9),
			10: ByteField("UpperTransmitPowerThreshold", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 10),
			11: ByteField("UsageMode", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 11),
			12: Uint32Field("TargetUpstreamFrequency", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 12),
			13: Uint32Field("TargetDownstreamFrequency", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 13),
			14: ByteField("UpstreamSignalTransmissionMode", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 14),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewReAniG (class ID 313) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewReAniG(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*reanigBME, params...)
}
