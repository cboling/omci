/*
 * Copyright (c) 2018 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

// OnuDynamicPowerManagementControlClassID is the 16-bit ID for the OMCI
// Managed entity ONU dynamic power management control
const OnuDynamicPowerManagementControlClassID = ClassID(336) // 0x0150

var onudynamicpowermanagementcontrolBME *ManagedEntityDefinition

// OnuDynamicPowerManagementControl (Class ID: #336 / 0x0150)
//	This ME models the ONU's ability to enter power conservation modes in cooperation with the OLT
//	in an ITU-T G.987 system. [ITUT G.987.3] originally specified two alternative modes, doze and
//	cyclic sleep. The subsequent revision of [ITUT G.987.3] simplified the specification providing a
//	single power conservation mode, watchful sleep.
//
//	An ONU that supports power conservation modes automatically creates an instance of this ME.
//
//	Relationships
//		One instance of this ME is associated with the ONU ME.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. There is only one instance, number
//			0. (R) (mandatory) (2-bytes)
//
//		Power Reduction Management Capability
//			This attribute declares the ONU's support for managed power conservation modes, as defined in
//			[ITUT G.987.3]. It is a bit map in which the bit value 0 indicates no support for the specified
//			mode, while the bit value 1 indicates that the ONU does support the specified mode. (R)
//			(mandatory) (1-byte)
//
//			Codepoints are assigned as follows:
//
//			Value	Meaning
//
//			0	No support for power reduction
//
//			1	Doze mode supported
//
//			2	Cyclic sleep mode supported
//
//			3	Both doze and cyclic sleep modes supported
//
//			4	Watchful sleep mode supported
//
//			5..255	Reserved
//
//		Power Reduction Management Mode
//			This attribute enables one or more of the ONU's managed power conservation modes. It is a bit
//			map in which the bit value 0 disables the mode, while the value 1 enables the mode. Bit
//			assignments are the same as those of the power reduction management capability attribute. The
//			default value of each bit is 0. (R,-W) (mandatory) (1-byte)
//
//		Itransinit
//			This attribute is the ONU vendor's statement of the complete transceiver initialization time:
//			the worst-case time required for the ONU to regain full functionality when leaving the asleep
//			state in cyclic sleep mode or low-power state in watchful sleep mode (i.e., turning on both the
//			receiver and the transmitter and acquiring synchronization to the downstream flow), measured in
//			units of 125-us frames. The value zero indicates that the sleeping ONU can respond to a
//			bandwidth grant without delay. (R) (mandatory) (2-bytes)
//
//		Itxinit
//			This attribute is the ONU vendor's statement of the transmitter initialization time: the time
//			required for the ONU to regain full functionality when leaving the listen state (i.e., turning
//			on the transmitter), measured in units of 125-us frames. The value zero indicates that the
//			dozing ONU can respond to a bandwidth grant without delay. If watchful sleep is enabled, the ONU
//			ignores this attribute. (R) (mandatory) (2 bytes)
//
//		Maximum Sleep Interval
//			The Isleep/Ilowpower attribute specifies the maximum time the ONU spends in its asleep, listen,
//			or low-power states, as a count of 125-us frames. Local or remote events may truncate the ONU's
//			sojourn in these states. The default value of this attribute is 0. (R,-W) (mandatory) (4-bytes)
//
//		Maximum Receiver_Off Interval
//			Maximum receiver-off interval: The Irxoff attribute specifies the maximum time the OLT can
//			afford to wait from the moment it decides to wake up an ONU in the low-power state of the
//			watchful sleep mode until the ONU is fully operational, specified as a count of 125-us frames.
//			(R,-W) (mandatory) (4-bytes)
//
//		Minimum Aware Interval
//			The Iaware attribute specifies the time the ONU spends in its aware state, as a count of 125-us
//			frames, before it re-enters asleep or listen states. Local or remote events may independently
//			cause the ONU to enter an active state rather than returning to a sleep state. The default value
//			of this attribute is 0. (R,-W) (mandatory) (4-bytes)
//
//		Minimum Active Held Interval
//			The Ihold attribute specifies the minimum time during which the ONU remains in the active held
//			state, as a count of 125-us frames. Its initial value is zero. (R, W) (mandatory) (2-bytes)
//
//		Maximum Sleep Interval Extension
//			Maximum sleep interval for doze mode specifies the maximum time the ONU spends in its listen
//			state, as a count of 125-us frames. Local or remote events may truncate the ONU's sojourn in
//			these states. The default value is 0.
//
//			Maximum sleep interval for cyclic sleep mode specifies the maximum time the ONU spends in its
//			asleep state, as a count of 125-us frames. Local or remote events may truncate the ONU's sojourn
//			in these states. The default value is 0. If watchful sleep is enabled, the ONU ignores this
//			attribute.
//
//			(R,-W) (optional) (8-bytes)
//
//			This attribute designates maximum sleep interval values for doze mode and cyclic sleep mode
//			separately. When it supports this attribute, the ONU ignores the value of the maximum sleep
//			interval attribute.
//
//			Maximum sleep interval for doze mode	4-bytes
//
//			Maximum sleep interval for cyclic sleep mode	4-bytes
//
//		Ethernet Passive Optical Network Epon Capability Extension
//			Ethernet passive optical network (EPON) capability extension: This attribute declares EPON-
//			specific capabilities for the dynamic power management control.
//
//			Bits are assigned as follows.
//
//		Epon Setup Extension
//			The bits are assigned as follows.
//
//			This attribute specifies EPON specific configurations for the dynamic power management control.
//
//		Missing Consecutive Bursts Threshold
//			The Clobi attribute specifies the maximum number of missing consecutive scheduled bursts from
//			the ONU that the OLT is willing to tolerate without raising an alarm. The value of this
//			attribute defaults to 4. (R,-W) (mandatory) (4-bytes)
//
type OnuDynamicPowerManagementControl struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	onudynamicpowermanagementcontrolBME = &ManagedEntityDefinition{
		Name:    "OnuDynamicPowerManagementControl",
		ClassID: 336,
		MessageTypes: mapset.NewSetWith(
			Get,
			Set,
		),
		AllowedAttributeMask: 0xfff0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  ByteField("PowerReductionManagementCapability", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  ByteField("PowerReductionManagementMode", UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read, Write), false, false, false, 2),
			3:  Uint16Field("Itransinit", UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint16Field("Itxinit", UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("MaximumSleepInterval", UnsignedIntegerAttributeType, 0x0800, 0, mapset.NewSetWith(Read, Write), false, false, false, 5),
			6:  Uint32Field("MaximumReceiverOffInterval", UnsignedIntegerAttributeType, 0x0400, 0, mapset.NewSetWith(Read, Write), false, false, false, 6),
			7:  Uint32Field("MinimumAwareInterval", UnsignedIntegerAttributeType, 0x0200, 0, mapset.NewSetWith(Read, Write), false, false, false, 7),
			8:  Uint16Field("MinimumActiveHeldInterval", UnsignedIntegerAttributeType, 0x0100, 0, mapset.NewSetWith(Read, Write), false, false, false, 8),
			9:  Uint64Field("MaximumSleepIntervalExtension", UnsignedIntegerAttributeType, 0x0080, 0, mapset.NewSetWith(Read, Write), false, true, false, 9),
			10: ByteField("EthernetPassiveOpticalNetworkEponCapabilityExtension", UnsignedIntegerAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, true, false, 10),
			11: ByteField("EponSetupExtension", UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read, Write), false, true, false, 11),
			12: Uint32Field("MissingConsecutiveBurstsThreshold", UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read, Write), false, false, false, 12),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewOnuDynamicPowerManagementControl (class ID 336) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewOnuDynamicPowerManagementControl(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*onudynamicpowermanagementcontrolBME, params...)
}
