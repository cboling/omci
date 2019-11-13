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

// OnuDynamicPowerManagementControlClassID is the 16-bit ID for the OMCI
// Managed entity ONU dynamic power management control
const OnuDynamicPowerManagementControlClassID ClassID = ClassID(336)

var onudynamicpowermanagementcontrolBME *ManagedEntityDefinition

// OnuDynamicPowerManagementControl (class ID #336)
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
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. There is only
//			one instance, number 0. (R) (mandatory) (2-bytes)
//
//		Power Reduction Management Capability
//			5..255	Reserved
//
//		Power Reduction Management Mode
//			Power reduction management mode: This attribute enables one or more of the ONU's managed power
//			conservation modes. It is a bit map in which the bit value 0 disables the mode, while the value
//			1 enables the mode. Bit assignments are the same as those of the power reduction management
//			capability attribute. The default value of each bit is 0. (R,-W) (mandatory) (1-byte)
//
//		Itransinit
//			Itransinit:	This attribute is the ONU vendor's statement of the complete transceiver
//			initialization time: the worst-case time required for the ONU to regain full functionality when
//			leaving the asleep state in cyclic sleep mode or low-power state in watchful sleep mode (i.e.,
//			turning on both the receiver and the transmitter and acquiring synchronization to the downstream
//			flow), measured in units of 125-us frames. The value zero indicates that the sleeping ONU can
//			respond to a bandwidth grant without delay. (R) (mandatory) (2-bytes)
//
//		Itxinit
//			Itxinit:	This attribute is the ONU vendor's statement of the transmitter initialization time:
//			the time required for the ONU to regain full functionality when leaving the listen state (i.e.,
//			turning on the transmitter), measured in units of 125-us frames. The value zero indicates that
//			the dozing ONU can respond to a bandwidth grant without delay. If watchful sleep is enabled, the
//			ONU ignores this attribute. (R) (mandatory) (2 bytes)
//
//		Maximum Sleep Interval
//			Maximum sleep interval: The Isleep/Ilowpower attribute specifies the maximum time the ONU spends
//			in its asleep, listen, or low-power states, as a count of 125-us frames. Local or remote events
//			may truncate the ONU's sojourn in these states. The default value of this attribute is 0. (R,-W)
//			(mandatory) (4-bytes)
//
//		Maximum Receiver_Off Interval
//			Maximum receiver-off interval: The Irxoff attribute specifies the maximum time the OLT can
//			afford to wait from the moment it decides to wake up an ONU in the low-power state of the
//			watchful sleep mode until the ONU is fully operational, specified as a count of 125-us frames.
//			(R,-W) (mandatory) (4-bytes)
//
//		Minimum Aware Interval
//			Minimum aware interval: The Iaware attribute specifies the time the ONU spends in its aware
//			state, as a count of 125-us frames, before it re-enters asleep or listen states. Local or remote
//			events may independently cause the ONU to enter an active state rather than returning to a sleep
//			state. The default value of this attribute is 0. (R,-W) (mandatory) (4-bytes)
//
//		Minimum Active Held Interval
//			Minimum active held interval: The Ihold attribute specifies the minimum time during which the
//			ONU remains in the active held state, as a count of 125-us frames. Its initial value is zero.
//			(R, W) (mandatory) (2-bytes)
//
//		Maximum Sleep Interval Extension
//			(R,-W) (optional) (8-bytes)
//
//		Ethernet Passive Optical Network Epon  Capability Extension
//			-	Configurations: ackEnable configuration = enable, Sleep indication configuration = disable,
//			Early wake-up configuration = enable
//
//		Epon Setup Extension
//			(R,-W) (optional) (1-byte)
//
//		Missing Consecutive Bursts Threshold
//			Missing consecutive bursts threshold: The Clobi attribute specifies the maximum number of
//			missing consecutive scheduled bursts from the ONU that the OLT is willing to tolerate without
//			raising an alarm. The value of this attribute defaults to 4. (R,-W) (mandatory) (4-bytes)
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
		AllowedAttributeMask: 0XFFF0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  ByteField("PowerReductionManagementCapability", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  ByteField("PowerReductionManagementMode", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 2),
			3:  Uint16Field("Itransinit", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint16Field("Itxinit", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint32Field("MaximumSleepInterval", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 5),
			6:  Uint32Field("MaximumReceiverOffInterval", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 6),
			7:  Uint32Field("MinimumAwareInterval", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 7),
			8:  Uint16Field("MinimumActiveHeldInterval", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 8),
			9:  Uint64Field("MaximumSleepIntervalExtension", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 9),
			10: ByteField("EthernetPassiveOpticalNetworkEponCapabilityExtension", 0, mapset.NewSetWith(Read), false, false, true, false, 10),
			11: ByteField("EponSetupExtension", 0, mapset.NewSetWith(Read, Write), false, false, true, false, 11),
			12: Uint32Field("MissingConsecutiveBurstsThreshold", 0, mapset.NewSetWith(Read, Write), false, false, false, false, 12),
		},
	}
}

// NewOnuDynamicPowerManagementControl (class ID 336 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewOnuDynamicPowerManagementControl(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*onudynamicpowermanagementcontrolBME, params...)
}
