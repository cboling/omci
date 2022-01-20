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

// EthernetFrameExtendedPmClassID is the 16-bit ID for the OMCI
// Managed entity Ethernet frame extended PM
const EthernetFrameExtendedPmClassID = ClassID(334) // 0x014e

var ethernetframeextendedpmBME *ManagedEntityDefinition

// EthernetFrameExtendedPm (Class ID: #334 / 0x014e)
//	This ME collects some of the PM data at a point where an Ethernet flow can be observed. It is
//	based on the Etherstats group of [IETF RFC 2819]. Instances of this ME are created and deleted
//	by the OLT. References to received frames are to be interpreted as the number of frames entering
//	the monitoring point in the direction specified by the control block.
//
//	For a complete discussion of generic PM architecture, refer to clause I.4.
//
//	Relationships
//		An instance of this ME may be associated with an instance of an ME at any Ethernet interface
//		within the ONU. The specific ME is identified in the control block attribute.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. To facilitate discovery, the
//			identification of instances sequentially starting with 1 is encouraged. (R, setbycreate)
//			(mandatory) (2 bytes)
//
//		Interval End Time
//			This attribute identifies the most recently finished 15-min interval. If continuous accumulation
//			is enabled in the control block, this attribute is not used and has the fixed value 0. (R)
//			(mandatory) (1 byte)
//
//		Control Block
//			This attribute contains fields defined as follows.+
//
//			Threshold data 1/2 ID: (2 bytes) This attribute points to an instance of the threshold data 1 ME
//			that contains PM threshold values. Since no threshold value attribute number exceeds 7, a
//			threshold data 2 ME is optional. When PM is collected on a continuously running basis, rather
//			than in 15-min intervals, counter thresholds should not be established. There is no mechanism to
//			clear a TCA, and any counter parameter may eventually be expected to cross any given threshold
//			value.
//
//			Parent ME class: (2 bytes) This field contains the enumerated value of the ME class of the PM
//			ME's parent. Together with the parent ME instance field, this permits a given PM ME to be
//			associated with any OMCI ME. The supported ME classes are as follows.
//
//			46	MAC bridge configuration data
//
//			47	MAC bridge port configuration data
//
//			11	Physical path termination point Ethernet UNI
//
//			98	Physical path termination point xDSL UNI part 1
//
//			266	GEM IW termination point
//
//			281	Multicast GEM IW termination point
//
//			329	Virtual Ethernet interface point
//
//			162	Physical path termination point MoCA UNI
//
//			Parent ME instance: (2 bytes) This field identifies the specific parent ME instance to which the
//			PM ME is attached.
//
//			Accumulation disable: (2 bytes) This bit field allows PM accumulation to be disabled; refer to
//			Table 9.3.32-1. The default value 0 enables PM collection. If bit 15 is set to 1, no PM is
//			collected by this ME instance. If bit 15-=-0 and any of bits 14..1 are set to 1, PM collection
//			is inhibited for the attributes indicated by the 1 bits. Inhibiting PM collection does not
//			change the value of a PM attribute, but if PM is accumulated in 15-min intervals, the value is
//			lost at the next 15-min interval boundary.
//
//			Bit 16 is an action bit that always reads back as 0. When written to 1, it resets all PM
//			attributes in the ME, and clears any TCAs that may be outstanding.
//
//			TCA disable: (2 bytes). Also clarified in Table 9.3.32-1, this field permits TCAs to be
//			inhibited, either individually or for the complete ME instance. As with the accumulation disable
//			field, the default value 0 enables TCAs, and setting the global disable bit overrides the
//			settings of the individual thresholds. Unlike the accumulation disable field, the bits are
//			mapped to the thresholds defined in the associated threshold data 1 and 2 ME instances. When the
//			global or attribute-specific value changes from 0 to 1, outstanding TCAs are cleared, either for
//			the ME instance globally or for the individual disabled threshold. These bits affect only
//			notifications, not the underlying parameter accumulation or storage.
//
//			If the threshold data 1/2 ID attribute does not contain a valid pointer, this field is not
//			meaningful.
//
//			Thresholds should be used with caution if PM attributes are accumulated continuously.
//
//			Control fields: (2 bytes). This field is a bit map whose values govern the behaviour of the PM
//			ME. Bits are assigned as follows.
//
//			Bit 1 (LSB)	The value 1 specifies continuous accumulation, regardless of 15-min intervals. There
//			is no concept of current and historical accumulators; get and get current data (if supported)
//			both return current values. The value 0 specifies 15-min accumulators exactly like those of
//			classical PM.
//
//			Bit 2	This bit indicates directionality for the collection of data. The value 0 indicates that
//			data are to be collected for upstream traffic. The value 1 indicates that data are to be
//			collected for downstream traffic.
//
//			Bits 3..14	Reserved, should be set to 0 by the OLT and ignored by the ONU.
//
//			Bit 15	When this bit is 1, the P bits of the TCI field are used to filter the PM data collected.
//			The value 0 indicates that PM is collected without regard to P bits.
//
//			Bit 16	When this bit is 1, the VID bits of the TCI field are used to filter the PM data
//			collected. The value 0 indicates that PM is collected without regard to VID.
//
//			TCI: (2 bytes). This field contains the value optionally used as a filter for the PM data
//			collected, under the control of bits 15..16 of the control fields. This value is matched to the
//			outer tag of a frame. Untagged frames are not counted when this field is used.
//
//			Reserved: (2 bytes). Not used; should be set to 0 by the OLT and ignored by the ONU.
//
//			(R, W, setbycreate) (mandatory) (16 bytes)
//
//		Drop Events
//			The total number of events in which frames were dropped due to a lack of resources. This is not
//			necessarily the number of frames dropped; it is the number of times this event was detected. (R)
//			(mandatory) (4 bytes)
//
//		Octets
//			The total number of octets received, including those in bad frames, excluding framing bits, but
//			including FCS. (R) (mandatory) (4 bytes)
//
//		Frames
//			The total number of frames received, including bad frames, broadcast frames and multicast
//			frames. (R) (mandatory) (4 bytes)
//
//		Broadcast Frames
//			The total number of received good frames directed to the broadcast address. This does not
//			include multicast frames. (R) (mandatory) (4 bytes)
//
//		Multicast Frames
//			The total number of received good frames directed to a multicast address. This does not include
//			broadcast frames. (R) (mandatory) (4 bytes)
//
//		Crc Errored Frames
//			The total number of frames received that had a length (excluding framing bits, but including FCS
//			octets) of between 64 and 1518 octets, inclusive, but had either a bad FCS with an integral
//			number of octets (FCS error) or a bad FCS with a non-integral number of octets (alignment
//			error). (R) (mandatory) (4 bytes)
//
//		Undersize Frames
//			The total number of frames received that were less than 64 octets long but were otherwise well
//			formed (excluding framing bits, but including FCS octets). (R) (mandatory) (4 bytes)
//
//		Oversize Frames
//			The total number of frames received that were longer than 1518 octets (excluding framing bits,
//			but including FCS octets) and were otherwise well formed. (R) (mandatory) (4 bytes)
//
//		Frames 64 Octets
//			The total number of received frames (including bad frames) that were 64-octets long, excluding
//			framing bits but including FCS. (R) (mandatory) (4-bytes)
//
//		Frames 65 To 127 Octets
//			The total number of received frames (including bad frames) that were 65..127 octets long,
//			excluding framing bits but including FCS. (R) (mandatory) (4 bytes)
//
//		Frames 128 To 255 Octets
//			The total number of frames (including bad frames) received that were 128..255 octets long,
//			excluding framing bits but including FCS. (R) (mandatory) (4 bytes)
//
//		Frames 256 To 511 Octets
//			The total number of frames (including bad frames) received that were 256..511 octets long,
//			excluding framing bits but including FCS. (R) (mandatory) (4 bytes)
//
//		Frames 512 To 1 023 Octets
//			Frames 512 to 1-023 octets: The total number of frames (including bad frames) received that were
//			512..1-023 octets long, excluding framing bits but including FCS. (R) (mandatory) (4 bytes)
//
//		Frames 1024 To 1518 Octets
//			The total number of frames (including bad frames) received that were 1024..1518 octets long,
//			excluding framing bits but including FCS. (R) (mandatory) (4 bytes)
//
type EthernetFrameExtendedPm struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	ethernetframeextendedpmBME = &ManagedEntityDefinition{
		Name:    "EthernetFrameExtendedPm",
		ClassID: 334,
		MessageTypes: mapset.NewSetWith(
			Create,
			Delete,
			Get,
			Set,
			GetCurrentData,
		),
		AllowedAttributeMask: 0xffff,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read, SetByCreate), false, false, false, 0),
			1:  ByteField("IntervalEndTime", UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  MultiByteField("ControlBlock", OctetsAttributeType, 0x4000, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read, SetByCreate, Write), false, false, false, 2),
			3:  Uint32Field("DropEvents", CounterAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint32Field("Octets", CounterAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  Uint32Field("Frames", CounterAttributeType, 0x0800, 0, mapset.NewSetWith(Read), false, false, false, 5),
			6:  Uint32Field("BroadcastFrames", CounterAttributeType, 0x0400, 0, mapset.NewSetWith(Read), false, false, false, 6),
			7:  Uint32Field("MulticastFrames", CounterAttributeType, 0x0200, 0, mapset.NewSetWith(Read), false, false, false, 7),
			8:  Uint32Field("CrcErroredFrames", CounterAttributeType, 0x0100, 0, mapset.NewSetWith(Read), false, false, false, 8),
			9:  Uint32Field("UndersizeFrames", CounterAttributeType, 0x0080, 0, mapset.NewSetWith(Read), false, false, false, 9),
			10: Uint32Field("OversizeFrames", CounterAttributeType, 0x0040, 0, mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field("Frames64Octets", CounterAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field("Frames65To127Octets", CounterAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: Uint32Field("Frames128To255Octets", CounterAttributeType, 0x0008, 0, mapset.NewSetWith(Read), false, false, false, 13),
			14: Uint32Field("Frames256To511Octets", CounterAttributeType, 0x0004, 0, mapset.NewSetWith(Read), false, false, false, 14),
			15: Uint32Field("Frames512To1023Octets", CounterAttributeType, 0x0002, 0, mapset.NewSetWith(Read), false, false, false, 15),
			16: Uint32Field("Frames1024To1518Octets", CounterAttributeType, 0x0001, 0, mapset.NewSetWith(Read), false, false, false, 16),
		},
		Access:  CreatedByOlt,
		Support: UnknownSupport,
		Alarms: AlarmMap{
			1: "Drop events",
			2: "CRC errored frames",
			3: "Undersize frames",
			4: "Oversize frames",
		},
	}
}

// NewEthernetFrameExtendedPm (class ID 334) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewEthernetFrameExtendedPm(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*ethernetframeextendedpmBME, params...)
}
