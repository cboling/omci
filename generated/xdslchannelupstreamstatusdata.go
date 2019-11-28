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

// XdslChannelUpstreamStatusDataClassID is the 16-bit ID for the OMCI
// Managed entity xDSL channel upstream status data
const XdslChannelUpstreamStatusDataClassID ClassID = ClassID(103)

var xdslchannelupstreamstatusdataBME *ManagedEntityDefinition

// XdslChannelUpstreamStatusData (class ID #103)
//	This ME contains upstream channel status data for an xDSL UNI. The ONU automatically creates or
//	deletes instances of this ME upon the creation or deletion of a PPTP xDSL UNI part 1.
//
//	Relationships
//		One or more instances of this ME are associated with an instance of an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. The two MSBs of
//			the first byte are the bearer channel ID. Excluding the first 2-bits of the first byte, the
//			remaining part of the ME ID is identical to that of this ME's parent PPTP xDSL UNI part 1. (R)
//			(mandatory) (2-bytes)
//
//		Actual Interleaving Delay
//			Actual interleaving delay: This attribute is the actual one-way interleaving delay introduced by
//			the PMS-TC between the alpha and beta reference points, excluding the L1 and L2 states. In the
//			L1 and L2 states, this attribute contains the interleaving delay in the previous L0 state. For
//			ADSL, this attribute is derived from the S and D attributes as cap(S*D)/4-ms, where S is the
//			number of symbols per codeword, D is the interleaving depth and cap() denotes rounding to the
//			next higher integer. For [ITU-T G.993.2], this attribute is computed according to the formula in
//			clause 9.7 of [ITUT G.993.2]. The actual interleaving delay is coded in milliseconds, rounded to
//			the nearest millisecond. (R) (mandatory) (1-byte)
//
//		Actual Data Rate
//			Actual data rate: This parameter reports the actual net data rate of the bearer channel,
//			excluding the L1 and L2 states. In the L1 or L2 state, the parameter contains the net data rate
//			in the previous L0 state. The data rate is coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Previous Data Rate
//			Previous data rate: This parameter reports the previous net data rate of the bearer channel just
//			before the latest rate change event occurred, excluding transitions between the L0 state and the
//			L1 or L2 state. A rate change can occur at a power management state transition, e.g., at full or
//			short initialization, fast retrain or power down, or at a dynamic rate adaptation. The rate is
//			coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Actual Impulse Noise Protection
//			Actual impulse noise protection: The ACTINP attribute reports the actual INP on the bearer
//			channel in the L0 state. In the L1 or L2 state, the attribute contains the INP in the previous
//			L0 state. The value is coded in fractions of DMT symbols with a granularity of 0.1 symbols. The
//			range is from 0 (0.0 symbols) to 254 (25.4 symbols). The special value 255 indicates an ACTINP
//			higher than 25.4. (R) (mandatory for ITU-T G.993.2 VDSL2, optional for other xDSL
//			Recommendations that support it) (1-byte)
//
//		Impulse Noise Protection Reporting Mode
//			Impulse noise protection reporting mode: The INPREPORT attribute reports the method used to
//			compute the ACTINP. If set to 0, the ACTINP is computed according to the INP_no_erasure formula
//			(clause 9.6 of [ITUT G.993.2]). If set to 1, ACTINP is the value estimated by the xTU receiver.
//			(R) (mandatory for  ITU-T G.993.2 VDSL2) (1-byte)
//
//		Actual Size Of Reed_Solomon Codeword
//			Actual size of Reed-Solomon codeword: The NFEC attribute reports the actual Reed-Solomon
//			codeword size used in the latency path in which the bearer channel is transported. Its value is
//			coded in bytes in the range 0..255. (R) (mandatory for ITU-T G.993.2 VDSL2, optional for others)
//			(1-byte)
//
//		Actual Number Of Reed_Solomon Redundancy Bytes
//			Actual number of Reed-Solomon redundancy bytes: The RFEC attribute reports the actual number of
//			Reed-Solomon redundancy bytes per codeword used in the latency path in which the bearer channel
//			is transported. Its value is coded in bytes in the range 0..16. The value 0 indicates no Reed-
//			Solomon coding. (R) (mandatory for ITUT-G.993.2 VDSL2, optional for others) (1-byte)
//
//		Actual Number Of Bits Per Symbol
//			Actual number of bits per symbol: The LSYMB attribute reports the actual number of bits per
//			symbol assigned to the latency path in which the bearer channel is transported, excluding
//			trellis overhead. Its value is coded in bits in the range 0..65535. (R) (mandatory for
//			ITUT-G.993.2 VDSL2, optional for others) (2-bytes)
//
//		Actual Interleaving Depth
//			Actual interleaving depth: The INTLVDEPTH attribute reports the actual depth of the interleaver
//			used in the latency path in which the bearer channel is transported. Its value ranges from
//			1..4096 in steps of 1. The value 1 indicates no interleaving. (R) (mandatory for ITU-T G.993.2
//			VDSL2, optional for others) (2-bytes)
//
//		Actual Interleaving Block Length
//			Actual interleaving block length: The INTLVBLOCK attribute reports the actual block length of
//			the interleaver used in the latency part in which the bearer channel is transported. Its value
//			ranges from 4..255 in steps of 1. (R) (mandatory forITU-T G.993.2 VDSL2, optional for others)
//			(1-byte)
//
//		Actual Latency Path
//			Actual latency path: The LPATH attribute reports the index of the actual latency path in which
//			the bearer channel is transported. Valid values are 0..3. In [ITUT-G.992.1], the fast path is
//			mapped to latency index 0; the interleaved path to index 1. (R) (mandatory for ITU-T G.993.2
//			VDSL2, optional for others) (1-byte)
//
type XdslChannelUpstreamStatusData struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdslchannelupstreamstatusdataBME = &ManagedEntityDefinition{
		Name:    "XdslChannelUpstreamStatusData",
		ClassID: 103,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xffe0,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  ByteField("ActualInterleavingDelay", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint32Field("ActualDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3:  Uint32Field("PreviousDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  ByteField("ActualImpulseNoiseProtection", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  ByteField("ImpulseNoiseProtectionReportingMode", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  ByteField("ActualSizeOfReedSolomonCodeword", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  ByteField("ActualNumberOfReedSolomonRedundancyBytes", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint16Field("ActualNumberOfBitsPerSymbol", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint16Field("ActualInterleavingDepth", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: ByteField("ActualInterleavingBlockLength", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
			11: ByteField("ActualLatencyPath", 0, mapset.NewSetWith(Read), false, false, false, false, 11),
		},
		Access:  UnknownAccess,
		Support: UnknownSupport,
	}
}

// NewXdslChannelUpstreamStatusData (class ID 103) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslChannelUpstreamStatusData(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdslchannelupstreamstatusdataBME, params...)
}
