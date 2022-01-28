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

// XdslLineInventoryAndStatusDataPart1ClassID is the 16-bit ID for the OMCI
// Managed entity xDSL line inventory and status data part 1
const XdslLineInventoryAndStatusDataPart1ClassID = ClassID(100) // 0x0064

var xdsllineinventoryandstatusdatapart1BME *ManagedEntityDefinition

// XdslLineInventoryAndStatusDataPart1 (Class ID: #100 / 0x0064)
//	This ME contains part 1 of the line inventory and status data for an xDSL UNI. The ONU
//	automatically creates or deletes an instance of this ME upon the creation or deletion of a PPTP
//	xDSL UNI part 1.
//
//	Relationships
//		An instance of this ME is associated with an xDSL UNI.
//
//	Attributes
//		Managed Entity Id
//			This attribute uniquely identifies each instance of this ME. Through an identical ID, this ME is
//			implicitly linked to an instance of the PPTP xDSL UNI part 1. (R) (mandatory) (2-bytes)
//
//		Xtu_C G.994.1 Vendor Id
//			xTU-C G.994.1 vendor ID: This is the vendor ID as inserted by the xTU-C in the ITUT-G.994.1 CL
//			message. It comprises 8 octets, including a country code followed by a (regionally allocated)
//			provider code, as defined in [ITUT-T.35]. (R) (mandatory) (8-bytes)
//
//		Xtu_R G.994.1 Vendor Id
//			xTU-R G.994.1 vendor ID: This is the vendor ID as inserted by the xTU-R in the ITUT-G.994.1 CLR
//			message. It comprises 8 binary octets, with the same format as the xTUC ITUT G.994.1 vendor ID.
//			(R) (mandatory) (8-bytes)
//
//		Xtu_C System Vendor Id
//			xTU-C system vendor ID: This is the vendor ID as inserted by the xTU-C in the overhead messages
//			of [ITU-T G.992.3] and [ITU-T G.992.4]. It comprises 8 binary octets, with the same format as
//			the xTU-C ITUT-G.994.1 vendor ID. (R) (mandatory) (8-bytes)
//
//		Xtu_R System Vendor Id
//			xTU-R system vendor ID: This is the vendor ID as inserted by the xTU-R in the embedded
//			operations channel and overhead messages of [ITU-T G.992.3] and [ITUT-G.992.4]. It comprises 8
//			binary octets, with the same format as the xTU-C ITUT-G.994.1 vendor ID. (R) (mandatory)
//			(8-bytes)
//
//		Xtu_C Version Number
//			xTU-C version number: This is the vendorspecific version number as inserted by the xTUC in the
//			overhead messages of [ITU-T G.992.3] and [ITU-T G.992.4]. It comprises up to 16 binary octets.
//			(R) (mandatory) (16-bytes)
//
//		Xtu_R Version Number
//			xTU-R version number: This is the version number as inserted by the xTUR in the embedded
//			operations channel of [ITU-T G.992.1] or [ITU-T G.992.2], or the overhead messages of [ITU-T
//			G.992.3], [ITU-T G.992.4], [ITU-T G.992.5] and [ITU-T G.993.2]. The attribute value may be
//			vendor-specific, but is recommended to comprise up to 16 ASCII characters, null-terminated if it
//			is shorter than 16. The string should contain the xTU-R firmware version and the xTU-R model,
//			encoded in that order and separated by a space character: "<xTU-R firmware version><xTU-R
//			model>". It is recognized that legacy xTU-Rs may not support this format. (R) (mandatory)
//			(16-bytes)
//
//		Xtu_C Serial Number Part 1
//			xTU-C serial number part 1: The vendorspecific serial number inserted by the xTU-C in the
//			overhead messages of [ITU-T G.992.3] and [ITU-T G.992.4] comprises up to 32 ASCII characters,
//			null terminated if it is shorter than 32 characters. This attribute contains the first 16
//			characters. (R) (mandatory) (16-bytes)
//
//		Xtu_C Serial Number Part 2
//			xTU-C serial number part 2: This attribute contains the second 16 characters of the xTU-C serial
//			number. (R) (mandatory) (16-bytes)
//
//		Xtu_R Serial Number Part 1
//			xTU-R serial number part 1: The serial number inserted by the xTU-R in the embedded operations
//			channel of [ITU-T G.992.1] or [ITU-T G.992.2], or the overhead messages of [ITU-T G.992.3],
//			[ITU-T G.992.4], [ITU-T G.992.5] and [ITUT-G.993.2], comprises up to 32 ASCII characters,
//			nullterminated if it is shorter than 32. It is recommended that the equipment serial number, the
//			equipment model and the equipment firmware version, encoded in that order and separated by space
//			characters, be contained: "<equipment serial number><equipment model><equipment firmware
//			version>". It is recognized that legacy xTU-Rs may not support this format. This attribute
//			contains the first 16 characters. (R) (mandatory) (16-bytes)
//
//		Xtu_R Serial Number Part 2
//			xTU-R serial number part 2: This attribute contains the second 16 characters of the xTU-R serial
//			number. (R) (mandatory) (16-bytes)
//
//		Xtu_C Self Test Results
//			xTU-C selftest results: This parameter reports the xTU-C self-test result. It is coded in two
//			fields. The most significant octet is 0 if the self-test passed and 1 if it failed. The three
//			least significant octets are a vendor-discretionary integer that can be interpreted in
//			combination with [ITU-T G.994.1] and the system vendor ID. (R) (mandatory) (4-bytes)
//
//		Xtu_R Self Test Results
//			xTU-R selftest results: This parameter defines the xTU-R self-test result. It is coded in two
//			fields. The most significant octet is 0 if the self-test passed and 1 if it failed. The three
//			least significant octets are a vendor-discretionary integer that can be interpreted in
//			combination with [ITU-T G.994.1] and the system vendor ID. (R) (mandatory) (4-bytes)
//
//		Xtu_C Transmission System Capability
//			xTU-C transmission system capability: This attribute lists xTUC transmission system
//			capabilities. It is a bit map, defined in Table 9.7.12-1. (R) (mandatory) (7-bytes)
//
//			NOTE 1 - This attribute is only 7-bytes long. An eighth byte identifying VDSL2 capabilities is
//			defined in the VDSL2 line inventory and status data part 1 ME.
//
//		Xtu_R Transmission System Capability
//			xTU-R transmission system capability: This attribute lists xTUR transmission system
//			capabilities. It is a bit map, defined in Table 9.7.121. (R) (mandatory) (7-bytes)
//
//			NOTE 2 - This attribute is only 7-bytes long. An eighth byte identifying VDSL2 capabilities is
//			defined in the VDSL2 line inventory and status data part 2 ME.
//
//		Initialization Success_Failure Cause
//			(R) (mandatory) (1-byte)
//
//			Initialization success/failure cause: This parameter represents the success or failure cause of
//			the last full initialization performed on the line. It is coded as follows.
//
//			0	Successful
//
//			1	Configuration error
//
//			This error occurs with inconsistencies in configuration parameters, e.g., when the line is
//			initialized in an xDSL transmission system whose xTU does not support the configured maximum
//			delay or the configured minimum or maximum data rate for one or more bearer channels.
//
//			2	Configuration not feasible on the line
//
//			This error occurs if the minimum data rate cannot be achieved on the line with the minimum noise
//			margin, maximum PSD level, maximum delay and maximum bit error ratio for one or more bearer
//			channels.
//
//			3	Communication problem
//
//			This error occurs, for example, due to corrupted messages, bad syntax messages, if no common
//			mode can be selected in the ITUT-G.994.1 handshake procedure or due to a timeout.
//
//			4	No peer xTU detected
//
//			This error occurs if the peer xTU is not powered or not connected or if the line is too long to
//			allow detection of a peer xTU.
//
//			5	Any other or unknown initialization failure cause.
//
type XdslLineInventoryAndStatusDataPart1 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

// Attribute name constants

const XdslLineInventoryAndStatusDataPart1_XtuCG9941VendorId = "XtuCG9941VendorId"
const XdslLineInventoryAndStatusDataPart1_XtuRG9941VendorId = "XtuRG9941VendorId"
const XdslLineInventoryAndStatusDataPart1_XtuCSystemVendorId = "XtuCSystemVendorId"
const XdslLineInventoryAndStatusDataPart1_XtuRSystemVendorId = "XtuRSystemVendorId"
const XdslLineInventoryAndStatusDataPart1_XtuCVersionNumber = "XtuCVersionNumber"
const XdslLineInventoryAndStatusDataPart1_XtuRVersionNumber = "XtuRVersionNumber"
const XdslLineInventoryAndStatusDataPart1_XtuCSerialNumberPart1 = "XtuCSerialNumberPart1"
const XdslLineInventoryAndStatusDataPart1_XtuCSerialNumberPart2 = "XtuCSerialNumberPart2"
const XdslLineInventoryAndStatusDataPart1_XtuRSerialNumberPart1 = "XtuRSerialNumberPart1"
const XdslLineInventoryAndStatusDataPart1_XtuRSerialNumberPart2 = "XtuRSerialNumberPart2"
const XdslLineInventoryAndStatusDataPart1_XtuCSelfTestResults = "XtuCSelfTestResults"
const XdslLineInventoryAndStatusDataPart1_XtuRSelfTestResults = "XtuRSelfTestResults"
const XdslLineInventoryAndStatusDataPart1_XtuCTransmissionSystemCapability = "XtuCTransmissionSystemCapability"
const XdslLineInventoryAndStatusDataPart1_XtuRTransmissionSystemCapability = "XtuRTransmissionSystemCapability"
const XdslLineInventoryAndStatusDataPart1_InitializationSuccessFailureCause = "InitializationSuccessFailureCause"

func init() {
	xdsllineinventoryandstatusdatapart1BME = &ManagedEntityDefinition{
		Name:    "XdslLineInventoryAndStatusDataPart1",
		ClassID: XdslLineInventoryAndStatusDataPart1ClassID,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0xfffe,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field(ManagedEntityID, PointerAttributeType, 0x0000, 0, mapset.NewSetWith(Read), false, false, false, 0),
			1:  Uint64Field(XdslLineInventoryAndStatusDataPart1_XtuCG9941VendorId, UnsignedIntegerAttributeType, 0x8000, 0, mapset.NewSetWith(Read), false, false, false, 1),
			2:  Uint64Field(XdslLineInventoryAndStatusDataPart1_XtuRG9941VendorId, UnsignedIntegerAttributeType, 0x4000, 0, mapset.NewSetWith(Read), false, false, false, 2),
			3:  Uint64Field(XdslLineInventoryAndStatusDataPart1_XtuCSystemVendorId, UnsignedIntegerAttributeType, 0x2000, 0, mapset.NewSetWith(Read), false, false, false, 3),
			4:  Uint64Field(XdslLineInventoryAndStatusDataPart1_XtuRSystemVendorId, UnsignedIntegerAttributeType, 0x1000, 0, mapset.NewSetWith(Read), false, false, false, 4),
			5:  MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuCVersionNumber, OctetsAttributeType, 0x0800, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 5),
			6:  MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuRVersionNumber, OctetsAttributeType, 0x0400, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 6),
			7:  MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuCSerialNumberPart1, OctetsAttributeType, 0x0200, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 7),
			8:  MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuCSerialNumberPart2, OctetsAttributeType, 0x0100, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 8),
			9:  MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuRSerialNumberPart1, OctetsAttributeType, 0x0080, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 9),
			10: MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuRSerialNumberPart2, OctetsAttributeType, 0x0040, 16, toOctets("AAAAAAAAAAAAAAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 10),
			11: Uint32Field(XdslLineInventoryAndStatusDataPart1_XtuCSelfTestResults, UnsignedIntegerAttributeType, 0x0020, 0, mapset.NewSetWith(Read), false, false, false, 11),
			12: Uint32Field(XdslLineInventoryAndStatusDataPart1_XtuRSelfTestResults, UnsignedIntegerAttributeType, 0x0010, 0, mapset.NewSetWith(Read), false, false, false, 12),
			13: MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuCTransmissionSystemCapability, OctetsAttributeType, 0x0008, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 13),
			14: MultiByteField(XdslLineInventoryAndStatusDataPart1_XtuRTransmissionSystemCapability, OctetsAttributeType, 0x0004, 7, toOctets("AAAAAAAAAA=="), mapset.NewSetWith(Read), false, false, false, 14),
			15: ByteField(XdslLineInventoryAndStatusDataPart1_InitializationSuccessFailureCause, UnsignedIntegerAttributeType, 0x0002, 0, mapset.NewSetWith(Read), false, false, false, 15),
		},
		Access:  CreatedByOnu,
		Support: UnknownSupport,
	}
}

// NewXdslLineInventoryAndStatusDataPart1 (class ID 100) creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from or transmitted to the OMCC.
func NewXdslLineInventoryAndStatusDataPart1(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdsllineinventoryandstatusdatapart1BME, params...)
}
