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

// XdslLineInventoryAndStatusDataPart5ClassId is the 16-bit ID for the OMCI
// Managed entity xDSL line inventory and status data part 5
const XdslLineInventoryAndStatusDataPart5ClassId ClassID = ClassID(325)

var xdsllineinventoryandstatusdatapart5BME *ManagedEntityDefinition

// XdslLineInventoryAndStatusDataPart5 (class ID #325)
//	This ME extends the attributes defined in the xDSL line inventory and status data parts 1..4.
//	This ME reports FEXT and NEXT attributes, and pertains to Annex C of [ITUT G.992.3] (ADSL2) and
//	Annex C of [ITUT G.992.5] (ADSL2plus).
//
//	Relationships
//		This is one of the status data MEs associated with an xDSL UNI. The ONU automatically creates or
//		deletes an instance of this ME upon creation or deletion of a PPTP xDSL UNI part 1 that supports
//		these attributes.
//
//	Attributes
//		Managed Entity Id
//			Managed entity ID: This attribute uniquely identifies each instance of this ME. Through an
//			identical ID, this ME is implicitly linked to an instance of the PPTP xDSL UNI part 1 ME. (R)
//			(mandatory) (2-bytes)
//
//		Fext Downstream Snr Margin
//			FEXT downstream SNR margin: The FEXT SNRMds attribute is the downstream SNR margin measured
//			during FEXTR duration at the ATU-R. The attribute value ranges from 0 (-64.0-dB) to 1270
//			(+63.0-dB). The special value 0xFFFF indicates that the attribute is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Next Downstream Snr Margin
//			NEXT downstream SNR margin: The NEXT SNRMds attribute is the downstream SNR margin measured
//			during NEXTR duration at the ATU-R. The attribute value ranges from 0 (-64.0-dB) to 1270
//			(+63.0-dB). The special value 0xFFFF indicates that the attribute is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Fext Upstream Snr Margin
//			FEXT upstream SNR margin: The FEXT SNRMus attribute is the upstream SNR margin (see clause
//			7.5.1.16 of [ITUT G.997.1]) measured during FEXTC duration at the ATU-C. The attribute value
//			ranges from 0 (-64.0-dB) to 1270 (+63.0-dB). The special value 0xFFFF indicates that the
//			attribute is out of range. (R) (mandatory) (2-bytes)
//
//		Next Upstream Snr Margin
//			NEXT upstream SNR margin: The NEXT SNRMus attribute is the upstream SNR margin (see clause
//			7.5.1.16 of [ITUT-G.997.1]) measured during NEXTC duration at the ATU-C. The attribute value
//			ranges from 0 (-64.0-dB) to 1270 (+63.0-dB). The special value 0xFFFF indicates that the
//			attribute is out of range. (R) (mandatory) (2-bytes)
//
//		Fext Downstream Maximum Attainable Data Rate
//			FEXT downstream maximum attainable data rate: The FEXT ATTNDRds attribute is the maximum
//			downstream net data rate calculated from FEXT downstream SNR(f) (see clause 7.5.1.28.3.1 of
//			[ITUT G.997.1]). The rate is coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Next Downstream Maximum Attainable Data Rate
//			NEXT downstream maximum attainable data rate: The NEXT ATTNDRds attribute is the maximum
//			downstream net data rate calculated from NEXT downstream SNR(f) (see clause 7.5.1.28.3.2 of
//			[ITUT G.997.1]). The rate is coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Fext Upstream Maximum Attainable Data Rate
//			FEXT upstream maximum attainable data rate: The FEXT ATTNDRus attribute is the maximum upstream
//			net data rate calculated from FEXT upstream SNR(f) (see clause 7.5.1.28.6.1 of [ITUT G.997.1]).
//			The rate is coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Next Upstream Maximum Attainable Data Rate
//			NEXT upstream maximum attainable data rate: The NEXT ATTNDRus attribute is the maximum upstream
//			net data rate calculated from NEXT upstream SNR(f) (see clause 7.5.1.28.6.2 of [ITUT G.997.1]).
//			The rate is coded in bits per second. (R) (mandatory) (4-bytes)
//
//		Fext Downstream Actual Power Spectral Density
//			FEXT downstream actual power spectral density: The FEXT ACTPSDds attribute is the average
//			downstream transmit PSD over the used subcarriers (see clause-7.5.1.21.1 of [ITUT G.997.1])
//			calculated from the REFPSDds and RMSGIds for FEXTR duration. The attribute value ranges from 0
//			(-90.0-dBm/Hz) to 900 (0.0-dBm/Hz). The special value 0xFFFF indicates that the parameter is out
//			of range. (R) (mandatory) (2-bytes)
//
//		Next Downstream Actual Power Spectral Density
//			NEXT downstream actual power spectral density: The NEXT ACTPSDds attribute is the average
//			downstream transmit PSD over the used subcarriers (see clause-7.5.1.21.2 of [ITUT G.997.1])
//			calculated from the REFPSDds and RMSGIds for NEXTR duration. The attribute value ranges from 0
//			(-90.0-dBm/Hz) to 900 (0.0-dBm/Hz). The special value 0xFFFF indicates that the parameter is out
//			of range. (R) (mandatory) (2-bytes)
//
//		Fext Upstream Actual Power Spectral Density
//			FEXT upstream actual power spectral density: The FEXT ACTPSDus attribute is the average upstream
//			transmit PSD over the used subcarriers (see clause-7.5.1.22.1 of [ITUT G.997.1]) calculated from
//			the REFPSDus and RMSGIus for FEXTC duration. The attribute value ranges from 0 (-90.0-dBm/Hz) to
//			900 (0.0-dBm/Hz). The special value 0xFFFF indicates that the parameter is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Next Upstream Actual Power Spectral Density
//			NEXT upstream actual power spectral density: The NEXT ACTPSDus attribute is the average upstream
//			transmit PSD over the used subcarriers (see clause-7.5.1.22.2 of [ITUT G.997.1]) calculated from
//			the REFPSDus and RMSGIus for NEXTC duration. The attribute value ranges from 0 (-90.0-dBm/Hz) to
//			900 (0.0-dBm/Hz). The special value 0xFFFF indicates that the parameter is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Fext Downstream Actual Aggregate Transmit Power
//			FEXT downstream actual aggregate transmit power: The FEXT ACTATPds attribute is the total amount
//			of transmit power (see clause 7.5.1.24.1 of [ITUT G.997.1]) calculated from PSDds measured
//			during FEXTR duration at the ATU-R. The attribute value ranges from 0 (-31.0-dBm) to 620
//			(+31.0-dBm). The special value 0xFFFF indicates that the parameter is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Next Downstream Actual Aggregate Transmit Power
//			NEXT downstream actual aggregate transmit power: The NEXT ACTATPds attribute is the total amount
//			of transmit power (see clause 7.5.1.24.2 of [ITUT G.997.1]) calculated from PSDds measured
//			during NEXTR duration at the ATU-R. The attribute value ranges from 0 (-31.0-dBm) to 620
//			(+31.0-dBm). The special value 0xFFFF indicates that the parameter is out of range. (R)
//			(mandatory) (2-bytes)
//
//		Fext Upstream Actual Aggregate Transmit Power
//			FEXT upstream actual aggregate transmit power: The FEXT ACTATPus attribute is the total transmit
//			power (see clause 7.5.1.25.1 of [ITUT G.997.1]) calculated from PSDus measured during FEXTC
//			duration at the ATU-C. The attribute value ranges from 0 (-31.0-dBm) to 620 (+31.0-dBm). The
//			special value 0xFFFF indicates that the parameter is out of range. (R) (mandatory) (2-bytes)
//
//		Next Upstream Actual Aggregate Transmit Power
//			NEXT upstream actual aggregate transmit power: The NEXT ACTATPus attribute is the total transmit
//			power (see clause 7.5.1.25.2 of [ITUT G.997.1]) calculated from PSDus measured during NEXTC
//			duration at the ATU-C. The attribute value ranges from 0 (-31.0-dBm) to 620 (+31.0-dBm). The
//			special value 0xFFFF indicates that the parameter is out of range. (R) (mandatory) (2-bytes)
//
type XdslLineInventoryAndStatusDataPart5 struct {
	ManagedEntityDefinition
	Attributes AttributeValueMap
}

func init() {
	xdsllineinventoryandstatusdatapart5BME = &ManagedEntityDefinition{
		Name:    "XdslLineInventoryAndStatusDataPart5",
		ClassID: 325,
		MessageTypes: mapset.NewSetWith(
			Get,
		),
		AllowedAttributeMask: 0XFFFF,
		AttributeDefinitions: AttributeDefinitionMap{
			0:  Uint16Field("ManagedEntityId", 0, mapset.NewSetWith(Read), false, false, false, false, 0),
			1:  Uint16Field("FextDownstreamSnrMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 1),
			2:  Uint16Field("NextDownstreamSnrMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 2),
			3:  Uint16Field("FextUpstreamSnrMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 3),
			4:  Uint16Field("NextUpstreamSnrMargin", 0, mapset.NewSetWith(Read), false, false, false, false, 4),
			5:  Uint32Field("FextDownstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 5),
			6:  Uint32Field("NextDownstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 6),
			7:  Uint32Field("FextUpstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 7),
			8:  Uint32Field("NextUpstreamMaximumAttainableDataRate", 0, mapset.NewSetWith(Read), false, false, false, false, 8),
			9:  Uint16Field("FextDownstreamActualPowerSpectralDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 9),
			10: Uint16Field("NextDownstreamActualPowerSpectralDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 10),
			11: Uint16Field("FextUpstreamActualPowerSpectralDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 11),
			12: Uint16Field("NextUpstreamActualPowerSpectralDensity", 0, mapset.NewSetWith(Read), false, false, false, false, 12),
			13: Uint16Field("FextDownstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 13),
			14: Uint16Field("NextDownstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 14),
			15: Uint16Field("FextUpstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 15),
			16: Uint16Field("NextUpstreamActualAggregateTransmitPower", 0, mapset.NewSetWith(Read), false, false, false, false, 16),
		},
	}
}

// NewXdslLineInventoryAndStatusDataPart5 (class ID 325 creates the basic
// Managed Entity definition that is used to validate an ME of this type that
// is received from the wire, about to be sent on the wire.
func NewXdslLineInventoryAndStatusDataPart5(params ...ParamData) (*ManagedEntity, OmciErrors) {
	return NewManagedEntity(*xdsllineinventoryandstatusdatapart5BME, params...)
}
