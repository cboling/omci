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

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var uintZero = UintConstraint{
	Value: 0,
}

var uintOnes = UintConstraint{
	Value: 0xFF,
}

var oneToTen = UintMaxMinConstraint{
	Min: 1,
	Max: 10,
}

var tenToTwelve = UintMaxMinConstraint{
	Min: 10,
	Max: 12,
}

var fifty = UintConstraint{
	Value: 50,
}

var bitTest = BitmapConstraint{
	Bitmask: 0xAA,
}

var biggerBitTest = BitmapConstraint{
	Bitmask: 0xAA55AA55,
}
var bitmaskAboveAsDecimal = "2857740885"

func tShouldPanic(t *testing.T) {

	if r := recover(); r == nil {
		t.Errorf("The code did not panic")
	}
}

func TestIntegerConstraintString(t *testing.T) {
	constraint := NewIntegerConstraint("0")
	assert.IsType(t, &UintConstraint{}, constraint)
	assert.Equal(t, uintZero, *constraint.(*UintConstraint))

	constraintSpaces := NewIntegerConstraint(" 0    ")
	assert.IsType(t, &UintConstraint{}, constraintSpaces)
	assert.Equal(t, uintZero, *constraintSpaces.(*UintConstraint))

	constraintOnes := NewIntegerConstraint("0xff")
	assert.IsType(t, &UintConstraint{}, constraintOnes)
	assert.Equal(t, uintOnes, *constraintOnes.(*UintConstraint))

	constraintOnesDecimal := NewIntegerConstraint("255")
	assert.IsType(t, &UintConstraint{}, constraintOnesDecimal)
	assert.Equal(t, uintOnes, *constraintOnesDecimal.(*UintConstraint))
}

func TestIntegerRangeConstraintString(t *testing.T) {
	constraint := NewIntegerConstraint("1..10")
	assert.IsType(t, &UintMaxMinConstraint{}, constraint)
	assert.Equal(t, oneToTen, *constraint.(*UintMaxMinConstraint))

	constraintHex := NewIntegerConstraint("1..0x0A")
	assert.IsType(t, &UintMaxMinConstraint{}, constraintHex)
	assert.Equal(t, oneToTen, *constraintHex.(*UintMaxMinConstraint))

	constraintSpaces := NewIntegerConstraint(" 1  ..   10   ")
	assert.IsType(t, &UintMaxMinConstraint{}, constraintSpaces)
	assert.Equal(t, oneToTen, *constraintSpaces.(*UintMaxMinConstraint))
}

func TestIntegerRangeConstraintStringMissingBoth(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("..")
}

func TestIntegerRangeConstraintStringNoMin(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("..1")
}

func TestIntegerRangeConstraintStringNoMax(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("1..")
}

func TestIntegerRangeConstraintStringPanicMinNoNumber(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("NoWay..1")
}

func TestIntegerRangeConstraintStringPanicMaxNoNumber(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("10..NoWay")
}

func TestIntegerRangeConstraintStringPanicMaxLessThanMin(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("10..1")
}

func TestIntegerNonIntegerNotSupportedAndIsFalse(t *testing.T) {
	assert.True(t, uintZero.Valid(0))
	assert.False(t, uintZero.Valid(float32(0.0)))
	assert.False(t, uintZero.Valid(float64(0.0)))
	assert.False(t, uintZero.Valid(bool(false)))
}

func TestIntegerConstraintNilIfBlank(t *testing.T) {
	assert.Nil(t, NewIntegerConstraint(""))
	assert.Nil(t, NewIntegerConstraint("     "))
}

func TestIntegerConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("InvalidConstraint")
}

func TestIntegerConstraintTypoPanics(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("0..0xFFFw")
}

func TestIntegerConstraintListString(t *testing.T) {
	constraint := NewIntegerConstraintList("0,1..10,50")
	assert.IsType(t, []IConstraint{}, constraint)
	assert.Equal(t, 3, len(constraint))
	assert.Equal(t, &uintZero, constraint[0])
	assert.Equal(t, &oneToTen, constraint[1])
	assert.Equal(t, &fifty, constraint[2])

	constraintSpaces := NewIntegerConstraintList(" 0  ,  1.. 10, 50")
	assert.IsType(t, []IConstraint{}, constraintSpaces)
	assert.Equal(t, 3, len(constraintSpaces))
	assert.Equal(t, &uintZero, constraintSpaces[0])
	assert.Equal(t, &oneToTen, constraintSpaces[1])
	assert.Equal(t, &fifty, constraintSpaces[2])

	constraintJustOneOk := NewIntegerConstraintList("1..10")
	assert.IsType(t, []IConstraint{}, constraintJustOneOk)
	assert.Equal(t, 1, len(constraintJustOneOk))
	assert.Equal(t, &oneToTen, constraintJustOneOk[0])
}

func TestBitFieldConstraintString(t *testing.T) {
	constraint := NewBitFieldConstraint("0xAA")
	assert.IsType(t, &BitmapConstraint{}, constraint)
	assert.Equal(t, bitTest, *constraint)

	constraintLower := NewBitFieldConstraint("0xaa")
	assert.IsType(t, &BitmapConstraint{}, constraintLower)
	assert.Equal(t, bitTest, *constraintLower)

	constraintMixed := NewBitFieldConstraint("0xaA")
	assert.IsType(t, &BitmapConstraint{}, constraintMixed)
	assert.Equal(t, bitTest, *constraintMixed)

	constraintSpaces := NewBitFieldConstraint(" 0xAA       ")
	assert.IsType(t, &BitmapConstraint{}, constraintSpaces)
	assert.Equal(t, bitTest, *constraintSpaces)

	decimalConstraint := NewBitFieldConstraint("170")
	assert.IsType(t, &BitmapConstraint{}, decimalConstraint)
	assert.Equal(t, bitTest, *decimalConstraint)

	bigConstraint := NewBitFieldConstraint("0xaa55aa55")
	assert.IsType(t, &BitmapConstraint{}, bigConstraint)
	assert.Equal(t, biggerBitTest, *bigConstraint)

	bigDecimalConstraint := NewBitFieldConstraint(bitmaskAboveAsDecimal)
	assert.IsType(t, &BitmapConstraint{}, bigDecimalConstraint)
	assert.Equal(t, biggerBitTest, *bigDecimalConstraint)
}

func TestBitFieldConstraintNils(t *testing.T) {
	assert.Nil(t, NewBitFieldConstraint(""))
	assert.Nil(t, NewBitFieldConstraint("     "))
}

func TestBitfieldConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	NewBitFieldConstraint("InvalidConstraint")
}

func TestUnknownAttributeTypeConstraintIsNil(t *testing.T) {
	assert.Nil(t, NewConstraint("99", UnknownAttributeType))
	assert.Nil(t, NewConstraint("", UnknownAttributeType))
	assert.Nil(t, NewConstraint("ReallyAnythingHereAsWeDoNotCare", UnknownAttributeType))
}

func TestCounterAttributeTypeConstraintIsNil(t *testing.T) {
	assert.Nil(t, NewConstraint("99", CounterAttributeType))
	assert.Nil(t, NewConstraint("", CounterAttributeType))
	assert.Nil(t, NewConstraint("ReallyAnythingHereAsWeDoNotCare", CounterAttributeType))
}

func TestOctetsConstraintString(t *testing.T) {
	// TODO: Implement me
	//assert.True(t, false)
}

var octetLen12 = OctetConstraint{
	Length: 12,
	RegEx:  nil,
	Fill:   nil,
}

var octetRegEx8 = OctetConstraint{
	Length: 14,
	RegEx:  nil,
	Fill:   nil,
}

func TestOctetsConstraints(t *testing.T) {
	// NewOctetsConstraints parses an input string and generates an appropriate IConstraint type
	// to handle processing.  The input takes on the form of:
	//
	//   [len(<values>)][,regex(<allowed-pattern>)][,fill(<value>)]
	//     where:
	//       len()    is a function that checks a string/octets for a specific length and the
	//                result should match one of the <values>.  For tables, this is the length
	//                of a row entry.  If not specified, the octet/string/table row can be any
	//                length.
	//
	//       regex()  is an optional regular expression that will check the values of
	//                the collection of octets. Any pattern is provided
	//
	//       fill())  is an optional fill value to add to the end of a supplied string so that
	//                the entire string length is set to the maximum allowed. Typically this is
	//                either an ASCII space (0x20) or a null (0x00).
	//
	constraint12 := NewOctetsConstraint("len(12)")
	assert.IsType(t, &OctetConstraint{}, constraint12)
	//assert.Equal(t, octetLen12, *constraint12.(*OctetConstraint))

	vendorIDConstraint := NewOctetsConstraint("len(4), regex([a-zA-Z]{4})")
	assert.IsType(t, &UintConstraint{}, vendorIDConstraint)
	//assert.Equal(t, uintZero, *vendorIDRegEx.(*vendorIDConstraint))

	serialNumberConstraint := NewOctetsConstraint("len(8), regex([a-zA-Z]{4}.{4})")
	assert.IsType(t, &UintConstraint{}, serialNumberConstraint)
	//assert.Equal(t, uintZero, *vendorIDRegEx.(*serialNumberConstraint))

	// TODO: Implement me
	//assert.True(t, false)

	// CLEI  (20 Characters  Equipement ID
	//
	// SERIAL NUMBER   [a-zA-Z]{4}....
}

func TestOctetsConstraintArray(t *testing.T) {
	// Allow multiple constraint checks
	//constraintList := []interface{}{test1, test2, }

	// TODO: Implement me
	//assert.True(t, false)
}

func TestOctetsConstraintNils(t *testing.T) {
	assert.Nil(t, NewOctetsConstraint(""))
	assert.Nil(t, NewOctetsConstraint("     "))
}

func TestOctetsConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("InvalidConstraint")
}

func TestOctetsConstraintPanicsLengthPartial1(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("len(1")
}

func TestOctetsConstraintPanicsLengthDangling(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("len(12),")
}

func TestOctetsConstraintPanicsLengthOnce(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("len(12),len(12)")
}

func TestOctetsConstraintPanics2(t *testing.T) {
	defer tShouldPanic(t)
	NewIntegerConstraint("Length(12)")
}

func TestUintConstraint(t *testing.T) {
	assert.True(t, uintZero.Valid(0))
	assert.True(t, uintZero.Valid(uint(0)))
	assert.True(t, uintZero.Valid(uint8(0)))
	assert.True(t, uintZero.Valid(uint16(0)))
	assert.True(t, uintZero.Valid(uint32(0)))
	assert.True(t, uintZero.Valid(uint64(0)))
	assert.True(t, uintZero.Valid(int(0)))
	assert.True(t, uintZero.Valid(int8(0)))
	assert.True(t, uintZero.Valid(int16(0)))
	assert.True(t, uintZero.Valid(int32(0)))
	assert.True(t, uintZero.Valid(int64(0)))

	assert.False(t, uintZero.Valid(uint(1)))
	assert.False(t, uintZero.Valid(uint8(1)))
	assert.False(t, uintZero.Valid(uint16(1)))
	assert.False(t, uintZero.Valid(uint32(1)))
	assert.False(t, uintZero.Valid(uint64(1)))
	assert.False(t, uintZero.Valid(int(1)))
	assert.False(t, uintZero.Valid(int8(1)))
	assert.False(t, uintZero.Valid(int16(1)))
	assert.False(t, uintZero.Valid(int32(1)))
	assert.False(t, uintZero.Valid(int64(1)))
	assert.False(t, uintZero.Valid(-1))
	assert.False(t, uintZero.Valid(int(-1)))
	assert.False(t, uintZero.Valid(int8(-1)))
	assert.False(t, uintZero.Valid(int16(-1)))
	assert.False(t, uintZero.Valid(int32(-1)))
	assert.False(t, uintZero.Valid(int64(-1)))

	assert.True(t, uintOnes.Valid(0xff))
	assert.True(t, uintOnes.Valid(uint(0xff)))
	assert.True(t, uintOnes.Valid(uint8(0xff)))
	assert.True(t, uintOnes.Valid(uint16(0xff)))
	assert.True(t, uintOnes.Valid(uint32(0xff)))
	assert.True(t, uintOnes.Valid(uint64(0xff)))
}

func TestUint8Constraint(t *testing.T) {

	constraint := UintConstraint{
		Value: 0xFF,
	}
	assert.True(t, constraint.Valid(0xFF))
	assert.False(t, constraint.Valid(0x100))
}

func TestUint16Constraint(t *testing.T) {

	constraint := UintConstraint{
		Value: 0xFFFF,
	}
	assert.True(t, constraint.Valid(0xFFFF))
	assert.False(t, constraint.Valid(0x10000))
}

func TestUint32Constraint(t *testing.T) {

	constraint := UintConstraint{
		Value: 0xFFFFFFFF,
	}
	assert.True(t, constraint.Valid(0xFFFFFFFF))
	assert.False(t, constraint.Valid(0x100000000))
}

func TestUint64Constraint(t *testing.T) {

	constraint := UintConstraint{
		Value: 0xFFFFFFFFFFFFFFFF,
	}
	assert.True(t, constraint.Valid(uint64(0xFFFFFFFFFFFFFFFF)))
}

func TestUintMaxMinConstraint(t *testing.T) {

	assert.True(t, oneToTen.Valid(1))
	assert.True(t, oneToTen.Valid(10))
	assert.True(t, oneToTen.Valid(uint(1)) && oneToTen.Valid(uint(10)))
	assert.True(t, oneToTen.Valid(uint8(1)) && oneToTen.Valid(uint8(10)))
	assert.True(t, oneToTen.Valid(uint16(1)) && oneToTen.Valid(uint16(10)))
	assert.True(t, oneToTen.Valid(uint32(1)) && oneToTen.Valid(uint32(10)))
	assert.True(t, oneToTen.Valid(uint64(1)) && oneToTen.Valid(uint64(10)))

	assert.False(t, oneToTen.Valid(-1))
	assert.False(t, oneToTen.Valid(0))
	assert.False(t, oneToTen.Valid(11))
	assert.False(t, oneToTen.Valid(uint(0)) || oneToTen.Valid(uint(11)))
	assert.False(t, oneToTen.Valid(uint8(0)) || oneToTen.Valid(uint8(11)))
	assert.False(t, oneToTen.Valid(uint16(0)) || oneToTen.Valid(uint16(11)))
	assert.False(t, oneToTen.Valid(uint32(0)) || oneToTen.Valid(uint32(11)))
	assert.False(t, oneToTen.Valid(uint64(0)) || oneToTen.Valid(uint64(11)))
}

func TestUintConstraintArray(t *testing.T) {

	constraintList := []interface{}{uintZero, tenToTwelve, fifty}

	assert.True(t, ConstraintsValid(0, constraintList))
	assert.True(t, ConstraintsValid(10, constraintList))
	assert.True(t, ConstraintsValid(11, constraintList))
	assert.True(t, ConstraintsValid(12, constraintList))
	assert.True(t, ConstraintsValid(50, constraintList))

	assert.False(t, ConstraintsValid(-1, constraintList))
	assert.False(t, ConstraintsValid(1, constraintList))
	assert.False(t, ConstraintsValid(9, constraintList))
	assert.False(t, ConstraintsValid(13, constraintList))
	assert.False(t, ConstraintsValid(100, constraintList))
}

func TestBitmapConstraint(t *testing.T) {
	assert.True(t, bitTest.Valid(0x00) && bitTest.Valid(0x02) && bitTest.Valid(0x08) && bitTest.Valid(0x0A))
	assert.True(t, bitTest.Valid(0x20) && bitTest.Valid(0x80) && bitTest.Valid(0xAA))
	assert.True(t, bitTest.Valid(0x22) && bitTest.Valid(0x28) && bitTest.Valid(0x82) && bitTest.Valid(0x88))

	assert.True(t, bitTest.Valid(uint(0x00)) && bitTest.Valid(uint(0x02)) && bitTest.Valid(uint(0x08)) && bitTest.Valid(uint(0x0A)))
	assert.True(t, bitTest.Valid(uint(0x20)) && bitTest.Valid(uint(0x80)) && bitTest.Valid(uint(0xAA)))
	assert.True(t, bitTest.Valid(uint(0x22)) && bitTest.Valid(uint(0x28)) && bitTest.Valid(uint(0x82)) && bitTest.Valid(uint(0x88)))

	assert.True(t, bitTest.Valid(uint8(0x00)) && bitTest.Valid(uint8(0x02)) && bitTest.Valid(uint8(0x08)) && bitTest.Valid(uint8(0x0A)))
	assert.True(t, bitTest.Valid(uint8(0x20)) && bitTest.Valid(uint8(0x80)) && bitTest.Valid(uint8(0xAA)))
	assert.True(t, bitTest.Valid(uint8(0x22)) && bitTest.Valid(uint8(0x28)) && bitTest.Valid(uint8(0x82)) && bitTest.Valid(uint8(0x88)))

	assert.True(t, bitTest.Valid(uint16(0x00)) && bitTest.Valid(uint16(0x02)) && bitTest.Valid(uint16(0x08)) && bitTest.Valid(uint16(0x0A)))
	assert.True(t, bitTest.Valid(uint16(0x20)) && bitTest.Valid(uint16(0x80)) && bitTest.Valid(uint16(0xAA)))
	assert.True(t, bitTest.Valid(uint16(0x22)) && bitTest.Valid(uint16(0x28)) && bitTest.Valid(uint16(0x82)) && bitTest.Valid(uint16(0x88)))

	assert.True(t, bitTest.Valid(uint32(0x00)) && bitTest.Valid(uint32(0x02)) && bitTest.Valid(uint32(0x08)) && bitTest.Valid(uint32(0x0A)))
	assert.True(t, bitTest.Valid(uint32(0x20)) && bitTest.Valid(uint32(0x80)) && bitTest.Valid(uint32(0xAA)))
	assert.True(t, bitTest.Valid(uint32(0x22)) && bitTest.Valid(uint32(0x28)) && bitTest.Valid(uint32(0x82)) && bitTest.Valid(uint32(0x88)))

	assert.True(t, bitTest.Valid(uint64(0x00)) && bitTest.Valid(uint64(0x02)) && bitTest.Valid(uint64(0x08)) && bitTest.Valid(uint64(0x0A)))
	assert.True(t, bitTest.Valid(uint64(0x20)) && bitTest.Valid(uint64(0x80)) && bitTest.Valid(uint64(0xAA)))
	assert.True(t, bitTest.Valid(uint64(0x22)) && bitTest.Valid(uint64(0x28)) && bitTest.Valid(uint64(0x82)) && bitTest.Valid(uint64(0x88)))

	assert.True(t, bitTest.Valid(int(0x00)) && bitTest.Valid(int(0x02)) && bitTest.Valid(int(0x08)) && bitTest.Valid(int(0x0A)))
	assert.True(t, bitTest.Valid(int(0x20)) && bitTest.Valid(int(0x80)) && bitTest.Valid(int(0xAA)))
	assert.True(t, bitTest.Valid(int(0x22)) && bitTest.Valid(int(0x28)) && bitTest.Valid(int(0x82)) && bitTest.Valid(int(0x88)))

	assert.True(t, bitTest.Valid(int8(0x00)) && bitTest.Valid(int8(0x02)) && bitTest.Valid(int8(0x08)) && bitTest.Valid(int8(0x0A)))
	assert.True(t, bitTest.Valid(int8(0x20)))
	assert.True(t, bitTest.Valid(int8(0x22)) && bitTest.Valid(int8(0x28)))

	assert.True(t, bitTest.Valid(int16(0x00)) && bitTest.Valid(int16(0x02)) && bitTest.Valid(int16(0x08)) && bitTest.Valid(int16(0x0A)))
	assert.True(t, bitTest.Valid(int16(0x20)) && bitTest.Valid(int16(0x80)) && bitTest.Valid(int16(0xAA)))
	assert.True(t, bitTest.Valid(int16(0x22)) && bitTest.Valid(int16(0x28)) && bitTest.Valid(int16(0x82)) && bitTest.Valid(int16(0x88)))

	assert.True(t, bitTest.Valid(int32(0x00)) && bitTest.Valid(int32(0x02)) && bitTest.Valid(int32(0x08)) && bitTest.Valid(int32(0x0A)))
	assert.True(t, bitTest.Valid(int32(0x20)) && bitTest.Valid(int32(0x80)) && bitTest.Valid(int32(0xAA)))
	assert.True(t, bitTest.Valid(int32(0x22)) && bitTest.Valid(int32(0x28)) && bitTest.Valid(int32(0x82)) && bitTest.Valid(int32(0x88)))

	assert.True(t, bitTest.Valid(int64(0x00)) && bitTest.Valid(int64(0x02)) && bitTest.Valid(int64(0x08)) && bitTest.Valid(int64(0x0A)))
	assert.True(t, bitTest.Valid(int64(0x20)) && bitTest.Valid(int64(0x80)) && bitTest.Valid(int64(0xAA)))
	assert.True(t, bitTest.Valid(int64(0x22)) && bitTest.Valid(int64(0x28)) && bitTest.Valid(int64(0x82)) && bitTest.Valid(int64(0x88)))

	assert.False(t, bitTest.Valid(0x01))
	assert.False(t, bitTest.Valid(0x04))
	assert.False(t, bitTest.Valid(0x03))
	assert.False(t, bitTest.Valid(0xff))
	assert.False(t, bitTest.Valid(0x10))

	assert.False(t, bitTest.Valid(-1))
}

func TestBitmapConstraintArray(t *testing.T) {
	// While bitmaps are only single entry, the ConstraintsValid func can still be used
	constraintList := []interface{}{bitTest}

	assert.True(t, ConstraintsValid(0x02, constraintList))
	assert.False(t, ConstraintsValid(0x01, constraintList))
}

func TestCreateConstraintByType(t *testing.T) {

	unknownConstraint := NewConstraint("", UnknownAttributeType)
	assert.Nil(t, unknownConstraint)

	uintConstraint := NewConstraint("123", UnsignedIntegerAttributeType)
	assert.IsType(t, &UintConstraint{}, uintConstraint)

	uintConstraint2 := NewConstraint("10..0xFF00", UnsignedIntegerAttributeType)
	assert.IsType(t, &UintMaxMinConstraint{}, uintConstraint2)

	intConstraint := NewConstraint("456", SignedIntegerAttributeType)
	assert.IsType(t, &UintConstraint{}, intConstraint)

	pointerConstraint := NewConstraint("0", PointerAttributeType)
	assert.IsType(t, &UintConstraint{}, pointerConstraint)

	pointerConstraint2 := NewConstraint("1..0xFFFE", PointerAttributeType)
	assert.IsType(t, &UintMaxMinConstraint{}, pointerConstraint2)

	bitConstraint := NewConstraint("0xAA", BitFieldAttributeType)
	assert.IsType(t, &BitmapConstraint{}, bitConstraint)

	enumConstraint := NewConstraint("0", EnumerationAttributeType)
	assert.IsType(t, &UintConstraint{}, enumConstraint)

	counterConstraint := NewConstraint("", CounterAttributeType)
	assert.Nil(t, counterConstraint)

	// TODO: add tests for these
	//OctetsAttributeType        // Series of zero or more octets
	//StringAttributeType        // Readable String
	//TableAttributeType         // Table (of Octets)
}
