/*
* Copyright (c) 2020 - present.  Boling Consulting Solutions (bcsw.net)
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
*
 */
package omci

import (
	me "github.com/cboling/omci/generated"
	"github.com/stretchr/testify/assert"
	"testing"
)

var uint_zero = me.UintConstraint{
	Value: 0,
}

var uint_ones = me.UintConstraint{
	Value: 0xFF,
}

var one_to_ten = me.UintMaxMinConstraint{
	Min: 1,
	Max: 10,
}

var tenToTwelve = me.UintMaxMinConstraint{
	Min: 10,
	Max: 12,
}

var fifty = me.UintConstraint{
	Value: 50,
}

var bitTest = me.BitmapConstraint{
	Bitmask: 0xAA,
}

var biggerBitTest = me.BitmapConstraint{
	Bitmask: 0xAA55AA55,
}
var bitmaskAboveAsDecimal = "2857740885"

func tShouldPanic(t *testing.T) {

	if r := recover(); r == nil {
		t.Errorf("The code did not panic")
	}
}

func TestOctetsConstraintString(t *testing.T) {
	// TODO: Implement me
	//assert.True(t, false)
}

func TestIntegerConstraintString(t *testing.T) {
	constraint := me.NewIntegerConstraint("0")
	assert.IsType(t, &me.UintConstraint{}, constraint)
	assert.Equal(t, uint_zero, *constraint.(*me.UintConstraint))

	constraintSpaces := me.NewIntegerConstraint(" 0    ")
	assert.IsType(t, &me.UintConstraint{}, constraintSpaces)
	assert.Equal(t, uint_zero, *constraintSpaces.(*me.UintConstraint))

	constraintOnes := me.NewIntegerConstraint("0xff")
	assert.IsType(t, &me.UintConstraint{}, constraintOnes)
	assert.Equal(t, uint_ones, *constraintOnes.(*me.UintConstraint))

	constraintOnesDecimal := me.NewIntegerConstraint("255")
	assert.IsType(t, &me.UintConstraint{}, constraintOnesDecimal)
	assert.Equal(t, uint_ones, *constraintOnesDecimal.(*me.UintConstraint))
}

func TestIntegerRangeConstraintString(t *testing.T) {
	constraint := me.NewIntegerConstraint("1..10")
	assert.IsType(t, &me.UintMaxMinConstraint{}, constraint)
	assert.Equal(t, one_to_ten, *constraint.(*me.UintMaxMinConstraint))

	constraintHex := me.NewIntegerConstraint("1..0x0A")
	assert.IsType(t, &me.UintMaxMinConstraint{}, constraintHex)
	assert.Equal(t, one_to_ten, *constraintHex.(*me.UintMaxMinConstraint))

	constraintSpaces := me.NewIntegerConstraint(" 1  ..   10   ")
	assert.IsType(t, &me.UintMaxMinConstraint{}, constraintSpaces)
	assert.Equal(t, one_to_ten, *constraintSpaces.(*me.UintMaxMinConstraint))
}

func TestIntegerRangeConstraintStringMissingBoth(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("..")
}

func TestIntegerRangeConstraintStringNoMin(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("..1")
}

func TestIntegerRangeConstraintStringNoMax(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("1..")
}

func TestIntegerRangeConstraintStringPanicMinNoNumber(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("NoWay..1")
}

func TestIntegerRangeConstraintStringPanicMaxNoNumber(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("10..NoWay")
}

func TestIntegerRangeConstraintStringPanicMaxLessThanMin(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("10..1")
}

func TestIntegerConstraintNilIfBlank(t *testing.T) {
	assert.Nil(t, me.NewIntegerConstraint(""))
	assert.Nil(t, me.NewIntegerConstraint("     "))
}

func TestIntegerConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("InvalidConstraint")
}

func TestIntegerConstraintListString(t *testing.T) {
	constraint := me.NewIntegerConstraintList("0,1..10,50")
	assert.IsType(t, []me.IConstraint{}, constraint)
	assert.Equal(t, 3, len(constraint))
	assert.Equal(t, &uint_zero, constraint[0])
	assert.Equal(t, &one_to_ten, constraint[1])
	assert.Equal(t, &fifty, constraint[2])

	constraintSpaces := me.NewIntegerConstraintList(" 0  ,  1.. 10, 50")
	assert.IsType(t, []me.IConstraint{}, constraintSpaces)
	assert.Equal(t, 3, len(constraintSpaces))
	assert.Equal(t, &uint_zero, constraintSpaces[0])
	assert.Equal(t, &one_to_ten, constraintSpaces[1])
	assert.Equal(t, &fifty, constraintSpaces[2])

	constraintJustOneOk := me.NewIntegerConstraintList("1..10")
	assert.IsType(t, []me.IConstraint{}, constraintJustOneOk)
	assert.Equal(t, 1, len(constraintJustOneOk))
	assert.Equal(t, &one_to_ten, constraintJustOneOk[0])
}

func TestBitFieldConstraintString(t *testing.T) {
	constraint := me.NewBitFieldConstraint("0xAA")
	assert.IsType(t, &me.BitmapConstraint{}, constraint)
	assert.Equal(t, bitTest, *constraint)

	constraintLower := me.NewBitFieldConstraint("0xaa")
	assert.IsType(t, &me.BitmapConstraint{}, constraintLower)
	assert.Equal(t, bitTest, *constraintLower)

	constraintMixed := me.NewBitFieldConstraint("0xaA")
	assert.IsType(t, &me.BitmapConstraint{}, constraintMixed)
	assert.Equal(t, bitTest, *constraintMixed)

	constraintSpaces := me.NewBitFieldConstraint(" 0xAA       ")
	assert.IsType(t, &me.BitmapConstraint{}, constraintSpaces)
	assert.Equal(t, bitTest, *constraintSpaces)

	decimalConstraint := me.NewBitFieldConstraint("170")
	assert.IsType(t, &me.BitmapConstraint{}, decimalConstraint)
	assert.Equal(t, bitTest, *decimalConstraint)

	bigConstraint := me.NewBitFieldConstraint("0xaa55aa55")
	assert.IsType(t, &me.BitmapConstraint{}, bigConstraint)
	assert.Equal(t, biggerBitTest, *bigConstraint)

	bigDecimalConstraint := me.NewBitFieldConstraint(bitmaskAboveAsDecimal)
	assert.IsType(t, &me.BitmapConstraint{}, bigDecimalConstraint)
	assert.Equal(t, biggerBitTest, *bigDecimalConstraint)
}

func TestBitFieldConstraintNils(t *testing.T) {
	assert.Nil(t, me.NewBitFieldConstraint(""))
	assert.Nil(t, me.NewBitFieldConstraint("     "))
}

func TestBitfieldConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	me.NewBitFieldConstraint("InvalidConstraint")
}

func TestUnknownAttributeTypeConstraintIsNil(t *testing.T) {
	assert.Nil(t, me.NewConstraint("99", me.UnknownAttributeType))
	assert.Nil(t, me.NewConstraint("", me.UnknownAttributeType))
	assert.Nil(t, me.NewConstraint("ReallyAnythingHereAsWeDoNotCare", me.UnknownAttributeType))
}

func TestCounterAttributeTypeConstraintIsNil(t *testing.T) {
	assert.Nil(t, me.NewConstraint("99", me.CounterAttributeType))
	assert.Nil(t, me.NewConstraint("", me.CounterAttributeType))
	assert.Nil(t, me.NewConstraint("ReallyAnythingHereAsWeDoNotCare", me.CounterAttributeType))
}

func TestOctetsConstrains(t *testing.T) {
	// TODO: Implement me
	//assert.True(t, false)
}

func TestOctetsConstraintNils(t *testing.T) {
	assert.Nil(t, me.NewOctetsConstraint(""))
	assert.Nil(t, me.NewOctetsConstraint("     "))
}

func TestOctetsConstraintPanics(t *testing.T) {
	defer tShouldPanic(t)
	me.NewIntegerConstraint("InvalidConstraint")

	// TODO: Test other octet string patterns that should fail
}

func TestUintConstraint(t *testing.T) {
	assert.True(t, uint_zero.Valid(0))
	assert.True(t, uint_zero.Valid(uint(0)))
	assert.True(t, uint_zero.Valid(uint8(0)))
	assert.True(t, uint_zero.Valid(uint16(0)))
	assert.True(t, uint_zero.Valid(uint32(0)))
	assert.True(t, uint_zero.Valid(uint64(0)))
	assert.True(t, uint_zero.Valid(int(0)))
	assert.True(t, uint_zero.Valid(int8(0)))
	assert.True(t, uint_zero.Valid(int16(0)))
	assert.True(t, uint_zero.Valid(int32(0)))
	assert.True(t, uint_zero.Valid(int64(0)))

	assert.False(t, uint_zero.Valid(uint(1)))
	assert.False(t, uint_zero.Valid(uint8(1)))
	assert.False(t, uint_zero.Valid(uint16(1)))
	assert.False(t, uint_zero.Valid(uint32(1)))
	assert.False(t, uint_zero.Valid(uint64(1)))
	assert.False(t, uint_zero.Valid(int(1)))
	assert.False(t, uint_zero.Valid(int8(1)))
	assert.False(t, uint_zero.Valid(int16(1)))
	assert.False(t, uint_zero.Valid(int32(1)))
	assert.False(t, uint_zero.Valid(int64(1)))
	assert.False(t, uint_zero.Valid(-1))
	assert.False(t, uint_zero.Valid(int(-1)))
	assert.False(t, uint_zero.Valid(int8(-1)))
	assert.False(t, uint_zero.Valid(int16(-1)))
	assert.False(t, uint_zero.Valid(int32(-1)))
	assert.False(t, uint_zero.Valid(int64(-1)))

	assert.True(t, uint_ones.Valid(0xff))
	assert.True(t, uint_ones.Valid(uint(0xff)))
	assert.True(t, uint_ones.Valid(uint8(0xff)))
	assert.True(t, uint_ones.Valid(uint16(0xff)))
	assert.True(t, uint_ones.Valid(uint32(0xff)))
	assert.True(t, uint_ones.Valid(uint64(0xff)))
}

func TestUint8Constraint(t *testing.T) {

	constraint := me.UintConstraint{
		Value: 0xFF,
	}
	assert.True(t, constraint.Valid(0xFF))
	assert.False(t, constraint.Valid(0x100))
}

func TestUint16Constraint(t *testing.T) {

	constraint := me.UintConstraint{
		Value: 0xFFFF,
	}
	assert.True(t, constraint.Valid(0xFFFF))
	assert.False(t, constraint.Valid(0x10000))
}

func TestUint32Constraint(t *testing.T) {

	constraint := me.UintConstraint{
		Value: 0xFFFFFFFF,
	}
	assert.True(t, constraint.Valid(0xFFFFFFFF))
	assert.False(t, constraint.Valid(0x100000000))
}

func TestUint64Constraint(t *testing.T) {

	constraint := me.UintConstraint{
		Value: 0xFFFFFFFFFFFFFFFF,
	}
	assert.True(t, constraint.Valid(uint64(0xFFFFFFFFFFFFFFFF)))
}

func TestUintMaxMinConstraint(t *testing.T) {

	assert.True(t, one_to_ten.Valid(1))
	assert.True(t, one_to_ten.Valid(10))
	assert.True(t, one_to_ten.Valid(uint(1)) && one_to_ten.Valid(uint(10)))
	assert.True(t, one_to_ten.Valid(uint8(1)) && one_to_ten.Valid(uint8(10)))
	assert.True(t, one_to_ten.Valid(uint16(1)) && one_to_ten.Valid(uint16(10)))
	assert.True(t, one_to_ten.Valid(uint32(1)) && one_to_ten.Valid(uint32(10)))
	assert.True(t, one_to_ten.Valid(uint64(1)) && one_to_ten.Valid(uint64(10)))

	assert.False(t, one_to_ten.Valid(-1))
	assert.False(t, one_to_ten.Valid(0))
	assert.False(t, one_to_ten.Valid(11))
	assert.False(t, one_to_ten.Valid(uint(0)) || one_to_ten.Valid(uint(11)))
	assert.False(t, one_to_ten.Valid(uint8(0)) || one_to_ten.Valid(uint8(11)))
	assert.False(t, one_to_ten.Valid(uint16(0)) || one_to_ten.Valid(uint16(11)))
	assert.False(t, one_to_ten.Valid(uint32(0)) || one_to_ten.Valid(uint32(11)))
	assert.False(t, one_to_ten.Valid(uint64(0)) || one_to_ten.Valid(uint64(11)))
}

func TestUintConstraintArray(t *testing.T) {

	constraintList := []interface{}{uint_zero, tenToTwelve, fifty}

	assert.True(t, me.ConstraintsValid(0, constraintList))
	assert.True(t, me.ConstraintsValid(10, constraintList))
	assert.True(t, me.ConstraintsValid(11, constraintList))
	assert.True(t, me.ConstraintsValid(12, constraintList))
	assert.True(t, me.ConstraintsValid(50, constraintList))

	assert.False(t, me.ConstraintsValid(-1, constraintList))
	assert.False(t, me.ConstraintsValid(1, constraintList))
	assert.False(t, me.ConstraintsValid(9, constraintList))
	assert.False(t, me.ConstraintsValid(13, constraintList))
	assert.False(t, me.ConstraintsValid(100, constraintList))
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
