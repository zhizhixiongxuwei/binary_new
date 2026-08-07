package bytecode

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const pycMarshalReferenceFlag byte = 0x80

const (
	pycTypeNull               byte = '0'
	pycTypeNone               byte = 'N'
	pycTypeFalse              byte = 'F'
	pycTypeTrue               byte = 'T'
	pycTypeStopIteration      byte = 'S'
	pycTypeEllipsis           byte = '.'
	pycTypeInt                byte = 'i'
	pycTypeInt64              byte = 'I'
	pycTypeFloat              byte = 'f'
	pycTypeBinaryFloat        byte = 'g'
	pycTypeComplex            byte = 'x'
	pycTypeBinaryComplex      byte = 'y'
	pycTypeLong               byte = 'l'
	pycTypeBytes              byte = 's'
	pycTypeInterned           byte = 't'
	pycTypeReference          byte = 'r'
	pycTypeTuple              byte = '('
	pycTypeList               byte = '['
	pycTypeDictionary         byte = '{'
	pycTypeCode               byte = 'c'
	pycTypeUnicode            byte = 'u'
	pycTypeSet                byte = '<'
	pycTypeFrozenSet          byte = '>'
	pycTypeASCII              byte = 'a'
	pycTypeASCIIInterned      byte = 'A'
	pycTypeSmallTuple         byte = ')'
	pycTypeShortASCII         byte = 'z'
	pycTypeShortASCIIInterned byte = 'Z'
)

const (
	pycCodeFlagVarArgs     = 0x04
	pycCodeFlagVarKeywords = 0x08
)

type pycMarshalObject struct {
	kind       byte
	bytes      []byte
	byteOffset uint64
	items      []*pycMarshalObject
	code       *pycCodeObject
}

type pycCodeObject struct {
	argCount      int
	posOnlyCount  int
	kwOnlyCount   int
	nlocals       int
	stackSize     int
	flags         uint32
	bytecode      *pycMarshalObject
	constants     *pycMarshalObject
	names         *pycMarshalObject
	variableNames *pycMarshalObject
	freeVariables *pycMarshalObject
	cellVariables *pycMarshalObject
	filename      *pycMarshalObject
	name          *pycMarshalObject
	firstLine     int
	lineTable     *pycMarshalObject
}

type pycMarshalParser struct {
	ctx             context.Context
	payload         []byte
	position        int
	config          PYCConfig
	objects         int
	references      []*pycMarshalObject
	scalarBytes     int64
	bytecodeBytes   int64
	codeObjectCount int
}

func parsePYCMarshal(
	ctx context.Context,
	payload []byte,
	headerSize int,
	config PYCConfig,
) (*pycMarshalObject, error) {
	parser := &pycMarshalParser{
		ctx: ctx, payload: payload, position: headerSize, config: config,
		references: []*pycMarshalObject{},
	}
	root, err := parser.readObject(1)
	if err != nil {
		return nil, err
	}
	if root == nil || root.kind != pycTypeCode || root.code == nil {
		return nil, malformedPYC("marshal root is not a code object")
	}
	if parser.position != len(payload) {
		return nil, malformedPYC("marshal payload contains trailing bytes")
	}
	return root, nil
}

func (parser *pycMarshalParser) readObject(depth int) (*pycMarshalObject, error) {
	if err := parser.ctx.Err(); err != nil {
		return nil, err
	}
	if depth > parser.config.MaxObjectDepth {
		return nil, pycLimit("marshal object depth")
	}
	if parser.objects >= parser.config.MaxObjects {
		return nil, pycLimit("marshal object count")
	}
	rawType, err := parser.readByte()
	if err != nil {
		return nil, err
	}
	parser.objects++
	kind := rawType &^ pycMarshalReferenceFlag
	flaggedReference := rawType&pycMarshalReferenceFlag != 0
	if kind == pycTypeReference {
		if flaggedReference {
			return nil, malformedPYC("reference record has the reference flag")
		}
		index, readErr := parser.readInt32()
		if readErr != nil {
			return nil, readErr
		}
		if index < 0 || int64(index) >= int64(len(parser.references)) {
			return nil, malformedPYC("marshal reference index is invalid")
		}
		return parser.references[index], nil
	}
	if kind == pycTypeNull && flaggedReference {
		return nil, malformedPYC("null record has the reference flag")
	}

	object := &pycMarshalObject{kind: kind}
	if flaggedReference {
		if len(parser.references) >= parser.config.MaxObjects {
			return nil, pycLimit("marshal reference count")
		}
		parser.references = append(parser.references, object)
	}

	switch kind {
	case pycTypeNull, pycTypeNone, pycTypeFalse, pycTypeTrue,
		pycTypeStopIteration, pycTypeEllipsis:
		return object, nil
	case pycTypeInt:
		_, err = parser.take(4)
	case pycTypeInt64:
		_, err = parser.take(8)
	case pycTypeFloat:
		err = parser.skipShortScalar()
	case pycTypeBinaryFloat:
		_, err = parser.take(8)
	case pycTypeComplex:
		if err = parser.skipShortScalar(); err == nil {
			err = parser.skipShortScalar()
		}
	case pycTypeBinaryComplex:
		_, err = parser.take(16)
	case pycTypeLong:
		err = parser.skipLongInteger()
	case pycTypeBytes, pycTypeInterned, pycTypeUnicode,
		pycTypeASCII, pycTypeASCIIInterned:
		object.bytes, object.byteOffset, err = parser.readLongBlob()
		if err == nil && (kind == pycTypeASCII || kind == pycTypeASCIIInterned) &&
			!isASCII(object.bytes) {
			err = malformedPYC("ASCII marshal string contains non-ASCII bytes")
		}
	case pycTypeShortASCII, pycTypeShortASCIIInterned:
		object.bytes, object.byteOffset, err = parser.readShortBlob()
		if err == nil && !isASCII(object.bytes) {
			err = malformedPYC("short ASCII marshal string contains non-ASCII bytes")
		}
	case pycTypeTuple, pycTypeList, pycTypeSet, pycTypeFrozenSet:
		var count int
		count, err = parser.readContainerCount32()
		if err == nil {
			object.items, err = parser.readItems(depth, count)
		}
	case pycTypeSmallTuple:
		var countByte byte
		countByte, err = parser.readByte()
		if err == nil {
			object.items, err = parser.readItems(depth, int(countByte))
		}
	case pycTypeDictionary:
		object.items, err = parser.readDictionary(depth)
	case pycTypeCode:
		if parser.codeObjectCount >= parser.config.MaxCodeObjects {
			return nil, pycLimit("code object count")
		}
		parser.codeObjectCount++
		object.code, err = parser.readCodeObject(depth)
	default:
		err = malformedPYC(fmt.Sprintf("marshal type 0x%02x is unsupported", kind))
	}
	if err != nil {
		return nil, err
	}
	return object, nil
}

func (parser *pycMarshalParser) readCodeObject(depth int) (*pycCodeObject, error) {
	values := make([]int32, 6)
	for index := range values {
		value, err := parser.readInt32()
		if err != nil {
			return nil, err
		}
		if value < 0 {
			return nil, malformedPYC("code object integer field is negative")
		}
		values[index] = value
	}
	code := &pycCodeObject{
		argCount: int(values[0]), posOnlyCount: int(values[1]),
		kwOnlyCount: int(values[2]), nlocals: int(values[3]),
		stackSize: int(values[4]), flags: uint32(values[5]),
	}
	fields := []**pycMarshalObject{
		&code.bytecode, &code.constants, &code.names, &code.variableNames,
		&code.freeVariables, &code.cellVariables, &code.filename, &code.name,
	}
	for _, field := range fields {
		object, err := parser.readObject(depth + 1)
		if err != nil {
			return nil, err
		}
		*field = object
	}
	firstLine, err := parser.readInt32()
	if err != nil {
		return nil, err
	}
	if firstLine < 0 {
		return nil, malformedPYC("code object first line is negative")
	}
	code.firstLine = int(firstLine)
	code.lineTable, err = parser.readObject(depth + 1)
	if err != nil {
		return nil, err
	}
	if err := parser.validateCodeObject(code); err != nil {
		return nil, err
	}
	if int64(len(code.bytecode.bytes)) > parser.config.MaxBytecodeBytes-parser.bytecodeBytes {
		return nil, pycLimit("bytecode bytes")
	}
	parser.bytecodeBytes += int64(len(code.bytecode.bytes))
	return code, nil
}

func (parser *pycMarshalParser) validateCodeObject(code *pycCodeObject) error {
	if code.posOnlyCount > code.argCount || code.argCount > code.nlocals ||
		code.stackSize > parser.config.MaxContainerItems {
		return malformedPYC("code object counters are inconsistent")
	}
	requiredLocals := int64(code.argCount) + int64(code.kwOnlyCount)
	if code.flags&pycCodeFlagVarArgs != 0 {
		requiredLocals++
	}
	if code.flags&pycCodeFlagVarKeywords != 0 {
		requiredLocals++
	}
	if requiredLocals > int64(code.nlocals) ||
		requiredLocals > int64(parser.config.MaxContainerItems) {
		return malformedPYC("code object local-variable counters are inconsistent")
	}
	if !pycBytesObject(code.bytecode) || !pycTupleObject(code.constants) ||
		!pycStringTuple(code.names) || !pycStringTuple(code.variableNames) ||
		!pycStringTuple(code.freeVariables) || !pycStringTuple(code.cellVariables) ||
		!pycTextObject(code.filename) || !pycTextObject(code.name) ||
		!pycBytesObject(code.lineTable) {
		return malformedPYC("code object contains a field with the wrong marshal type")
	}
	if code.nlocals != len(code.variableNames.items) ||
		len(code.variableNames.items) < int(requiredLocals) {
		return malformedPYC("code object variable names do not match local count")
	}
	for _, value := range []*pycMarshalObject{code.filename, code.name} {
		if !validPYCTextBytes(value.bytes, 4096) {
			return malformedPYC("code object name is invalid")
		}
	}
	return nil
}

func (parser *pycMarshalParser) readItems(
	depth int,
	count int,
) ([]*pycMarshalObject, error) {
	if count < 0 || count > parser.config.MaxContainerItems ||
		count > parser.config.MaxObjects-parser.objects {
		return nil, pycLimit("marshal container item count")
	}
	items := make([]*pycMarshalObject, count)
	for index := range items {
		item, err := parser.readObject(depth + 1)
		if err != nil {
			return nil, err
		}
		if item.kind == pycTypeNull {
			return nil, malformedPYC("null record appears outside a dictionary terminator")
		}
		items[index] = item
	}
	return items, nil
}

func (parser *pycMarshalParser) readDictionary(
	depth int,
) ([]*pycMarshalObject, error) {
	items := make([]*pycMarshalObject, 0)
	for pairs := 0; ; pairs++ {
		if pairs >= parser.config.MaxContainerItems {
			return nil, pycLimit("marshal dictionary item count")
		}
		key, err := parser.readObject(depth + 1)
		if err != nil {
			return nil, err
		}
		if key.kind == pycTypeNull {
			return items, nil
		}
		value, err := parser.readObject(depth + 1)
		if err != nil {
			return nil, err
		}
		if value.kind == pycTypeNull {
			return nil, malformedPYC("marshal dictionary value is null")
		}
		items = append(items, key, value)
	}
}

func (parser *pycMarshalParser) readContainerCount32() (int, error) {
	value, err := parser.readInt32()
	if err != nil {
		return 0, err
	}
	if value < 0 || int64(value) > int64(parser.config.MaxContainerItems) {
		return 0, pycLimit("marshal container item count")
	}
	return int(value), nil
}

func (parser *pycMarshalParser) readLongBlob() ([]byte, uint64, error) {
	length, err := parser.readInt32()
	if err != nil {
		return nil, 0, err
	}
	if length < 0 {
		return nil, 0, malformedPYC("marshal byte length is negative")
	}
	return parser.readBlob(int64(length))
}

func (parser *pycMarshalParser) readShortBlob() ([]byte, uint64, error) {
	length, err := parser.readByte()
	if err != nil {
		return nil, 0, err
	}
	return parser.readBlob(int64(length))
}

func (parser *pycMarshalParser) readBlob(length int64) ([]byte, uint64, error) {
	if length < 0 || length > parser.config.MaxStringBytes-parser.scalarBytes ||
		length > int64(math.MaxInt) {
		return nil, 0, pycLimit("marshal scalar bytes")
	}
	offset := parser.position
	payload, err := parser.take(int(length))
	if err != nil {
		return nil, 0, err
	}
	parser.scalarBytes += length
	return payload, uint64(offset), nil
}

func (parser *pycMarshalParser) skipShortScalar() error {
	length, err := parser.readByte()
	if err != nil {
		return err
	}
	_, _, err = parser.readBlob(int64(length))
	return err
}

func (parser *pycMarshalParser) skipLongInteger() error {
	digits, err := parser.readInt32()
	if err != nil {
		return err
	}
	absDigits := int64(digits)
	if absDigits < 0 {
		absDigits = -absDigits
	}
	if absDigits > int64(parser.config.MaxContainerItems) ||
		absDigits > math.MaxInt64/2 {
		return pycLimit("marshal long integer digits")
	}
	_, _, err = parser.readBlob(absDigits * 2)
	return err
}

func (parser *pycMarshalParser) readInt32() (int32, error) {
	payload, err := parser.take(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(payload)), nil
}

func (parser *pycMarshalParser) readByte() (byte, error) {
	payload, err := parser.take(1)
	if err != nil {
		return 0, err
	}
	return payload[0], nil
}

func (parser *pycMarshalParser) take(count int) ([]byte, error) {
	if count < 0 || parser.position < 0 || parser.position > len(parser.payload) ||
		count > len(parser.payload)-parser.position {
		return nil, malformedPYC("marshal payload is truncated")
	}
	start := parser.position
	parser.position += count
	return parser.payload[start:parser.position], nil
}

func pycBytesObject(object *pycMarshalObject) bool {
	return object != nil && object.kind == pycTypeBytes
}

func pycTupleObject(object *pycMarshalObject) bool {
	return object != nil &&
		(object.kind == pycTypeTuple || object.kind == pycTypeSmallTuple)
}

func pycStringTuple(object *pycMarshalObject) bool {
	if !pycTupleObject(object) {
		return false
	}
	for _, item := range object.items {
		if !pycTextObject(item) || !validPYCTextBytes(item.bytes, 4096) {
			return false
		}
	}
	return true
}

func pycTextObject(object *pycMarshalObject) bool {
	if object == nil {
		return false
	}
	switch object.kind {
	case pycTypeInterned, pycTypeUnicode, pycTypeASCII, pycTypeASCIIInterned,
		pycTypeShortASCII, pycTypeShortASCIIInterned:
		return true
	default:
		return false
	}
}

func validPYCTextBytes(payload []byte, maximum int) bool {
	return len(payload) > 0 && len(payload) <= maximum && utf8.Valid(payload) &&
		!strings.ContainsRune(string(payload), '\x00')
}

func isASCII(payload []byte) bool {
	for _, value := range payload {
		if value > 0x7f {
			return false
		}
	}
	return true
}
