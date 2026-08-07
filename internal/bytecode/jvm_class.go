package bytecode

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var errMalformedJVMClass = errors.New("malformed JVM class")

type jvmParsedClass struct {
	BinaryName   string
	SourceFile   string
	MinorVersion uint16
	MajorVersion uint16
	AccessFlags  uint16
	SHA256       string
	Methods      []jvmParsedMethod
}

type jvmParsedMethod struct {
	Name        string
	Descriptor  string
	AccessFlags uint16
	Code        *jvmParsedCode
}

type jvmParsedCode struct {
	OffsetBytes uint64
	SizeBytes   uint64
	SHA256      string
	Hex         string
}

type jvmConstant struct {
	tag    byte
	utf8   string
	index1 uint16
	index2 uint16
}

type jvmClassReader struct {
	payload  []byte
	position int
	base     int
}

func parseJVMClass(payload []byte) (jvmParsedClass, error) {
	reader := jvmClassReader{payload: payload}
	magic, err := reader.u4()
	if err != nil || magic != 0xcafebabe {
		return jvmParsedClass{}, malformedJVMClass("magic is invalid")
	}
	minor, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	major, err := reader.u2()
	if err != nil || major < 45 || major > 1000 {
		return jvmParsedClass{}, malformedJVMClass("version is invalid")
	}
	constants, err := parseJVMConstantPool(&reader)
	if err != nil {
		return jvmParsedClass{}, err
	}
	if err := validateJVMConstantPool(constants, major); err != nil {
		return jvmParsedClass{}, err
	}
	accessFlags, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	thisClass, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	superClass, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	internalName, err := jvmClassName(constants, thisClass)
	if err != nil || !validJVMInternalName(internalName) {
		return jvmParsedClass{}, malformedJVMClass("class name is invalid")
	}
	if superClass != 0 {
		superName, superErr := jvmClassName(constants, superClass)
		if superErr != nil || !validJVMInternalName(superName) {
			return jvmParsedClass{}, malformedJVMClass("super class is invalid")
		}
	}
	interfaceCount, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	for range int(interfaceCount) {
		index, indexErr := reader.u2()
		if indexErr != nil {
			return jvmParsedClass{}, indexErr
		}
		interfaceName, nameErr := jvmClassName(constants, index)
		if nameErr != nil || !validJVMInternalName(interfaceName) {
			return jvmParsedClass{}, malformedJVMClass("interface is invalid")
		}
	}
	fieldCount, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	for range int(fieldCount) {
		if err := parseJVMField(&reader, constants); err != nil {
			return jvmParsedClass{}, err
		}
	}
	methodCount, err := reader.u2()
	if err != nil {
		return jvmParsedClass{}, err
	}
	methods := make([]jvmParsedMethod, 0, methodCount)
	methodSignatures := make(map[string]struct{}, methodCount)
	for range int(methodCount) {
		method, methodErr := parseJVMMethod(&reader, constants)
		if methodErr != nil {
			return jvmParsedClass{}, methodErr
		}
		signature := method.Name + "\x00" + method.Descriptor
		if _, exists := methodSignatures[signature]; exists {
			return jvmParsedClass{}, malformedJVMClass("method is duplicated")
		}
		methodSignatures[signature] = struct{}{}
		methods = append(methods, method)
	}
	sourceFile, err := parseJVMClassAttributes(&reader, constants)
	if err != nil {
		return jvmParsedClass{}, err
	}
	if reader.remaining() != 0 {
		return jvmParsedClass{}, malformedJVMClass("trailing bytes are present")
	}
	digest := sha256.Sum256(payload)
	return jvmParsedClass{
		BinaryName:   strings.ReplaceAll(internalName, "/", "."),
		SourceFile:   sourceFile,
		MinorVersion: minor,
		MajorVersion: major,
		AccessFlags:  accessFlags,
		SHA256:       hex.EncodeToString(digest[:]),
		Methods:      methods,
	}, nil
}

func parseJVMConstantPool(reader *jvmClassReader) ([]jvmConstant, error) {
	count, err := reader.u2()
	if err != nil || count == 0 {
		return nil, malformedJVMClass("constant pool count is invalid")
	}
	constants := make([]jvmConstant, int(count))
	for index := 1; index < int(count); index++ {
		tag, tagErr := reader.u1()
		if tagErr != nil {
			return nil, tagErr
		}
		entry := jvmConstant{tag: tag}
		switch tag {
		case 1:
			length, lengthErr := reader.u2()
			if lengthErr != nil {
				return nil, lengthErr
			}
			encoded, takeErr := reader.take(uint64(length))
			if takeErr != nil {
				return nil, takeErr
			}
			entry.utf8, takeErr = decodeModifiedUTF8(encoded)
			if takeErr != nil {
				return nil, malformedJVMClass("constant UTF-8 is invalid")
			}
		case 3, 4:
			if _, tagErr = reader.take(4); tagErr != nil {
				return nil, tagErr
			}
		case 5, 6:
			if index+1 >= int(count) {
				return nil, malformedJVMClass("wide constant is truncated")
			}
			if _, tagErr = reader.take(8); tagErr != nil {
				return nil, tagErr
			}
			constants[index] = entry
			index++
			continue
		case 7, 8, 16, 19, 20:
			entry.index1, tagErr = reader.u2()
			if tagErr != nil {
				return nil, tagErr
			}
		case 9, 10, 11, 12, 17, 18:
			entry.index1, tagErr = reader.u2()
			if tagErr != nil {
				return nil, tagErr
			}
			entry.index2, tagErr = reader.u2()
			if tagErr != nil {
				return nil, tagErr
			}
		case 15:
			kind, kindErr := reader.u1()
			if kindErr != nil || kind < 1 || kind > 9 {
				return nil, malformedJVMClass("method handle is invalid")
			}
			entry.index1 = uint16(kind)
			entry.index2, tagErr = reader.u2()
			if tagErr != nil {
				return nil, tagErr
			}
		default:
			return nil, malformedJVMClass("constant pool tag is unsupported")
		}
		constants[index] = entry
	}
	return constants, nil
}

func validateJVMConstantPool(constants []jvmConstant, major uint16) error {
	for index := 1; index < len(constants); index++ {
		entry := constants[index]
		switch entry.tag {
		case 0:
			if index == 1 || (constants[index-1].tag != 5 && constants[index-1].tag != 6) {
				return malformedJVMClass("constant pool contains an empty slot")
			}
		case 1, 3, 4, 5, 6:
			continue
		case 7:
			name, err := jvmUTF8(constants, entry.index1)
			if err != nil || !validJVMClassConstantName(name) {
				return malformedJVMClass("class constant is invalid")
			}
		case 8:
			if _, err := jvmUTF8(constants, entry.index1); err != nil {
				return malformedJVMClass("string constant is invalid")
			}
		case 9:
			name, descriptor, err := validateJVMReference(constants, entry, 9)
			if err != nil || !validJVMMemberName(name, false) ||
				!validJVMFieldDescriptor(descriptor) {
				return malformedJVMClass("field reference is invalid")
			}
		case 10, 11:
			name, descriptor, err := validateJVMReference(constants, entry, entry.tag)
			if err != nil || !validJVMMemberName(name, true) ||
				name == "<clinit>" || (entry.tag == 11 && name == "<init>") ||
				!validJVMMethodDescriptor(descriptor) {
				return malformedJVMClass("method reference is invalid")
			}
		case 12:
			name, descriptor, err := jvmNameAndType(constants, uint16(index))
			if err != nil ||
				(!validJVMMemberName(name, false) && !validJVMMemberName(name, true)) ||
				(!validJVMFieldDescriptor(descriptor) &&
					!validJVMMethodDescriptor(descriptor)) {
				return malformedJVMClass("name-and-type constant is invalid")
			}
		case 15:
			if major < 51 || !validJVMMethodHandle(constants, entry) {
				return malformedJVMClass("method handle constant is invalid")
			}
		case 16:
			descriptor, err := jvmUTF8(constants, entry.index1)
			if major < 51 || err != nil || !validJVMMethodDescriptor(descriptor) {
				return malformedJVMClass("method type constant is invalid")
			}
		case 17:
			name, descriptor, err := jvmNameAndType(constants, entry.index2)
			if major < 55 || err != nil || !validJVMMemberName(name, false) ||
				!validJVMFieldDescriptor(descriptor) {
				return malformedJVMClass("dynamic constant is invalid")
			}
		case 18:
			name, descriptor, err := jvmNameAndType(constants, entry.index2)
			if major < 51 || err != nil || !validJVMMemberName(name, true) ||
				strings.ContainsAny(name, "<>") || !validJVMMethodDescriptor(descriptor) {
				return malformedJVMClass("invoke-dynamic constant is invalid")
			}
		case 19, 20:
			name, err := jvmUTF8(constants, entry.index1)
			if major < 53 || err != nil || !validJVMText(name, 2048) {
				return malformedJVMClass("module constant is invalid")
			}
		default:
			return malformedJVMClass("constant pool entry is invalid")
		}
	}
	return nil
}

func validateJVMReference(
	constants []jvmConstant,
	entry jvmConstant,
	wantTag byte,
) (string, string, error) {
	if entry.tag != wantTag || entry.index1 == 0 ||
		int(entry.index1) >= len(constants) || constants[entry.index1].tag != 7 {
		return "", "", errMalformedJVMClass
	}
	return jvmNameAndType(constants, entry.index2)
}

func jvmNameAndType(
	constants []jvmConstant,
	index uint16,
) (string, string, error) {
	if index == 0 || int(index) >= len(constants) || constants[index].tag != 12 {
		return "", "", errMalformedJVMClass
	}
	name, err := jvmUTF8(constants, constants[index].index1)
	if err != nil {
		return "", "", err
	}
	descriptor, err := jvmUTF8(constants, constants[index].index2)
	return name, descriptor, err
}

func validJVMMethodHandle(constants []jvmConstant, entry jvmConstant) bool {
	kind := byte(entry.index1)
	if entry.index2 == 0 || int(entry.index2) >= len(constants) {
		return false
	}
	referenceTag := constants[entry.index2].tag
	switch kind {
	case 1, 2, 3, 4:
		return referenceTag == 9
	case 5, 8:
		return referenceTag == 10
	case 6, 7:
		return referenceTag == 10 || referenceTag == 11
	case 9:
		return referenceTag == 11
	default:
		return false
	}
}

func validJVMClassConstantName(value string) bool {
	if strings.HasPrefix(value, "[") {
		return validJVMFieldDescriptor(value)
	}
	return validJVMInternalName(value)
}

func parseJVMField(reader *jvmClassReader, constants []jvmConstant) error {
	if _, err := reader.u2(); err != nil {
		return err
	}
	nameIndex, err := reader.u2()
	if err != nil {
		return err
	}
	descriptorIndex, err := reader.u2()
	if err != nil {
		return err
	}
	name, err := jvmUTF8(constants, nameIndex)
	if err != nil || !validJVMMemberName(name, false) {
		return malformedJVMClass("field name is invalid")
	}
	descriptor, err := jvmUTF8(constants, descriptorIndex)
	if err != nil || !validJVMFieldDescriptor(descriptor) {
		return malformedJVMClass("field descriptor is invalid")
	}
	attributeCount, err := reader.u2()
	if err != nil {
		return err
	}
	return skipJVMAttributes(reader, constants, int(attributeCount))
}

func parseJVMMethod(
	reader *jvmClassReader,
	constants []jvmConstant,
) (jvmParsedMethod, error) {
	accessFlags, err := reader.u2()
	if err != nil {
		return jvmParsedMethod{}, err
	}
	nameIndex, err := reader.u2()
	if err != nil {
		return jvmParsedMethod{}, err
	}
	descriptorIndex, err := reader.u2()
	if err != nil {
		return jvmParsedMethod{}, err
	}
	name, err := jvmUTF8(constants, nameIndex)
	if err != nil || !validJVMMemberName(name, true) {
		return jvmParsedMethod{}, malformedJVMClass("method name is invalid")
	}
	descriptor, err := jvmUTF8(constants, descriptorIndex)
	if err != nil || !validJVMMethodDescriptor(descriptor) {
		return jvmParsedMethod{}, malformedJVMClass("method descriptor is invalid")
	}
	if name == "<init>" && !strings.HasSuffix(descriptor, ")V") {
		return jvmParsedMethod{}, malformedJVMClass("constructor descriptor is invalid")
	}
	if name == "<clinit>" && descriptor != "()V" {
		return jvmParsedMethod{}, malformedJVMClass("class initializer is invalid")
	}
	attributeCount, err := reader.u2()
	if err != nil {
		return jvmParsedMethod{}, err
	}
	method := jvmParsedMethod{
		Name: name, Descriptor: descriptor, AccessFlags: accessFlags,
	}
	for range int(attributeCount) {
		attributeName, payload, attributeErr := readJVMAttribute(reader, constants)
		if attributeErr != nil {
			return jvmParsedMethod{}, attributeErr
		}
		if attributeName != "Code" {
			continue
		}
		if method.Code != nil {
			return jvmParsedMethod{}, malformedJVMClass("Code attribute is duplicated")
		}
		code, codeErr := parseJVMCodeAttribute(payload, constants)
		if codeErr != nil {
			return jvmParsedMethod{}, codeErr
		}
		method.Code = &code
	}
	abstractOrNative := accessFlags&(0x0400|0x0100) != 0
	if abstractOrNative == (method.Code != nil) {
		return jvmParsedMethod{}, malformedJVMClass("method Code attribute is inconsistent")
	}
	return method, nil
}

func parseJVMCodeAttribute(
	reader jvmClassReader,
	constants []jvmConstant,
) (jvmParsedCode, error) {
	if _, err := reader.u2(); err != nil {
		return jvmParsedCode{}, err
	}
	if _, err := reader.u2(); err != nil {
		return jvmParsedCode{}, err
	}
	codeLength, err := reader.u4()
	if err != nil || codeLength == 0 || codeLength > 65535 {
		return jvmParsedCode{}, malformedJVMClass("method bytecode length is invalid")
	}
	codeOffset := reader.absolutePosition()
	code, err := reader.take(uint64(codeLength))
	if err != nil {
		return jvmParsedCode{}, err
	}
	exceptionCount, err := reader.u2()
	if err != nil {
		return jvmParsedCode{}, err
	}
	for range int(exceptionCount) {
		start, tableErr := reader.u2()
		if tableErr != nil {
			return jvmParsedCode{}, tableErr
		}
		end, tableErr := reader.u2()
		if tableErr != nil {
			return jvmParsedCode{}, tableErr
		}
		handler, tableErr := reader.u2()
		if tableErr != nil {
			return jvmParsedCode{}, tableErr
		}
		catchType, tableErr := reader.u2()
		if tableErr != nil {
			return jvmParsedCode{}, tableErr
		}
		if start >= end || uint32(end) > codeLength ||
			uint32(handler) >= codeLength {
			return jvmParsedCode{}, malformedJVMClass("exception table range is invalid")
		}
		if catchType != 0 {
			if _, tableErr = jvmClassName(constants, catchType); tableErr != nil {
				return jvmParsedCode{}, malformedJVMClass("exception type is invalid")
			}
		}
	}
	nestedCount, err := reader.u2()
	if err != nil {
		return jvmParsedCode{}, err
	}
	if err := skipJVMAttributes(&reader, constants, int(nestedCount)); err != nil {
		return jvmParsedCode{}, err
	}
	if reader.remaining() != 0 {
		return jvmParsedCode{}, malformedJVMClass("Code attribute has trailing bytes")
	}
	digest := sha256.Sum256(code)
	return jvmParsedCode{
		OffsetBytes: uint64(codeOffset),
		SizeBytes:   uint64(len(code)),
		SHA256:      hex.EncodeToString(digest[:]),
		Hex:         hex.EncodeToString(code),
	}, nil
}

func parseJVMClassAttributes(
	reader *jvmClassReader,
	constants []jvmConstant,
) (string, error) {
	count, err := reader.u2()
	if err != nil {
		return "", err
	}
	sourceFile := ""
	seenSourceFile := false
	for range int(count) {
		name, payload, attributeErr := readJVMAttribute(reader, constants)
		if attributeErr != nil {
			return "", attributeErr
		}
		if name != "SourceFile" {
			continue
		}
		if seenSourceFile || payload.remaining() != 2 {
			return "", malformedJVMClass("SourceFile attribute is invalid")
		}
		seenSourceFile = true
		index, indexErr := payload.u2()
		if indexErr != nil {
			return "", indexErr
		}
		candidate, indexErr := jvmUTF8(constants, index)
		if indexErr != nil || !validJVMSourceFile(candidate) {
			return "", malformedJVMClass("source file name is invalid")
		}
		sourceFile = candidate
	}
	return sourceFile, nil
}

func skipJVMAttributes(
	reader *jvmClassReader,
	constants []jvmConstant,
	count int,
) error {
	for range count {
		if _, _, err := readJVMAttribute(reader, constants); err != nil {
			return err
		}
	}
	return nil
}

func readJVMAttribute(
	reader *jvmClassReader,
	constants []jvmConstant,
) (string, jvmClassReader, error) {
	nameIndex, err := reader.u2()
	if err != nil {
		return "", jvmClassReader{}, err
	}
	name, err := jvmUTF8(constants, nameIndex)
	if err != nil || !validJVMAttributeName(name) {
		return "", jvmClassReader{}, malformedJVMClass("attribute name is invalid")
	}
	length, err := reader.u4()
	if err != nil {
		return "", jvmClassReader{}, err
	}
	payload, absolute, err := reader.takeAt(uint64(length))
	if err != nil {
		return "", jvmClassReader{}, err
	}
	return name, jvmClassReader{payload: payload, base: absolute}, nil
}

func jvmUTF8(constants []jvmConstant, index uint16) (string, error) {
	if index == 0 || int(index) >= len(constants) || constants[index].tag != 1 {
		return "", errMalformedJVMClass
	}
	return constants[index].utf8, nil
}

func jvmClassName(constants []jvmConstant, index uint16) (string, error) {
	if index == 0 || int(index) >= len(constants) || constants[index].tag != 7 {
		return "", errMalformedJVMClass
	}
	return jvmUTF8(constants, constants[index].index1)
}

func (reader *jvmClassReader) u1() (byte, error) {
	payload, err := reader.take(1)
	if err != nil {
		return 0, err
	}
	return payload[0], nil
}

func (reader *jvmClassReader) u2() (uint16, error) {
	payload, err := reader.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(payload), nil
}

func (reader *jvmClassReader) u4() (uint32, error) {
	payload, err := reader.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(payload), nil
}

func (reader *jvmClassReader) take(length uint64) ([]byte, error) {
	payload, _, err := reader.takeAt(length)
	return payload, err
}

func (reader *jvmClassReader) takeAt(length uint64) ([]byte, int, error) {
	if length > uint64(reader.remaining()) {
		return nil, 0, malformedJVMClass("class structure is truncated")
	}
	start := reader.position
	reader.position += int(length)
	return reader.payload[start:reader.position], reader.base + start, nil
}

func (reader *jvmClassReader) remaining() int {
	return len(reader.payload) - reader.position
}

func (reader *jvmClassReader) absolutePosition() int {
	return reader.base + reader.position
}

func malformedJVMClass(message string) error {
	return fmt.Errorf("%w: %s", errMalformedJVMClass, message)
}

func validJVMText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) ||
		strings.IndexByte(value, 0) >= 0 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validJVMInternalName(value string) bool {
	if !validJVMText(value, 2048) || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, ".;[") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validJVMMemberName(value string, method bool) bool {
	if !validJVMText(value, 1024) || strings.ContainsAny(value, ".;[/") {
		return false
	}
	if strings.ContainsAny(value, "<>") {
		return method && (value == "<init>" || value == "<clinit>")
	}
	return true
}

func validJVMAttributeName(value string) bool {
	return validJVMText(value, 1024) && !strings.ContainsAny(value, ".;[/<>")
}

func validJVMSourceFile(value string) bool {
	return validJVMText(value, 2048) && value != "." && value != ".." &&
		!strings.ContainsAny(value, "/\\")
}

func validJVMFieldDescriptor(value string) bool {
	position := 0
	return parseJVMFieldType(value, &position, false) && position == len(value)
}

func validJVMMethodDescriptor(value string) bool {
	if len(value) < 3 || value[0] != '(' || len(value) > 4096 {
		return false
	}
	position := 1
	for position < len(value) && value[position] != ')' {
		if !parseJVMFieldType(value, &position, false) {
			return false
		}
	}
	if position >= len(value) || value[position] != ')' {
		return false
	}
	position++
	if position < len(value) && value[position] == 'V' {
		position++
		return position == len(value)
	}
	return parseJVMFieldType(value, &position, false) && position == len(value)
}

func parseJVMFieldType(value string, position *int, allowVoid bool) bool {
	if *position >= len(value) {
		return false
	}
	switch value[*position] {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		*position++
		return true
	case 'V':
		if !allowVoid {
			return false
		}
		*position++
		return true
	case 'L':
		start := *position + 1
		end := strings.IndexByte(value[start:], ';')
		if end < 0 {
			return false
		}
		end += start
		if !validJVMInternalName(value[start:end]) {
			return false
		}
		*position = end + 1
		return true
	case '[':
		dimensions := 0
		for *position < len(value) && value[*position] == '[' {
			*position++
			dimensions++
			if dimensions > 255 {
				return false
			}
		}
		return parseJVMFieldType(value, position, false)
	default:
		return false
	}
}

func decodeModifiedUTF8(encoded []byte) (string, error) {
	runes := make([]rune, 0, len(encoded))
	for position := 0; position < len(encoded); {
		first := encoded[position]
		switch {
		case first > 0 && first < 0x80:
			runes = append(runes, rune(first))
			position++
		case first&0xe0 == 0xc0:
			if position+1 >= len(encoded) || encoded[position+1]&0xc0 != 0x80 {
				return "", errMalformedJVMClass
			}
			value := rune(first&0x1f)<<6 | rune(encoded[position+1]&0x3f)
			if value < 0x80 && !(first == 0xc0 && encoded[position+1] == 0x80) {
				return "", errMalformedJVMClass
			}
			runes = append(runes, value)
			position += 2
		case first&0xf0 == 0xe0:
			value, next, err := decodeModifiedUTF8Triple(encoded, position)
			if err != nil {
				return "", err
			}
			position = next
			if value >= 0xd800 && value <= 0xdbff {
				low, afterLow, lowErr := decodeModifiedUTF8Triple(encoded, position)
				if lowErr != nil || low < 0xdc00 || low > 0xdfff {
					return "", errMalformedJVMClass
				}
				runes = append(runes, 0x10000+(value-0xd800)<<10+(low-0xdc00))
				position = afterLow
			} else if value >= 0xdc00 && value <= 0xdfff {
				return "", errMalformedJVMClass
			} else {
				runes = append(runes, value)
			}
		default:
			return "", errMalformedJVMClass
		}
	}
	decoded := string(runes)
	if !utf8.ValidString(decoded) {
		return "", errMalformedJVMClass
	}
	return decoded, nil
}

func decodeModifiedUTF8Triple(encoded []byte, position int) (rune, int, error) {
	if position+2 >= len(encoded) || encoded[position]&0xf0 != 0xe0 ||
		encoded[position+1]&0xc0 != 0x80 || encoded[position+2]&0xc0 != 0x80 {
		return 0, position, errMalformedJVMClass
	}
	value := rune(encoded[position]&0x0f)<<12 |
		rune(encoded[position+1]&0x3f)<<6 |
		rune(encoded[position+2]&0x3f)
	if value < 0x800 {
		return 0, position, errMalformedJVMClass
	}
	return value, position + 3, nil
}
