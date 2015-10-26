package rawzip

import "io"

/*
   [local file header 1]
   [encryption header 1]
   [file data 1]
   [data descriptor 1]
   ...
   [local file header n]
   [encryption header n]
   [file data n]
   [data descriptor n]
   [archive decryption header]
   [archive extra data record]
   [central directory header 1]
   ...
   [central directory header n]
   [zip64 end of central directory record]
   [zip64 end of central directory locator]
   [end of central directory record]
*/

// NewZipReader returns a new instance of ZipReader.
func NewZipReader(r *io.ReadSeeker) *ZipReader {
	return nil
}

type ZipReader struct {
	r     *io.ReadSeeker
	state zipReaderState
}

type zipRecordSignature uint32

const (
	zipRecordLocalFile      zipRecordSignature = 0x04034b50
	zipRecordDataDescriptor zipRecordSignature = 0x08074b50
	zipRecordCD             zipRecordSignature = 0x02014b50
	zipRecordCDEnd          zipRecordSignature = 0x06054b50

	zipRecordExtraData        zipRecordSignature = 0x08064b50
	zipRecordDigitalSignature zipRecordSignature = 0x05054b50
	zipRecordZip64CDEnd       zipRecordSignature = 0x06064b50
	zipRecordZip64CDEndLoc    zipRecordSignature = 0x07064b50
)

type zipReaderState int

const (
	stateUninitialized zipReaderState = iota
	stateReading
	stateFinished
)

type ZipEntryEncryption uint16

const (
	// EncryptionNone indicates that no encryption is applied
	EncryptionNone ZipEntryEncryption = 0x00

	// EncryptionWeak indicates that data is encrypted with proprietary PKWARE enryption
	EncryptionWeak ZipEntryEncryption = 0x01

	// EncryptionStrong indicates that data is encrypted with AES or something else
	EncryptionStrong ZipEntryEncryption = 0x41
)

type ZipArchive struct {
	reader  io.ReadSeeker
	Entries []*ZipEntry
}
type ZipEntry struct {
	reader      io.ReadSeeker
	offset      int64 // matching io.Seeker
	Header      privateZipHeader
	filenameRaw []byte
	extraFields []byte
}
type privateZipHeader struct {
	Signature        uint32
	ReaderVer        uint16
	Flags            uint16
	Method           uint16
	ModTime          uint16
	ModDate          uint16
	CRC32            uint32
	SizeCompressed   uint32
	SizeUncompressed uint32
	FilenameLen      uint16
	ExtraFieldLen    uint16
}

func (z *ZipEntry) IsSignatureValid() bool {
	return z.Header.Signature == 0x04034b50
}
func (z *ZipEntry) IsWeakEncryption() bool {
	return (z.Header.flags & 0x41) == 0x01
}
func (z *ZipEntry) IsStrongEncryption() bool {
	return (z.Header.flags & 0x41) == 0x41
}
func (z *ZipEntry) IsPlaintext() bool {
	return (z.Header.flags & 0x41) == 0x00
}
