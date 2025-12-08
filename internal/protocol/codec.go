package protocol

import (
	"bufio"
	"encoding/json"
	"io"
)

// defaultDecoderBufferSize 는 pion/dtls 가 복호화한 애플리케이션 데이터를
// JSON 디코더가 안전하게 처리할 수 있도록 사용하는 버퍼 크기입니다.
// This matches existing 64KiB readers used around DTLS sessions.
const defaultDecoderBufferSize = 64 * 1024

// WireCodec 는 protocol.Envelope 의 직렬화/역직렬화를 추상화합니다.
// JSON, Protobuf, length-prefixed binary 등으로 교체할 때 이 인터페이스만 유지하면 됩니다.
type WireCodec interface {
	Encode(w io.Writer, env *Envelope) error
	Decode(r io.Reader, env *Envelope) error
}

// jsonCodec 은 현재 사용 중인 JSON 기반 WireCodec 구현입니다.
type jsonCodec struct{}

// Encode 는 Envelope 를 JSON 으로 인코딩해 작성합니다.
// Encode encodes an Envelope as JSON to the given writer.
func (jsonCodec) Encode(w io.Writer, env *Envelope) error {
	enc := json.NewEncoder(w)
	return enc.Encode(env)
}

// Decode 는 DTLS 세션에서 읽은 데이터를 JSON Envelope 로 디코딩합니다.
// pion/dtls 의 버퍼 특성 때문에, 충분히 큰 bufio.Reader 로 감싸서 사용합니다.
// Decode decodes an Envelope from JSON using a buffered reader on top of the DTLS session.
func (jsonCodec) Decode(r io.Reader, env *Envelope) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, defaultDecoderBufferSize))
	return dec.Decode(env)
}

// DefaultCodec 은 현재 런타임에서 사용하는 기본 WireCodec 입니다.
// 초기 구현은 JSON 기반이지만, 추후 Protobuf/length-prefixed binary 로 교체 가능하도록 분리해 두었습니다.
var DefaultCodec WireCodec = jsonCodec{}
