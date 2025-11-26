package logging

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

// Level 은 로그의 심각도 레벨을 나타냅니다.
type Level string

const (
	DebugLevel Level = "debug"
	InfoLevel  Level = "info"
	WarnLevel  Level = "warn"
	ErrorLevel Level = "error"
)

// Fields 는 구조적 로그의 key/value 필드를 표현합니다.
// Loki/Promtail 에서 라벨/필드로 활용할 수 있습니다.
type Fields map[string]any

// Logger 는 Loki/Grafana 스택에 적합한 구조적 로그 인터페이스입니다.
//
// - 모든 구현체는 단일 라인 JSON 을 stdout/stderr 로 출력하는 것을 목표로 합니다.
// - Promtail 은 stdout 을 수집해 Loki 로 전송하고, Grafana 에서 쿼리/대시보딩 할 수 있습니다.
type Logger interface {
	// Debug 는 디버그 레벨 로그를 기록합니다.
	Debug(msg string, fields Fields)

	// Info 는 정보 레벨 로그를 기록합니다.
	Info(msg string, fields Fields)

	// Warn 는 경고 레벨 로그를 기록합니다.
	Warn(msg string, fields Fields)

	// Error 는 에러 레벨 로그를 기록합니다.
	Error(msg string, fields Fields)

	// With 는 추가 필드를 항상 포함하는 child logger 를 생성합니다.
	With(fields Fields) Logger
}

// stdLogger 는 표준 log.Logger 를 감싼 구현체입니다.
// 개발 단계에서 간단히 사용하거나 JSON 형식이 필요 없을 때 사용할 수 있습니다.
type stdLogger struct {
	l      *log.Logger
	fields Fields
}

func (s *stdLogger) log(level Level, msg string, fields Fields) {
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}

	// 공통 필드 병합
	for k, v := range s.fields {
		entry[k] = v
	}
	// 호출 시 전달된 필드 병합(우선순위 높음)
	for k, v := range fields {
		entry[k] = v
	}

	b, err := json.Marshal(entry)
	if err != nil {
		// JSON 마샬 실패 시 fallback 으로 기본 포맷 사용
		s.l.Printf("level=%s msg=%s marshal_error=%v", level, msg, err)
		return
	}
	s.l.Println(string(b))
}

func (s *stdLogger) Debug(msg string, fields Fields) { s.log(DebugLevel, msg, fields) }
func (s *stdLogger) Info(msg string, fields Fields)  { s.log(InfoLevel, msg, fields) }
func (s *stdLogger) Warn(msg string, fields Fields)  { s.log(WarnLevel, msg, fields) }
func (s *stdLogger) Error(msg string, fields Fields) { s.log(ErrorLevel, msg, fields) }

func (s *stdLogger) With(fields Fields) Logger {
	merged := Fields{}
	for k, v := range s.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &stdLogger{
		l:      s.l,
		fields: merged,
	}
}

// NewStdJSONLogger 는 stdout 으로 단일 라인 JSON 로그를 출력하는 기본 Logger 를 생성합니다.
// Promtail 이 stdout 을 Loki 로 수집하는 전형적인 구성에 적합합니다.
//
// component, service, client_id, request_id 같은 필드를 With 로 미리 설정해 두면
// Grafana 에서 필터링/그룹핑에 활용할 수 있습니다.
func NewStdJSONLogger(component string) Logger {
	baseFields := Fields{
		"component": component,
	}
	return &stdLogger{
		l:      log.New(os.Stdout, "", 0), // 프리픽스/타임스탬프는 JSON 필드로만 사용
		fields: baseFields,
	}
}
