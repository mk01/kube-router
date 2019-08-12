package tools

import (
	"errors"
	"fmt"
	"github.com/golang/glog"
	"io"
	"log"
	"strings"
)

type errorWriterType struct {
	logger *log.Logger
	io.Writer
}

var errorWriter errorWriterType

func init() {
	errorWriter = errorWriterType{}
	errorWriter.logger = log.New(errorWriter, "", log.Lshortfile)
}

func (nl errorWriterType) Write(p []byte) (int, error) {
	err := strings.SplitN(string(p[:len(p)-1]), ": ", 2)
	return 0, errors.New(fmt.Sprintf("%s [@%s]", err[1], err[0]))
}

func NewError(s string) error {
	return errorWriter.logger.Output(2, s)
}

func newErrorf(back int, format string, v ...interface{}) error {
	return errorWriter.logger.Output(back, fmt.Sprintf(format, v...))
}

func NewErrorf(format string, v ...interface{}) error {
	return newErrorf(3, format, v...)
}

func AppendErrorf(err error, format string, v ...interface{}) error {
	if err == nil {
		return newErrorf(3, "\n"+format, v...)
	}
	return fmt.Errorf("%w%s", err, newErrorf(3, "\n"+format, v...).Error())
}

func UpdateErrorf(err *error, errNew error) {
	if errNew == nil {
		return
	}
	*err = fmt.Errorf("%w%s", err, newErrorf(3, "\n"+errNew.Error()).Error())
}

func EvalPass(err error) error {
	if err != nil {
		glog.Error(newErrorf(3, err.Error()))
	}
	return err
}

func Eval(err error) {
	EvalPass(err)
}
