package types

type SSZSerializable interface {
	Serialize() []byte
}
