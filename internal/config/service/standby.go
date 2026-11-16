package service

import "github.com/MimoProxy/reka/internal/config/model"

// networkOffDocument preserves every other local setting and comment. The
// caller commits it before preparing any persisted takeover configuration.
func networkOffDocument(data []byte) ([]byte, bool, error) {
	settings, _, ds := model.ParseLocal(data)
	if ds.HasErrors() {
		return nil, false, ds.Errors()
	}
	if settings.Network == nil || settings.Network.Mode == "" || settings.Network.Mode == "off" {
		return data, false, nil
	}
	doc, ds := model.LoadDoc(model.DocLocal, data)
	if ds.HasErrors() {
		return nil, false, ds.Errors()
	}
	if err := doc.Apply(model.Op{Op: "set", Path: "/network/mode", Value: []byte(`"off"`)}); err != nil {
		return nil, false, err
	}
	return doc.Bytes(), true, nil
}
