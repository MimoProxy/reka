package api

type StageResourceRequest struct {
	Hash   string `json:"hash"`
	Size   int    `json:"size"`
	Offset int    `json:"offset"`
	Data   []byte `json:"data"`
}

type StageResourceResult struct {
	Hash     string `json:"hash"`
	Size     int    `json:"size"`
	Received int    `json:"received"`
	Ready    bool   `json:"ready"`
}
