package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	h "github.com/ubirch/ubirch-client-go/main/handlers/httphelper"
	"testing"
)

const (
	testInputStr string = "{\n  \"id\": \"ba70ad8b-a564-4e58-9a3b-224ac0f0153f\",\n  \"ts\": 1613733623,\n  \"big\": 5102163654257655,\n  \"tpl\": [\n    801874468,\n    \"<f,c\",\n    66,\n    \"#_Ÿ1cb\",\n    19875,\n    \"#d\",\n    10,\n    \"}d$\\\\n'™!&#8482{ï\\\"e%7ü\"\n  ],\n  \"lst\": [\n    \"%20\",\n    \"5\",\n    \"6\",\n    \"_\",\n    \"_\",\n    \"c\",\n    \"Ï\",\n    \"D\"\n  ],\n  \"map\": {\n    \"Ë\": 11,\n    \"F\": 44464,\n    \"`\": 114,\n    \"\": 2033005546\n  },\n  \"str\": \" |8_;5Ï®d;F),$:bfä\\\\nÿd./A\\\"9(£C8< |Ï(Ä[äü2\\\\,fU+2122e07]{9Eë`_Df);C])¬ÿ:7 |9}DË+f?U+2122ïa(®%E:8£27&\\\\&ÜU+2122Äc+!0f!ü™4Äb4'`.ÄÄ0$ü;~Fc'8'8e0ÄAfEC<}\"\n}"
	expOutputStr string = "{\"big\":5102163654257655,\"id\":\"ba70ad8b-a564-4e58-9a3b-224ac0f0153f\",\"lst\":[\"%20\",\"5\",\"6\",\"_\",\"_\",\"c\",\"Ï\",\"D\"],\"map\":{\"\":2033005546,\"F\":44464,\"`\":114,\"Ë\":11},\"str\":\" |8_;5Ï®d;F),$:bfä\\\\nÿd./A\\\"9(£C8< |Ï(Ä[äü2\\\\,fU+2122e07]{9Eë`_Df);C])¬ÿ:7 |9}DË+f?U+2122ïa(®%E:8£27&\\\\&ÜU+2122Äc+!0f!ü™4Äb4'`.ÄÄ0$ü;~Fc'8'8e0ÄAfEC<}\",\"tpl\":[801874468,\"<f,c\",66,\"#_Ÿ1cb\",19875,\"#d\",10,\"}d$\\\\n'™!&#8482{ï\\\"e%7ü\"],\"ts\":1613733623}"
	expHash_64   string = "eOp3knHnkZ3Hu7q33OGl4EwC5hXrPK78STk76cMfI4Q="
)

func TestSortedCompactJson(t *testing.T) {
	var tests = []struct {
		testInput      []byte
		expectedOutput []byte
		expectedHash   string
	}{
		{
			testInput:      []byte(testInputStr),
			expectedOutput: []byte(expOutputStr),
			expectedHash:   expHash_64,
		},
	}

	for _, test := range tests {
		out, err := h.GetSortedCompactJSON(test.testInput)
		if err != nil {
			t.Errorf("getSortedCompactJSON returned error: %v", err)
		}

		if !bytes.Equal(out, test.expectedOutput) {
			t.Errorf("getSortedCompactJSON did not return expected output:\n"+
				"- expected: %s\n"+
				"-      got: %s", test.expectedOutput, out)
		}

		hash := sha256.Sum256(out)
		expHash, err := base64.StdEncoding.DecodeString(test.expectedHash)
		if err != nil {
			t.Errorf("could not decode expected hash from base64 string: %v", err)
		}

		if !bytes.Equal(hash[:], expHash) {
			t.Errorf("hash not as expected:\n"+
				"- expected: %s\n"+
				"-      got: %s", test.expectedHash, base64.StdEncoding.EncodeToString(hash[:]))
		}
	}
}
