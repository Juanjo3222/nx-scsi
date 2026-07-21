package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func tok(nsa string) string {
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + nsa + `"}`))
	return "Bearer h." + p + ".s"
}

func rq(t *testing.T, srv *httptest.Server, method, host, pathQ, body string) (int, string) {
	r, _ := http.NewRequest(method, srv.URL+pathQ, strings.NewReader(body))
	r.Host = host
	r.Header.Set("Authorization", tok("testnsa"))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("%s %s err: %v", method, pathQ, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Rejoue un upload DELTA (avec archive précédente) comme la trace réelle.
func TestReplayDeltaUpload(t *testing.T) {
	store = newStore()
	const prevID = uint64(1000)
	prev := &Archive{
		ID: prevID, NsaID: "testnsa", ApplicationID: "0100152000022000",
		DeviceID: "6365870a09241c0e", DeviceSerial: "XAJ40022916590",
		Datatype: 0, Status: "fixed", NumOfPartitions: 1,
		ComponentFiles: []*ComponentFile{
			{ID: 111, Index: 0, Datatype: "meta", Status: "fixed", ArchiveSize: pi64(8192), EncodedArchiveDigest: ps("aaa==")},
			{ID: 222, Index: 4096, Datatype: "save", Status: "fixed", ArchiveSize: pi64(6323490), EncodedArchiveDigest: ps("bbb==")},
		},
	}
	store.archives[prevID] = prev
	for _, c := range prev.ComponentFiles {
		store.compTo[c.ID] = prevID
	}

	srv := httptest.NewServer(http.HandlerFunc(route))
	defer srv.Close()
	const H = "storage.hac.lp1.scsi.srv.nintendo.net"

	// 1) start_upload (corps réel capturé, SANS application_id)
	body := `{"datatype":0,"data_size":108920832,"saved_at_as_unixtime":1783207776,"launch_required_version":21,"series_id":8074304520302577754,"encoded_digest":"IHrhTwvELqY","desc":null,"auto_backup":false,"acd_index":0}`
	code, resp := rq(t, srv, "POST", H, "/api/console/v3/save_data_archives/1000/start_upload", body)
	t.Logf("START_UPLOAD -> %d\n%s\n", code, resp)
	if code != 201 {
		t.Fatalf("!! start_upload code=%d", code)
	}
	var su struct {
		A Archive `json:"save_data_archive"`
	}
	json.Unmarshal([]byte(resp), &su.A)
	json.Unmarshal([]byte(resp), &su)
	t.Logf("=> new id=%d, %d composants, num_of_partitions=%d, app=%q, nsa=%q", su.A.ID, len(su.A.ComponentFiles), su.A.NumOfPartitions, su.A.ApplicationID, su.A.NsaID)
	for _, c := range su.A.ComponentFiles {
		t.Logf("   comp id=%d idx=%d type=%s status=%s size=%v", c.ID, c.Index, c.Datatype, c.Status, c.ArchiveSize)
	}

	// 2) pour chaque composant save : update -> PUT blob -> finish
	for _, c := range su.A.ComponentFiles {
		if c.Datatype != "save" {
			continue
		}
		code, resp = rq(t, srv, "POST", H, "/api/console/v3/component_files/"+u64s(c.ID)+"/update", `{}`)
		t.Logf("UPDATE comp=%d -> %d %s", c.ID, code, resp)
		if code != 200 {
			t.Fatalf("!! update comp=%d code=%d", c.ID, code)
		}
		var up struct {
			C ComponentFile `json:"component_file"`
		}
		json.Unmarshal([]byte(resp), &up)
		u, _ := url.Parse(up.C.PutURL)
		t.Logf("   put_url host=%s path=%s", u.Host, u.Path)
		code, resp = rq(t, srv, "PUT", u.Host, u.Path+"?"+u.RawQuery, "FAKESAVEDATA_"+u64s(c.ID))
		t.Logf("PUT blob -> %d %s", code, resp)
		if code != 200 {
			t.Fatalf("!! blob PUT comp=%d code=%d (host=%s)", c.ID, code, u.Host)
		}
		code, resp = rq(t, srv, "POST", H, "/api/console/v3/component_files/"+u64s(c.ID)+"/finish_upload", `{"archive_size":12,"encoded_archive_digest":"ccc=="}`)
		t.Logf("FINISH comp=%d -> %d", c.ID, code)
		if code != 200 {
			t.Fatalf("!! comp finish=%d code=%d", c.ID, code)
		}
	}

	// 3) archive finish
	code, resp = rq(t, srv, "POST", H, "/api/console/v3/save_data_archives/"+u64s(su.A.ID)+"/finish_upload", `{"encoded_mac":"zzz"}`)
	t.Logf("ARCHIVE_FINISH -> %d\n%s", code, resp)
	if code != 200 {
		t.Fatalf("!! archive finish code=%d", code)
	}
	t.Logf("======== UPLOAD DELTA COMPLET OK (nx-scsi local) ========")
}
