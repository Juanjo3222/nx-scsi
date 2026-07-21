package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// storage.hac.lp1.scsi — l'API REST
// ---------------------------------------------------------------------------

func storageAPI(w http.ResponseWriter, r *http.Request) {
	// /api/console/v3/<resource>/...
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: [api console v3 <resource> ...]
	if len(parts) < 4 || parts[0] != "api" || parts[2] != "v3" {
		http.NotFound(w, r)
		return
	}
	resource := parts[3]
	rest := parts[4:]

	switch resource {
	case "network_service_accounts":
		// .../network_service_accounts/<nsaId>/notification_tokens
		if len(rest) == 2 && rest[1] == "notification_tokens" {
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			tok, _ := in["notification_token"].(string)
			writeJSON(w, http.StatusOK, map[string]any{"notification_token": tok})
			return
		}
	case "save_data_archives":
		archivesRoute(w, r, rest)
		return
	case "component_files":
		componentRoute(w, r, rest)
		return
	}
	http.NotFound(w, r)
}

func archivesRoute(w http.ResponseWriter, r *http.Request, rest []string) {
	nsa := nsaFromToken(r)

	// GET /save_data_archives?datatype=0[&application_id=..]
	if len(rest) == 0 {
		listArchives(w, r, nsa)
		return
	}

	id, err := strconv.ParseUint(rest[0], 10, 64)
	if err != nil {
		// action SANS id d'archive -> 1er upload : POST /save_data_archives/start_upload
		if len(rest) == 1 && rest[0] == "start_upload" {
			startUpload(w, r, 0)
			return
		}
		http.NotFound(w, r)
		return
	}

	// GET /save_data_archives/<id>
	if len(rest) == 1 {
		store.mu.Lock()
		a := store.archives[id]
		store.mu.Unlock()
		if a == nil {
			http.NotFound(w, r)
			return
		}
		resp := a
		if a.Status == "uploading" {
			// pendant l'upload : renvoyer les put_url par composant (la console upload depuis ici)
			c := cloneArchive(a)
			c.TimeoutAtAsUnixtime = time.Now().Unix() + 3600
			for _, cf := range c.ComponentFiles {
				if cf.Status == "hand_over" || cf.Status == "uploading" {
					cf.PutURL = putURL(a, cf)
				}
			}
			resp = c
		}
		writeJSON(w, http.StatusOK, map[string]any{"save_data_archive": resp})
		return
	}

	// POST /save_data_archives/<id>/<action>
	action := rest[1]
	switch action {
	case "generate_key_seed_package":
		generateKeySeed(w, r, id)
	case "start_download":
		startDownload(w, r, id)
	case "finish_download":
		archiveEcho(w, id)
	case "start_upload":
		startUpload(w, r, id)
	case "extend_upload_timeout":
		extendTimeout(w, id)
	case "finish_upload":
		finishArchiveUpload(w, r, id)
	case "component_files":
		// POST /save_data_archives/<id>/component_files/create  (1er upload : la console crée un composant)
		if len(rest) >= 3 && rest[2] == "create" {
			createComponent(w, r, id)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func countSave(cfs []*ComponentFile) int {
	n := 0
	for _, c := range cfs {
		if c.Datatype == "save" {
			n++
		}
	}
	return n
}

// POST /save_data_archives/<id>/component_files/create — la console crée un composant (1er upload).
func createComponent(w http.ResponseWriter, r *http.Request, archiveID uint64) {
	raw, _ := io.ReadAll(r.Body)
	log.Printf("[scsi] COMPONENT_CREATE archive=%d body=%s", archiveID, string(raw))
	var in struct {
		Index    int    `json:"index"`
		Datatype string `json:"datatype"`
	}
	_ = json.Unmarshal(raw, &in)
	if in.Datatype == "" {
		in.Datatype = "save"
	}
	store.mu.Lock()
	a := store.archives[archiveID]
	if a == nil {
		store.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	cf := &ComponentFile{ID: randU64(), Index: in.Index, Datatype: in.Datatype, Status: "hand_over"}
	a.ComponentFiles = append(a.ComponentFiles, cf)
	a.NumOfPartitions = countSave(a.ComponentFiles)
	store.compTo[cf.ID] = archiveID
	store.mu.Unlock()
	store.persist(a)
	resp := *cf
	resp.PutURL = putURL(a, cf) // renvoie l'URL d'upload direct
	rb, _ := json.Marshal(map[string]any{"component_file": &resp})
	log.Printf("[scsi] COMPONENT_CREATE resp=%s", string(rb))
	writeJSON(w, http.StatusCreated, map[string]any{"component_file": &resp})
}

func listArchives(w http.ResponseWriter, r *http.Request, nsa string) {
	q := r.URL.Query()
	datatype := q.Get("datatype") // "0" | "3" | ""
	appID := q.Get("application_id")

	store.mu.Lock()
	var out []*Archive
	for _, a := range store.archives {
		if nsa != "" && a.NsaID != nsa {
			continue
		}
		if a.Status != "fixed" {
			continue
		}
		if datatype != "" && itoa(a.Datatype) != datatype {
			continue
		}
		if appID != "" && a.ApplicationID != appID {
			continue
		}
		la := cloneArchive(a)
		la.ComponentFiles = nil       // la liste n'embarque pas les composants
		la.TimeoutAtAsUnixtime = 0
		out = append(out, la)
	}
	store.mu.Unlock()
	if out == nil {
		out = []*Archive{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"save_data_archives": out})
}

// POST /save_data_archives/<id>/generate_key_seed_package  {"encoded_challenge":".."}
// → {"encoded_key_seed_package":".."}. On rejoue le package stocké de l'archive.
func generateKeySeed(w http.ResponseWriter, r *http.Request, id uint64) {
	_, _ = io.Copy(io.Discard, r.Body)
	store.mu.Lock()
	a := store.archives[id]
	store.mu.Unlock()
	pkg := defaultKeySeed
	if a != nil && a.KeySeedPackage != "" {
		pkg = a.KeySeedPackage
	}
	// jamais de 404 ici : la console a besoin d'un package même si l'archive nous est inconnue
	// (1er upload = référence une archive "précédente" qu'on n'a pas encore).
	writeJSON(w, http.StatusOK, map[string]any{"encoded_key_seed_package": pkg})
}

// POST /save_data_archives/<id>/start_download → l'archive avec get_url par composant + timeout
func startDownload(w http.ResponseWriter, r *http.Request, id uint64) {
	_, _ = io.Copy(io.Discard, r.Body)
	store.mu.Lock()
	a := store.archives[id]
	store.mu.Unlock()
	if a == nil {
		http.NotFound(w, r)
		return
	}
	c := cloneArchive(a)
	c.TimeoutAtAsUnixtime = time.Now().Unix() + 3600
	var fixed []*ComponentFile
	for _, cf := range c.ComponentFiles {
		if cf.Status != "fixed" {
			continue // ignore un composant jamais uploadé (meta par défaut de start_upload)
		}
		cf.GetURL = getURL(a, cf)
		fixed = append(fixed, cf)
	}
	c.ComponentFiles = fixed
	writeJSON(w, http.StatusOK, map[string]any{"save_data_archive": c})
}

func archiveEcho(w http.ResponseWriter, id uint64) {
	store.mu.Lock()
	a := store.archives[id]
	store.mu.Unlock()
	if a == nil {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"save_data_archive": a})
}

func extendTimeout(w http.ResponseWriter, id uint64) {
	store.mu.Lock()
	a := store.archives[id]
	if a != nil {
		a.TimeoutAtAsUnixtime = time.Now().Unix() + 600
	}
	store.mu.Unlock()
	if a == nil {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"save_data_archive": a})
}

// POST /save_data_archives/<prevId>/start_upload  {metadata}
// Crée une NOUVELLE archive (nouveaux ids de composants, status hand_over) à partir de la
// structure de la précédente. Réponse 201.
func startUpload(w http.ResponseWriter, r *http.Request, prevID uint64) {
	var in struct {
		ApplicationID         string  `json:"application_id"`
		Datatype              int     `json:"datatype"`
		DataSize              int64   `json:"data_size"`
		SavedAtAsUnixtime     int64   `json:"saved_at_as_unixtime"`
		LaunchRequiredVersion int     `json:"launch_required_version"`
		SeriesID              uint64  `json:"series_id"`
		EncodedDigest         string  `json:"encoded_digest"`
		Desc                  *string `json:"desc"`
		AutoBackup            bool    `json:"auto_backup"`
		AcdIndex              int     `json:"acd_index"`
	}
	raw, _ := io.ReadAll(r.Body)
	log.Printf("[scsi] START_UPLOAD prev=%d body=%s", prevID, string(raw))
	_ = json.Unmarshal(raw, &in)

	store.mu.Lock()
	prev := store.archives[prevID]
	store.mu.Unlock()

	newID := randU64()
	a := &Archive{
		ID:                    newID,
		Datatype:              in.Datatype,
		DataSize:              in.DataSize,
		Desc:                  in.Desc,
		SeriesID:              in.SeriesID,
		Status:                "uploading",
		AutoBackup:            in.AutoBackup,
		LaunchRequiredVersion: in.LaunchRequiredVersion,
		AcdIndex:              in.AcdIndex,
		EncodedDigest:         in.EncodedDigest,
		SavedAtAsUnixtime:     in.SavedAtAsUnixtime,
		PlatformKeyGeneration: 0,
		TimeoutAtAsUnixtime:   time.Now().Unix() + 600,
		PreviousSaveDataArchiveID: func() *uint64 {
			if prev != nil {
				return p64(prevID)
			}
			return nil
		}(),
	}
	// identité (repris du corps + token/précédent)
	a.NsaID = nsaFromToken(r)
	a.ApplicationID = in.ApplicationID
	a.DeviceID = "0000000000000000"
	a.DeviceSerial = "XAX00000000000"
	if prev != nil {
		if a.NsaID == "" {
			a.NsaID = prev.NsaID
		}
		if a.ApplicationID == "" {
			a.ApplicationID = prev.ApplicationID
		}
		a.DeviceID = prev.DeviceID
		a.DeviceSerial = prev.DeviceSerial
		a.KeySeedPackage = prev.KeySeedPackage // continuité de clé de série
	}
	// log de la réponse pour comparer à la trace (0083)
	defer func() { rb, _ := json.Marshal(map[string]any{"save_data_archive": a}); log.Printf("[scsi] START_UPLOAD resp=%s", string(rb)) }()

	// composants : copiés de la précédente ; 1er upload (prev==nil) -> structure minimale
	// (meta + 1 save) que la console accepte pour démarrer, puis elle en crée d'autres via create.
	if prev != nil && len(prev.ComponentFiles) > 0 {
		for _, t := range prev.ComponentFiles {
			cf := &ComponentFile{ID: randU64(), Index: t.Index, Datatype: t.Datatype, Status: "hand_over"}
			if t.ArchiveSize != nil {
				cf.ArchiveSize = pi64(*t.ArchiveSize)
			}
			if t.EncodedArchiveDigest != nil {
				cf.EncodedArchiveDigest = ps(*t.EncodedArchiveDigest)
			}
			a.ComponentFiles = append(a.ComponentFiles, cf)
		}
	} else {
		// meta SEUL : la console crée elle-même les composants "save" (index 4096+) via create.
		a.ComponentFiles = []*ComponentFile{
			{ID: randU64(), Index: 0, Datatype: "meta", Status: "hand_over"},
		}
	}
	a.NumOfPartitions = countSave(a.ComponentFiles) // vrai Nintendo = nb de SAVES (exclut meta), pas len

	store.mu.Lock()
	store.archives[newID] = a
	for _, cf := range a.ComponentFiles {
		store.compTo[cf.ID] = newID
	}
	store.mu.Unlock()
	store.persist(a)

	writeJSON(w, http.StatusCreated, map[string]any{"save_data_archive": a})
}

// POST /save_data_archives/<id>/finish_upload  {"encoded_mac":".."}  → archive "fixed"
func finishArchiveUpload(w http.ResponseWriter, r *http.Request, id uint64) {
	_, _ = io.Copy(io.Discard, r.Body)
	store.mu.Lock()
	a := store.archives[id]
	if a != nil {
		// purge les composants jamais uploadés (ex. meta par défaut si la console a créé le sien)
		kept := make([]*ComponentFile, 0, len(a.ComponentFiles))
		for _, cf := range a.ComponentFiles {
			if cf.Status == "fixed" {
				kept = append(kept, cf)
			}
		}
		a.ComponentFiles = kept
		a.NumOfPartitions = countSave(a.ComponentFiles)
		a.Status = "fixed"
		now := time.Now().Unix()
		a.FinishedAtAsUnixtime = pi64(now)
		a.TimeoutAtAsUnixtime = 0
	}
	store.mu.Unlock()
	if a == nil {
		http.NotFound(w, r)
		return
	}
	store.persist(a)
	writeJSON(w, http.StatusOK, map[string]any{"save_data_archive": a})
}

// ---------------------------------------------------------------------------
// component_files/<id>/<action>
// ---------------------------------------------------------------------------

func componentRoute(w http.ResponseWriter, r *http.Request, rest []string) {
	if len(rest) < 2 {
		http.NotFound(w, r)
		return
	}
	compID, err := strconv.ParseUint(rest[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	action := rest[1]

	store.mu.Lock()
	aid := store.compTo[compID]
	a := store.archives[aid]
	store.mu.Unlock()
	if a == nil {
		http.NotFound(w, r)
		return
	}
	var comp *ComponentFile
	for _, c := range a.ComponentFiles {
		if c.ID == compID {
			comp = c
			break
		}
	}
	if comp == nil {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "signed_uri": // download : renvoie le composant avec get_url
		_, _ = io.Copy(io.Discard, r.Body)
		c := *comp
		c.GetURL = getURL(a, comp)
		writeJSON(w, http.StatusOK, map[string]any{"component_file": &c})
	case "update": // upload : renvoie le composant avec put_url
		_, _ = io.Copy(io.Discard, r.Body)
		comp.Status = "uploading"
		c := *comp
		c.ArchiveSize = nil
		c.EncodedArchiveDigest = nil
		c.PutURL = putURL(a, comp)
		writeJSON(w, http.StatusOK, map[string]any{"component_file": &c})
	case "finish_upload": // upload fini : {archive_size, encoded_archive_digest} → composant fixed
		var in struct {
			ArchiveSize          int64  `json:"archive_size"`
			EncodedArchiveDigest string `json:"encoded_archive_digest"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		comp.Status = "fixed"
		comp.ArchiveSize = pi64(in.ArchiveSize)
		comp.EncodedArchiveDigest = ps(in.EncodedArchiveDigest)
		store.persist(a)
		c := *comp
		c.GetURL, c.PutURL = "", ""
		writeJSON(w, http.StatusOK, map[string]any{"component_file": &c})
	default:
		http.NotFound(w, r)
	}
}

// ---------------------------------------------------------------------------
// scsi-download / scsi-upload — les blobs
// ---------------------------------------------------------------------------

// GET /<nsaId>/<appId>/<compId>_<index>.bin
func downloadBlob(w http.ResponseWriter, r *http.Request) {
	a, comp := blobLookup(r)
	if a == nil || comp == nil {
		log.Printf("[scsi] DOWNLOAD blob INTROUVABLE (lookup nil) path=%s", r.URL.Path)
		http.NotFound(w, r)
		return
	}
	bp := store.blobPath(a, comp.ID, comp.Index)
	f, err := os.Open(bp)
	if err != nil {
		log.Printf("[scsi] DOWNLOAD blob ABSENT sur disque: %s (comp=%d idx=%d) -> 404 (= la save précédente manque, le delta-upload va échouer)", bp, comp.ID, comp.Index)
		http.Error(w, "blob absent", http.StatusNotFound)
		return
	}
	log.Printf("[scsi] DOWNLOAD blob OK %s/%s comp=%d", a.NsaID, a.ApplicationID, comp.ID)
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

// PUT /<nsaId>/<appId>/<compId>_<index>.bin
func uploadBlob(w http.ResponseWriter, r *http.Request) {
	a, comp := blobLookup(r)
	if a == nil || comp == nil {
		http.NotFound(w, r)
		return
	}
	_ = os.MkdirAll(store.archiveDir(a), 0o755)
	f, err := os.Create(store.blobPath(a, comp.ID, comp.Index))
	if err != nil {
		http.Error(w, "write fail", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	n, _ := io.Copy(f, r.Body)
	log.Printf("[scsi] blob reçu %s/%s comp=%d %d o", a.NsaID, a.ApplicationID, comp.ID, n)
	w.WriteHeader(http.StatusOK)
}

// résout (archive, composant) depuis le path /<nsaId>/<appId>/<compId>_<index>.bin
func blobLookup(r *http.Request) (*Archive, *ComponentFile) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		return nil, nil
	}
	file := parts[len(parts)-1]           // <compId>_<index>.bin
	file = strings.TrimSuffix(file, ".bin")
	seg := strings.SplitN(file, "_", 2)
	if len(seg) != 2 {
		return nil, nil
	}
	compID, err := strconv.ParseUint(seg[0], 10, 64)
	if err != nil {
		return nil, nil
	}
	store.mu.Lock()
	a := store.archives[store.compTo[compID]]
	store.mu.Unlock()
	if a == nil {
		return nil, nil
	}
	for _, c := range a.ComponentFiles {
		if c.ID == compID {
			return a, c
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// policy.hac.lp1.scsi — policy par jeu (on autorise)
// ---------------------------------------------------------------------------

func policyAPI(w http.ResponseWriter, r *http.Request) {
	// GET /api/console/v2/application_policy/<titleId>/<ver>?dtoken=...
	// Vraie reponse measuremente = {"policy_type":"ALL_OK"} (autorise) / "ALL_NG" (bloque, ex. Splatoon).
	// On autorise TOUT -> cloud save Nextendo meme pour les jeux que Nintendo bloque.
	writeJSON(w, http.StatusOK, map[string]any{"policy_type": "ALL_OK"})
}

// ---------------------------------------------------------------------------
// Seeding (charge la save MK8 capturée si présente) — stub pour l'instant.
// ---------------------------------------------------------------------------

func seedFromCapture() {
	// Si /data/scsi contient déjà des archives (posées au déploiement), store.load() les a prises.
	// Le seeding depuis la trace (archive.json + key_seed + blobs) se fait via un script de deploy.
	if _, err := os.Stat(dataDir); err == nil {
		return
	}
}
