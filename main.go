// nx-scsi — service de sauvegarde cloud (SCSI) pour Nextendo.
//
// Réplique le service Nintendo "scsi" capturé au measurement (voir memory nextendo-cloud-saves-scsi) :
//   - storage.hac.lp1.scsi.srv.nintendo.net  = l'API REST (/api/console/v3/...)
//   - scsi-download.lp1.scsi.srv.nintendo.net = download des blobs (on émet nos propres URLs)
//   - scsi-upload.lp1.scsi.srv.nintendo.net   = upload des blobs (variante nintendo, redirigée VPS)
//   - policy.hac.lp1.scsi.srv.nintendo.net    = policy par jeu
//
// Modèle : une SAVE = un "save_data_archive" (métadonnées) découpé en "component_files"
// (partitions : index 0 = meta, 4096+ = save). On stocke blobs + métadonnées sur disque et on
// les ressert tels quels → round-trip. La couche crypto (generate_key_seed_package challenge→
// réponse + encoded_mac) est REJOUÉE (on stocke le key_seed_package) : à valider console-side.
//
// stdlib uniquement (comme nx-dauth), CGO off, TLS self-signed, écoute :443, volume /data.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const dataDir = "/data/scsi"

// jwtPublicKey is the RSA public key used to verify JWT tokens from nx-dauth.
// Set via JWT_PUBLIC_KEY (PEM inline) or JWT_PUBLIC_KEY_PATH (file path).
// When neither is set, verification is skipped and a warning is logged at startup.
var jwtPublicKey *rsa.PublicKey

func init() {
	keyPEM := os.Getenv("JWT_PUBLIC_KEY")
	if keyPEM == "" {
		if p := os.Getenv("JWT_PUBLIC_KEY_PATH"); p != "" {
			if b, err := os.ReadFile(p); err == nil {
				keyPEM = string(b)
			} else {
				log.Printf("[scsi] WARNING: JWT_PUBLIC_KEY_PATH=%s: %v — JWT verification disabled", p, err)
			}
		}
	}
	if keyPEM != "" {
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil {
			log.Printf("[scsi] WARNING: JWT_PUBLIC_KEY: no PEM block found — JWT verification disabled")
		} else if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if rk, ok := key.(*rsa.PublicKey); ok {
				jwtPublicKey = rk
				log.Printf("[scsi] JWT verification enabled with RSA public key")
			} else {
				log.Printf("[scsi] WARNING: JWT_PUBLIC_KEY is not RSA — JWT verification disabled")
			}
		} else {
			log.Printf("[scsi] WARNING: JWT_PUBLIC_KEY: %v — JWT verification disabled", err)
		}
	} else {
		log.Printf("[scsi] WARNING: neither JWT_PUBLIC_KEY nor JWT_PUBLIC_KEY_PATH set — JWT signature verification DISABLED")
	}
}

// verifyJWT verifies the RS256 signature of a JWT and returns its claims.
func verifyJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: %d parts", len(parts))
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature encoding: %v", err)
	}

	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(jwtPublicKey, crypto.SHA256, hash[:], sig); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %v", err)
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// ---------------------------------------------------------------------------
// Modèle (JSON fidèle à la trace)
// ---------------------------------------------------------------------------

type ComponentFile struct {
	ID                   uint64  `json:"id"`
	Index                int     `json:"index"`     // 0 = meta, 4096.. = save
	Datatype             string  `json:"datatype"`  // "meta" | "save"
	Status               string  `json:"status"`    // "fixed" | "hand_over" | "uploading"
	ArchiveSize          *int64  `json:"archive_size"`
	EncodedArchiveDigest *string `json:"encoded_archive_digest"`
	GetURL               string  `json:"get_url,omitempty"`
	PutURL               string  `json:"put_url,omitempty"`
}

type Archive struct {
	ID                        uint64           `json:"id"`
	NsaID                     string           `json:"nsa_id"`
	ApplicationID             string           `json:"application_id"`
	DeviceID                  string           `json:"device_id"`
	DeviceSerial              string           `json:"device_serial"`
	DataSize                  int64            `json:"data_size"`
	Desc                      *string          `json:"desc"`
	SeriesID                  uint64           `json:"series_id"`
	Datatype                  int              `json:"datatype"`
	Status                    string           `json:"status"` // "fixed" | "uploading"
	AutoBackup                bool             `json:"auto_backup"`
	NumOfPartitions           int              `json:"num_of_partitions"`
	LaunchRequiredVersion     int              `json:"launch_required_version"`
	PreviousSaveDataArchiveID *uint64          `json:"previous_save_data_archive_id"`
	AcdIndex                  int              `json:"acd_index"`
	EncodedDigest             string           `json:"encoded_digest"`
	SavedAtAsUnixtime         int64            `json:"saved_at_as_unixtime"`
	FinishedAtAsUnixtime      *int64           `json:"finished_at_as_unixtime"`
	PlatformKeyGeneration     int              `json:"platform_key_generation"`
	TimeoutAtAsUnixtime       int64            `json:"timeout_at_as_unixtime,omitempty"`
	ComponentFiles            []*ComponentFile `json:"component_files,omitempty"`

	// interne (pas sérialisé dans les réponses) :
	KeySeedPackage string `json:"-"` // le encoded_key_seed_package rejoué au download
}

// ---------------------------------------------------------------------------
// Store (mémoire + persistance disque)
// ---------------------------------------------------------------------------

type Store struct {
	mu       sync.Mutex
	archives map[uint64]*Archive           // id -> archive
	compTo   map[uint64]uint64             // componentId -> archiveId (pour /component_files/<id>/...)
}

func newStore() *Store {
	return &Store{archives: map[uint64]*Archive{}, compTo: map[uint64]uint64{}}
}

func (s *Store) archiveDir(a *Archive) string {
	// [Sécurité] NsaID vient du token (sub) et ApplicationID du corps de requête, tous deux
	// contrôlés par le client. filepath.Join résout les "..", donc un composant piégé
	// ("../../..") permettrait d'écrire HORS de dataDir (path traversal). pathComp confine
	// chaque composant : tout ce qui n'est pas un identifiant sûr devient "_invalid_", ce qui
	// rend l'échappement impossible même si une valeur non validée arrivait jusqu'ici.
	return filepath.Join(dataDir, pathComp(a.NsaID), pathComp(a.ApplicationID), u64s(a.ID))
}

// safeIDComponent : un identifiant sûr pour UN composant de chemin — non vide, borné, et
// composé uniquement de [0-9a-zA-Z_-]. Les NSA id et application id sont des jetons hex/alnum,
// donc la règle est stricte volontairement (aucun "/", "\", "..", ":", ni caractère de contrôle).
func safeIDComponent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// pathComp renvoie s s'il est un composant de chemin sûr, sinon un placeholder fixe — de sorte
// qu'un NsaID/ApplicationID forgé ne puisse jamais sortir de dataDir.
func pathComp(s string) string {
	if safeIDComponent(s) {
		return s
	}
	return "_invalid_"
}

func (s *Store) persist(a *Archive) {
	dir := s.archiveDir(a)
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.MarshalIndent(a, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "archive.json"), b, 0o644)
}

func (s *Store) blobPath(a *Archive, compID uint64, index int) string {
	return filepath.Join(s.archiveDir(a), u64s(compID)+"_"+itoa(index)+".bin")
}

// index disque -> mémoire au démarrage
func (s *Store) load() {
	_ = filepath.Walk(dataDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "archive.json" {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		var a Archive
		if json.Unmarshal(b, &a) != nil {
			return nil
		}
		s.archives[a.ID] = &a
		for _, c := range a.ComponentFiles {
			s.compTo[c.ID] = a.ID
		}
		return nil
	})
	log.Printf("[scsi] %d archives chargées depuis %s", len(s.archives), dataDir)
}

var store = newStore()

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func u64s(v uint64) string { return strconv.FormatUint(v, 10) }
func itoa(v int) string    { return strconv.Itoa(v) }

func randU64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// nsaId extrait du Bearer (sub du JWT vérifié) ; fallback sur vide si le token est absent
// ou invalide. Quand jwtPublicKey est configuré, la signature RS256 est vérifiée — un token
// forgé ou altéré renvoie "" (l'appelant reçoit une réponse vide/404, pas un accès indu).
func nsaFromToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	claims, err := verifyJWT(token)
	if err != nil {
		log.Printf("[scsi] JWT verification FAILED from %s: %v", r.RemoteAddr, err)
		return ""
	}

	if sub, ok := claims["sub"].(string); ok && safeIDComponent(sub) {
		return sub
	}
	return ""
}

// clone superficiel + composants clonés (pour ajouter des URLs sans muter le store)
func cloneArchive(a *Archive) *Archive {
	c := *a
	c.ComponentFiles = make([]*ComponentFile, len(a.ComponentFiles))
	for i, cf := range a.ComponentFiles {
		cc := *cf
		c.ComponentFiles[i] = &cc
	}
	return &c
}

func p64(v uint64) *uint64 { return &v }
func pi64(v int64) *int64  { return &v }
func ps(v string) *string  { return &v }

// ---------------------------------------------------------------------------
// URLs de blob (nos propres "signed URLs" -> notre service)
// ---------------------------------------------------------------------------

func getURL(a *Archive, c *ComponentFile) string {
	return "https://scsi-download.lp1.scsi.srv.nintendo.net/" + a.NsaID + "/" + a.ApplicationID +
		"/" + u64s(c.ID) + "_" + itoa(c.Index) + ".bin?Expires=" + itoa(int(time.Now().Unix()+3600)) + "&nx=1"
}
func putURL(a *Archive, c *ComponentFile) string {
	return "https://scsi-upload.lp1.scsi.srv.nintendo.net/" + a.NsaID + "/" + a.ApplicationID +
		"/" + u64s(c.ID) + "_" + itoa(c.Index) + ".bin?Expires=" + itoa(int(time.Now().Unix()+3600)) + "&nx=1"
}

func main() {
	_ = os.MkdirAll(dataDir, 0o755)
	store.load()
	seedFromCapture()

	mux := http.NewServeMux()
	mux.HandleFunc("/", route)

	cert := selfSignedCert()
	srv := &http.Server{
		Addr:      ":443",
		Handler:   logMW(mux),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.NoClientCert},
	}
	log.Println("[scsi] nx-scsi en écoute :443 (storage/scsi-download/scsi-upload/policy)")
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

type statusRec struct {
	http.ResponseWriter
	code int
	n    int64
}

func (s *statusRec) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusRec) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.n += int64(n)
	return n, err
}

func logMW(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sr := &statusRec{ResponseWriter: w, code: 200}
		h.ServeHTTP(sr, r)
		// statut de CHAQUE requête -> on voit immédiatement laquelle échoue (4xx/5xx)
		log.Printf("[scsi] %d %s %s%s (%dB)", sr.code, r.Method, r.Host, r.URL.Path, sr.n)
	})
}

// route par HOST (le service termine le TLS et sert 4 hosts)
func route(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	switch {
	case strings.HasPrefix(host, "storage.hac.lp1.scsi"):
		storageAPI(w, r)
	case strings.HasPrefix(host, "scsi-download"):
		downloadBlob(w, r)
	case strings.HasPrefix(host, "scsi-upload"):
		uploadBlob(w, r)
	case strings.HasPrefix(host, "policy.hac.lp1.scsi"):
		policyAPI(w, r)
	default:
		http.NotFound(w, r)
	}
}
