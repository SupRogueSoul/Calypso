package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu       sync.Mutex
	dbPath   string
	history  []ScanRecord
	quarantine []QuarantineRecord
	blocklist  []HashBlocklistEntry
}

type ScanRecord struct {
	ID        int64     `json:"id"`
	FilePath  string    `json:"file_path"`
	SHA256    string    `json:"sha256,omitempty"`
	MD5       string    `json:"md5,omitempty"`
	Verdict   string    `json:"verdict"`
	Score     float64   `json:"score"`
	Engines   string    `json:"engines,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type QuarantineRecord struct {
	ID             int64     `json:"id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path,omitempty"`
	SHA256         string    `json:"sha256,omitempty"`
	FileName       string    `json:"file_name"`
	Verdict        string    `json:"verdict"`
	Score          float64   `json:"score"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
}

type HashBlocklistEntry struct {
	SHA256  string `json:"sha256"`
	MD5     string `json:"md5,omitempty"`
	Verdict string `json:"verdict"`
	Source  string `json:"source"`
}

type dbData struct {
	History    []ScanRecord       `json:"history"`
	Quarantine []QuarantineRecord `json:"quarantine"`
	Blocklist  []HashBlocklistEntry `json:"blocklist"`
}

func New(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	s := &Store{
		dbPath: dbPath,
	}

	if err := s.load(); err != nil {
		return s, nil
	}

	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var d dbData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}

	s.history = d.History
	s.quarantine = d.Quarantine
	s.blocklist = d.Blocklist
	return nil
}

func (s *Store) save() error {
	d := dbData{
		History:    s.history,
		Quarantine: s.quarantine,
		Blocklist:  s.blocklist,
	}

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	// Write to a temp file in the same directory, then rename over the real
	// path so a crash mid-write can never leave a truncated/corrupt DB.
	dir := filepath.Dir(s.dbPath)
	tmp, err := os.CreateTemp(dir, "calypso-*.db.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.dbPath); err != nil {
		os.Remove(tmpName)
		return err
	}

	return nil
}

func (s *Store) Close() error {
	return nil
}

func (s *Store) nextID(history []ScanRecord) int64 {
	var maxID int64
	for _, r := range history {
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	return maxID + 1
}

func (s *Store) LogScan(rec ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.ID = s.nextID(s.history)
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	s.history = append(s.history, rec)

	if len(s.history) > 10000 {
		s.history = s.history[len(s.history)-10000:]
	}

	return s.save()
}

func (s *Store) GetHistory(limit int) ([]ScanRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 50
	}

	start := len(s.history) - limit
	if start < 0 {
		start = 0
	}

	result := make([]ScanRecord, len(s.history[start:]))
	copy(result, s.history[start:])

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}

func (s *Store) GetHistoryByID(id int64) (*ScanRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.history {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("record not found")
}

func (s *Store) LookupHash(sha256Hash string) (verdict, source string, found bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range s.blocklist {
		if e.SHA256 == sha256Hash {
			return e.Verdict, e.Source, true
		}
	}
	return "", "", false
}

func (s *Store) ListBlocklist() []HashBlocklistEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]HashBlocklistEntry, len(s.blocklist))
	copy(result, s.blocklist)
	return result
}

func (s *Store) AddToBlocklist(sha256Hash, md5Hash, verdict, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range s.blocklist {
		if e.SHA256 == sha256Hash {
			return nil
		}
	}

	s.blocklist = append(s.blocklist, HashBlocklistEntry{
		SHA256:  sha256Hash,
		MD5:     md5Hash,
		Verdict: verdict,
		Source:  source,
	})

	return s.save()
}

func (s *Store) AddQuarantine(rec QuarantineRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.ID = s.nextQuarantineID()
	if rec.QuarantinedAt.IsZero() {
		rec.QuarantinedAt = time.Now()
	}
	s.quarantine = append(s.quarantine, rec)

	return s.save()
}

func (s *Store) nextQuarantineID() int64 {
	var maxID int64
	for _, r := range s.quarantine {
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	return maxID + 1
}

func (s *Store) ListQuarantine() ([]QuarantineRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]QuarantineRecord, len(s.quarantine))
	copy(result, s.quarantine)

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}

func (s *Store) GetQuarantineByID(id int64) (*QuarantineRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range s.quarantine {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("quarantine record not found")
}

func (s *Store) RemoveQuarantine(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, r := range s.quarantine {
		if r.ID == id {
			s.quarantine = append(s.quarantine[:i], s.quarantine[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("quarantine record not found")
}
