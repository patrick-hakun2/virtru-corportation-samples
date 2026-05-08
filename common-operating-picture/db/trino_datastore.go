package db

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	_ "github.com/trinodb/trino-go-client/trino" // register "trino" sql driver
	trino "github.com/trinodb/trino-go-client/trino"
	geos "github.com/twpayne/go-geos"
	"github.com/virtru-corp/dsp-cop/pkg/config"
)

// TrinoDataStore implements DataStore using the TDF-Trino query engine.
//
// Reads are routed through Trino so the tdf_postgresql connector can
// transparently decrypt TDF-protected columns based on the caller's JWT
// entitlements.  The bearer token is forwarded as an AccessToken on a
// per-query sql.DB — the trino-go-client sets it as the HTTP Authorization
// header, which Trino's header-authenticator then validates.
//
// Writes (INSERT / UPDATE / DELETE) are also sent through Trino; the
// tdf_postgresql connector pushes them down to PostgreSQL.
type TrinoDataStore struct {
	db           *sql.DB
	serverURI    string // base URI, e.g. https://admin@host:8443
	catalog      string
	plainCatalog string // plain postgresql catalog (no TDF interception) for tdf_blob reads
	schema       string
	sslCertPath  string // PEM CA cert path for HTTPS (empty = system pool)

	// fallbackToken is a service-account JWT used when no user token is in context.
	// The TDF connector requires a JWT on every table access, so server-initiated
	// queries (e.g. src_type lookups) use this token.
	fallbackMu    sync.RWMutex
	fallbackToken string

	// signingSecret is the HMAC-SHA256 key used to sign tdf_policy rows on insert.
	// Must match tdf.policy-signing-secret in the Trino catalog properties file.
	signingSecret string

	// userDBs caches one sql.DB per access token so we don't open a new
	// Trino session (and Postgres connection) on every query. Each entry is
	// paired with its expiry time so expired connections are closed and evicted
	// rather than leaking indefinitely.
	userDBsMu sync.Mutex
	userDBs   map[string]*sql.DB
	userDBExp map[string]time.Time
}

// SetFallbackToken updates the service-account JWT used for queries that have
// no user bearer token in their context (e.g. src_type lookups on startup).
func (s *TrinoDataStore) SetFallbackToken(token string) {
	s.fallbackMu.Lock()
	s.fallbackToken = strings.TrimPrefix(token, "Bearer ")
	s.fallbackMu.Unlock()
}

func (s *TrinoDataStore) getFallbackToken() string {
	s.fallbackMu.RLock()
	defer s.fallbackMu.RUnlock()
	return s.fallbackToken
}

// NewTrinoDataStore opens a connection pool to Trino and pings it to verify
// connectivity.
func NewTrinoDataStore(cfg config.TrinoConfig) (*TrinoDataStore, error) {
	// The trino-go-client embeds the user inside the ServerURI.
	serverURI := cfg.URL
	if cfg.User != "" && !strings.Contains(serverURI, "@") {
		// Insert user into the URI: https://user@host:port
		serverURI = strings.Replace(serverURI, "://", "://"+cfg.User+"@", 1)
	}

	baseCfg := &trino.Config{
		ServerURI:   serverURI,
		Catalog:     cfg.Catalog,
		Schema:      cfg.Schema,
		SSLCertPath: cfg.SSLCertPath,
		// Placeholder so the startup ping query has a non-empty extra-credential
		// map. The Virtru agent's SessionRepresentationDelegate blindly accesses
		// values()[0]; an empty map causes AIOOBE in the Trino web UI query list.
		ExtraCredentials: map[string]string{"jwt": "n/a"},
	}
	baseDSN, err := baseCfg.FormatDSN()
	if err != nil {
		return nil, fmt.Errorf("formatting trino DSN: %w", err)
	}

	db, err := sql.Open("trino", baseDSN)
	if err != nil {
		return nil, fmt.Errorf("opening trino connection: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(10 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging trino at %s: %w", cfg.URL, err)
	}

	slog.Info("Trino connection established",
		slog.String("url", cfg.URL),
		slog.String("catalog", cfg.Catalog),
		slog.String("schema", cfg.Schema),
	)

	return &TrinoDataStore{
		db:            db,
		serverURI:     serverURI,
		catalog:       cfg.Catalog,
		plainCatalog:  "postgresql",
		schema:        cfg.Schema,
		sslCertPath:   cfg.SSLCertPath,
		signingSecret: cfg.PolicySigningSecret,
		userDBs:       make(map[string]*sql.DB),
		userDBExp:     make(map[string]time.Time),
	}, nil
}

// Close releases the underlying Trino connection pool and all cached user DBs.
func (s *TrinoDataStore) Close() error {
	s.userDBsMu.Lock()
	for _, db := range s.userDBs {
		db.Close()
	}
	s.userDBs = make(map[string]*sql.DB)
	s.userDBExp = make(map[string]time.Time)
	s.userDBsMu.Unlock()
	return s.db.Close()
}

// evictExpiredDBs closes and removes cached user DBs whose JWT has expired.
// Must be called with s.userDBsMu held.
func (s *TrinoDataStore) evictExpiredDBs() {
	now := time.Now()
	for token, exp := range s.userDBExp {
		if now.After(exp) {
			s.userDBs[token].Close()
			delete(s.userDBs, token)
			delete(s.userDBExp, token)
		}
	}
}

// jwtExpiry decodes the JWT exp claim without verifying the signature.
// Returns a zero time on any parse error (treated as already expired).
func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// jwtPreferredUsername decodes the JWT payload (without signature verification —
// Trino verifies it) and returns the preferred_username claim.
// Falls back to "admin" on any parse error.
func jwtPreferredUsername(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "admin"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "admin"
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "admin"
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	return claims.Sub
}

// serverURIForUser returns the ServerURI with the given username embedded,
// replacing whatever user is currently in the URI.
func serverURIForUser(baseURI, user string) string {
	// Strip existing user (e.g. https://admin@host → https://host)
	if at := strings.Index(baseURI, "@"); at != -1 {
		scheme := baseURI[:strings.Index(baseURI, "//")+2]
		rest := baseURI[at+1:]
		baseURI = scheme + rest
	}
	return strings.Replace(baseURI, "://", "://"+user+"@", 1)
}

// dbForCtx returns a *sql.DB scoped to the bearer token in ctx.
// User-scoped DBs are cached by token so only one Trino session (and therefore
// one Postgres connection) is maintained per active user rather than creating a
// fresh sql.DB — and a fresh Postgres connection — on every query.
// When no user token is present the service-account fallback token is used.
// The returned cleanup func is a no-op; the DB lives in the cache.
func (s *TrinoDataStore) dbForCtx(ctx context.Context) (db *sql.DB, cleanup func(), err error) {
	token := strings.TrimPrefix(trinoAuthTokenFromContext(ctx), "Bearer ")
	if token == "" {
		token = s.getFallbackToken()
	}
	if token == "" {
		// No token at all — return base pool; query will fail at Trino with a
		// meaningful auth error rather than a nil-pointer panic.
		return s.db, func() {}, nil
	}

	s.userDBsMu.Lock()
	s.evictExpiredDBs()
	if cached, ok := s.userDBs[token]; ok {
		s.userDBsMu.Unlock()
		return cached, func() {}, nil
	}

	// Derive the Trino user from the JWT so X-Trino-User matches the
	// authenticated principal and Trino doesn't reject it as impersonation.
	user := jwtPreferredUsername(token)
	serverURI := serverURIForUser(s.serverURI, user)

	dsn, err := (&trino.Config{
		ServerURI:   serverURI,
		Catalog:     s.catalog,
		Schema:      s.schema,
		AccessToken: token,
		SSLCertPath: s.sslCertPath,
		// The Virtru TDF agent's SessionRepresentationDelegate reads the user JWT
		// from session.getExtraCredentials().values()[0] when the web UI lists
		// queries. Without this, the agent throws ArrayIndexOutOfBoundsException
		// (→ HTTP 500) because AccessToken only sets the Authorization header,
		// not the Trino extra-credential map.
		ExtraCredentials: map[string]string{"jwt": token},
	}).FormatDSN()
	if err != nil {
		s.userDBsMu.Unlock()
		return nil, nil, fmt.Errorf("formatting trino DSN with token: %w", err)
	}

	authedDB, err := sql.Open("trino", dsn)
	if err != nil {
		s.userDBsMu.Unlock()
		return nil, nil, fmt.Errorf("opening token-scoped trino connection: %w", err)
	}
	authedDB.SetMaxOpenConns(3)
	authedDB.SetMaxIdleConns(1)
	authedDB.SetConnMaxLifetime(10 * time.Minute)

	s.userDBs[token] = authedDB
	s.userDBExp[token] = jwtExpiry(token)
	s.userDBsMu.Unlock()
	return authedDB, func() {}, nil
}

// table returns the fully-qualified Trino table reference catalog.schema.table.
func (s *TrinoDataStore) table(name string) string {
	return fmt.Sprintf("%s.%s.%s", s.catalog, s.schema, name)
}

// plainTable returns the fully-qualified table reference using the plain
// postgresql catalog (no TDF interception), used for reads that include tdf_blob.
func (s *TrinoDataStore) plainTable(name string) string {
	return fmt.Sprintf("%s.%s.%s", s.plainCatalog, s.schema, name)
}

// parseGeoJSON converts a nullable GeoJSON string (from to_geojson_geometry) into a
// *geos.Geom.  Returns nil when the string is empty or NULL.
func parseGeoJSON(raw sql.NullString) (*geos.Geom, error) {
	if !raw.Valid || raw.String == "" {
		return nil, nil
	}
	g, err := geos.NewGeomFromGeoJSON(raw.String)
	if err != nil {
		return nil, fmt.Errorf("parsing GeoJSON from Trino: %w", err)
	}
	return g, nil
}

// logTdfFilter logs TDF row-filtering telemetry for the List* operations.
// It queries the plain (non-TDF) catalog to get the unfiltered row count for
// the same src_type + time window, then compares that with the number of rows
// Trino actually returned after applying the caller's TDF policy entitlements.
func (s *TrinoDataStore) logTdfFilter(ctx context.Context, authedDB *sql.DB, table string, returned int, srcType string, start, end time.Time, extraFilters ...string) {
	token := strings.TrimPrefix(trinoAuthTokenFromContext(ctx), "Bearer ")
	if token == "" {
		token = s.getFallbackToken()
	}
	user := jwtPreferredUsername(token)

	var total int
	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE src_type = ? AND ts >= ? AND ts <= ?`, s.plainTable(table))
	if err := authedDB.QueryRowContext(ctx, countQ, srcType, start, end).Scan(&total); err != nil {
		slog.Warn("TDF filter audit: plain count failed", slog.String("error", err.Error()))
		return
	}

	filters := append([]string{"tdf_policy"}, extraFilters...)
	slog.Info("TDF row filter",
		slog.String("user", user),
		slog.String("table", table),
		slog.String("src_type", srcType),
		slog.Int("total_rows", total),
		slog.Int("returned_rows", returned),
		slog.Int("filtered_rows", total-returned),
		slog.Any("filters_applied", filters),
	)
}

// ── TDF object reads ──────────────────────────────────────────────────────────

const trinoGetTdfObject = `
SELECT
    CAST(id AS VARCHAR)          AS id,
    ts,
    src_type,
    to_geojson_geometry(to_spherical_geography(geo)) AS geo,
    JSON_FORMAT(search)           AS search,
    JSON_FORMAT(metadata)         AS metadata,
    tdf_blob,
    CAST(tdf_uri  AS VARCHAR)    AS tdf_uri
FROM %s
WHERE id = CAST(? AS UUID)
LIMIT 1
`

func (s *TrinoDataStore) GetTdfObject(ctx context.Context, id uuid.UUID) (GetTdfObjectRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return GetTdfObjectRow{}, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoGetTdfObject, s.table("tdf_objects"))
	row := db.QueryRowContext(ctx, q, id.String())

	var (
		idStr, srcType     string
		ts                 time.Time
		geoRaw, search     sql.NullString
		metadata, tdfURI   sql.NullString
		tdfBlob            []byte
	)
	if err := row.Scan(&idStr, &ts, &srcType, &geoRaw, &search, &metadata, &tdfBlob, &tdfURI); err != nil {
		return GetTdfObjectRow{}, err
	}
	parsedID, err := uuid.Parse(idStr)
	if err != nil {
		return GetTdfObjectRow{}, fmt.Errorf("parsing uuid %q: %w", idStr, err)
	}
	geom, err := parseGeoJSON(geoRaw)
	if err != nil {
		return GetTdfObjectRow{}, err
	}
	return GetTdfObjectRow{
		ID:       parsedID,
		Ts:       pgtype.Timestamp{Time: ts, Valid: true},
		SrcType:  srcType,
		Geo:      geom,
		Search:   []byte(search.String),
		Metadata: []byte(metadata.String),
		TdfBlob:  tdfBlob,
		TdfUri:   pgtype.Text{String: tdfURI.String, Valid: tdfURI.Valid},
	}, nil
}

const trinoListTdfObjects = `
SELECT
    CAST(id AS VARCHAR)          AS id,
    ts,
    src_type,
    to_geojson_geometry(to_spherical_geography(geo)) AS geo,
    JSON_FORMAT(search)           AS search,
    JSON_FORMAT(metadata)         AS metadata,
    tdf_blob,
    CAST(tdf_uri  AS VARCHAR)    AS tdf_uri
FROM %s
WHERE src_type = ? AND ts >= ? AND ts <= ?
ORDER BY ts DESC
`

func (s *TrinoDataStore) ListTdfObjects(ctx context.Context, arg ListTdfObjectsParams) ([]ListTdfObjectsRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoListTdfObjects, s.table("tdf_objects"))
	rows, err := db.QueryContext(ctx, q, arg.SourceType, arg.StartTime.Time, arg.EndTime.Time)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanTdfObjectRows[ListTdfObjectsRow](rows, func(r tdfObjectScanResult) ListTdfObjectsRow {
		return ListTdfObjectsRow(r)
	})
	if err != nil {
		return nil, err
	}
	s.logTdfFilter(ctx, db, "tdf_objects", len(items), arg.SourceType, arg.StartTime.Time, arg.EndTime.Time)
	return items, nil
}

const trinoListTdfObjectsWithGeo = `
SELECT
    CAST(id AS VARCHAR)          AS id,
    ts,
    src_type,
    to_geojson_geometry(to_spherical_geography(geo)) AS geo,
    JSON_FORMAT(search)           AS search,
    JSON_FORMAT(metadata)         AS metadata,
    tdf_blob,
    CAST(tdf_uri  AS VARCHAR)    AS tdf_uri
FROM %s
WHERE src_type = ? AND ts >= ? AND ts <= ?
  AND ST_Within(geo, to_geometry(from_geojson_geometry(?)))
ORDER BY ts DESC
`

func (s *TrinoDataStore) ListTdfObjectsWithGeo(ctx context.Context, arg ListTdfObjectsWithGeoParams) ([]ListTdfObjectsWithGeoRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoListTdfObjectsWithGeo, s.table("tdf_objects"))
	rows, err := db.QueryContext(ctx, q,
		arg.SourceType, arg.StartTime.Time, arg.EndTime.Time, arg.Geometry)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanTdfObjectRows[ListTdfObjectsWithGeoRow](rows, func(r tdfObjectScanResult) ListTdfObjectsWithGeoRow {
		return ListTdfObjectsWithGeoRow(r)
	})
	if err != nil {
		return nil, err
	}
	s.logTdfFilter(ctx, db, "tdf_objects", len(items), arg.SourceType, arg.StartTime.Time, arg.EndTime.Time, "geo")
	return items, nil
}

const trinoListTdfObjectsWithSearch = `
SELECT
    CAST(id AS VARCHAR)          AS id,
    ts,
    src_type,
    to_geojson_geometry(to_spherical_geography(geo)) AS geo,
    JSON_FORMAT(search)           AS search,
    JSON_FORMAT(metadata)         AS metadata,
    tdf_blob,
    CAST(tdf_uri  AS VARCHAR)    AS tdf_uri
FROM %s
WHERE src_type = ? AND ts >= ? AND ts <= ?
  AND CAST(search AS VARCHAR) LIKE ?
ORDER BY ts DESC
`

func (s *TrinoDataStore) ListTdfObjectsWithSearch(ctx context.Context, arg ListTdfObjectsWithSearchParams) ([]ListTdfObjectsWithSearchRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoListTdfObjectsWithSearch, s.table("tdf_objects"))
	rows, err := db.QueryContext(ctx, q,
		arg.SourceType, arg.StartTime.Time, arg.EndTime.Time, "%"+string(arg.Search)+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanTdfObjectRows[ListTdfObjectsWithSearchRow](rows, func(r tdfObjectScanResult) ListTdfObjectsWithSearchRow {
		return ListTdfObjectsWithSearchRow(r)
	})
	if err != nil {
		return nil, err
	}
	s.logTdfFilter(ctx, db, "tdf_objects", len(items), arg.SourceType, arg.StartTime.Time, arg.EndTime.Time, "search")
	return items, nil
}

const trinoListTdfObjectsWithSearchAndGeo = `
SELECT
    CAST(id AS VARCHAR)          AS id,
    ts,
    src_type,
    to_geojson_geometry(to_spherical_geography(geo)) AS geo,
    JSON_FORMAT(search)           AS search,
    JSON_FORMAT(metadata)         AS metadata,
    tdf_blob,
    CAST(tdf_uri  AS VARCHAR)    AS tdf_uri
FROM %s
WHERE src_type = ? AND ts >= ? AND ts <= ?
  AND CAST(search AS VARCHAR) LIKE ?
  AND ST_Within(geo, to_geometry(from_geojson_geometry(?)))
ORDER BY ts DESC
`

func (s *TrinoDataStore) ListTdfObjectsWithSearchAndGeo(ctx context.Context, arg ListTdfObjectsWithSearchAndGeoParams) ([]ListTdfObjectsWithSearchAndGeoRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoListTdfObjectsWithSearchAndGeo, s.table("tdf_objects"))
	rows, err := db.QueryContext(ctx, q,
		arg.SourceType, arg.StartTime.Time, arg.EndTime.Time,
		"%"+string(arg.Search)+"%", arg.Geometry)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanTdfObjectRows[ListTdfObjectsWithSearchAndGeoRow](rows, func(r tdfObjectScanResult) ListTdfObjectsWithSearchAndGeoRow {
		return ListTdfObjectsWithSearchAndGeoRow(r)
	})
	if err != nil {
		return nil, err
	}
	s.logTdfFilter(ctx, db, "tdf_objects", len(items), arg.SourceType, arg.StartTime.Time, arg.EndTime.Time, "geo", "search")
	return items, nil
}

// tdfObjectScanResult is the common row shape for all tdf_objects SELECT queries.
// It mirrors ListTdfObjectsRow / ListTdfObjectsWithGeoRow etc., which are
// identical structs — the generic helper converts between them.
type tdfObjectScanResult struct {
	ID       uuid.UUID
	Ts       pgtype.Timestamp
	SrcType  string
	Geo      interface{}
	Search   []byte
	Metadata []byte
	TdfBlob  []byte
	TdfUri   pgtype.Text
}

// scanTdfObjectRows scans the common tdf_objects column set and maps each row
// into the target type T using the provided converter.
func scanTdfObjectRows[T any](rows *sql.Rows, convert func(tdfObjectScanResult) T) ([]T, error) {
	var items []T
	for rows.Next() {
		var (
			idStr              string
			ts                 time.Time
			srcType            string
			geoRaw, search     sql.NullString
			metadata, tdfURI   sql.NullString
			tdfBlob            []byte
		)
		if err := rows.Scan(&idStr, &ts, &srcType, &geoRaw, &search, &metadata, &tdfBlob, &tdfURI); err != nil {
			return nil, err
		}
		parsedID, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("parsing uuid %q: %w", idStr, err)
		}
		geom, err := parseGeoJSON(geoRaw)
		if err != nil {
			return nil, err
		}
		items = append(items, convert(tdfObjectScanResult{
			ID:       parsedID,
			Ts:       pgtype.Timestamp{Time: ts, Valid: true},
			SrcType:  srcType,
			Geo:      geom,
			Search:   []byte(search.String),
			Metadata: []byte(metadata.String),
			TdfBlob:  tdfBlob,
			TdfUri:   pgtype.Text{String: tdfURI.String, Valid: tdfURI.Valid},
		}))
	}
	return items, rows.Err()
}

// ── TDF policy helpers ────────────────────────────────────────────────────────

// toStringSlice converts a raw JSON value (string or array of strings) to []string.
func toStringSlice(raw json.RawMessage) []string {
	if raw == nil {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	return nil
}

// buildTdfPolicy constructs the tdf_policy JSON string from the object's search
// attributes. The canonical form is HMAC-SHA256 signed with secret so Trino can
// verify integrity on every read.
//
// Policy structure mirrors the client-side logic in attributes.ts:
//   - default_policy: classification + needToKnow (user must have ALL)
//   - tdf_policies:   each relTo value as its own group (user needs ANY one)
func buildTdfPolicy(search []byte, secret string) string {
	defaultPolicy := []string{}
	tdfPolicies := [][]string{}

	if len(search) > 0 && string(search) != "null" {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(search, &m); err == nil {
			classification := toStringSlice(m["attrClassification"])
			needToKnow := toStringSlice(m["attrNeedToKnow"])
			relTo := toStringSlice(m["attrRelTo"])

			defaultPolicy = append(defaultPolicy, classification...)
			defaultPolicy = append(defaultPolicy, needToKnow...)
			sort.Strings(defaultPolicy)

			for _, r := range relTo {
				tdfPolicies = append(tdfPolicies, []string{r})
			}
			sort.Slice(tdfPolicies, func(i, j int) bool {
				fi, fj := "", ""
				if len(tdfPolicies[i]) > 0 {
					fi = tdfPolicies[i][0]
				}
				if len(tdfPolicies[j]) > 0 {
					fj = tdfPolicies[j][0]
				}
				return fi < fj
			})
		} else {
			slog.Warn("buildTdfPolicy: failed to parse search JSON; using open policy", slog.String("error", err.Error()))
		}
	}

	type canonicalDoc struct {
		TdfPolicies   [][]string `json:"tdf_policies"`
		DefaultPolicy []string   `json:"default_policy"`
	}
	canonical, _ := json.Marshal(canonicalDoc{TdfPolicies: tdfPolicies, DefaultPolicy: defaultPolicy})

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	tag := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	type fullDoc struct {
		TdfPolicies   [][]string `json:"tdf_policies"`
		DefaultPolicy []string   `json:"default_policy"`
		PolicyTag     string     `json:"policy_tag"`
	}
	full, _ := json.Marshal(fullDoc{TdfPolicies: tdfPolicies, DefaultPolicy: defaultPolicy, PolicyTag: tag})
	return string(full)
}

// ── TDF object writes ─────────────────────────────────────────────────────────

// pgQL escapes a string for use as a PostgreSQL string literal (single-quote style).
func pgQL(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// InsertTdfObject inserts a row into tdf_objects via Trino.
// The UUID is generated client-side because Trino does not support RETURNING.
//
// Uses system.execute passthrough because the TDF JDBC connector's beginInsert
// returns null write-mappings for jsonb and bytea column types, causing an NPE.
func (s *TrinoDataStore) InsertTdfObject(ctx context.Context, arg CreateTdfObjectsParams) (uuid.UUID, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer cleanup()

	id := uuid.New()
	tdfURI := ""
	if arg.TdfUri.Valid {
		tdfURI = arg.TdfUri.String
	}

	var geoExpr string
	if arg.Geo != nil {
		geoExpr = "ST_GeomFromGeoJSON(" + pgQL(arg.Geo.ToGeoJSON(0)) + ")"
	} else {
		geoExpr = "NULL"
	}

	tdfPolicy := buildTdfPolicy(arg.Search, s.signingSecret)

	innerSQL := fmt.Sprintf(
		"INSERT INTO %s.tdf_objects (id, ts, src_type, geo, search, metadata, tdf_blob, tdf_uri, tdf_policy) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, decode(%s, 'hex'), %s, %s::jsonb)",
		s.schema,
		pgQL(id.String()),
		pgQL(arg.Ts.Time.UTC().Format("2006-01-02 15:04:05.999999")),
		pgQL(arg.SrcType),
		geoExpr,
		pgQL(string(arg.Search)),
		pgQL(string(arg.Metadata)),
		pgQL(fmt.Sprintf("%x", arg.TdfBlob)),
		pgQL(tdfURI),
		pgQL(tdfPolicy),
	)

	callSQL := fmt.Sprintf("CALL %s.system.execute(query => '%s')",
		s.catalog, strings.ReplaceAll(innerSQL, "'", "''"))
	_, err = db.ExecContext(ctx, callSQL)
	if err != nil {
		return uuid.Nil, fmt.Errorf("trino insert tdf_object: %w", err)
	}
	return id, nil
}

const trinoUpdateTdfObject = `
UPDATE %s
SET ts       = COALESCE(CAST(? AS TIMESTAMP), ts),
    src_type = COALESCE(?, src_type),
    tdf_blob = COALESCE(?, tdf_blob),
    tdf_uri  = COALESCE(?, tdf_uri)
WHERE id = CAST(? AS UUID)
`

func (s *TrinoDataStore) UpdateTdfObject(ctx context.Context, arg UpdateTdfObjectParams) (UpdateTdfObjectRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return UpdateTdfObjectRow{}, err
	}
	defer cleanup()

	var tsVal interface{}
	if arg.Ts.Valid {
		tsVal = arg.Ts.Time.UTC().Format(time.RFC3339Nano)
	}
	var srcType interface{}
	if arg.SrcType.Valid {
		srcType = arg.SrcType.String
	}
	var tdfURI interface{}
	if arg.TdfUri.Valid {
		tdfURI = arg.TdfUri.String
	}

	q := fmt.Sprintf(trinoUpdateTdfObject, s.table("tdf_objects"))
	_, err = db.ExecContext(ctx, q, tsVal, srcType, arg.TdfBlob, tdfURI, arg.ID.String())
	if err != nil {
		return UpdateTdfObjectRow{}, fmt.Errorf("trino update tdf_object: %w", err)
	}
	return UpdateTdfObjectRow{ID: arg.ID, SrcType: arg.SrcType.String, Ts: arg.Ts}, nil
}

const trinoDeleteTdfObject = `DELETE FROM %s WHERE id = CAST(? AS UUID)`

func (s *TrinoDataStore) DeleteTdfObject(ctx context.Context, id uuid.UUID) (TdfObject, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return TdfObject{}, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoDeleteTdfObject, s.table("tdf_objects"))
	if _, err = db.ExecContext(ctx, q, id.String()); err != nil {
		return TdfObject{}, fmt.Errorf("trino delete tdf_object: %w", err)
	}
	return TdfObject{ID: id}, nil
}

// ── TDF note operations ───────────────────────────────────────────────────────

const trinoGetNoteByID = `
SELECT
    CAST(id        AS VARCHAR) AS id,
    ts,
    CAST(parent_id AS VARCHAR) AS parent_id,
    tdf_blob,
    JSON_FORMAT(search)        AS search,
    CAST(tdf_uri   AS VARCHAR) AS tdf_uri
FROM %s
WHERE id = CAST(? AS UUID)
LIMIT 1
`

func (s *TrinoDataStore) GetNoteByID(ctx context.Context, id uuid.UUID) (GetNoteByIDRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return GetNoteByIDRow{}, err
	}
	defer cleanup()

	// Notes tdf_blob is created by the JS SDK with EMBEDDED_POLICY_ENCRYPTED; the TDF connector
	// requires EMBEDDED_POLICY_PLAIN_TEXT and rejects the blob at read time. Use the plain catalog
	// to bypass blob interception. Row-level access control is enforced on the parent tdf_objects
	// row, which is always fetched through the TDF connector before notes are displayed.
	q := fmt.Sprintf(trinoGetNoteByID, s.plainTable("tdf_notes"))
	row := db.QueryRowContext(ctx, q, id.String())

	var (
		idStr, parentIDStr string
		ts                 time.Time
		tdfBlob            []byte
		search, tdfURI     sql.NullString
	)
	if err := row.Scan(&idStr, &ts, &parentIDStr, &tdfBlob, &search, &tdfURI); err != nil {
		return GetNoteByIDRow{}, err
	}
	parsedID, err := uuid.Parse(idStr)
	if err != nil {
		return GetNoteByIDRow{}, fmt.Errorf("parsing note uuid %q: %w", idStr, err)
	}
	parsedParentID, err := uuid.Parse(parentIDStr)
	if err != nil {
		return GetNoteByIDRow{}, fmt.Errorf("parsing parent uuid %q: %w", parentIDStr, err)
	}
	return GetNoteByIDRow{
		ID:       parsedID,
		Ts:       pgtype.Timestamp{Time: ts, Valid: true},
		ParentID: parsedParentID,
		TdfBlob:  tdfBlob,
		Search:   []byte(search.String),
		TdfUri:   pgtype.Text{String: tdfURI.String, Valid: tdfURI.Valid},
	}, nil
}

const trinoGetNotesFromPar = `
SELECT
    CAST(id        AS VARCHAR) AS id,
    ts,
    CAST(parent_id AS VARCHAR) AS parent_id,
    JSON_FORMAT(search)        AS search,
    tdf_blob,
    CAST(tdf_uri   AS VARCHAR) AS tdf_uri
FROM %s
WHERE parent_id = CAST(? AS UUID)
`

func (s *TrinoDataStore) GetNotesFromPar(ctx context.Context, parentID uuid.UUID) ([]GetNotesFromParRow, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Same reason as GetNoteByID: use plain catalog to avoid TDF connector blob interception.
	q := fmt.Sprintf(trinoGetNotesFromPar, s.plainTable("tdf_notes"))
	rows, err := db.QueryContext(ctx, q, parentID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []GetNotesFromParRow
	for rows.Next() {
		var (
			idStr, parentIDStr string
			ts                 time.Time
			tdfBlob            []byte
			search, tdfURI     sql.NullString
		)
		if err := rows.Scan(&idStr, &ts, &parentIDStr, &search, &tdfBlob, &tdfURI); err != nil {
			return nil, err
		}
		parsedID, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("parsing note uuid %q: %w", idStr, err)
		}
		parsedParentID, err := uuid.Parse(parentIDStr)
		if err != nil {
			return nil, fmt.Errorf("parsing parent uuid %q: %w", parentIDStr, err)
		}
		items = append(items, GetNotesFromParRow{
			ID:       parsedID,
			Ts:       pgtype.Timestamp{Time: ts, Valid: true},
			ParentID: parsedParentID,
			Search:   []byte(search.String),
			TdfBlob:  tdfBlob,
			TdfUri:   pgtype.Text{String: tdfURI.String, Valid: tdfURI.Valid},
		})
	}
	return items, rows.Err()
}

// InsertNoteObject inserts a row into tdf_notes via Trino.
// UUID is generated client-side since Trino does not support RETURNING.
//
// Uses system.execute passthrough because the TDF JDBC connector's beginInsert
// returns null write-mappings for jsonb and bytea column types, causing an NPE.
func (s *TrinoDataStore) InsertNoteObject(ctx context.Context, arg CreateNoteObjectParams) (uuid.UUID, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer cleanup()

	id := uuid.New()
	tdfURI := ""
	if arg.TdfUri.Valid {
		tdfURI = arg.TdfUri.String
	}

	tdfPolicy := buildTdfPolicy(arg.Search, s.signingSecret)

	innerSQL := fmt.Sprintf(
		"INSERT INTO %s.tdf_notes (id, ts, parent_id, search, tdf_blob, tdf_uri, tdf_policy) VALUES (%s, %s, %s, %s::jsonb, decode(%s, 'hex'), %s, %s::jsonb)",
		s.schema,
		pgQL(id.String()),
		pgQL(arg.Ts.Time.UTC().Format("2006-01-02 15:04:05.999999")),
		pgQL(arg.ParentID.String()),
		pgQL(string(arg.Search)),
		pgQL(fmt.Sprintf("%x", arg.TdfBlob)),
		pgQL(tdfURI),
		pgQL(tdfPolicy),
	)

	callSQL := fmt.Sprintf("CALL %s.system.execute(query => '%s')",
		s.catalog, strings.ReplaceAll(innerSQL, "'", "''"))
	_, err = db.ExecContext(ctx, callSQL)
	if err != nil {
		return uuid.Nil, fmt.Errorf("trino insert tdf_note: %w", err)
	}
	return id, nil
}

// ── Source type operations ────────────────────────────────────────────────────

const trinoListSrcTypes = `SELECT id FROM %s`

func (s *TrinoDataStore) ListSrcTypes(ctx context.Context) ([]string, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoListSrcTypes, s.plainTable("src_types"))
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

const trinoGetSrcType = `
SELECT
    id,
    JSON_FORMAT(form_schema)     AS form_schema,
    JSON_FORMAT(ui_schema)       AS ui_schema,
    JSON_FORMAT(metadata)        AS metadata
FROM %s
WHERE id = ?
`

func (s *TrinoDataStore) GetSrcType(ctx context.Context, id string) (SrcType, error) {
	db, cleanup, err := s.dbForCtx(ctx)
	if err != nil {
		return SrcType{}, err
	}
	defer cleanup()

	q := fmt.Sprintf(trinoGetSrcType, s.plainTable("src_types"))
	row := db.QueryRowContext(ctx, q, id)

	var (
		srcID                          string
		formSchema, uiSchema, metadata sql.NullString
	)
	if err := row.Scan(&srcID, &formSchema, &uiSchema, &metadata); err != nil {
		return SrcType{}, err
	}
	return SrcType{
		ID:         srcID,
		FormSchema: []byte(formSchema.String),
		UiSchema:   []byte(uiSchema.String),
		Metadata:   []byte(metadata.String),
	}, nil
}
